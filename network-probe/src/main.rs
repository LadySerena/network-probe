#![deny(clippy::correctness)]
#![warn(clippy::style)]
#![warn(clippy::complexity)]
#![warn(clippy::suspicious)]
#![deny(deprecated)]
#![warn(clippy::perf)]

use anyhow::bail;
use anyhow::Error;
use clap::Parser;
use egress::egress_types::event;
use k8s_cri::v1::runtime_service_client::RuntimeServiceClient;
use k8s_cri::v1::ContainerStatusRequest;
use regex::Regex;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use tonic::transport::Endpoint;
use tonic::transport::Uri;
use tower::service_fn;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
mod egress {
    include!(concat!(env!("OUT_DIR"), "/egress.skel.rs"));
}
use anyhow::Result;
unsafe impl Plain for egress_types::event {}
use egress::*;
use libbpf_rs::RingBufferBuilder;
use plain::Plain;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(short, long)]
    ancestor_level: i32,
    #[arg(short = 'c', long)]
    cri_socket: PathBuf,
    #[arg(short = 'g', long)]
    cgroup_path: PathBuf,
}

async fn post_process(cri_socket_path: PathBuf, event: event) -> Result<(String, String)> {
    let re = Regex::new(r"(cri-containerd-)?([^\.]+)")?;
    // TODO pass this in instead of creating a connection for every event
    let channel = Endpoint::try_from("http://[::]")?
        .connect_with_connector(service_fn(move |_: Uri| {
            UnixStream::connect(cri_socket_path.clone())
        }))
        .await?;
    let mut client = RuntimeServiceClient::new(channel);
    let cgroup_path = get_cgroup_path_from_pid(event.pid)?;
    let container_id: String = {
        let this = cgroup_path.split('/').last();
        match this {
            Some(val) => val,
            None => {
                return Err(Error::msg(format!(
                    "failed to find container_id from cgroup: {cgroup_path}"
                )));
            }
        }
    }
    .to_string();
    let clean_id = {
        let this = {
            let this = re.captures(&container_id);
            match this {
                Some(val) => val,
                None => return Err(Error::msg("regex failed match")),
            }
        }
        .get(2);
        match this {
            Some(val) => val,
            None => return Err(Error::msg("not found in 1")),
        }
    };
    let request = ContainerStatusRequest {
        container_id: clean_id.as_str().to_string(),
        verbose: true,
    };
    let response = client.container_status(request).await?.into_inner();
    let status = {
        let this = response.status;
        match this {
            Some(val) => val,
            None => {
                return Err(Error::msg(format!(
                    "could not retrieve pod status from {}",
                    container_id.clone()
                )));
            }
        }
    }
    .labels;
    let pod_name = {
        let this = status.get("io.kubernetes.pod.name");
        match this {
            Some(val) => val,
            None => {
                return Err(Error::msg(format!(
                    "could not retrive pod name from metadata for container: {container_id}"
                )))
            }
        }
    };
    let namespace = {
        let this = status.get("io.kubernetes.pod.namespace");
        match this {
            Some(val) => val,
            None => {
                return Err(Error::msg(format!(
                    "could not retrieve pod namespace for pod: {pod_name}"
                )))
            }
        }
    };
    Ok((pod_name.to_string(), namespace.to_string()))
}

// upstream uses this to bump memory limits for the probes
fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_cgroup_path_from_pid(pid: i32) -> Result<String> {
    let proc_info = procfs::process::Process::new(pid)?;
    // This is for systems with cgroup v2 so we can assume process and cgroup is 1:1
    let binding = proc_info.cgroups()?;
    let cgroups = {
        let this = binding.0.first();
        match this {
            Some(val) => val,
            None => return Err(Error::msg(format!("could not find cgroup for pid: {pid}"))),
        }
    };
    Ok(cgroups.pathname.clone())
}

fn measure_egress(data: &[u8]) -> event {
    let mut event = egress_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("data buffer too short");
    event
}

fn main() {
    let opts = Cli::parse();
    let skeleton_builder = EgressSkelBuilder::default();

    {
        let this = bump_memlock_rlimit();
        match this {
            Ok(t) => t,
            Err(e) => {
                println!("{e}");
                println!("couldn't increase memory limit, no exiting");
                return;
            }
        }
    };
    let mut open_skeleton = skeleton_builder.open().expect("couldn't open skeleton");

    open_skeleton.rodata_mut().ancestor_level = opts.ancestor_level;

    let mut skeleton = open_skeleton.load().expect("couldn't load from skeleton");
    skeleton.attach().expect("couldn't attach ebpf program");

    let mut ring_buffer_builder = RingBufferBuilder::new();
    let mut skeleton_maps = skeleton.maps_mut();
    let ring_buffer_callback = |data: &[u8]| -> i32 {
        let event = measure_egress(data);
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("couldn't build tokio runtime");
        let cri_socket_path = opts.cri_socket.clone();
        let handle = runtime.spawn(post_process(cri_socket_path, event));
        let info = {
            let this = runtime
                .block_on(handle)
                .expect("error occurred during runtime blocking");
            match this {
                Ok(t) => t,
                Err(e) => {
                    println!("{e}");
                    return 0;
                }
            }
        };
        println!(
            "pod: {0}, namespace: {1}, bytes: {2}",
            info.0, info.1, event.packet_length
        );
        0
    };

    ring_buffer_builder
        .add(skeleton_maps.rb(), ring_buffer_callback)
        .expect("couldn't add callback to ring buffer");
    let ring_buffer = ring_buffer_builder
        .build()
        .expect("couldn't build ring buffer");
    println!("starting");

    let f = {
        let this = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(opts.cgroup_path);
        match this {
            Ok(t) => t,
            Err(e) => {
                println!("{e}");
                println!("exiting due to missing cgroup hierarchy");
                return;
            }
        }
    };

    let cgroup_fd = f.as_raw_fd();
    let _bpf_sockops = {
        let this = skeleton
            .progs_mut()
            .measure_packet_len()
            .attach_cgroup(cgroup_fd);
        match this {
            Ok(t) => t,
            Err(e) => {
                println!("{e}");
                println!("exiting due to failed attachment to cgroup");
                return;
            }
        }
    };
    loop {
        {
            let this = ring_buffer.poll(Duration::from_millis(100));
            match this {
                Ok(t) => t,
                Err(e) => println!("{e}"),
            }
        };
    }
}
