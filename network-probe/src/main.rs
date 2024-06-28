#![deny(clippy::correctness)]
#![warn(clippy::unwrap_used)]
#![deny(deprecated)]
#![warn(clippy::perf)]

use anyhow::bail;
use anyhow::Error;
use egress::egress_types::event;
use k8s_cri::v1::runtime_service_client::RuntimeServiceClient;
use k8s_cri::v1::ContainerStatusRequest;
use std::os::fd::AsRawFd;
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

async fn post_process(event: event) -> Result<(String, String)> {
    // TODO make this configurable
    let path = "/run/containerd/containerd.sock";
    let channel = Endpoint::try_from("http://[::]")?
        .connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(path)))
        .await?;
    let mut client = RuntimeServiceClient::new(channel);
    let cgroup_path = get_cgroup_path_from_pid(event.pid);
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

    let request = ContainerStatusRequest {
        container_id: container_id.clone(),
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

fn get_cgroup_path_from_pid(pid: i32) -> String {
    let proc_info = procfs::process::Process::new(pid).unwrap();
    // This is for systems with cgroup v2 so we can assume process and cgroup is 1:1
    let binding = proc_info.cgroups().unwrap();
    let cgroups = binding.0.first().unwrap();
    cgroups.pathname.clone()
}

fn measure_egress(data: &[u8]) -> event {
    let mut event = egress_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("data buffer too short");
    // TODO get container name from event
    // let cgroup_path = get_cgroup_path_from_pid(event.pid);
    // // TODO configurable cri endpoint
    // let container_path = "/run/containerd/containerd.sock";
    event
}

fn main() {
    let skeleton_builder = EgressSkelBuilder::default();

    bump_memlock_rlimit().unwrap();
    let open_skeleton = skeleton_builder.open().unwrap();
    let mut skeleton = open_skeleton.load().unwrap();
    skeleton.attach().unwrap();

    let mut ring_buffer_builder = RingBufferBuilder::new();
    let mut skeleton_maps = skeleton.maps_mut();
    let ring_buffer_callback = |data: &[u8]| -> i32 {
        let event = measure_egress(data);
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let handle = runtime.spawn(post_process(event));
        let info = runtime.block_on(handle).unwrap().unwrap();
        println!(
            "pod: {0}, namespace: {1}, bytes: {2}",
            info.0, info.1, event.packet_length
        );
        0
    };

    ring_buffer_builder
        .add(skeleton_maps.rb(), ring_buffer_callback)
        .unwrap();
    let ring_buffer = ring_buffer_builder.build().unwrap();
    println!("starting");

    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open("/sys/fs/cgroup/kubepods/")
        .unwrap();

    let cgroup_fd = f.as_raw_fd();
    let _bpf_sockops = skeleton
        .progs_mut()
        .measure_packet_len()
        .attach_cgroup(cgroup_fd)
        .unwrap();
    loop {
        ring_buffer.poll(Duration::from_millis(100)).unwrap();
    }
}
