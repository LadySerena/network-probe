/*!
eBPF probe to measure network traffic emitted by containers.
*/

#![deny(clippy::correctness)]
#![warn(clippy::style)]
#![warn(clippy::complexity)]
#![warn(clippy::suspicious)]
#![deny(deprecated)]
#![warn(clippy::perf)]
#![warn(missing_docs)]

mod init;

use axum::routing::get;
use axum::Router;
use clap::Parser;
use container_meta::get_cgroup_path_from_pid;
use egress::egress_types::bpf_event;
use k8s_cri::v1::runtime_service_client::RuntimeServiceClient;
use k8s_cri::v1::ContainerStatusRequest;
use opentelemetry::global;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Encoder;
use prometheus::Registry;
use prometheus::TextEncoder;
use regex::Regex;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use tokio::sync;
use tokio::sync::mpsc::Sender;
use tonic::transport::Endpoint;
use tonic::transport::Uri;
use tower::service_fn;
use tracing::event;
use tracing::Level;
/// rust bindings for the ebpf skeleton.
mod egress {
    include!(concat!(env!("OUT_DIR"), "/egress.skel.rs"));
}
use anyhow::Result;
unsafe impl Plain for egress_types::bpf_event {}
use egress::*;
use libbpf_rs::RingBufferBuilder;
use plain::Plain;

use crate::init::bump_memlock_rlimit;
use crate::init::setup_skeleton;
use crate::init::setup_tracing;

/// Defines the CLI arguments using clap's derive API.
#[derive(Debug, Parser)]
struct Cli {
    #[arg(short = 'g', long)]
    cgroup_path: PathBuf,
    #[arg(short = 'c', long)]
    cri_socket: PathBuf,
    #[arg(short = 'p', long)]
    proc_fs_path: PathBuf,
}

struct EnrichedData {
    pod_name: String,
    pod_namespace: String,
    local_ipv4: Ipv4Addr,
    remote_ipv4: Ipv4Addr,
    raw_event: bpf_event,
}

async fn post_process(
    cri_socket_path: PathBuf,
    proc_path: PathBuf,
    event: bpf_event,
) -> Result<EnrichedData> {
    let re = Regex::new(r"(cri-containerd-)?([^\.]+)")?;
    // TODO pass this in instead of creating a connection for every event
    let channel = Endpoint::try_from("http://[::]")?
        .connect_with_connector(service_fn(move |_: Uri| {
            UnixStream::connect(cri_socket_path.clone())
        }))
        .await?;
    let mut client = RuntimeServiceClient::new(channel);
    let cgroup_path = get_cgroup_path_from_pid(&proc_path, event.pid)?;
    let container_id: String = {
        let this = cgroup_path.split('/').last();
        match this {
            Some(val) => val,
            None => {
                return Err(anyhow::Error::msg(format!(
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
                None => return Err(anyhow::Error::msg("regex failed match")),
            }
        }
        .get(2);
        match this {
            Some(val) => val,
            None => return Err(anyhow::Error::msg("not found in 1")),
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
                return Err(anyhow::Error::msg(format!(
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
                return Err(anyhow::Error::msg(format!(
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
                return Err(anyhow::Error::msg(format!(
                    "could not retrieve pod namespace for pod: {pod_name}"
                )))
            }
        }
    };
    let local_ipv4 = Ipv4Addr::from(event.local_ip4);
    let remote_ipv4 = Ipv4Addr::from(event.remote_ip4);
    Ok(EnrichedData {
        pod_name: pod_name.to_string(),
        pod_namespace: namespace.to_string(),
        local_ipv4,
        remote_ipv4,
        raw_event: event,
    })
}

fn measure_egress(data: &[u8]) -> bpf_event {
    let mut event = egress_types::bpf_event::default();
    plain::copy_from_bytes(&mut event, data).expect("data buffer too short");
    event
}

type RingBufferCallback = Box<dyn Fn(&[u8]) -> i32>;

fn callback(sender: Sender<bpf_event>) -> RingBufferCallback {
    // return 0 to continue operation

    let meep = move |data: &[u8]| -> i32 {
        let event = measure_egress(data);
        sender.blocking_send(event).unwrap();
        0
    };
    Box::new(meep)
}

fn tokio_stuff(
    cri_socket_path: PathBuf,
    proc_path: PathBuf,
    mut channel: sync::mpsc::Receiver<bpf_event>,
    prom_registry: Registry,
) {
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    let meter = global::meter("network-probe");
    let counter = meter
        .u64_counter("pod.network.egress")
        .with_unit("By")
        .with_description("number of bytes sent by the pod")
        .init();
    runtime.spawn(async move {
        while let Some(event) = channel.recv().await {
            let data = post_process(cri_socket_path.clone(), proc_path.clone(), event).await;
            match data {
                Ok(process) => {
                    event!(
                        Level::INFO,
                        pod = process.pod_name,
                        namespace = process.pod_namespace,
                        bytes = process.raw_event.packet_length,
                        local_ip4 = process.local_ipv4.to_string(),
                        local_port = process.raw_event.local_port,
                        remote_ip4 = process.remote_ipv4.to_string(),
                        remote_port = process.raw_event.remote_port,
                        "received packet"
                    );
                    counter.add(
                        process.raw_event.packet_length.into(),
                        &[
                            KeyValue::new("pod_name", process.pod_name),
                            KeyValue::new("pod_namespace", process.pod_namespace),
                        ],
                    );
                }
                Err(e) => {
                    event!(Level::ERROR, "couldn't parse data {e}");
                }
            };
        }
    });

    let server_handle = runtime.spawn(async {
        let metrics = Router::new().route(
            "/metrics",
            get(|| async move {
                let encoder = TextEncoder::new();
                let metric_families = prom_registry.gather();
                let mut result = Vec::new();
                encoder.encode(&metric_families, &mut result).unwrap();
                result
            }),
        );
        let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, metrics).await.unwrap();
    });

    runtime.block_on(server_handle).unwrap();
}

fn main() {
    bump_memlock_rlimit();
    setup_tracing();
    let opts = Cli::parse();

    let registry = prometheus::Registry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .unwrap();

    let provider = SdkMeterProvider::builder().with_reader(exporter).build();
    global::set_meter_provider(provider.clone());

    let (sender, receiver) = sync::mpsc::channel::<bpf_event>(1000);

    let mut ring_buffer_builder = RingBufferBuilder::new();
    let mut skeleton = setup_skeleton()
        .expect("skeleton should open since the bpf program should have compiled sucessfully");
    let mut skeleton_maps = skeleton.maps_mut();

    ring_buffer_builder
        .add(skeleton_maps.rb(), callback(sender))
        .expect("should be able to open ringbuffer with appropriate permissions");
    let ring_buffer = ring_buffer_builder
        .build()
        .expect("should be able to open ringbuffer with appropriate permissions");

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

    thread::Builder::new()
        .name("async-tasks".to_string())
        .spawn(move || {
            tokio_stuff(
                opts.cri_socket.clone(),
                opts.proc_fs_path.clone(),
                receiver,
                registry,
            )
        })
        .unwrap();

    loop {
        let this = ring_buffer.poll(Duration::from_millis(100));
        match this {
            Ok(t) => t,
            Err(e) => println!("{e}"),
        }
    }
}
