/*!
eBPF probe to measure network traffic emitted by containers.
*/
#![deny(unused_crate_dependencies)]
#![deny(clippy::correctness)]
#![warn(clippy::style)]
#![warn(clippy::complexity)]
#![warn(clippy::suspicious)]
#![deny(deprecated)]
#![warn(clippy::perf)]
#![warn(missing_docs)]

mod init;

use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    os::fd::AsRawFd,
    path::PathBuf,
    thread,
    time::Duration,
};

use axum::{routing::get, Router};
use clap::Parser;
use egress::egress_types::bpf_event;
use ipnet::IpAddrRange;
use kube::{api::ListParams, Api, Client, ResourceExt};
use opentelemetry::{
    global,
    metrics::{MeterProvider, UpDownCounter},
    KeyValue,
};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry, TextEncoder};
use tokio::{net::TcpListener, runtime, sync, sync::mpsc::Sender, task, try_join};
use tracing::{event, Level};
/// rust bindings for the ebpf skeleton.
mod egress {
    include!(concat!(env!("OUT_DIR"), "/egress.skel.rs"));
}
use anyhow::Result;
use egress::*;
use libbpf_rs::RingBufferBuilder;
use plain::Plain;

use crate::init::{bump_memlock_rlimit, setup_skeleton, setup_tracing};

unsafe impl Plain for egress_types::bpf_event {}
/// Defines the CLI arguments using clap's derive API.
#[derive(Debug, Parser)]
struct Cli {
    #[arg(short = 'g', long)]
    cgroup_path: PathBuf,
    #[arg(short = 'c', long)]
    cri_socket: PathBuf,
    #[arg(short = 'p', long)]
    proc_fs_path: PathBuf,
    #[arg(short = 'a', long)]
    cluster_cidr: ipnet::IpNet,
}

struct WorkloadMeta {
    role: String,
    project: String,
    product: String,
    team: String,
}

struct EnrichedData {
    pod_namespace: String,
    local_ipv4: Ipv4Addr,
    remote_ipv4: Ipv4Addr,
    raw_event: bpf_event,
    workload_meta: WorkloadMeta,
}

async fn post_process(
    event: bpf_event,
    pod_api: &Api<k8s_openapi::api::core::v1::Pod>,
) -> Result<EnrichedData> {
    let default = &"unknown".to_string();
    let local_ipv4 = Ipv4Addr::from(event.local_ip4);
    let params = ListParams::default()
        .fields(format!("status.podIP={local_ipv4}").as_str())
        .limit(1);
    let list = pod_api.list(&params).await?;
    let Some(pod) = list.iter().next() else {
        return Err(anyhow::Error::msg(format!(
            "could not find pod for ip {local_ipv4}"
        )));
    };
    let namespace = pod.namespace().unwrap_or("unknown".to_string());
    let remote_ipv4 = Ipv4Addr::from(event.remote_ip4);
    let labels = pod.labels();
    let product = labels.get("product").unwrap_or(default);
    let project = labels.get("project").unwrap_or(default);
    let team = labels.get("team").unwrap_or(default);
    let role = labels.get("role").unwrap_or(default);
    Ok(EnrichedData {
        pod_namespace: namespace.to_string(),
        local_ipv4,
        remote_ipv4,
        raw_event: event,
        workload_meta: WorkloadMeta {
            role: role.clone(),
            project: project.clone(),
            product: product.clone(),
            team: team.clone(),
        },
    })
}

fn measure_egress(data: &[u8]) -> bpf_event {
    let mut event = egress_types::bpf_event::default();
    plain::copy_from_bytes(&mut event, data).expect("data buffer too short");
    event
}

type RingBufferCallback = Box<dyn Fn(&[u8]) -> i32>;

fn callback(
    sender: Sender<bpf_event>,
    channel_guage: UpDownCounter<i64>,
    cluster_cidr: ipnet::IpNet,
    own_ip: IpAddr,
) -> RingBufferCallback {
    // return 0 to continue operation

    let meep = move |data: &[u8]| -> i32 {
        let event = measure_egress(data);
        let packet_ip = IpAddr::V4(Ipv4Addr::from(event.local_ip4));
        // TODO ignore pod's own network requests to apiserver
        if !cluster_cidr.contains(&packet_ip) || packet_ip == own_ip {
            // ignore non kubernetes pod packet
            return 0;
        }
        sender.blocking_send(event).unwrap();
        channel_guage.add(-1, &[KeyValue::new("queue_name", "enrichment")]);
        0
    };
    Box::new(meep)
}

async fn setup_tasks(
    mut channel: sync::mpsc::Receiver<bpf_event>,
    prom_registry: Registry,
    channel_gauge: UpDownCounter<i64>,
) {
    let meter = global::meter("network-probe");
    let counter = meter
        .u64_counter("pod.network.egress")
        .with_unit("By") // bytes according to https://ucum.org/ by way of the otel spec
        .with_description("number of bytes sent by the pod")
        .init();

    let enrichment_handle = task::spawn(async move {
        let client = Client::try_default().await.unwrap();
        let pod_api: Api<k8s_openapi::api::core::v1::Pod> = Api::all(client);
        while let Some(event) = channel.recv().await {
            channel_gauge.add(1, &[KeyValue::new("queue_name", "enrichment")]);
            let data = post_process(event, &pod_api).await;
            let process = match data {
                Ok(d) => d,
                Err(e) => {
                    event!(Level::ERROR, "could not process event {e}");
                    continue;
                }
            };
            counter.add(
                process.raw_event.packet_length.into(),
                &[
                    KeyValue::new("product", process.workload_meta.role),
                    KeyValue::new("project", process.workload_meta.project),
                    KeyValue::new("project", process.workload_meta.team),
                    KeyValue::new("project", process.workload_meta.product),
                    KeyValue::new("pod_namespace", process.pod_namespace),
                ],
            );
        }
    });

    let server_handle = task::spawn(async {
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

    match try_join!(enrichment_handle, server_handle) {
        Ok(_) => event!(Level::ERROR, "should not have returned"),
        Err(err) => event!(Level::ERROR, "async failure {err}"),
    }
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
    let meter = provider.meter("network-probe");
    global::set_meter_provider(provider.clone());

    let capacity: i64 = 1000;

    let (sender, receiver) = sync::mpsc::channel::<bpf_event>(
        capacity
            .try_into()
            .expect("initial capacity ({capacity}) to be less than usize max ({usize.MAX})"),
    );

    let capacity_counter = meter
        .i64_up_down_counter("channel.capacity")
        .with_description("available slots within the channel")
        .with_unit("{item}")
        .init();

    capacity_counter.add(capacity, &[KeyValue::new("queue_name", "enrichment")]);

    let mut ring_buffer_builder = RingBufferBuilder::new();
    let mut skeleton = setup_skeleton()
        .expect("skeleton should open since the bpf program should have compiled sucessfully");
    let mut skeleton_maps = skeleton.maps_mut();

    let Ok(raw_ip) = env::var("POD_IP") else {
        panic!("POD_IP is not set");
    };

    let Ok(own_ip) = raw_ip.parse() else {
        panic!("could not parse {raw_ip} into an IpAddr");
    };

    ring_buffer_builder
        .add(
            skeleton_maps.rb(),
            callback(sender, capacity_counter.clone(), opts.cluster_cidr, own_ip),
        )
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
            runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("network-probe-workers")
                .build()
                .unwrap()
                .block_on(async { setup_tasks(receiver, registry, capacity_counter).await })
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
