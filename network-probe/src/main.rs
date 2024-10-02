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
    fmt::Display,
    future::ready,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    path::PathBuf,
    thread,
    time::Duration,
};

use axum::{routing::get, Router};
use clap::Parser;
use egress::egress_types::bpf_event;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{
    runtime::{
        reflector::{self, Store},
        watcher::Config,
        WatchStreamExt,
    },
    Api, Client, ResourceExt,
};
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
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'g', long)]
    cgroup_path: PathBuf,
    #[arg(short = 'p', long)]
    proc_fs_path: PathBuf,
    // TODO separate args for pod and service cidr
    #[arg(short = 'a', long)]
    cluster_cidr: ipnet::IpNet,
    #[arg(short = 'b', long, default_value_t = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000) )]
    server_bind_address: SocketAddr,
}

struct WorkloadMeta {
    role: String,
    project: String,
    product: String,
    team: String,
}
enum Destination {
    ClusterLocal,
    Unknown,
}

impl Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            Destination::Unknown => "unknown",
            Destination::ClusterLocal => "cluster",
        };
        write!(f, "{output}")
    }
}
struct EnrichedData {
    pod_namespace: String,
    raw_event: bpf_event,
    destination: Destination,
    workload_meta: WorkloadMeta,
}

fn annotate_event(
    event: bpf_event,
    pod_store: &Store<Pod>,
    service_store: &Store<Service>,
) -> Result<EnrichedData> {
    let (_, _, pod_namespace, remote_ipv4, workload_meta) = get_pod_metadata(event, pod_store)?;
    let destination = get_event_destination(IpAddr::V4(remote_ipv4), pod_store, service_store);
    Ok(EnrichedData {
        pod_namespace,
        raw_event: event,
        destination,
        workload_meta,
    })
}

fn get_event_destination(
    remote_ip: IpAddr,
    pod_store: &Store<Pod>,
    service_store: &Store<Service>,
) -> Destination {
    let pod_opt = pod_store.find(|p| {
        p.status
            .clone()
            .is_some_and(|s| s.pod_ip.is_some_and(|ip| ip == remote_ip.to_string()))
    });
    if pod_opt.is_some() {
        return Destination::ClusterLocal;
    };
    let service_opt = service_store.find(|s| {
        s.spec.clone().is_some_and(|spec| {
            spec.cluster_ip
                .is_some_and(|ip| ip == remote_ip.to_string())
        })
    });
    if service_opt.is_some() {
        return Destination::ClusterLocal;
    }
    Destination::Unknown
}

fn get_pod_metadata(
    event: bpf_event,
    store: &Store<Pod>,
) -> Result<(Ipv4Addr, String, String, Ipv4Addr, WorkloadMeta)> {
    let local_ipv4 = Ipv4Addr::from(event.local_ip4);
    let pod_opt = store.find(|p| {
        p.status
            .clone()
            .is_some_and(|s| s.pod_ip.is_some_and(|ip| ip == local_ipv4.to_string()))
    });
    let Some(pod) = pod_opt else {
        return Err(anyhow::Error::msg(format!(
            "could not find pod for ip {local_ipv4}"
        )));
    };
    let default = "unknown".to_string();
    let pod_name = pod.name_any();
    let pod_namespace = pod.namespace().unwrap_or(default.clone());
    let remote_ipv4 = Ipv4Addr::from(event.remote_ip4);
    let team = pod.labels().get("team").unwrap_or(&default).clone();
    let role = pod.labels().get("role").unwrap_or(&default).clone();
    let project = pod.labels().get("project").unwrap_or(&default).clone();
    let product = pod.labels().get("product").unwrap_or(&default).clone();
    Ok((
        local_ipv4,
        pod_name,
        pod_namespace,
        remote_ipv4,
        WorkloadMeta {
            role,
            project,
            product,
            team,
        },
    ))
}

fn parse_event_into_struct(data: &[u8]) -> bpf_event {
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
    let ring_buffer_closure = move |data: &[u8]| -> i32 {
        let event = parse_event_into_struct(data);
        let packet_ip = IpAddr::V4(Ipv4Addr::from(event.local_ip4));
        // TODO ignore these packets within the probe itself
        if !cluster_cidr.contains(&packet_ip) || packet_ip == own_ip {
            // ignore non kubernetes pod packet
            return 0;
        }
        sender.blocking_send(event).unwrap();
        channel_guage.add(-1, &[KeyValue::new("queue_name", "enrichment")]);
        // return 0 to continue operation
        0
    };
    Box::new(ring_buffer_closure)
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

    let client = Client::try_default().await.unwrap();
    let pod_api: Api<Pod> = Api::all(client.clone());
    let service: Api<Service> = Api::all(client.clone());
    let active_pod_filter = Config::default().fields("status.phase=Running");
    let service_filter = Config::default();
    // TODO wrap in helper
    let (pod_reader, pod_writer) = reflector::store();
    let (service_reader, service_writer) = reflector::store();

    let pod_reflector = reflector::reflector(
        pod_writer,
        kube::runtime::watcher(pod_api.clone(), active_pod_filter.clone()),
    );

    let service_reflector = reflector::reflector(
        service_writer,
        kube::runtime::watcher(service.clone(), service_filter),
    );

    let pod_watch = pod_reflector.applied_objects().for_each(|_| ready(()));
    let service_watch = service_reflector.applied_objects().for_each(|_| ready(()));

    // refresh our cache in the background
    let pod_update_handle = task::spawn(async move {
        pod_watch.await;
    });

    let service_update_handle = task::spawn(async move {
        service_watch.await;
    });

    // handles getting the pod name from the raw bpf event
    let enrichment_handle = task::spawn(async move {
        while let Some(event) = channel.recv().await {
            channel_gauge.add(1, &[KeyValue::new("queue_name", "enrichment")]);
            let process = match annotate_event(event, &pod_reader, &service_reader) {
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
                    KeyValue::new("destination", process.destination.to_string()),
                    KeyValue::new("pod_namespace", process.pod_namespace),
                ],
            );
        }
    });

    // runs the metrics webserver to expose metrics
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

    match try_join!(
        enrichment_handle,
        server_handle,
        pod_update_handle,
        service_update_handle
    ) {
        Ok(_) => event!(Level::ERROR, "should not have returned"),
        Err(err) => event!(Level::ERROR, "async failure {err}"),
    }
}

fn main() {
    let opts = Cli::parse();
    bump_memlock_rlimit();
    setup_tracing();

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

    // make async run on it's own thread(s)
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
    // continue main thread by polling the ring buffer
    // TODO graceful shutdown of all threads / tasks
    loop {
        let this = ring_buffer.poll(Duration::from_millis(100));
        match this {
            Ok(t) => t,
            Err(e) => println!("{e}"),
        }
    }
}
