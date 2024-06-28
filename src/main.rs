#![deny(clippy::correctness)]
#![deny(deprecated)]
#![warn(clippy::perf)]

use anyhow::bail;
use std::os::fd::AsRawFd;
use std::time::Duration;

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

fn measure_egress(data: &[u8]) -> i32 {
    let mut event = egress_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("data buffer too short");
    println!("{:?}", event);
    0
}
fn main() {
    let skeleton_builder = EgressSkelBuilder::default();

    bump_memlock_rlimit().unwrap();
    let open_skeleton = skeleton_builder.open().unwrap();
    let mut skeleton = open_skeleton.load().unwrap();
    skeleton.attach().unwrap();

    let mut ring_buffer_builder = RingBufferBuilder::new();
    let mut skeleton_maps = skeleton.maps_mut();
    ring_buffer_builder
        .add(skeleton_maps.rb(), measure_egress)
        .unwrap();
    let ring_buffer = ring_buffer_builder.build().unwrap();
    println!("starting");

    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open("/sys/fs/cgroup/")
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
