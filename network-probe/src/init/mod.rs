use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

use crate::{EgressSkel, EgressSkelBuilder};

pub fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        panic!("Failed to increase rlimit");
    }
}

pub fn setup_tracing() {
    tracing_subscriber::FmtSubscriber::builder().init();
}

pub fn setup_skeleton<'a>() -> Result<EgressSkel<'a>, libbpf_rs::Error> {
    let skeleton_builder = EgressSkelBuilder::default();

    let open = skeleton_builder.open()?;
    let mut skel = open.load()?;
    skel.attach()?;
    Ok(skel)
}
