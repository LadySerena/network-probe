use std::{error::Error, fmt::Display, path::PathBuf};

use procfs::process::Process;

#[derive(Debug)]
pub enum MetadataError {
    CgroupReadFailure(PathBuf, String),
    NoCgroupForPid(PathBuf),
    ProcReadFailure(PathBuf, String),
}

impl Error for MetadataError {}

impl Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            MetadataError::CgroupReadFailure(p, c) => {
                write!(
                    f,
                    "could not read cgroup for proc entry {} due to {}",
                    p.display(),
                    c
                )
            }
            MetadataError::NoCgroupForPid(p) => {
                write!(f, "missing cgroup for proc entry {}", p.display())
            }
            MetadataError::ProcReadFailure(p, c) => {
                write!(f, "could not read proc entry {} due to {}", p.display(), c)
            }
        }
    }
}

pub fn get_cgroup_path_from_pid(proc_path: PathBuf, pid: i32) -> Result<String, MetadataError> {
    let joined_path = proc_path.join(pid.to_string());
    let proc_info = match Process::new_with_root(joined_path.clone()) {
        Ok(p) => p,
        Err(e) => return Err(MetadataError::ProcReadFailure(joined_path, e.to_string())),
    };
    // This is for systems with cgroup v2 so we can assume process and cgroup is 1:1
    let process_cgroups = match proc_info.cgroups() {
        Ok(cgs) => cgs,
        Err(e) => return Err(MetadataError::CgroupReadFailure(joined_path, e.to_string())),
    };
    let Some(cgroup) = process_cgroups.0.first() else {
        return Err(MetadataError::NoCgroupForPid(joined_path));
    };
    Ok(cgroup.pathname.clone())
}
