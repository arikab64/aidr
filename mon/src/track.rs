use anyhow::{Context, Result};
use libbpf_rs::{ErrorKind, MapCore};
use tracing::{info, warn};

use crate::bpf::{Bpf, TrackError, UntrackError};
use crate::server::Response;

/// Track a PID using BPF test run mechanism.
pub fn track_pid(bpf: &Bpf, pid: u32) -> std::result::Result<(), TrackError> {
    bpf.register_pid(pid)
}

/// Untrack a PID using BPF test run mechanism.
pub fn untrack_pid(bpf: &Bpf, pid: u32) -> std::result::Result<bool, UntrackError> {
    bpf.untrack_pid(pid)
}

/// Untrack all PIDs by removing all entries from userspace directly from the BPF map.
pub fn untrack_all(bpf: &Bpf) -> Result<usize> {
    let map = &bpf.files.maps.tracked_pids;
    let keys: Vec<Vec<u8>> = map.keys().collect();
    let count = keys.len();
    for key in keys {
        if let Err(e) = map.delete(&key) {
            if e.kind() != ErrorKind::NotFound {
                return Err(e).with_context(|| "failed to delete entry from tracked_pids");
            }
        }
    }
    Ok(count)
}

pub fn handle_track(bpf: &Bpf, pid: u32) -> Response {
    match track_pid(bpf, pid) {
        Ok(()) => {
            info!(pid, "tracking process");
            Response::ok(format!("tracking pid {pid}"))
        }
        Err(TrackError::NoSuchProcess) => {
            warn!(pid, "cannot track: no such process or already exiting");
            Response::error(format!("process {pid} does not exist or already exited"))
        }
        Err(TrackError::NotAProcess) => {
            warn!(pid, "cannot track: TID given instead of PID");
            Response::error(format!("PID {pid} is a TID, not a thread group leader"))
        }
        Err(TrackError::Full) => {
            warn!(pid, "cannot track: map full");
            Response::error("tracked processes map is full")
        }
        Err(e) => {
            warn!(pid, error = %e, "failed to track");
            Response::error(format!("failed to track pid {pid}: {e}"))
        }
    }
}

pub fn handle_untrack(bpf: &Bpf, pid: u32) -> Response {
    match untrack_pid(bpf, pid) {
        Ok(true) => {
            info!(pid, "untracked process");
            Response::ok(format!("untracked pid {pid}"))
        }
        Ok(false) => {
            warn!(pid, "PID was not tracked");
            Response::error(format!("pid {pid} was not in tracked processes"))
        }
        Err(e) => {
            warn!(pid, error = %e, "failed to untrack");
            Response::error(format!("failed to untrack pid {pid}: {e}"))
        }
    }
}

pub fn handle_untrack_all(bpf: &Bpf) -> Response {
    match untrack_all(bpf) {
        Ok(count) => {
            info!(count, "untracked all processes");
            Response::ok(format!("untracked all {count} process(es)"))
        }
        Err(e) => {
            warn!(error = %e, "failed to untrack all");
            Response::error(format!("failed to untrack all processes: {e}"))
        }
    }
}



