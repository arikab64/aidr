use std::io::Read;

use anyhow::{Context, Result};
use libbpf_rs::Iter;
use tracing::{info, warn};

use crate::bpf::Bpf;
use crate::server::Response;

// Must match enum mon_iter_op in bpf/mon_procs.bpf.c.
const MON_ITER_MARK: u32 = 0;
const MON_ITER_UNMARK: u32 = 1;

/// Run one pass of the `mon_iter_task` iterator with the given root and
/// operation, returning its text output (a header line followed by one line
/// per task the pass acted on).
///
/// The iterator program is attached once at load; every call here creates a
/// fresh iterator fd from that link, so each pass sees the current task list.
fn run_iter(bpf: &mut Bpf, root_pid: u32, op: u32) -> Result<String> {
    let bss = bpf
        .procs
        .maps
        .bss_data
        .as_mut()
        .context("failed to get BSS data")?;
    bss.mon_iter_root_pid = root_pid;
    bss.mon_iter_op = op;

    let mut iter = Iter::new(&bpf.task_iter).context("failed to create task iterator")?;
    let mut out = String::new();
    iter.read_to_string(&mut out)
        .context("failed to read task iterator")?;
    Ok(out)
}

/// Number of task lines in an iterator pass output, i.e. minus the header.
fn task_count(out: &str) -> usize {
    out.lines().count().saturating_sub(1)
}

/// Seed `task_ctx_map` with every task below `root_pid`.
pub fn build_tree(bpf: &mut Bpf, root_pid: u32) -> Result<String> {
    run_iter(bpf, root_pid, MON_ITER_MARK)
}

/// Drop every task context whose root is `root_pid`.
///
/// A tracked parent that forks while the pass is running can hand its context
/// to a child in a PID slot the iterator already passed, so if the first pass
/// removed anything, run a second one to catch stragglers.
pub fn untrack_tree(bpf: &mut Bpf, root_pid: u32) -> Result<String> {
    let out = run_iter(bpf, root_pid, MON_ITER_UNMARK)?;
    if task_count(&out) > 0 {
        let second = run_iter(bpf, root_pid, MON_ITER_UNMARK)?;
        let stragglers = task_count(&second);
        if stragglers > 0 {
            info!(pid = root_pid, stragglers, "second untrack pass removed stragglers");
        }
    }
    Ok(out)
}

pub fn handle_tree(bpf: &mut Bpf, pid: u32) -> Response {
    match build_tree(bpf, pid) {
        Ok(out) => {
            let count = task_count(&out);
            info!(pid, count, "built process tree");
            Response::ok(out)
        }
        Err(e) => {
            warn!(pid, error = %e, "failed to build process tree");
            Response::error(format!("failed to build tree for pid {pid}: {e}"))
        }
    }
}

pub fn handle_untrack(bpf: &mut Bpf, pid: u32) -> Response {
    match untrack_tree(bpf, pid) {
        Ok(out) => {
            let count = task_count(&out);
            info!(pid, count, "untracked process tree");
            Response::ok(out)
        }
        Err(e) => {
            warn!(pid, error = %e, "failed to untrack process tree");
            Response::error(format!("failed to untrack tree for pid {pid}: {e}"))
        }
    }
}
