use std::io::Read;

use anyhow::{Context, Result};
use libbpf_rs::Iter;

use crate::bpf::Bpf;

/// Run one pass of the `mon_iter_task_file` iterator: stamp every TCP socket
/// held open by a task of `workload_id` with a `conn_ident`. Returns the
/// iterator's text output (a header line followed by one line per socket
/// stamped).
///
/// Meant to run right after `tasks::build_tree`, so the tasks already carry
/// their `task_ctx` when the pass looks them up. Sockets that connect later
/// are stamped by the `tcp_connect` hook.
pub fn seed_sockets(bpf: &mut Bpf, workload_id: u64) -> Result<String> {
    let bss = bpf
        .net
        .maps
        .bss_data
        .as_mut()
        .context("failed to get mon_net BSS data")?;
    bss.mon_net_iter_workload_id = workload_id;

    let mut iter = Iter::new(&bpf.task_file_iter).context("failed to create task_file iterator")?;
    let mut out = String::new();
    iter.read_to_string(&mut out)
        .context("failed to read task_file iterator")?;
    Ok(out)
}

/// Number of socket lines in a seed pass output, i.e. minus the header.
pub fn socket_count(out: &str) -> usize {
    out.lines().count().saturating_sub(1)
}
