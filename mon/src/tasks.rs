use std::io::Read;

use anyhow::{Context, Result};
use libbpf_rs::Iter;
use tracing::{info, warn};

use crate::bpf::Bpf;
use crate::server::Response;

pub fn build_tree(bpf: &mut Bpf, root_pid: u32) -> Result<String> {
    let bss = bpf
        .procs
        .maps
        .bss_data.as_mut()
        .context("failed to get BSS data")?;

      bss.mon_iter_root_pid = root_pid;
     
     let mut iter = Iter::new(&bpf.task_iter).context("failed to create task iterator")?;
     let mut out = String::new();
     iter.read_to_string(&mut out)
         .context("failed to read task iterator")?;

     Ok(out)
}

pub fn handle_tree(bpf: &mut Bpf, pid: u32) -> Response {
    match build_tree(bpf, pid) {
        Ok(out) => {
            let count = out.lines().count().saturating_sub(1); // minus header
            info!(pid, count, "built process tree");
            Response::ok(out)
        }
        Err(e) => {
            warn!(pid, error = %e, "failed to build process tree");
            Response::error(format!("failed to build tree for pid {pid}: {e}"))
        }
    }
}
