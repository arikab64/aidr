use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{IterOpts, Link, MapCore, Object, OpenObject, ProgramAttachType, ProgramType};
use tracing::info;
use tracing_subscriber::filter::LevelFilter;

use crate::mon_files_skel::{MonFilesSkel, MonFilesSkelBuilder};
use crate::mon_net_skel::{MonNetSkel, MonNetSkelBuilder};
use crate::mon_procs_skel::{MonProcsSkel, MonProcsSkelBuilder};


// PROGRAMS
pub const PROG_PARSE_DNS_QNAME: u32 = 0;


pub struct Bpf {
    /// Own the loaded BPF objects; held so the programs stay loaded for as
    /// long as `Bpf` lives. `task_ctx_map` is created by `files` and shared
    /// with `procs` and `net` via fd reuse.
    pub files: MonFilesSkel<'static>,
    pub procs: MonProcsSkel<'static>,
    pub net: MonNetSkel<'static>,
    links: Vec<(String, Link)>,
    /// Link for the `mon_iter_task` iterator. Attached once; every
    /// `bpf_iter_create()` on it (see `tasks::run_iter`) runs a fresh pass.
    pub task_iter: Link,
    /// Link for the `mon_iter_task_file` iterator: the socket seed pass run
    /// after a tree is built (see `net::seed_sockets`).
    pub task_file_iter: Link,
    /// Link for the `mon_iter_tcp` iterator: dump and unmark passes over
    /// `conn_ident_map`.
    pub tcp_iter: Link,
}

// Must match enum mon_log_level in bpf/logger.h.
fn bpf_log_level(filter: LevelFilter) -> u32 {
    if filter >= LevelFilter::DEBUG {
        0
    } else if filter >= LevelFilter::INFO {
        1
    } else if filter >= LevelFilter::WARN {
        2
    } else if filter >= LevelFilter::ERROR {
        3
    } else {
        4
    }
}

/// The skeletons borrow their OpenObject storage; leak it so they can live
/// for the rest of the process.
fn leak_storage() -> &'static mut MaybeUninit<OpenObject> {
    Box::leak(Box::new(MaybeUninit::uninit()))
}

/// Attach every hook program in `obj`, returning the links that keep them
/// attached. Skips `SEC("syscall")` programs (driven via test_run) and
/// iterators (attached explicitly in `load`, since their link must be kept
/// by name so userspace can create iterator fds from it).
fn attach_all(obj: &mut Object, links: &mut Vec<(String, Link)>) -> Result<()> {
    for prog in obj.progs_mut() {
        if prog.prog_type() == ProgramType::Syscall
            || matches!(prog.attach_type(), ProgramAttachType::TraceIter)
        {
            continue;
        }
        let name = prog.name().to_string_lossy().into_owned();
        if name == "mon_parse_dns_qname" {
            continue; // Tail call target, attached manually
        }
        let section = prog.section().to_string_lossy().into_owned();
        let link = prog
            .attach()
            .with_context(|| format!("failed to attach {name}"))?;
        info!(
            "attached hook {name} ({section}, type {:?})",
            prog.prog_type()
        );
        links.push((name, link));
    }
    Ok(())
}

pub fn load(log_level: LevelFilter) -> Result<Bpf> {
    let level = bpf_log_level(log_level);

    // mon_files owns tracked_pids: open and load.
    let mut open_files = MonFilesSkelBuilder::default()
        .open(leak_storage())
        .context("failed to open mon_files skeleton")?;

    // rodata is frozen at load, so the verifier prunes disabled log calls.
    if let Some(rodata) = open_files.maps.rodata_data.as_mut() {
        rodata.mon_log_level = level;
    }

    let mut files = open_files.load().context("failed to load mon_files skeleton")?;

    // mon_procs declares the same task storage map; point it at the one
    // mon_files created instead of letting libbpf make a second, empty copy.
    let mut open_procs = MonProcsSkelBuilder::default()
        .open(leak_storage())
        .context("failed to open mon_procs skeleton")?;

    if let Some(rodata) = open_procs.maps.rodata_data.as_mut() {
        rodata.mon_log_level = level;
    }

    open_procs
        .maps
        .task_ctx_map
        .reuse_fd(files.maps.task_ctx_map.as_fd())
        .context("failed to share task_ctx_map with mon_procs")?;

    let mut procs = open_procs.load().context("failed to load mon_procs skeleton")?;

    // mon_net also declares task_ctx_map; share the same one.
    let mut open_net = MonNetSkelBuilder::default()
        .open(leak_storage())
        .context("failed to open mon_net skeleton")?;

    if let Some(rodata) = open_net.maps.rodata_data.as_mut() {
        rodata.mon_log_level = level;
    }

    open_net
        .maps
        .task_ctx_map
        .reuse_fd(files.maps.task_ctx_map.as_fd())
        .context("failed to share task_ctx_map with mon_net")?;

    let mut net = open_net.load().context("failed to load mon_net skeleton")?;

    let mut links = Vec::new();
    attach_all(files.object_mut(), &mut links)?;
    attach_all(procs.object_mut(), &mut links)?;
    attach_all(net.object_mut(), &mut links)?;



    // These iterators have no target (no map, no cgroup), so plain options.
    let task_iter = procs
        .progs
        .mon_iter_task
        .attach_iter_with_opts(IterOpts::None)
        .context("failed to attach mon_iter_task iterator")?;
    info!("attached iterator mon_iter_task (iter/task)");

    let task_file_iter = net
        .progs
        .mon_iter_task_file
        .attach_iter_with_opts(IterOpts::None)
        .context("failed to attach mon_iter_task_file iterator")?;
    info!("attached iterator mon_iter_task_file (iter/task_file)");

    let tcp_iter = net
        .progs
        .mon_iter_tcp
        .attach_iter_with_opts(IterOpts::None)
        .context("failed to attach mon_iter_tcp iterator")?;
    info!("attached iterator mon_iter_tcp (iter/tcp)");

    let fd = net.progs.mon_parse_dns_qname.as_fd().as_raw_fd() as u32;
    let key: u32 = PROG_PARSE_DNS_QNAME;
    net.maps
        .jmp_table
        .update(&key.to_ne_bytes(), &fd.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
        .context("failed to populate jmp_table with target_prog")?;
    info!("registered tail call mon_parse_dns_qname at index {}", key);

    Ok(Bpf {
        files,
        procs,
        net,
        links,
        task_iter,
        task_file_iter,
        tcp_iter,
    })
}


pub fn detach(bpf: Bpf) -> Result<()> {
    for (name, link) in bpf.links {
        // BPF_LINK_DETACH is not supported for tracing links (EOPNOTSUPP);
        // dropping the link destroys it (closes its fd), which detaches.
        drop(link);
        info!("detached hook {name}");
    }

    drop(bpf.task_iter);
    info!("detached iterator mon_iter_task");

    drop(bpf.task_file_iter);
    info!("detached iterator mon_iter_task_file");

    drop(bpf.tcp_iter);
    info!("detached iterator mon_iter_tcp");

    Ok(())
}

