use std::mem::MaybeUninit;
use std::os::fd::AsFd;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, Object, OpenObject, ProgramInput, ProgramType};
use tracing::info;
use tracing_subscriber::filter::LevelFilter;

use crate::mon_files_skel::{MonFilesSkel, MonFilesSkelBuilder};
use crate::mon_procs_skel::{MonProcsSkel, MonProcsSkelBuilder};

pub struct Bpf {
    /// Own the loaded BPF objects; held so the programs stay loaded for as
    /// long as `Bpf` lives. `tracked_pids` is created by `files` and shared
    /// with `procs` via fd reuse.
    pub files: MonFilesSkel<'static>,
    pub procs: MonProcsSkel<'static>,
    links: Vec<(String, Link)>,
}

/// Must match struct mon_track_req in bpf/mon.bpf.h.
#[repr(C)]
pub struct MonTrackReq {
    pub pid: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum TrackError {
    #[error("no such process, or process is already exiting")]
    NoSuchProcess,
    #[error("TID given instead of PID (thread group leader)")]
    NotAProcess,
    #[error("tracked processes map is full")]
    Full,
    #[error("failed to run BPF program: {0}")]
    Run(libbpf_rs::Error),
    #[error("OS error: {0}")]
    Os(i32),
}

#[derive(Debug, thiserror::Error)]
pub enum UntrackError {
    #[error("failed to run BPF program: {0}")]
    Run(libbpf_rs::Error),
    #[error("OS error: {0}")]
    Os(i32),
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

/// Attach every program in `obj`, returning the links that keep them attached.
fn attach_all(obj: &mut Object, links: &mut Vec<(String, Link)>) -> Result<()> {
    for prog in obj.progs_mut() {
        if prog.prog_type() == ProgramType::Syscall {
            continue;
        }
        let name = prog.name().to_string_lossy().into_owned();
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

    // mon_procs declares the same map; point it at the one mon_files created
    // instead of letting libbpf make a second, empty copy.
    let mut open_procs = MonProcsSkelBuilder::default()
        .open(leak_storage())
        .context("failed to open mon_procs skeleton")?;

    if let Some(rodata) = open_procs.maps.rodata_data.as_mut() {
        rodata.mon_log_level = level;
    }

    open_procs
        .maps
        .tracked_pids
        .reuse_fd(files.maps.tracked_pids.as_fd())
        .context("failed to share tracked_pids with mon_procs")?;

    let mut procs = open_procs.load().context("failed to load mon_procs skeleton")?;

    let mut links = Vec::new();
    attach_all(files.object_mut(), &mut links)?;
    attach_all(procs.object_mut(), &mut links)?;

    Ok(Bpf { files, procs, links })
}

impl Bpf {
    /// Register a host tgid synchronously via the kernel BPF program `mon_track_pid`.
    ///
    /// The BPF program verifies `task->pid == task->tgid`, inserts the entry, and only then
    /// checks `task->signal->live`, undoing the insert if the thread group is already dead.
    /// Checking after the insert (rather than before) closes the race where a process exits
    /// between the check and the insert and leaves a dead PID stuck in `tracked_pids`.
    pub fn register_pid(&self, pid: u32) -> std::result::Result<(), TrackError> {
        let mut req = MonTrackReq { pid };
        let ctx = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut req as *mut MonTrackReq).cast::<u8>(),
                std::mem::size_of::<MonTrackReq>(),
            )
        };

        let out = self
            .procs
            .progs
            .mon_track_pid
            .test_run(ProgramInput {
                context_in: Some(ctx),
                ..Default::default()
            })
            .map_err(TrackError::Run)?;

        match out.return_value as i32 {
            0 => Ok(()),
            -3 => Err(TrackError::NoSuchProcess), // ESRCH
            -22 => Err(TrackError::NotAProcess), // EINVAL, tid given
            -7 => Err(TrackError::Full),         // E2BIG
            e => Err(TrackError::Os(-e)),
        }
    }

    /// Untrack a host tgid synchronously via the kernel BPF program `mon_untrack_pid`.
    ///
    /// Returns `Ok(true)` if the PID was in `tracked_pids` and deleted,
    /// or `Ok(false)` if the PID was not present (-ENOENT).
    pub fn untrack_pid(&self, pid: u32) -> std::result::Result<bool, UntrackError> {
        let mut req = MonTrackReq { pid };
        let ctx = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut req as *mut MonTrackReq).cast::<u8>(),
                std::mem::size_of::<MonTrackReq>(),
            )
        };

        let out = self
            .procs
            .progs
            .mon_untrack_pid
            .test_run(ProgramInput {
                context_in: Some(ctx),
                ..Default::default()
            })
            .map_err(UntrackError::Run)?;

        match out.return_value as i32 {
            0 => Ok(true),
            -2 => Ok(false), // -ENOENT
            e => Err(UntrackError::Os(-e)),
        }
    }
}

pub fn detach(bpf: Bpf) -> Result<()> {
    for (name, link) in bpf.links {
        // BPF_LINK_DETACH is not supported for tracing links (EOPNOTSUPP);
        // dropping the link destroys it (closes its fd), which detaches.
        drop(link);
        info!("detached hook {name}");
    }

    Ok(())
}

