use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::bpf::Bpf;
use crate::tasks;

pub const DEFAULT_SOCKET_PATH: &str = "/run/aidr/mon.sock";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Seed task_ctx_map with every task under `pid` and return the list.
    Tree { pid: u32 },
    /// Drop every task context rooted at `pid` and return the list.
    Untrack { pid: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    Error {
        error: String,
    },
}

impl Response {
    pub fn ok(msg: impl Into<String>) -> Self {
        Self::Ok {
            message: Some(msg.into()),
        }
    }

    pub fn error(err: impl Into<String>) -> Self {
        Self::Error { error: err.into() }
    }
}

pub fn handle_command(bpf: &mut Bpf, cmd: Command) -> Response {
    match cmd {
        Command::Tree { pid } => tasks::handle_tree(bpf, pid),
        Command::Untrack { pid } => tasks::handle_untrack(bpf, pid),
    }
}

fn bind_unix_listener(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777));
        }
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind socket at {}", path.display()))?;
    listener
        .set_nonblocking(true)
        .context("failed to set non-blocking on listener")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    }
    Ok(listener)
}

pub struct Server {
    listener: UnixListener,
    socket_path: PathBuf,
}

pub type CommandListener = Server;

impl Server {
    /// Bind exactly `path`; a failure is fatal to the caller (no fallback).
    pub fn bind(path: &Path) -> Result<Self> {
        let listener = bind_unix_listener(path)?;
        info!(path = %path.display(), "bound to unix socket");
        Ok(Self {
            listener,
            socket_path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.socket_path
    }

    pub fn accept(&self) -> std::io::Result<(UnixStream, std::os::unix::net::SocketAddr)> {
        self.listener.accept()
    }

    pub fn poll_and_handle(&self, bpf: &mut Bpf) -> Result<()> {
        loop {
            match self.accept() {
                Ok((stream, _)) => {
                    if let Err(e) = handle_stream(bpf, stream) {
                        warn!(error = %e, "error processing client request");
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    break;
                }
            }
        }
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
        info!("removed socket {}", self.socket_path.display());
    }
}

fn handle_stream(bpf: &mut Bpf, mut stream: UnixStream) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .context("failed to set read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .context("failed to set write timeout")?;

    let reader = BufReader::new(stream.try_clone().context("failed to clone stream")?);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e).context("failed reading line from client"),
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        info!(raw = trimmed, "command arrived");

        let resp = match serde_json::from_str::<Command>(trimmed) {
            Ok(cmd) => {
                info!(command = ?cmd, "processing command");
                handle_command(bpf, cmd)
            }
            Err(e) => {
                warn!(raw = trimmed, error = %e, "failed to parse arrived command");
                Response::error(format!("invalid command JSON: {e}"))
            }
        };

        let mut out = serde_json::to_vec(&resp)?;
        out.push(b'\n');
        stream.write_all(&out).context("failed writing response")?;
        stream.flush().context("failed flushing response")?;
    }
    Ok(())
}
