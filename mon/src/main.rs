use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::info;

use mon::server::{self, Server};
use mon::{bpf, logger, signals};

/// How often the main loop re-checks the shutdown flag and polls for incoming commands.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Parser, Debug)]
struct Args {
    #[command(flatten)]
    log: logger::LoggerOpts,

    /// Path to Unix domain socket for receiving commands
    #[arg(long = "socket-path", default_value = server::DEFAULT_SOCKET_PATH)]
    socket_path: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let _log_guards = logger::init(&args.log)?;

    run_daemon(&args.socket_path, args.log.level_filter()?)
}

fn run_daemon(
    socket_path: &Path,
    log_level: tracing_subscriber::filter::LevelFilter,
) -> Result<()> {
    let shutdown = signals::init()?;

    info!("Starting...");

    let mut bpf = bpf::load(log_level)?;
    let server = Server::bind(socket_path)?;
    info!(socket = %server.path().display(), "listening for commands");

    while !shutdown.requested() {
        server.poll_and_handle(&mut bpf)?;
        thread::sleep(POLL_INTERVAL);
    }

    info!(
        signal = shutdown.signal_name().unwrap_or("unknown"),
        "Received termination signal"
    );

    bpf::detach(bpf)?;

    info!("exiting...");

    Ok(())
}
