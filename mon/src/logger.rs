use std::path::PathBuf;
use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use libbpf_rs::PrintLevel;
use tracing::{debug, info, warn};
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{RollingFileAppender, Rotation},
};
use tracing_subscriber::{fmt, prelude::*};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum LogRotation {
    Daily,
    Weekly,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum LogFormat {
    Compact,
    Json,
}

#[derive(ClapArgs, Debug)]
pub struct LoggerOpts {
    #[arg(long, default_value = "info", help = "info, debug, warn, error")]
    pub log_level: String,

    /// Directory for rotating log files. Without it, logs go to stderr only.
    #[arg(long)]
    pub log_dir: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = LogRotation::Daily, help = "daily or weekly")]
    pub log_rotation: LogRotation,

    #[arg(long, value_enum, default_value_t = LogFormat::Compact, help = "compact or json")]
    pub log_format: LogFormat,

   #[arg(long)]
    pub libbpf_debug: bool,
}

impl LoggerOpts {
    pub fn level_filter(&self) -> Result<tracing_subscriber::filter::LevelFilter> {
        Ok(self.log_level.parse()?)
    }
}

pub fn init(opt: &LoggerOpts) -> Result<Vec<WorkerGuard>> {
    let mut guards = Vec::new();

    let filter = opt.level_filter()?;

    let (stderr_writer, guard) = tracing_appender::non_blocking(std::io::stderr());
    guards.push(guard);

    let stderr_layer = fmt::layer()
        .with_writer(stderr_writer)
        .with_target(true)
        .with_thread_names(true)
        .with_line_number(true)
        .compact();

    let file_layer = match &opt.log_dir {
        Some(dir) => {
            let rotation = match opt.log_rotation {
                LogRotation::Daily => Rotation::DAILY,
                LogRotation::Weekly => Rotation::WEEKLY,
            };

            let appender = RollingFileAppender::builder()
                .rotation(rotation)
                .filename_prefix("mon")
                .filename_suffix("log")
                .build(dir)
                .with_context(||{
                    format!("Failed to create log file in directory: {:?}", dir.display())
                })?;

            let (file_writer, file_guard) = tracing_appender::non_blocking(appender);
            guards.push(file_guard);

            let layer = fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false)
                .with_thread_names(true)
                .with_line_number(true);
            let layer = match opt.log_format {
                LogFormat::Compact => layer.compact().boxed(),
                LogFormat::Json => layer.json().boxed(),
            };

            Some(layer)
        }
        None => None,
    };

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .with(filter)
        .init();

    install_libbpf_forwarding(opt.libbpf_debug);

    Ok(guards)
}


fn install_libbpf_forwarding(debug_output: bool) {
    let min = if debug_output {
        PrintLevel::Debug
    } else {
        PrintLevel::Info
    };

    libbpf_rs::set_print(Some((min, libbpf_print)));
}


fn libbpf_print(level: PrintLevel, msg: String) {
    let msg = msg.trim_end();
    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}
