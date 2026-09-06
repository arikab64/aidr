use std::ffi::c_int;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::low_level::signal_name;

const TERM_SIGNALS: [c_int; 2] = [SIGTERM, SIGINT];

#[derive(Clone, Debug)]
pub struct Shutdown(Arc<AtomicUsize>);

impl Shutdown {
    /// The signal that requested shutdown, or `None` if none has arrived yet.
    pub fn signal(&self) -> Option<c_int> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            signal => Some(signal as c_int),
        }
    }

    /// Whether a termination signal has been delivered.
    pub fn requested(&self) -> bool {
        self.signal().is_some()
    }

    /// Name of the signal that requested shutdown, e.g. `"SIGTERM"`.
    pub fn signal_name(&self) -> Option<&'static str> {
        self.signal().and_then(signal_name)
    }
}

pub fn init() -> Result<Shutdown> {
    let flag = Arc::new(AtomicUsize::new(0));

    for signal in TERM_SIGNALS {
        signal_hook::flag::register_usize(signal, Arc::clone(&flag), signal as usize)
            .with_context(|| {
                format!(
                    "Failed to register handler for {}",
                    signal_name(signal).unwrap_or("signal")
                )
            })?;
    }

    Ok(Shutdown(flag))
}
