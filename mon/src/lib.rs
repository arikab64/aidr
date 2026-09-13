#[path = "../../bpf/mon_files.skel.rs"]
pub mod mon_files_skel;

#[path = "../../bpf/mon_procs.skel.rs"]
pub mod mon_procs_skel;

#[path = "../../bpf/mon_net.skel.rs"]
pub mod mon_net_skel;

pub mod bpf;
pub mod logger;
pub mod net;
pub mod server;
pub mod signals;
pub mod tasks;
