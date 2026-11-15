//! VibePerf: real throughput between two machines, with a live graph, and latency while the link
//! is loaded. A native client and server that speak iperf3's protocol. A VibeWare app: Rust and
//! Slint on the software renderer, one small exe, no runtime beside it.
//!
//! The engine (`proto`, `client`, `server`, `tcp`, `udp`, `meter`, `tcpinfo`, `latency`) measures;
//! `run` and `view` say what it means; `firewall` and `helper` open the firewall for the server;
//! `controller` ties it all to the window, which only lays out and draws.

pub mod check;
pub mod client;
pub mod controller;
pub mod ctrl;
pub mod fake;
pub mod firewall;
pub mod helper;
pub mod history;
pub mod host;
pub mod latency;
pub mod launch;
pub mod meter;
pub mod netinfo;
pub mod prefs;
pub mod proto;
pub mod run;
pub mod server;
pub mod sock;
pub mod tcp;
pub mod tcpinfo;
pub mod text;
pub mod trust;
pub mod udp;
pub mod view;

use serde::{Deserialize, Serialize};
use slint::ComponentHandle;

slint::include_modules!();

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Recent hosts remembered.
pub const RECENT: usize = 12;
/// What the window offers: 1-8 streams, 1-300 s, UDP from 1 kbit/s to 100 Gbit/s.
pub const MAX_STREAMS: u32 = 8;
pub const MAX_SECONDS: u32 = 300;
pub const MIN_BITRATE: u64 = 1_000;
pub const MAX_BITRATE: u64 = 100_000_000_000;

/// What the window remembers between runs (prefs.json in %APPDATA%\com.tedkj.vibeperf).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
    /// "client" or "server".
    pub mode: String,
    /// Hosts tested, newest first.
    pub recent: Vec<String>,
    pub port: u16,
    /// "tcp" or "udp".
    pub proto: String,
    /// "normal", "reverse" or "both".
    pub direction: String,
    pub streams: u32,
    pub seconds: u32,
    /// UDP bits per second each way.
    pub bitrate: u64,
    pub server_port: u16,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            theme: None,
            mode: "client".into(),
            recent: Vec::new(),
            port: proto::DEFAULT_PORT,
            proto: "tcp".into(),
            direction: "normal".into(),
            streams: 1,
            seconds: 10,
            bitrate: 100_000_000,
            server_port: proto::DEFAULT_PORT,
        }
    }
}

impl Prefs {
    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => host::system_dark(),
        }
    }

    /// Only the values the window offers survive a hand-edited file; the rest fall back.
    pub fn sanitized(mut self) -> Prefs {
        let d = Prefs::default();
        if !matches!(self.theme.as_deref(), None | Some("dark") | Some("light")) {
            self.theme = None;
        }
        if !["client", "server"].contains(&self.mode.as_str()) {
            self.mode = d.mode;
        }
        if !["tcp", "udp"].contains(&self.proto.as_str()) {
            self.proto = d.proto;
        }
        if !["normal", "reverse", "both"].contains(&self.direction.as_str()) {
            self.direction = d.direction;
        }
        if self.port == 0 {
            self.port = d.port;
        }
        if self.server_port == 0 {
            self.server_port = d.server_port;
        }
        if !(1..=MAX_STREAMS).contains(&self.streams) {
            self.streams = d.streams;
        }
        if !(1..=MAX_SECONDS).contains(&self.seconds) {
            self.seconds = d.seconds;
        }
        if !(MIN_BITRATE..=MAX_BITRATE).contains(&self.bitrate) {
            self.bitrate = d.bitrate;
        }
        self.recent.retain(|r| netinfo::parse_target(r).is_ok());
        self.recent.truncate(RECENT);
        self
    }

    /// `host` to the front of the recent hosts (once, newest first, at most `RECENT`).
    pub fn remember(&mut self, host: &str) {
        self.recent.retain(|r| !r.eq_ignore_ascii_case(host));
        self.recent.insert(0, host.to_string());
        self.recent.truncate(RECENT);
    }
}

/// What a start was asked for (SPEC section 5).
#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    /// No arguments: the window.
    Window,
    /// `--server`: the window, serving.
    Server,
    /// `<host>`: the window, the client filled with it (`netinfo::parse_target` took it).
    Host(String),
    /// `--firewall <32 hex> <parent pid>`: the elevated firewall helper, in exactly the shape the
    /// app's relaunch sends (helper.rs).
    Firewall { id: String, pid: u32 },
    /// Only files dropped on the exe or its shortcut (each argument a path by its shape:
    /// `X:\`, `X:/` or `\\`, launch.rs): the window, and this toast. Nothing is filled in or read.
    Dropped(String),
}

/// The command line (the family rule, VibeTemplate), from `args_os` after the exe's own name:
/// None for anything the app does not take, which `main` refuses with exit code 2 before any
/// window, file or instance contact. That is an unknown option, an extra argument, a malformed
/// helper line, a host that is not a host name or an address, and an argument that is not
/// Unicode (RH3-I4: `std::env::args` would panic, and panic = abort ends the process without a
/// word; a lone surrogate is never U+FFFD'd into a host). One exception, after all of those:
/// a line whose every argument has a dropped file's shape by its text alone (`X:\`, `X:/`,
/// `\\`; `launch::dropped_file`, never asked of the disk) is `Dropped`, the window with a toast.
/// A word that is no host stays refused (a mistyped host, not a file); a host stays a host.
pub fn command_line(raw: &[std::ffi::OsString]) -> Option<Start> {
    taken(raw).or_else(|| match launch::dropped(raw) {
        launch::Dropped::Files(note) => Some(Start::Dropped(note)),
        launch::Dropped::No | launch::Dropped::Mixed => None,
    })
}

/// The lines the app takes itself (`command_line` before the dropped files).
fn taken(raw: &[std::ffi::OsString]) -> Option<Start> {
    let a = raw.iter().map(|x| x.to_str()).collect::<Option<Vec<&str>>>()?;
    match a[..] {
        [] => Some(Start::Window),
        ["--server"] => Some(Start::Server),
        [flag, id, pid] if flag == helper::ARG => {
            let hex = id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            let digits = !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit());
            let pid = pid.parse::<u32>().ok().filter(|_| hex && digits)?;
            Some(Start::Firewall { id: id.to_string(), pid })
        }
        // The `-` check runs on the host parse_target keeps (after its trims and brackets), so
        // `" --server"`, `"\"--x\""` and `[-x]` are refused like `--server` (RA-3), and none
        // has a dropped file's shape, so `command_line` refuses them too (exit 2).
        [host] if netinfo::parse_target(host).is_ok_and(|t| !t.host.starts_with('-')) => Some(Start::Host(host.to_string())),
        _ => None,
    }
}

/// The window with its basics wired: theme, version, copying. The controller adds the rest (the
/// theme switch too: it saves on the prefs thread).
pub fn window(prefs: prefs::Store<Prefs>) -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;
    let p = prefs.load().sanitized();
    ui.global::<Theme>().set_dark(p.dark());
    ui.set_version(VERSION.into());
    ui.on_copy_text(|t| host::copy_text(&t).is_ok());
    Ok(ui)
}
