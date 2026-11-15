//! Latency while the link is loaded: an idle baseline before the data starts (20 pings 100 ms
//! apart), then a ping every 100 ms during the test, and a bufferbloat grade on the latency the
//! load added, with Waveform's bands so results compare across tools.
//!
//! Pings are Windows' ICMP API (`IcmpSendEcho2`, `Icmp6SendEcho2`: no admin rights, no raw
//! socket), timed around the call with the performance counter, as in VibeTrace (the API's own
//! round trip is whole milliseconds). The statistics are pure and tested on their own.

use std::net::IpAddr;
use std::time::Instant;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

/// Pings in the idle baseline, and the gap between pings throughout.
pub const IDLE_PINGS: usize = 20;
pub const GAP_MS: u64 = 100;
/// How long one ping waits for its reply.
pub const TIMEOUT_MS: u32 = 1000;
/// A target is used when it answers at least this many of the idle pings (a quarter): a peer
/// behind Windows' default firewall answers none, a lossy Wi-Fi peer still most.
pub const ENOUGH: usize = IDLE_PINGS / 4;

// ---------- statistics ----------

fn sorted(v: &[u32]) -> Vec<u32> {
    let mut s = v.to_vec();
    s.sort_unstable();
    s
}

/// The median in microseconds (the mean of the middle two for an even count).
pub fn median_us(v: &[u32]) -> Option<f64> {
    let s = sorted(v);
    let n = s.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(s[n / 2] as f64),
        _ => Some((s[n / 2 - 1] as f64 + s[n / 2] as f64) / 2.0),
    }
}

/// The 95th percentile in microseconds, nearest rank (a value that was measured, never one
/// interpolated between two).
pub fn p95_us(v: &[u32]) -> Option<f64> {
    let s = sorted(v);
    if s.is_empty() {
        return None;
    }
    let rank = (0.95 * s.len() as f64).ceil() as usize;
    Some(s[rank.clamp(1, s.len()) - 1] as f64)
}

/// Waveform's bufferbloat bands on the added median latency (ms): A+ under 5, A under 30, B
/// under 60, C under 200, D under 400, F from 400.
pub fn grade(added_ms: f64) -> &'static str {
    let a = added_ms.max(0.0);
    if a < 5.0 {
        "A+"
    } else if a < 30.0 {
        "A"
    } else if a < 60.0 {
        "B"
    } else if a < 200.0 {
        "C"
    } else if a < 400.0 {
        "D"
    } else {
        "F"
    }
}

/// Who the latency was measured to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Target {
    Peer(String),
    /// The peer did not answer; this computer's default gateway did.
    Gateway(String),
}

/// One phase's pings: the round trips of those answered (µs) and how many were sent.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Pings {
    pub rtts: Vec<u32>,
    pub sent: usize,
}

impl Pings {
    pub fn lost(&self) -> usize {
        self.sent.saturating_sub(self.rtts.len())
    }
}

/// The target from the idle phase: the peer when it answered enough, else the gateway when it
/// did, else none ("latency not measured").
pub fn choose(peer: &Pings, gateway: Option<(&str, &Pings)>, peer_addr: &str) -> Option<Target> {
    if peer.rtts.len() >= ENOUGH {
        return Some(Target::Peer(peer_addr.to_string()));
    }
    match gateway {
        Some((g, p)) if p.rtts.len() >= ENOUGH => Some(Target::Gateway(g.to_string())),
        _ => None,
    }
}

/// The result: medians and the loaded 95th percentile in ms, the added latency and its grade.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Summary {
    pub target: Option<Target>,
    pub idle_ms: Option<f64>,
    pub loaded_ms: Option<f64>,
    pub loaded_p95_ms: Option<f64>,
    pub idle_sent: usize,
    pub idle_lost: usize,
    pub loaded_sent: usize,
    pub loaded_lost: usize,
}

impl Summary {
    pub fn build(target: Option<Target>, idle: &Pings, loaded: &Pings) -> Summary {
        Summary {
            target,
            idle_ms: median_us(&idle.rtts).map(|v| v / 1000.0),
            loaded_ms: median_us(&loaded.rtts).map(|v| v / 1000.0),
            loaded_p95_ms: p95_us(&loaded.rtts).map(|v| v / 1000.0),
            idle_sent: idle.sent,
            idle_lost: idle.lost(),
            loaded_sent: loaded.sent,
            loaded_lost: loaded.lost(),
        }
    }

    /// Latency the load added (ms), when both medians are known.
    pub fn added_ms(&self) -> Option<f64> {
        Some(self.loaded_ms? - self.idle_ms?)
    }

    pub fn grade(&self) -> Option<&'static str> {
        self.added_ms().map(grade)
    }
}

// ---------- pinging ----------

/// One target's pinger: a round trip in µs, or None (no reply in time, or an error).
pub trait Pinger: Send {
    fn ping(&mut self) -> Option<u32>;
}

/// Opens pingers (the system's ICMP, or the tests' fake).
pub trait PingNet: Send + Sync {
    fn open(&self, dest: IpAddr, scope_id: u32) -> Result<Box<dyn Pinger>, String>;
}

pub struct Icmp;

impl PingNet for Icmp {
    fn open(&self, dest: IpAddr, scope_id: u32) -> Result<Box<dyn Pinger>, String> {
        // SAFETY: no arguments; INVALID_HANDLE_VALUE on failure.
        let handle = unsafe { if dest.is_ipv6() { Icmp6CreateFile() } else { IcmpCreateFile() } };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(format!("Windows' ICMP service did not open: {}", std::io::Error::last_os_error()));
        }
        let reply = if dest.is_ipv6() { size_of::<ICMPV6_ECHO_REPLY_LH>() } else { size_of::<ICMP_ECHO_REPLY>() };
        // The reply, the echoed 32 bytes, room for an ICMP error and the header it quotes.
        let bytes = reply + 32 + 8 + 128;
        Ok(Box::new(IcmpPinger { handle, dest, scope_id, payload: [b'v'; 32], reply: vec![0u64; bytes.div_ceil(8)] }))
    }
}

struct IcmpPinger {
    handle: HANDLE,
    dest: IpAddr,
    scope_id: u32,
    payload: [u8; 32],
    reply: Vec<u64>,
}

// SAFETY: the handle belongs to this pinger alone and is used by one thread at a time.
unsafe impl Send for IcmpPinger {}

impl Drop for IcmpPinger {
    fn drop(&mut self) {
        // SAFETY: opened in `open`, closed once.
        unsafe { IcmpCloseHandle(self.handle) };
    }
}

impl Pinger for IcmpPinger {
    fn ping(&mut self) -> Option<u32> {
        self.reply.fill(0);
        let size = (self.reply.len() * 8) as u32;
        let buf = self.reply.as_mut_ptr().cast::<core::ffi::c_void>();
        let data = self.payload.as_ptr().cast();
        let t0 = Instant::now();
        let ok = match self.dest {
            IpAddr::V4(d) => {
                // SAFETY: a synchronous call (no event, no APC) writing at most `size` bytes.
                let n = unsafe { IcmpSendEcho2(self.handle, std::ptr::null_mut(), None, std::ptr::null(), u32::from_ne_bytes(d.octets()), data, 32, std::ptr::null(), buf, size, TIMEOUT_MS) };
                // SAFETY: zeroed, aligned, at least one ICMP_ECHO_REPLY long.
                let r = unsafe { &*(buf as *const ICMP_ECHO_REPLY) };
                n > 0 && r.Status == IP_SUCCESS && u32::from_ne_bytes(d.octets()) == r.Address
            }
            IpAddr::V6(d) => {
                // SAFETY: plain structs, zeroed, then the fields set.
                let src: SOCKADDR_IN6 = SOCKADDR_IN6 { sin6_family: AF_INET6, ..unsafe { std::mem::zeroed() } };
                let mut dst: SOCKADDR_IN6 = SOCKADDR_IN6 { sin6_family: AF_INET6, ..unsafe { std::mem::zeroed() } };
                dst.sin6_addr.u.Byte = d.octets();
                dst.Anonymous.sin6_scope_id = self.scope_id;
                // SAFETY: as above; the source is "any".
                let n = unsafe { Icmp6SendEcho2(self.handle, std::ptr::null_mut(), None, std::ptr::null(), &src, &dst, data, 32, std::ptr::null(), buf, size, TIMEOUT_MS) };
                // The synchronous form hands the reply back already parsed: nothing parses it
                // again (`Icmp6ParseReplies` is for the event/APC form only; FA3).
                // SAFETY: zeroed, aligned, at least one ICMPV6_ECHO_REPLY_LH long.
                let r = unsafe { &*(buf as *const ICMPV6_ECHO_REPLY_LH) };
                n > 0 && r.Status == IP_SUCCESS
            }
        };
        let us = t0.elapsed().as_micros().min(u32::MAX as u128) as u32;
        ok.then_some(us)
    }
}
