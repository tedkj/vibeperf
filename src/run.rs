//! A finished (or stopped, or failed) test as it is shown, copied and kept: the settings, what
//! each direction measured on both ends, latency under load, the link, the per-second series.
//! The summary uses the receiver's bytes over the receiver's time, as iperf3 does; the
//! sender's are shown beside it. Everything here is pure: built from numbers, tested on its own.

use crate::latency;
use crate::meter::{Point, Role};
use crate::proto::{Proto, Results};
use serde::{Deserialize, Serialize};

pub const APP: &str = concat!("VibePerf ", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// "TCP" or "UDP".
    pub proto: String,
    /// "normal", "reverse" or "both".
    pub direction: String,
    /// Streams each way.
    pub streams: u32,
    pub seconds: u32,
    /// UDP: the total rate asked for, bits per second (0 for TCP).
    pub bitrate: u64,
    pub port: u16,
    /// A socket buffer size the test asked for (0: Windows' auto-tuning).
    pub window: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { proto: "TCP".into(), direction: "normal".into(), streams: 1, seconds: 10, bitrate: 0, port: 5201, window: 0 }
    }
}

impl Settings {
    pub fn is_udp(&self) -> bool {
        self.proto == "UDP"
    }

    /// "TCP · 4 streams · reverse · 10 s".
    pub fn kind(&self) -> String {
        let mut s = format!("{} · {} stream{}", self.proto, self.streams, if self.streams == 1 { "" } else { "s" });
        if self.direction != "normal" {
            s.push_str(&format!(" · {}", self.direction));
        }
        s.push_str(&format!(" · {} s", self.seconds));
        s
    }
}

/// How a test ended.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Outcome {
    /// "complete", "stopped" or "failed".
    pub kind: String,
    /// Seconds into the test it stopped or failed at (None: before the data started).
    pub at: Option<f64>,
    pub reason: String,
}

impl Outcome {
    pub fn complete() -> Outcome {
        Outcome { kind: "complete".into(), at: None, reason: String::new() }
    }

    pub fn stopped(at: f64) -> Outcome {
        Outcome { kind: "stopped".into(), at: Some(at), reason: String::new() }
    }

    pub fn failed(reason: impl Into<String>, at: Option<f64>) -> Outcome {
        Outcome { kind: "failed".into(), at, reason: reason.into() }
    }

    pub fn is_complete(&self) -> bool {
        self.kind == "complete"
    }

    /// "complete", "stopped at 6 s", "failed at 6 s: the server closed the connection".
    pub fn words(&self) -> String {
        let at = self.at.map(|a| format!(" at {} s", a.floor() as u64)).unwrap_or_default();
        match self.kind.as_str() {
            "complete" => "complete".into(),
            "stopped" if self.reason.is_empty() => format!("stopped{at}"),
            "stopped" => format!("{}{at}", self.reason),
            _ => format!("failed{at}: {}", self.reason),
        }
    }
}

/// One direction's numbers, from this computer's side: `up` it sent, else it received.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DirResult {
    pub up: bool,
    pub streams: u32,
    pub sent_bytes: Option<u64>,
    pub sent_secs: Option<f64>,
    pub recv_bytes: Option<u64>,
    pub recv_secs: Option<f64>,
    /// Bytes Windows sent again (this computer sent TCP).
    pub retrans_bytes: Option<u64>,
    /// Retransmitted segments the peer reported (it sent TCP and counts segments: Linux).
    pub peer_retrans: Option<i64>,
    pub udp_lost: Option<u64>,
    pub udp_total: Option<u64>,
    pub udp_ooo: Option<u64>,
    pub jitter_ms: Option<f64>,
}

impl DirResult {
    pub fn recv_mbps(&self) -> Option<f64> {
        rate(self.recv_bytes?, self.recv_secs?)
    }

    pub fn sent_mbps(&self) -> Option<f64> {
        rate(self.sent_bytes?, self.sent_secs?)
    }

    /// The headline: the receiver's rate, else (unknown) the sender's.
    pub fn headline(&self) -> Option<(f64, bool)> {
        self.recv_mbps().map(|m| (m, true)).or_else(|| self.sent_mbps().map(|m| (m, false)))
    }

    /// Retransmitted bytes as a share of bytes sent (percent).
    pub fn retrans_share(&self) -> Option<f64> {
        let sent = self.sent_bytes?;
        (sent > 0).then(|| self.retrans_bytes.map(|r| r as f64 * 100.0 / sent as f64)).flatten()
    }

    pub fn loss_percent(&self) -> Option<f64> {
        let total = self.udp_total?;
        (total > 0).then(|| self.udp_lost.unwrap_or(0) as f64 * 100.0 / total as f64)
    }

    pub fn word(&self) -> &'static str {
        if self.up { "up" } else { "down" }
    }
}

fn rate(bytes: u64, secs: f64) -> Option<f64> {
    (secs > 0.0).then(|| bytes as f64 * 8.0 / secs / 1e6)
}

/// One stream's final numbers for the table.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamRow {
    pub id: i64,
    pub up: bool,
    pub bytes: u64,
    pub mbps: f64,
    pub retrans_bytes: Option<u64>,
    pub rtt_us: Option<u32>,
    pub cwnd: Option<u32>,
    pub jitter_ms: Option<f64>,
    pub lost: Option<u64>,
    pub total: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunRecord {
    pub id: String,
    /// Unix seconds.
    pub time: u64,
    /// The user's own words for it ("office to garage via powerline").
    pub label: String,
    /// The host as typed, and the address and port measured.
    pub host: String,
    pub addr: String,
    pub settings: Settings,
    pub outcome: Outcome,
    pub dirs: Vec<DirResult>,
    pub latency: Option<latency::Summary>,
    pub link: String,
    pub series: Vec<Point>,
    pub streams: Vec<StreamRow>,
    pub hints: Vec<String>,
    /// What the peer said it is ("3.16", "VibePerf 0.1.0"; the server's side is not told).
    pub peer_version: String,
    /// Kept by the server (a test it served): the peer is the client.
    pub served: bool,
}

impl RunRecord {
    pub fn dir(&self, up: bool) -> Option<&DirResult> {
        self.dirs.iter().find(|d| d.up == up)
    }

    /// The other end, in words: "server" in the client's records, "client" in the server's.
    pub fn peer_word(&self) -> &'static str {
        if self.served { "client" } else { "server" }
    }
}

// ---------- building ----------

/// One of this side's streams at the end.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Side {
    pub id: i64,
    pub send: bool,
    pub bytes: u64,
    pub packets: u64,
    pub lost: u64,
    pub ooo: u64,
    pub jitter: f64,
    pub retrans: Option<u64>,
}

/// A peer's counts (each up to u64::MAX) summed without wrapping (IN-VibePerf-5).
fn total(counts: impl Iterator<Item = u64>) -> u64 {
    counts.fold(0, u64::saturating_add)
}

/// Each direction's numbers from this side's streams (measured over `secs`) and the peer's
/// results (None: not exchanged, as for a stopped test). The peer's streams are matched by id:
/// an id that is not there leaves the other end unknown rather than guessed.
pub fn directions(proto: Proto, own: &[Side], secs: f64, peer: Option<&Results>) -> (Vec<DirResult>, Vec<String>) {
    let mut out = Vec::new();
    let mut hints = Vec::new();
    for send in [true, false] {
        let mine: Vec<&Side> = own.iter().filter(|s| s.send == send).collect();
        if mine.is_empty() {
            continue;
        }
        let mut d = DirResult { up: send, streams: mine.len() as u32, ..DirResult::default() };
        let bytes: u64 = mine.iter().map(|s| s.bytes).sum();
        let theirs: Option<Vec<&crate::proto::StreamResult>> = peer.map(|r| mine.iter().filter_map(|s| r.streams.iter().find(|p| p.id == s.id)).collect());
        let theirs = match theirs {
            Some(t) if t.len() == mine.len() => Some(t),
            Some(_) => {
                hints.push("The peer's results did not name the same streams: its side of the count is unknown.".into());
                None
            }
            None => None,
        };
        let their_bytes = theirs.as_ref().map(|t| total(t.iter().map(|p| p.bytes)));
        let their_secs = theirs.as_ref().map(|t| t.first().and_then(|p| p.duration()).unwrap_or(secs));
        if send {
            (d.sent_bytes, d.sent_secs) = (Some(bytes), Some(secs));
            (d.recv_bytes, d.recv_secs) = (their_bytes, their_secs);
        } else {
            (d.recv_bytes, d.recv_secs) = (Some(bytes), Some(secs));
            (d.sent_bytes, d.sent_secs) = (their_bytes, their_secs);
        }
        match proto {
            Proto::Tcp => {
                if send {
                    d.retrans_bytes = mine.iter().map(|s| s.retrans).sum::<Option<u64>>();
                } else if let (Some(t), Some(r)) = (&theirs, peer)
                    && r.sender_has_retransmits == 1
                {
                    d.peer_retrans = Some(t.iter().map(|p| p.retransmits.max(0)).fold(0, i64::saturating_add));
                }
            }
            Proto::Udp => {
                if send {
                    d.udp_total = Some(mine.iter().map(|s| s.packets).sum());
                    if let Some(t) = &theirs {
                        d.udp_lost = Some(total(t.iter().map(|p| p.errors.max(0) as u64)));
                        d.jitter_ms = Some(t.iter().map(|p| p.jitter).sum::<f64>() / t.len() as f64 * 1000.0);
                    }
                } else {
                    d.udp_lost = Some(total(mine.iter().map(|s| s.lost)));
                    d.udp_ooo = Some(total(mine.iter().map(|s| s.ooo)));
                    d.jitter_ms = Some(mine.iter().map(|s| s.jitter).sum::<f64>() / mine.len() as f64 * 1000.0);
                    // The total is what the sender sent (iperf3's sum line), else the highest
                    // number this side saw.
                    d.udp_total = Some(match &theirs {
                        Some(t) if t.iter().all(|p| p.packets > 0) => total(t.iter().map(|p| p.packets as u64)),
                        _ => total(mine.iter().map(|s| s.packets)),
                    });
                }
            }
        }
        out.push(d);
    }
    (out, hints)
}

// ---------- words ----------

/// A rate as people read it: three significant figures, Mbit/s or Gbit/s, kbit/s below 1.
pub fn rate_text(mbps: f64) -> String {
    let m = mbps.max(0.0);
    if m < 1.0 {
        return format!("{:.0} kbit/s", m * 1000.0);
    }
    let in_mbit = |v: f64| {
        if v >= 99.95 {
            format!("{v:.0}")
        } else if v >= 9.995 {
            format!("{v:.1}")
        } else {
            format!("{v:.2}")
        }
    };
    if m >= 999.5 {
        let g = m / 1000.0;
        return format!("{} Gbit/s", in_mbit(g));
    }
    format!("{} Mbit/s", in_mbit(m))
}

/// "1.17 GB", "117 MB", "950 kB", "512 B" (decimal units, as the rates).
pub fn bytes_text(b: u64) -> String {
    let v = b as f64;
    let three = |x: f64, unit: &str| {
        if x >= 99.95 {
            format!("{x:.0} {unit}")
        } else if x >= 9.995 {
            format!("{x:.1} {unit}")
        } else {
            format!("{x:.2} {unit}")
        }
    };
    if b < 1000 {
        format!("{b} B")
    } else if v < 999_500.0 {
        three(v / 1e3, "kB")
    } else if v < 999_500_000.0 {
        three(v / 1e6, "MB")
    } else if v < 999_500_000_000.0 {
        three(v / 1e9, "GB")
    } else {
        three(v / 1e12, "TB")
    }
}

/// Milliseconds: "0.42 ms", "3.1 ms", "41 ms".
pub fn ms_text(ms: f64) -> String {
    let m = ms.max(0.0);
    if m < 1.0 {
        format!("{m:.2} ms")
    } else if m < 10.0 {
        format!("{m:.1} ms")
    } else {
        format!("{m:.0} ms")
    }
}

/// Added latency with its sign: "+3.1 ms", "+0.00 ms", "-0.2 ms".
pub fn added_text(ms: f64) -> String {
    if ms < 0.0 { format!("-{}", ms_text(-ms)) } else { format!("+{}", ms_text(ms)) }
}

pub fn percent_text(p: f64) -> String {
    if p > 0.0 && p < 0.01 { "< 0.01 %".into() } else if p < 10.0 { format!("{p:.2} %") } else { format!("{p:.1} %") }
}

/// The one-line result: "941 Mbit/s down, 0.00 % retransmitted, +3.1 ms under load (A), 10 s TCP x4".
pub fn one_line(r: &RunRecord) -> String {
    let x = if r.settings.streams > 1 { format!(" x{}", r.settings.streams) } else { String::new() };
    if r.dirs.is_empty() {
        // Nothing measured: what happened, and what was asked.
        return format!("{} ({} s {}{x})", r.outcome.words(), r.settings.seconds, r.settings.proto);
    }
    let mut parts: Vec<String> = Vec::new();
    for d in &r.dirs {
        match d.headline() {
            Some((m, true)) => parts.push(format!("{} {}", rate_text(m), d.word())),
            Some((m, false)) => parts.push(format!("{} {} (sent; received unknown)", rate_text(m), d.word())),
            None => parts.push(format!("no result {}", d.word())),
        }
    }
    if r.settings.is_udp() {
        let lost: Vec<String> = r.dirs.iter().filter_map(|d| d.loss_percent().map(|p| format!("{} lost", percent_text(p)))).collect();
        parts.extend(lost.into_iter().take(1));
        if let Some(j) = r.dirs.iter().filter_map(|d| d.jitter_ms).reduce(f64::max) {
            parts.push(format!("{} jitter", ms_text(j)));
        }
    } else if let Some(s) = r.dirs.iter().filter_map(|d| d.retrans_share()).reduce(f64::max) {
        parts.push(format!("{} retransmitted", percent_text(s)));
    } else if let Some(n) = r.dirs.iter().filter_map(|d| d.peer_retrans).reduce(i64::saturating_add) {
        parts.push(format!("{n} segments retransmitted ({})", r.peer_word()));
    }
    match r.latency.as_ref().and_then(|l| Some((l.added_ms()?, l.grade()?))) {
        Some((a, g)) => parts.push(format!("{} under load ({g})", added_text(a))),
        None => parts.push("latency not measured".into()),
    }
    parts.push(format!("{} s {}{x}", r.settings.seconds, r.settings.proto));
    let mut line = parts.join(", ");
    if !r.outcome.is_complete() {
        line.push_str(&format!(" ({})", r.outcome.words()));
    }
    line
}

/// The text block "Copy as text" gives: iperf3's summary layout, with VibePerf's extras.
pub fn text_block(r: &RunRecord) -> String {
    let t = crate::host::local_time(r.time);
    let mut s = String::new();
    let label = if r.label.is_empty() { String::new() } else { format!(" · {}", r.label) };
    s.push_str(&format!("{APP} · {:04}-{:02}-{:02} {:02}:{:02}{label}\n", t.year, t.month, t.day, t.hour, t.minute));
    let host = if r.host.is_empty() || r.addr.starts_with(&r.host) { String::new() } else { format!(" ({})", r.host) };
    let ver = if r.peer_version.is_empty() { String::new() } else { format!(", {}", peer_name(&r.peer_version)) };
    s.push_str(&format!("Peer:     {}{host}{ver}\n", r.addr));
    let mut test = r.settings.kind().replace(" · ", ", ");
    if r.settings.is_udp() && r.settings.bitrate > 0 {
        test.push_str(&format!(", {} asked", rate_text(r.settings.bitrate as f64 / 1e6)));
    }
    if r.settings.window > 0 {
        test.push_str(&format!(", window {} asked (auto-tuning off)", bytes_text(r.settings.window as u64)));
    }
    s.push_str(&format!("Test:     {test}\n"));
    if !r.link.is_empty() {
        s.push_str(&format!("Link:     {}\n", r.link));
    }
    s.push_str(&format!("Result:   {}\n\n", r.outcome.words()));
    // Per second, each way.
    let both = r.dirs.len() > 1;
    if !r.series.is_empty() {
        s.push_str("Interval           ");
        for d in &r.dirs {
            s.push_str(&format!("{:<16}", if d.up { "sent" } else { "received" }));
        }
        s.push('\n');
        let mut from = 0.0;
        for p in &r.series {
            s.push_str(&format!("{:>6.2}-{:<6.2} sec  ", from, p.t));
            for d in &r.dirs {
                let v = if d.up { p.send } else { p.recv };
                s.push_str(&format!("{:<16}", v.map(rate_text).unwrap_or_else(|| "-".into())));
            }
            s.push('\n');
            from = p.t;
        }
        s.push('\n');
    }
    for d in &r.dirs {
        let tag = if both { format!(" {}", d.word()) } else { String::new() };
        let line = |who: &str, bytes: Option<u64>, secs: Option<f64>, extra: String| match (bytes, secs) {
            (Some(b), Some(t)) => format!("[SUM]{tag} 0.00-{t:.2} sec  {:<10} {:<14} {who}{extra}\n", bytes_text(b), rate_text(b as f64 * 8.0 / t.max(1e-9) / 1e6)),
            _ => format!("[SUM]{tag} {who}: not known\n"),
        };
        let mut sender_extra = String::new();
        if let Some(rb) = d.retrans_bytes {
            sender_extra = format!("  {} retransmitted ({})", bytes_text(rb), d.retrans_share().map(percent_text).unwrap_or_else(|| "-".into()));
        } else if let Some(n) = d.peer_retrans {
            sender_extra = format!("  {n} segments retransmitted (reported by the {})", r.peer_word());
        }
        s.push_str(&line("sender", d.sent_bytes, d.sent_secs, sender_extra));
        let mut recv_extra = String::new();
        if let (Some(l), Some(t)) = (d.udp_lost, d.udp_total) {
            recv_extra = format!("  {}  {l}/{t} lost ({})", d.jitter_ms.map(ms_text).unwrap_or_default(), d.loss_percent().map(percent_text).unwrap_or_default());
            if let Some(o) = d.udp_ooo.filter(|o| *o > 0) {
                recv_extra.push_str(&format!(", {o} out of order"));
            }
        }
        s.push_str(&line("receiver", d.recv_bytes, d.recv_secs, recv_extra));
    }
    s.push('\n');
    s.push_str(&format!("Latency:  {}\n", latency_text(r.latency.as_ref())));
    for h in &r.hints {
        s.push_str(&format!("Note:     {h}\n"));
    }
    s
}

/// "3.16" is an iperf3 version; anything else is shown as the peer said it.
pub fn peer_name(v: &str) -> String {
    let v = crate::netinfo::clean(v);
    if v.chars().next().is_some_and(|c| c.is_ascii_digit()) { format!("iperf3 {v}") } else { v }
}

/// "idle 0.42 ms, loaded 3.1 ms (95th 5.2 ms) to 192.168.1.20: +2.7 ms (A+)".
pub fn latency_text(l: Option<&latency::Summary>) -> String {
    let Some(l) = l else { return "not measured".into() };
    let to = match &l.target {
        Some(latency::Target::Peer(a)) => format!("to {a}"),
        Some(latency::Target::Gateway(a)) => format!("to the gateway {a} (the peer did not answer pings)"),
        None => return "not measured: neither the peer nor the gateway answered pings".into(),
    };
    match (l.idle_ms, l.loaded_ms, l.added_ms(), l.grade()) {
        (Some(i), Some(lo), Some(a), Some(g)) => {
            let p95 = l.loaded_p95_ms.map(|p| format!(" (95th {})", ms_text(p))).unwrap_or_default();
            format!("idle {}, loaded {}{p95} {to}: {} ({g})", ms_text(i), ms_text(lo), added_text(a))
        }
        (Some(i), None, _, _) => format!("idle {} {to}; no reply under load ({} of {} lost)", ms_text(i), l.loaded_lost, l.loaded_sent),
        _ => format!("not measured {to}"),
    }
}

/// The role a stream has as seen from the other end.
pub fn flip(r: Role) -> Role {
    match r {
        Role::Send => Role::Recv,
        Role::Recv => Role::Send,
    }
}
