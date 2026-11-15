//! What the window shows, in words and pixels, from a running test (`client::Live`) or a
//! record: the tiles, the graph's bars, the stream rows, the list rows, the titles. Pure: the
//! controller hands these to the .slint structs.

use crate::client::{Live, Phase};
use crate::latency::{self, Pings};
use crate::meter::Point;
use crate::run::{self, DirResult, RunRecord, StreamRow};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tile {
    pub caption: String,
    pub value: String,
    pub sub: String,
    /// 0 plain, 1 ok, 2 warn, 3 danger.
    pub state: i32,
    pub tip: String,
}

fn tile(caption: &str, value: impl Into<String>, sub: impl Into<String>) -> Tile {
    Tile { caption: caption.into(), value: value.into(), sub: sub.into(), state: 0, tip: String::new() }
}

const DASH: &str = "-";

/// A rate without its unit, for the table's MBIT/S column: "941", "85.2", "9412".
pub fn mbit(m: f64) -> String {
    if m >= 99.95 {
        format!("{m:.0}")
    } else if m >= 9.995 {
        format!("{m:.1}")
    } else {
        format!("{m:.2}")
    }
}

/// Two rates in one unit: ("941 / 935", "Mbit/s"), ("9.41 / 9.38", "Gbit/s").
fn pair(a: Option<f64>, b: Option<f64>) -> (String, &'static str) {
    let max = a.unwrap_or(0.0).max(b.unwrap_or(0.0));
    let (div, unit) = if max >= 999.5 { (1000.0, "Gbit/s") } else { (1.0, "Mbit/s") };
    let f = |v: Option<f64>| v.map(|v| mbit(v / div)).unwrap_or_else(|| DASH.into());
    (format!("{} / {}", f(a), f(b)), unit)
}

fn grade_state(g: &str) -> i32 {
    match g {
        "A+" | "A" => 1,
        "B" | "C" => 2,
        _ => 3,
    }
}

// ---------- tiles ----------

/// The tiles of a finished (or stopped, or failed) test. A served test has no latency (the
/// client measures that): `server` leaves those tiles out.
pub fn record_tiles(r: &RunRecord, server: bool) -> Vec<Tile> {
    let mut out = Vec::new();
    let udp = r.settings.is_udp();
    // THROUGHPUT: the receiver's count over its time; the sender's beside it.
    out.push(match r.dirs.as_slice() {
        [] => tile("THROUGHPUT", DASH, if r.outcome.is_complete() { "" } else { "no data" }),
        [d] => {
            let (value, sub) = match (d.recv_mbps(), d.sent_mbps()) {
                (Some(rv), Some(s)) => (run::rate_text(rv), format!("sent {}", run::rate_text(s))),
                (Some(rv), None) => (run::rate_text(rv), "sender unknown".into()),
                (None, Some(s)) => (DASH.into(), format!("sent {}; received unknown", run::rate_text(s))),
                (None, None) => (DASH.into(), String::new()),
            };
            let mut t = tile("THROUGHPUT", value, sub);
            t.tip = format!("Received ({}): the receiver's bytes over its time, as iperf3 counts. The sender's count is beside it.", d.word());
            t
        }
        ds => {
            let up = ds.iter().find(|d| d.up).and_then(|d| d.headline()).map(|h| h.0);
            let down = ds.iter().find(|d| !d.up).and_then(|d| d.headline()).map(|h| h.0);
            let (v, unit) = pair(up, down);
            let mut t = tile("THROUGHPUT", v, format!("{unit} up / down"));
            t.tip = "Each way: the receiver's bytes over its time.".into();
            t
        }
    });
    // RETRANSMITTED (TCP) or LOSS (UDP).
    if udp {
        out.push(loss_tile(&r.dirs));
        out.push(jitter_tile(&r.dirs));
    } else {
        out.push(retrans_tile(&r.dirs, r.peer_word()));
    }
    if !server {
        let (lat, grade) = latency_tiles(r.latency.as_ref());
        out.push(lat);
        out.push(grade);
    }
    out.push(link_tile(&r.link));
    out
}

fn retrans_tile(dirs: &[DirResult], peer: &str) -> Tile {
    let sent: Vec<&DirResult> = dirs.iter().filter(|d| d.retrans_bytes.is_some()).collect();
    if let Some(share) = sent.iter().filter_map(|d| d.retrans_share()).reduce(f64::max) {
        let bytes: u64 = sent.iter().filter_map(|d| d.retrans_bytes).fold(0, u64::saturating_add);
        let mut t = tile("RETRANSMITTED", run::percent_text(share), run::bytes_text(bytes));
        t.state = if share >= 1.0 { 3 } else if share >= 0.1 { 2 } else { 0 };
        t.tip = "Bytes Windows sent again, as a share of the bytes sent. Windows counts bytes, not segments.".into();
        return t;
    }
    if let Some(n) = dirs.iter().filter_map(|d| d.peer_retrans).reduce(i64::saturating_add) {
        let mut t = tile("RETRANSMITTED", format!("{n}"), format!("segments, reported by the {peer}"));
        t.tip = format!("The {peer} sent and counted these segments (Linux reports a count; Windows does not).");
        return t;
    }
    let mut t = tile("RETRANSMITTED", DASH, "the sender did not report any");
    t.tip = format!("Only a sender knows what it sent again, and this {peer} did not say (Windows and macOS do not count segments).");
    t
}

fn loss_tile(dirs: &[DirResult]) -> Tile {
    let known: Vec<&DirResult> = dirs.iter().filter(|d| d.loss_percent().is_some()).collect();
    if known.is_empty() {
        return tile("LOSS", DASH, "the receiver's count is unknown");
    }
    // Peer-reported counts (up to u64::MAX each, one direction each in a bidirectional test):
    // they saturate, never wrap or panic (RIN1-9).
    let (lost, total): (u64, u64) = known.iter().fold((0, 0), |(l, t), d| (l.saturating_add(d.udp_lost.unwrap_or(0)), t.saturating_add(d.udp_total.unwrap_or(0))));
    let p = if total > 0 { lost as f64 * 100.0 / total as f64 } else { 0.0 };
    let mut t = tile("LOSS", run::percent_text(p), format!("{} of {}", thousands(lost), thousands(total)));
    t.state = if p >= 1.0 { 3 } else if p > 0.0 { 2 } else { 1 };
    let ooo: u64 = known.iter().filter_map(|d| d.udp_ooo).fold(0, u64::saturating_add);
    t.tip = if ooo > 0 { format!("Datagrams lost (gaps in the sequence), of those sent. {ooo} more came out of order.") } else { "Datagrams lost (gaps in the sequence), of those sent.".into() };
    t
}

fn jitter_tile(dirs: &[DirResult]) -> Tile {
    match dirs.iter().filter_map(|d| d.jitter_ms).reduce(f64::max) {
        Some(j) => {
            let mut t = tile("JITTER", run::ms_text(j), "");
            t.tip = "RFC 3550 jitter of the datagrams' transit times, as the receiver measured.".into();
            t
        }
        None => tile("JITTER", DASH, "unknown"),
    }
}

/// LATENCY (idle to loaded) and GRADE.
fn latency_tiles(l: Option<&latency::Summary>) -> (Tile, Tile) {
    let Some(l) = l else { return (tile("LATENCY", DASH, "not measured"), tile("GRADE", DASH, "")) };
    let to = match &l.target {
        Some(latency::Target::Peer(_)) => String::new(),
        Some(latency::Target::Gateway(g)) => format!("to gateway {g}"),
        None => return (tile("LATENCY", DASH, "not measured: no ping answered"), tile("GRADE", DASH, "")),
    };
    let (Some(idle), Some(loaded)) = (l.idle_ms, l.loaded_ms) else {
        let mut t = tile("LATENCY", l.idle_ms.map(run::ms_text).unwrap_or_else(|| DASH.into()), "no reply under load");
        t.state = 3;
        return (t, tile("GRADE", DASH, ""));
    };
    let sub = match (l.loaded_p95_ms, to.is_empty()) {
        (_, false) => to,
        (Some(p), true) => format!("95th {}", run::ms_text(p)),
        (None, true) => String::new(),
    };
    let mut lt = tile("LATENCY", format!("{} \u{2192} {}", run::ms_text(idle), run::ms_text(loaded)), sub);
    lt.tip = "Median round trip idle, then under load (a ping every 100 ms during the test).".into();
    let added = loaded - idle;
    let g = latency::grade(added);
    let mut gt = tile("GRADE", g, format!("{} under load", run::added_text(added)));
    gt.state = grade_state(g);
    gt.tip = "Bufferbloat grade on the latency the load added (Waveform's bands): A+ under 5 ms, A under 30, B under 60, C under 200, D under 400.".into();
    (lt, gt)
}

fn link_tile(link: &str) -> Tile {
    match link.split_once(", ") {
        Some((kind, rest)) => tile("LINK", kind, rest),
        None if !link.is_empty() => tile("LINK", link, ""),
        None => tile("LINK", DASH, "unknown"),
    }
}

/// The tiles while a test runs: this side's last second, its retransmissions or loss so far,
/// latency so far.
pub fn live_tiles(l: &Live, udp: bool, server: bool) -> Vec<Tile> {
    let last = l.series.last();
    let sends = l.streams.iter().any(|s| s.up);
    let recvs = l.streams.iter().any(|s| !s.up);
    let (value, sub) = match (last, sends, recvs) {
        (Some(p), true, true) => {
            let (v, unit) = pair(p.send, p.recv);
            (v, format!("{unit} up / down, this second"))
        }
        (Some(p), true, false) => (run::rate_text(p.send.unwrap_or(0.0)), "sent, this second".into()),
        (Some(p), false, true) => (run::rate_text(p.recv.unwrap_or(0.0)), "received, this second".into()),
        _ => (DASH.into(), String::new()),
    };
    let mut out = vec![tile("THROUGHPUT", value, sub)];
    if udp {
        let rx: Vec<&StreamRow> = l.streams.iter().filter(|s| !s.up).collect();
        if rx.is_empty() {
            out.push(tile("LOSS", DASH, "the receiver counts it"));
            out.push(tile("JITTER", DASH, "the receiver measures it"));
        } else {
            let (lost, total) = rx.iter().fold((0u64, 0u64), |(a, b), s| (a + s.lost.unwrap_or(0), b + s.total.unwrap_or(0)));
            let p = if total > 0 { lost as f64 * 100.0 / total as f64 } else { 0.0 };
            out.push(tile("LOSS", run::percent_text(p), format!("{} of {}", thousands(lost), thousands(total))));
            let j = rx.iter().filter_map(|s| s.jitter_ms).fold(0.0, f64::max);
            out.push(tile("JITTER", run::ms_text(j), ""));
        }
    } else {
        let tx: Vec<&StreamRow> = l.streams.iter().filter(|s| s.up).collect();
        let sent: u64 = tx.iter().map(|s| s.bytes).sum();
        match tx.iter().map(|s| s.retrans_bytes).sum::<Option<u64>>() {
            Some(r) if sent > 0 => out.push(tile("RETRANSMITTED", run::percent_text(r as f64 * 100.0 / sent as f64), run::bytes_text(r))),
            _ => out.push(tile("RETRANSMITTED", DASH, if tx.is_empty() { "the sender counts it" } else { "" })),
        }
    }
    if !server {
        out.push(live_latency(&l.idle, &l.loaded, l.target.as_ref(), l.phase));
        out.push(live_grade(&l.idle, &l.loaded));
    }
    out.push(link_tile(&l.link));
    out
}

fn live_latency(idle: &Pings, loaded: &Pings, target: Option<&latency::Target>, phase: Phase) -> Tile {
    if phase == Phase::Pinging || (idle.sent == 0 && matches!(phase, Phase::Resolving | Phase::Connecting)) {
        return tile("LATENCY", DASH, "measuring idle...");
    }
    if target.is_none() {
        return tile("LATENCY", DASH, if idle.sent > 0 { "not measured: no ping answered" } else { "not measured" });
    }
    let i = latency::median_us(&idle.rtts).map(|v| v / 1000.0);
    let lo = latency::median_us(&loaded.rtts).map(|v| v / 1000.0);
    match (i, lo) {
        (Some(i), Some(lo)) => tile("LATENCY", format!("{} \u{2192} {}", run::ms_text(i), run::ms_text(lo)), "idle \u{2192} loaded so far"),
        (Some(i), None) => tile("LATENCY", run::ms_text(i), "idle"),
        _ => tile("LATENCY", DASH, ""),
    }
}

/// The grade so far: only after a second of pings under load (ten), never from one or two.
fn live_grade(idle: &Pings, loaded: &Pings) -> Tile {
    match (latency::median_us(&idle.rtts), latency::median_us(&loaded.rtts)) {
        (Some(i), Some(lo)) if loaded.rtts.len() >= 10 => {
            let added = (lo - i) / 1000.0;
            let g = latency::grade(added);
            let mut t = tile("GRADE", g, format!("{} so far", run::added_text(added)));
            t.state = grade_state(g);
            t
        }
        _ => tile("GRADE", DASH, ""),
    }
}

pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

// ---------- the graph ----------

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Chart {
    pub grid: String,
    pub up: String,
    pub down: String,
    pub y_top: String,
    pub y_mid: String,
    pub y_top_at: f32,
    pub y_mid_at: f32,
    pub x_left: String,
    pub x_right: String,
    pub empty: String,
    pub legend_up: String,
    pub legend_down: String,
    pub a11y: String,
}

/// The top of the scale: the next 1, 2, 2.5 or 5 times a power of ten above `v` (Mbit/s).
pub fn nice_max(v: f64) -> f64 {
    // NaN and the infinities are not finite; zero and below have no scale either.
    if !v.is_finite() || v <= 0.0 {
        return 1.0;
    }
    let p = 10f64.powf(v.log10().floor());
    for m in [1.0, 2.0, 2.5, 5.0, 10.0] {
        if v <= m * p * 1.000_000_1 {
            return m * p;
        }
    }
    10.0 * p
}

/// "1 Gbit/s", "500 Mbit/s", "2.5 Gbit/s", "250 kbit/s" (a scale's round numbers).
pub fn scale_text(m: f64) -> String {
    let trim = |x: f64| {
        let s = format!("{x:.2}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    };
    if m >= 1000.0 {
        format!("{} Gbit/s", trim(m / 1000.0))
    } else if m >= 1.0 {
        format!("{} Mbit/s", trim(m))
    } else {
        format!("{} kbit/s", trim(m * 1000.0))
    }
}

fn rect(out: &mut String, x0: f32, y0: f32, x1: f32, y1: f32) {
    if x1 - x0 < 0.5 || y1 - y0 < 0.25 {
        return;
    }
    out.push_str(&format!("M {x0:.1} {y0:.1} L {x1:.1} {y0:.1} L {x1:.1} {y1:.1} L {x0:.1} {y1:.1} Z "));
}

/// Bars in a plot of `w` x `h` pixels: one per second over `seconds` (or as many as there are
/// intervals), the scale from the highest bar. `up_only` / `down_only`: which ways ran.
pub fn chart(series: &[Point], seconds: u32, w: f32, h: f32, ups: bool, downs: bool, measured_here: bool) -> Chart {
    let mut c = Chart { x_left: "0 s".into(), ..Chart::default() };
    // The second an interval belongs to: a point a moment past a second (the test's last
    // sliver joined to it) is still that second.
    let second = |t: f64| (t - crate::meter::SLIVER).ceil().max(1.0);
    let n = (seconds as f64).max(series.last().map_or(0.0, |p| second(p.t))).max(1.0) as usize;
    c.x_right = format!("{n} s");
    let both = ups && downs;
    if both {
        c.legend_up = "up, as sent".into();
        c.legend_down = "down, as received".into();
    } else if ups {
        c.legend_up = if measured_here { "Mbit/s each second, as sent by this computer".into() } else { "Mbit/s each second, as sent".into() };
    } else if downs {
        c.legend_up = if measured_here { "Mbit/s each second, as received by this computer".into() } else { "Mbit/s each second, as received".into() };
    }
    if series.is_empty() {
        c.empty = "Waiting for the first second".into();
    }
    let max = series.iter().flat_map(|p| [p.send.unwrap_or(0.0), p.recv.unwrap_or(0.0)]).fold(0.0, f64::max);
    let top = nice_max(max * 1.05);
    // No scale over nothing.
    if !series.is_empty() {
        c.y_top = scale_text(top);
        c.y_mid = scale_text(top / 2.0);
    }
    if w < 4.0 || h < 4.0 {
        return c;
    }
    // Gridlines: the top, the middle, the base.
    let (top_y, mid_y, base) = (0.5f32, (h / 2.0).floor() + 0.5, h - 0.5);
    c.y_top_at = top_y;
    c.y_mid_at = mid_y;
    for y in [top_y, mid_y] {
        rect(&mut c.grid, 0.0, y - 0.5, w, y + 0.5);
    }
    rect(&mut c.grid, 0.0, base - 0.5, w, base + 0.5);
    let slot = w / n as f32;
    // Bars with air between them: a quarter of the slot (at least 2 px) when there is room.
    let gap = if slot >= 8.0 { (slot * 0.25).max(2.0).floor() } else if slot >= 4.0 { 1.0 } else { 0.0 };
    let scale = |v: f64| ((v / top) as f32 * (h - 1.0)).clamp(0.0, h - 1.0);
    for p in series {
        // The interval's second: a part-second at the end gets the slot after the last.
        let k = (second(p.t) as usize).min(n) - 1;
        let x0 = k as f32 * slot + gap / 2.0;
        let x1 = (k + 1) as f32 * slot - gap / 2.0;
        if both {
            let mid = (x0 + x1) / 2.0;
            if let Some(v) = p.send {
                rect(&mut c.up, x0, base - 0.5 - scale(v), mid - 0.5, base - 0.5);
            }
            if let Some(v) = p.recv {
                rect(&mut c.down, mid + 0.5, base - 0.5 - scale(v), x1, base - 0.5);
            }
        } else if let Some(v) = if ups { p.send } else { p.recv } {
            rect(&mut c.up, x0, base - 0.5 - scale(v), x1, base - 0.5);
        }
    }
    let rates: Vec<String> = series.iter().map(|p| match (p.send, p.recv) {
        (Some(s), Some(r)) => format!("{} up {} down", run::rate_text(s), run::rate_text(r)),
        (Some(s), None) => run::rate_text(s),
        (None, Some(r)) => run::rate_text(r),
        _ => String::new(),
    }).collect();
    c.a11y = if rates.is_empty() { "No seconds yet".into() } else { format!("{} seconds: {}", rates.len(), rates.join(", ")) };
    c
}

// ---------- the stream table ----------

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StreamText {
    pub id: String,
    pub dir: String,
    pub bytes: String,
    pub rate: String,
    pub a: String,
    pub b: String,
    pub c: String,
    pub a11y: String,
}

/// The three last columns' heads: TCP's or UDP's.
pub fn stream_heads(udp: bool) -> [&'static str; 3] {
    if udp { ["JITTER", "LOST / TOTAL", ""] } else { ["RETRANSMITTED", "RTT", "CWND"] }
}

pub fn stream_text(s: &StreamRow, udp: bool) -> StreamText {
    let dir = if s.up { "up" } else { "down" };
    let mut t = StreamText { id: s.id.to_string(), dir: dir.into(), bytes: run::bytes_text(s.bytes), rate: mbit(s.mbps), ..StreamText::default() };
    if udp {
        t.a = s.jitter_ms.map(run::ms_text).unwrap_or_else(|| DASH.into());
        t.b = match (s.lost, s.total) {
            (Some(l), Some(n)) => format!("{} / {}", thousands(l), thousands(n)),
            (None, Some(n)) => format!("- / {}", thousands(n)),
            _ => DASH.into(),
        };
    } else {
        t.a = match s.retrans_bytes {
            Some(r) if s.bytes > 0 => format!("{} ({})", run::bytes_text(r), run::percent_text(r as f64 * 100.0 / s.bytes as f64)),
            Some(r) => run::bytes_text(r),
            None => DASH.into(),
        };
        t.b = s.rtt_us.map(|u| run::ms_text(u as f64 / 1000.0)).unwrap_or_else(|| DASH.into());
        t.c = s.cwnd.map(|c| run::bytes_text(c as u64)).unwrap_or_else(|| DASH.into());
    }
    let heads = stream_heads(udp);
    t.a11y = format!("{dir}, {} at {} Mbit/s, {} {}, {} {}{}", t.bytes, t.rate, heads[0].to_lowercase(), t.a, heads[1].to_lowercase(), t.b, if udp { String::new() } else { format!(", cwnd {}", t.c) });
    t
}

// ---------- titles and rows ----------

/// "server.lan (192.168.1.20:5201) · TCP · 4 streams · reverse · 10 s".
pub fn run_title(r: &RunRecord) -> String {
    let who = if r.host.is_empty() || r.addr.starts_with(&r.host) || r.addr.trim_start_matches('[').starts_with(&r.host) { crate::netinfo::clean(&r.addr) } else { format!("{} ({})", crate::netinfo::clean(&r.host), crate::netinfo::clean(&r.addr)) };
    format!("{who} · {}", r.settings.kind())
}

/// The outcome's words and colour state: complete plain, stopped warn, failed danger.
pub fn outcome(r: &RunRecord) -> (String, i32) {
    match r.outcome.kind.as_str() {
        "complete" => ("complete".into(), 0),
        "stopped" => (r.outcome.words(), 2),
        _ => (crate::netinfo::clean(&r.outcome.words()), 3),
    }
}

/// "14:03" today, "10-21 14:03" another day.
pub fn when(t: u64, now: u64) -> String {
    let a = crate::host::local_time(t);
    let b = crate::host::local_time(now);
    if (a.year, a.month, a.day) == (b.year, b.month, b.day) {
        format!("{:02}:{:02}", a.hour, a.minute)
    } else if a.year == b.year {
        format!("{:02}-{:02} {:02}:{:02}", a.month, a.day, a.hour, a.minute)
    } else {
        format!("{:04}-{:02}-{:02}", a.year, a.month, a.day)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RunText {
    pub id: String,
    pub time: String,
    pub title: String,
    pub line: String,
    pub state: i32,
    pub a11y: String,
}

/// A history row: your label (or the host), the one-line result.
pub fn history_row(r: &RunRecord, now: u64) -> RunText {
    let title = if r.label.is_empty() { crate::netinfo::clean(if r.host.is_empty() { &r.addr } else { &r.host }) } else { crate::netinfo::clean(&r.label) };
    let line = crate::netinfo::clean(&run::one_line(r));
    let state = match r.outcome.kind.as_str() {
        "complete" => 0,
        "stopped" => 1,
        _ => 2,
    };
    let time = when(r.time, now);
    RunText { id: r.id.clone(), a11y: format!("{time}, {line}"), time, title, line, state }
}

/// A served test's row: who, what, the result in the server's words.
pub fn served_row(r: &RunRecord, now: u64) -> RunText {
    let line = crate::netinfo::clean(&crate::server::result_words(r));
    let state = match r.outcome.kind.as_str() {
        "complete" => 0,
        "stopped" => 1,
        _ => 2,
    };
    let time = when(r.time, now);
    let title = format!("{} · {}", crate::netinfo::clean(&r.host), r.settings.kind());
    RunText { id: r.id.clone(), a11y: format!("{time}, {title}, {line}"), time, title, line, state }
}
