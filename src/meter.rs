//! Measuring a running test, the same on the client and the server: each stream's thread counts
//! into its `Counters`; the control thread samples them once a second by the performance counter
//! (bytes per interval per direction, and TCP_INFO of every TCP stream), and notices when the
//! computer slept or stalled in between (an interval of seconds is not a second).

use crate::tcpinfo::{self, TcpInfo};
use crate::udp::RxStats;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// What one stream's thread has counted so far.
#[derive(Default)]
pub struct Counters {
    pub bytes: AtomicU64,
    /// UDP: datagrams sent, or the highest sequence number received.
    pub packets: AtomicU64,
    pub lost: AtomicU64,
    pub ooo: AtomicU64,
    /// UDP receiver's jitter (f64 seconds, as bits).
    jitter: AtomicU64,
    /// The peer closed the stream.
    pub closed: AtomicBool,
    failure: Mutex<Option<String>>,
}

impl Counters {
    pub fn add_bytes(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }

    pub fn set_udp(&self, rx: &RxStats) {
        self.bytes.store(rx.bytes, Ordering::Relaxed);
        self.packets.store(rx.packets, Ordering::Relaxed);
        self.lost.store(rx.lost, Ordering::Relaxed);
        self.ooo.store(rx.ooo, Ordering::Relaxed);
        self.jitter.store(rx.jitter.to_bits(), Ordering::Relaxed);
    }

    pub fn jitter(&self) -> f64 {
        f64::from_bits(self.jitter.load(Ordering::Relaxed))
    }

    /// The stream failed (the first reason is kept).
    pub fn fail(&self, why: String) {
        let mut f = self.failure.lock().unwrap_or_else(|e| e.into_inner());
        f.get_or_insert(why);
    }

    pub fn failure(&self) -> Option<String> {
        self.failure.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Which way a stream carries data, from this side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Role {
    Send,
    Recv,
}

/// One stream as the control thread keeps it.
pub struct Slot {
    pub id: i64,
    pub role: Role,
    pub c: Arc<Counters>,
    /// A second handle to a TCP stream's socket, for TCP_INFO only.
    pub info: Option<TcpStream>,
    pub thread: Option<JoinHandle<()>>,
    last_bytes: u64,
    first_info: Option<TcpInfo>,
    pub latest: Option<TcpInfo>,
    /// Every receive window this side advertised (a receiving TCP stream).
    pub rcv_wnds: Vec<u32>,
    /// Every window the peer advertised (a sending TCP stream).
    pub snd_wnds: Vec<u32>,
    /// Throughput of the last interval (Mbit/s).
    pub last_mbps: f64,
}

impl Slot {
    pub fn new(id: i64, role: Role, info: Option<TcpStream>) -> Slot {
        Slot { id, role, c: Arc::new(Counters::default()), info, thread: None, last_bytes: 0, first_info: None, latest: None, rcv_wnds: Vec::new(), snd_wnds: Vec::new(), last_mbps: 0.0 }
    }

    pub fn bytes(&self) -> u64 {
        self.c.bytes.load(Ordering::Relaxed)
    }

    /// Bytes Windows sent again on this (sending, TCP) stream since its first reading.
    pub fn retrans_bytes(&self) -> Option<u64> {
        match (self.first_info, self.latest) {
            (Some(a), Some(b)) if self.role == Role::Send => Some(tcpinfo::retrans_since(a.bytes_retrans, b.bytes_retrans)),
            _ => None,
        }
    }

    fn read_info(&mut self) {
        let Some(s) = &self.info else { return };
        let Some(i) = tcpinfo::read(s) else { return };
        if self.first_info.is_none() {
            self.first_info = Some(i);
        }
        self.latest = Some(i);
        match self.role {
            Role::Send => self.snd_wnds.push(i.snd_wnd),
            Role::Recv => self.rcv_wnds.push(i.rcv_wnd),
        }
    }
}

/// One interval of the per-second series: its end (seconds since the start) and the
/// throughput each way, from this side (Mbit/s; None when no stream goes that way).
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Point {
    pub t: f64,
    pub send: Option<f64>,
    pub recv: Option<f64>,
}

/// An interval longer than this (seconds) means the computer slept or stalled.
pub const STALL_SECS: f64 = 2.5;
/// A last part-interval shorter than this (seconds) joins the one before it.
pub const SLIVER: f64 = 0.5;
/// How long the end waits for the streams' threads, all of them together; one still running
/// then is left behind.
pub const STOP_WAIT: Duration = Duration::from_secs(3);

/// The control thread's view of the streams and the clock.
pub struct Meter {
    pub slots: Vec<Slot>,
    /// Senders stop at this; receivers stop at `stop_all`.
    pub stop_send: Arc<AtomicBool>,
    pub stop_all: Arc<AtomicBool>,
    /// Receivers count while this is set (TEST_START until the end).
    pub counting: Arc<AtomicBool>,
    pub series: Vec<Point>,
    start: Option<Instant>,
    wall_start: f64,
    last_t: f64,
    last_wall: f64,
    /// The test's measured time, fixed at `finish`.
    pub end_t: Option<f64>,
    /// Seconds the computer was away (slept or stalled), when it was.
    pub stalled: Option<f64>,
    finishing: bool,
}

/// Wait until `deadline` for a stream's thread to return, then let its handle go. It is never
/// joined: its counts are final once its function returned (`is_finished`), while `join` also
/// waits for Windows to end the thread itself, which under a flood (TCP both ways x8 on
/// loopback) took seconds after the function returned, and that wait was counted into the
/// test's time. A thread still running at the deadline is left behind. (A thread the system has
/// not run since the stop can still hold the end up to the deadline: it must notice the stop.)
fn wait_for(h: JoinHandle<()>, deadline: Instant) {
    while !h.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    // The thread's last counts come before its release of the handle's packet, which
    // `is_finished` saw: this makes them visible here, as `join` did.
    std::sync::atomic::fence(Ordering::Acquire);
}

fn wall_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

impl Default for Meter {
    fn default() -> Self {
        Meter::new()
    }
}

impl Meter {
    pub fn new() -> Meter {
        Meter {
            slots: Vec::new(),
            stop_send: Arc::new(AtomicBool::new(false)),
            stop_all: Arc::new(AtomicBool::new(false)),
            counting: Arc::new(AtomicBool::new(false)),
            series: Vec::new(),
            start: None,
            wall_start: 0.0,
            last_t: 0.0,
            last_wall: 0.0,
            end_t: None,
            stalled: None,
            finishing: false,
        }
    }

    /// The test starts now (TEST_START): the clock, and the receivers count from here.
    pub fn begin(&mut self) {
        self.start = Some(Instant::now());
        self.wall_start = wall_now();
        self.last_wall = self.wall_start;
        self.counting.store(true, Ordering::SeqCst);
        for s in &mut self.slots {
            s.read_info();
        }
    }

    pub fn started(&self) -> bool {
        self.start.is_some()
    }

    /// Seconds since `begin` (0 before it).
    pub fn elapsed(&self) -> f64 {
        self.start.map_or(0.0, |s| s.elapsed().as_secs_f64())
    }

    /// When the next interval ends (seconds since the start).
    pub fn next_tick(&self) -> f64 {
        self.last_t.floor() + 1.0
    }

    /// Time to the next interval's end.
    pub fn until_tick(&self) -> Duration {
        Duration::from_secs_f64((self.next_tick() - self.elapsed()).max(0.0))
    }

    /// Sample now if an interval has ended. Returns false when the computer slept or stalled
    /// (the test cannot be trusted any more).
    pub fn poll(&mut self) -> bool {
        if self.start.is_none() || self.end_t.is_some() {
            return true;
        }
        let t = self.elapsed();
        if t + 1e-9 < self.next_tick() {
            return true;
        }
        self.sample_at(t, wall_now())
    }

    /// One interval ending at `t` (performance counter) and `wall` (the system clock): every
    /// stream's bytes since the last, and its TCP_INFO.
    pub fn sample_at(&mut self, t: f64, wall: f64) -> bool {
        let dt = t - self.last_t;
        let dwall = wall - self.last_wall;
        // The counter and the clock must agree that about one interval passed: a long interval
        // (a stall, or a sleep the counter saw) or a clock that moved much more than the counter
        // (a sleep it did not see) ends the test's trust.
        if dt > STALL_SECS || dwall - dt > STALL_SECS {
            self.stalled = Some(dt.max(dwall));
            return false;
        }
        self.record(t, dt);
        self.last_wall = wall;
        true
    }

    fn record(&mut self, t: f64, dt: f64) {
        let (mut send, mut recv) = (None::<f64>, None::<f64>);
        for s in &mut self.slots {
            let b = s.bytes();
            let delta = b.saturating_sub(s.last_bytes);
            s.last_bytes = b;
            let mbps = if dt > 0.0 { delta as f64 * 8.0 / dt / 1e6 } else { 0.0 };
            s.last_mbps = mbps;
            let sum = if s.role == Role::Send { &mut send } else { &mut recv };
            *sum = Some(sum.unwrap_or(0.0) + mbps);
            s.read_info();
        }
        // A sliver at the very end (the test's last moments after its last full second) joins
        // the second before it: its bytes count there, over the longer time, instead of making
        // a bar of its own.
        let prev_t = self.series.len().checked_sub(2).map_or(0.0, |i| self.series[i].t);
        match self.series.last_mut() {
            Some(last) if dt < SLIVER && self.end_t.is_none() && self.finishing => {
                let pdt = last.t - prev_t;
                let join = |a: Option<f64>, b: Option<f64>| match (a, b) {
                    (Some(a), Some(b)) => Some((a * pdt + b * dt) / (pdt + dt)),
                    (a, b) => a.or(b),
                };
                last.send = join(last.send, send);
                last.recv = join(last.recv, recv);
                last.t = t;
            }
            _ if dt > 1e-3 => self.series.push(Point { t, send, recv }),
            _ => {}
        }
        self.last_t = t;
    }

    /// The end (TEST_END): receivers stop counting, the last part-interval is sampled, the
    /// test's time is fixed.
    pub fn finish(&mut self) {
        if self.end_t.is_some() || self.start.is_none() {
            return;
        }
        self.counting.store(false, Ordering::SeqCst);
        let t = self.elapsed();
        if self.stalled.is_none() {
            let dt = t - self.last_t;
            self.finishing = true;
            self.record(t, dt);
        }
        self.end_t = Some(t);
    }

    /// Stop every stream's thread and wait for them (each looks at its flag at least every
    /// 100 ms; one stuck in the system is left behind after 3 s rather than freezing the test).
    pub fn stop(&mut self) {
        self.stop_send.store(true, Ordering::SeqCst);
        self.stop_all.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + STOP_WAIT;
        for s in &mut self.slots {
            if let Some(h) = s.thread.take() {
                wait_for(h, deadline);
            }
        }
    }

    /// Stop only the senders (the test's end on the side that sends) and wait for them.
    pub fn stop_senders(&mut self) {
        self.stop_send.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + STOP_WAIT;
        for s in self.slots.iter_mut().filter(|s| s.role == Role::Send) {
            if let Some(h) = s.thread.take() {
                wait_for(h, deadline);
            }
        }
    }

    /// The first stream failure, if any ("stream 3: sending failed: ...").
    pub fn failure(&self) -> Option<String> {
        self.slots.iter().find_map(|s| s.c.failure().map(|f| format!("stream {}: {f}", s.id)))
    }

    /// A stream the peer closed while the test ran.
    pub fn closed_early(&self) -> Option<i64> {
        self.slots.iter().find(|s| s.c.closed.load(Ordering::Relaxed)).map(|s| s.id)
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        self.stop_send.store(true, Ordering::SeqCst);
        self.stop_all.store(true, Ordering::SeqCst);
    }
}
