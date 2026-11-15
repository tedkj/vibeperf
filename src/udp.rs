//! UDP streams: pacing a sender to its rate, and reading a receiver's datagrams into loss,
//! out-of-order and jitter exactly as iperf3 counts them (`iperf_udp.c`), so a VibePerf and an
//! iperf3 at either end agree.
//!
//! Pacing: what is due by the clock (the performance counter) goes out, then the thread waits
//! on a high-resolution waitable timer in steps of at most 1 ms; one wake-up never sends more
//! than 1 ms worth of the rate (a late wake-up does not turn into a burst).

use crate::meter::Counters;
use crate::proto::{parse_udp_header, put_udp_header, udp_header_len};
use crate::sock;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

// ---------- the clock ----------

fn origin() -> Instant {
    static O: OnceLock<Instant> = OnceLock::new();
    *O.get_or_init(Instant::now)
}

/// Seconds and microseconds of this process's monotonic clock (the performance counter), the
/// timestamp a datagram carries. Only differences count, so its start is arbitrary.
pub fn stamp() -> (u32, u32) {
    let d = origin().elapsed();
    (d.as_secs() as u32, d.subsec_micros())
}

/// Seconds on the same clock, for the arrival side of a transit time.
pub fn now_secs() -> f64 {
    origin().elapsed().as_secs_f64()
}

// ---------- the receiver's arithmetic ----------

/// What a UDP receiver knows of one stream, iperf3's way: `packets` is the highest sequence
/// number seen (iperf3's receiver `packet_count`), `lost` the gaps below it, less the datagrams
/// that came late and filled one (`cnt_error`), `ooo` those that came late.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RxStats {
    pub bytes: u64,
    pub datagrams: u64,
    pub packets: u64,
    pub lost: u64,
    pub ooo: u64,
    /// Seconds, RFC 3550: J += (|D| - J) / 16.
    pub jitter: f64,
    prev_transit: Option<f64>,
}

impl RxStats {
    /// One datagram: its sequence number and its transit time (arrival minus the sender's
    /// stamp; the clocks' offset cancels out in the differences).
    pub fn on_datagram(&mut self, seq: u64, transit: f64, len: usize) {
        self.bytes += len as u64;
        self.datagrams += 1;
        if seq > self.packets {
            if seq > self.packets + 1 {
                self.lost += seq - 1 - self.packets;
            }
            self.packets = seq;
        } else {
            self.ooo += 1;
            if self.lost > 0 {
                self.lost -= 1;
            }
        }
        let d = match self.prev_transit {
            Some(p) => (transit - p).abs(),
            None => 0.0,
        };
        self.prev_transit = Some(transit);
        self.jitter += (d - self.jitter) / 16.0;
    }
}

// ---------- the sender's schedule ----------

/// The schedule of a paced sender: `rate` bits per second of `len`-byte datagrams (iperf3
/// counts the payload: len * 8 bits each).
#[derive(Clone, Copy, Debug)]
pub struct Pacer {
    rate: f64,
    bits: f64,
}

impl Pacer {
    pub fn new(rate_bps: u64, len: u32) -> Pacer {
        Pacer { rate: rate_bps.max(1) as f64, bits: len.max(1) as f64 * 8.0 }
    }

    /// Datagrams due `elapsed` seconds after the start (the first is due at once).
    pub fn due(&self, elapsed: f64) -> u64 {
        (elapsed.max(0.0) * self.rate / self.bits).floor() as u64 + 1
    }

    /// At most this many per wake-up: 1 ms of the rate, and at least one.
    pub fn burst(&self) -> u64 {
        ((self.rate * 0.001) / self.bits).ceil().max(1.0) as u64
    }

    /// How many to send now, `sent` so far.
    pub fn to_send(&self, elapsed: f64, sent: u64) -> u64 {
        self.due(elapsed).saturating_sub(sent).min(self.burst())
    }

    /// How long to wait before the next one is due, at most 1 ms (seconds).
    pub fn wait(&self, elapsed: f64, sent: u64) -> f64 {
        let next = sent as f64 * self.bits / self.rate;
        (next - elapsed).clamp(0.0, 0.001)
    }
}

/// The shortest pause between two bursts (seconds).
pub const MIN_PAUSE: f64 = 0.0001;

/// A high-resolution waitable timer (1 ms steps are what pacing needs; the plain one rounds
/// to the 15.6 ms system tick).
pub struct HiResTimer(windows_sys::Win32::Foundation::HANDLE);

impl HiResTimer {
    pub fn new() -> Option<HiResTimer> {
        use windows_sys::Win32::System::Threading::{CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateWaitableTimerExW, TIMER_ALL_ACCESS};
        // SAFETY: no name, no attributes; closed in Drop.
        let h = unsafe { CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS) };
        if h.is_null() { None } else { Some(HiResTimer(h)) }
    }

    pub fn sleep(&self, d: Duration) {
        use windows_sys::Win32::System::Threading::{INFINITE, SetWaitableTimer, WaitForSingleObject};
        // Relative times are negative, in 100 ns units.
        let due: i64 = -((d.as_nanos() / 100).max(1) as i64);
        // SAFETY: our timer; no completion routine.
        unsafe {
            if SetWaitableTimer(self.0, &due, 0, None, std::ptr::null(), 0) != 0 {
                WaitForSingleObject(self.0, INFINITE);
            } else {
                std::thread::sleep(d);
            }
        }
    }
}

impl Drop for HiResTimer {
    fn drop(&mut self) {
        // SAFETY: our handle, closed once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

// ---------- the streams ----------

/// Where a sender's datagrams go: a connected socket (the client) or the server's one socket
/// with the stream's peer address.
pub enum Target {
    Connected(UdpSocket),
    Shared(Arc<UdpSocket>, SocketAddr),
}

impl Target {
    fn send(&self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Target::Connected(s) => s.send(b),
            Target::Shared(s, to) => s.send_to(b, to),
        }
    }

    fn socket(&self) -> &UdpSocket {
        match self {
            Target::Connected(s) => s,
            Target::Shared(s, _) => s,
        }
    }
}

/// Send paced datagrams until `stop`: `len` bytes each, numbered from 1, stamped with the
/// clock, `rate` bits per second (0: as fast as the socket takes them). Errors the system calls
/// soft (no buffer space, would block) wait and try the same number again, as iperf3 does.
pub fn run_sender(target: Target, len: u32, rate: u64, wide: bool, stop: Arc<AtomicBool>, c: Arc<Counters>) {
    let len = len.max(udp_header_len(wide) as u32) as usize;
    let mut buf = vec![0u8; len];
    for (i, b) in buf.iter_mut().enumerate().skip(16) {
        *b = (i % 251) as u8;
    }
    let _ = target.socket().set_nonblocking(true);
    let pacer = (rate > 0).then(|| Pacer::new(rate, len as u32));
    let timer = HiResTimer::new();
    let start = Instant::now();
    let mut seq: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let n = match pacer {
            Some(p) => p.to_send(start.elapsed().as_secs_f64(), seq),
            None => 64,
        };
        let mut sent_any = false;
        for _ in 0..n {
            let (s, us) = stamp();
            put_udp_header(&mut buf, s, us, seq + 1, wide);
            match target.send(&buf) {
                Ok(k) => {
                    seq += 1;
                    sent_any = true;
                    c.add_bytes(k as u64);
                    c.packets.store(seq, Ordering::Relaxed);
                }
                Err(e) if soft(&e) => {
                    let _ = sock::wait_writable(target.socket(), Duration::from_millis(1));
                    break;
                }
                Err(e) => {
                    c.fail(format!("sending failed: {e}"));
                    return;
                }
            }
        }
        if let Some(p) = pacer {
            // Behind (a late wake-up): still a pause between bursts, so packets never leave
            // back to back for more than 1 ms of the rate.
            let w = p.wait(start.elapsed().as_secs_f64(), seq).max(MIN_PAUSE);
            match &timer {
                Some(t) => t.sleep(Duration::from_secs_f64(w)),
                None => std::thread::sleep(Duration::from_secs_f64(w)),
            }
        } else if !sent_any {
            let _ = sock::wait_writable(target.socket(), sock::SLICE);
        }
    }
}

fn soft(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    // WSAENOBUFS (10055): the system's buffers are full for a moment.
    matches!(e.kind(), WouldBlock | Interrupted) || e.raw_os_error() == Some(10055)
}

/// Receive one stream on a connected socket until `stop`, counting while `counting` is set
/// (from TEST_START until the end is called: datagrams outside it are late, as in iperf3).
pub fn run_receiver(sock: UdpSocket, len: u32, wide: bool, stop: Arc<AtomicBool>, counting: Arc<AtomicBool>, c: Arc<Counters>) {
    let _ = sock.set_nonblocking(true);
    let mut buf = vec![0u8; (len as usize).max(65_536)];
    let mut rx = RxStats::default();
    while !stop.load(Ordering::Relaxed) {
        match sock.recv(&mut buf) {
            Ok(n) => {
                if counting.load(Ordering::Relaxed) {
                    take(&mut rx, &buf[..n], wide, &c);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let _ = sock::wait_readable(&sock, sock::SLICE);
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset || e.raw_os_error() == Some(10040) => {
                // A port-unreachable from earlier, or a datagram longer than the buffer
                // (WSAEMSGSIZE): neither ends the stream.
            }
            Err(e) => {
                c.fail(format!("receiving failed: {e}"));
                return;
            }
        }
    }
}

/// One datagram into a stream's numbers (and its counters, for the sampler).
pub fn take(rx: &mut RxStats, d: &[u8], wide: bool, c: &Counters) {
    let Some((s, us, seq)) = parse_udp_header(d, wide) else { return };
    let transit = now_secs() - (s as f64 + us as f64 / 1e6);
    rx.on_datagram(seq, transit, d.len());
    c.set_udp(rx);
}
