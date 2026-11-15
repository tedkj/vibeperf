//! The server: iperf3's server side on TCP and UDP (port 5201 by default), one test at a time
//! (a second client gets ACCESS_DENIED, as iperf3 does). It listens on every address (`::`
//! with IPv4 mapped), serves real iperf3 clients and VibePerf's own, and keeps a log of what it
//! served this session.
//!
//! Threads: the listener (accepting control connections, and during CREATE_STREAMS the TCP
//! data streams, which it hands to the test); one test thread at a time (the control
//! conversation and the meter); one UDP thread per test that sorts datagrams by sender; one
//! thread per stream.

use crate::client::{self, Live, Phase};
use crate::ctrl::{Ctrl, Recorder};
use crate::meter::{Meter, Role, Slot};
use crate::proto::{self, Direction, Params, ProtoError, Proto, State};
use crate::run::{self, Outcome, RunRecord, Settings};
use crate::udp::{self, RxStats};
use crate::{netinfo, sock, tcp};
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long the server waits for the client at each step.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// After a refusal, how long the server waits for the client to read it and close before it
/// closes (with a reset) itself.
pub const REFUSAL_READ: Duration = Duration::from_secs(2);
/// iperf3's grace beyond the test's time before the server gives up on a client that never
/// ends it (4 s for each of 10 state changes).
pub const GRACE_SECS: f64 = 40.0;
/// A receiving test with no data for this long ends (iperf3: 120 s, IENOMSG).
pub const NO_DATA_SECS: f64 = 120.0;
/// At most this many served tests are kept in the log.
pub const LOG_MAX: usize = 100;
/// The UDP socket's receive buffer per receiving stream, and its cap.
pub const UDP_RCVBUF: u32 = 4 << 20;
pub const UDP_RCVBUF_MAX: u32 = 32 << 20;
/// At most this many connections at a time may still be sending their cookie during
/// CREATE_STREAMS (IN-VibePerf-3); when they are all taken, the oldest makes way (RIN1-10).
pub const MAX_UNPROVEN: usize = 16;
/// A connection must send its whole cookie within this of its accept (iperf3 sends it right
/// after connecting), else it is denied and makes way (RIN1-10).
pub const COOKIE_WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub struct Opts {
    /// `::` (every address) in the app; loopback in tests.
    pub bind: IpAddr,
    pub port: u16,
    /// Tests: each test's control conversation lands here.
    pub record: Option<Recorder>,
}

/// What the window shows of the server.
#[derive(Clone, Debug, Default)]
pub struct ServerLive {
    pub seq: u64,
    pub listening: bool,
    /// Why it could not listen.
    pub error: Option<String>,
    /// The test being served: who, what, and its live numbers.
    pub current: Option<(String, Settings, Live)>,
    /// Served tests, oldest first (this session only).
    pub log: Vec<RunRecord>,
    /// The listener has ended (stopped, or it could not listen).
    pub stopped: bool,
}

pub struct Server {
    pub live: Arc<Mutex<ServerLive>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn finished(&self) -> bool {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).stopped
    }

    /// A server run by something else (the window tests' scripted engine).
    pub fn from_parts(live: Arc<Mutex<ServerLive>>, stop: Arc<AtomicBool>) -> Server {
        Server { live, stop, thread: None }
    }

    /// Whether Stop was asked (the scripted engine reads it).
    pub fn stop_asked(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Stop and wait (a test in progress gets SERVER_TERMINATE).
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn publish(live: &Mutex<ServerLive>, f: impl FnOnce(&mut ServerLive)) {
    let mut g = live.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut g);
    g.seq += 1;
}

/// The test in progress, as the listener sees it.
struct Busy {
    /// TCP data streams go here while the test opens them.
    streams: Option<Sender<TcpStream>>,
    done: Arc<AtomicBool>,
    /// The test has had its last word (or failed) and is cleaning up.
    ending: Arc<AtomicBool>,
}

pub fn start(opts: Opts) -> Server {
    let live = Arc::new(Mutex::new(ServerLive::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (l, st) = (live.clone(), stop.clone());
    let thread = std::thread::Builder::new().name("vibeperf-server".into()).spawn(move || listen(opts, l, st)).ok();
    Server { live, stop, thread }
}

fn port_words(port: u16, e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(10048) || e.raw_os_error() == Some(10013) {
        format!("Port {port} is in use by another program (an iperf3 server?).")
    } else {
        format!("Could not listen on port {port}: {e}")
    }
}

fn listen(opts: Opts, live: Arc<Mutex<ServerLive>>, stop: Arc<AtomicBool>) {
    let tcp = match sock::listen_tcp(opts.bind, opts.port) {
        Ok(l) => l,
        Err(e) => {
            return publish(&live, |l| {
                l.error = Some(port_words(opts.port, &e));
                l.stopped = true;
            });
        }
    };
    let udp = match sock::bind_udp(opts.bind, opts.port, UDP_RCVBUF) {
        Ok(u) => Arc::new(u),
        Err(e) => {
            return publish(&live, |l| {
                l.error = Some(port_words(opts.port, &e));
                l.stopped = true;
            });
        }
    };
    let _ = tcp.set_nonblocking(true);
    publish(&live, |l| l.listening = true);
    let busy: Arc<Mutex<Option<Busy>>> = Arc::new(Mutex::new(None));
    let mut test: Option<std::thread::JoinHandle<()>> = None;
    let test_stop = Arc::new(AtomicBool::new(false));
    // A client that came while the last test was ending waits for it (up to 5 s) instead of
    // hearing "busy": iperf3's own listener leaves it in the backlog meanwhile.
    let mut waiting: Option<(TcpStream, SocketAddr, Instant)> = None;
    let begin = |s: TcpStream, from: SocketAddr| {
        let done = Arc::new(AtomicBool::new(false));
        let ending = Arc::new(AtomicBool::new(false));
        *busy.lock().unwrap_or_else(|e| e.into_inner()) = Some(Busy { streams: None, done: done.clone(), ending: ending.clone() });
        let (l, bz, u, st, rec, port) = (live.clone(), busy.clone(), udp.clone(), test_stop.clone(), opts.record.clone(), opts.port);
        std::thread::Builder::new()
            .name("vibeperf-serve".into())
            .spawn(move || {
                let r = Serve::new(s, from, port, u, bz, st, rec, l.clone(), ending).run();
                publish(&l, |x| {
                    x.current = None;
                    if let Some(r) = r {
                        x.log.push(r);
                        if x.log.len() > LOG_MAX {
                            x.log.remove(0);
                        }
                    }
                });
                done.store(true, Ordering::SeqCst);
            })
            .ok()
    };
    let free = |busy: &Mutex<Option<Busy>>| busy.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_none_or(|b| b.done.load(Ordering::SeqCst));
    while !stop.load(Ordering::SeqCst) {
        if test.as_ref().is_some_and(|t| t.is_finished())
            && let Some(t) = test.take()
        {
            let _ = t.join();
        }
        if let Some((s, from, since)) = waiting.take() {
            if free(&busy) {
                test = begin(s, from);
            } else if since.elapsed() > Duration::from_secs(5) {
                deny(s);
            } else {
                waiting = Some((s, from, since));
            }
        }
        let slice = if waiting.is_some() { Duration::from_millis(10) } else { sock::SLICE };
        if !sock::wait_readable(&tcp, slice).unwrap_or(false) {
            continue;
        }
        let Ok((s, from)) = tcp.accept() else { continue };
        let _ = s.set_nonblocking(false);
        let route = {
            let b = busy.lock().unwrap_or_else(|e| e.into_inner());
            match b.as_ref() {
                Some(x) if !x.done.load(Ordering::SeqCst) => match &x.streams {
                    Some(tx) => {
                        let _ = tx.send(s);
                        None
                    }
                    None if x.ending.load(Ordering::SeqCst) && waiting.is_none() => Some((s, true)),
                    None => {
                        deny(s);
                        None
                    }
                },
                _ => Some((s, false)),
            }
        };
        match route {
            Some((s, true)) => waiting = Some((s, from, Instant::now())),
            Some((s, false)) => test = begin(s, from),
            None => {}
        }
    }
    if let Some((s, _, _)) = waiting.take() {
        deny(s);
    }
    test_stop.store(true, Ordering::SeqCst);
    if let Some(t) = test.take() {
        let _ = t.join();
    }
    publish(&live, |l| {
        l.listening = false;
        l.stopped = true;
    });
}

/// A connection while a test runs: ACCESS_DENIED, without reading anything the peer meant
/// (as iperf3). The byte goes out with a graceful close: the connection is shut for sending and
/// drained for up to a second, so unread bytes (the peer's cookie) do not turn the close into a
/// reset that destroys the byte before the peer reads it. On its own short-lived thread.
fn deny(s: TcpStream) {
    static DENYING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if DENYING.fetch_add(1, Ordering::SeqCst) >= 8 {
        // A flood: no thread each; the byte, then close.
        DENYING.fetch_sub(1, Ordering::SeqCst);
        let mut s = s;
        let _ = s.set_write_timeout(Some(Duration::from_millis(200)));
        let _ = s.write_all(&[State::AccessDenied.byte()]);
        return;
    }
    let spawned = std::thread::Builder::new().name("vibeperf-deny".into()).spawn(move || {
        let mut s = s;
        let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
        if s.write_all(&[State::AccessDenied.byte()]).is_ok() {
            let _ = s.shutdown(std::net::Shutdown::Write);
            let _ = s.set_read_timeout(Some(Duration::from_millis(250)));
            let until = Instant::now() + Duration::from_secs(1);
            let mut b = [0u8; 4096];
            while Instant::now() < until {
                match std::io::Read::read(&mut s, &mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        DENYING.fetch_sub(1, Ordering::SeqCst);
    });
    if spawned.is_err() {
        DENYING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Why a served test did not complete.
enum End {
    /// The client ended it (CLIENT_TERMINATE).
    ClientStopped,
    Failed(String),
    /// Nothing worth logging (a connection that never said anything iperf3-like).
    Silent,
}

struct Serve {
    ctrl: Option<TcpStream>,
    from: SocketAddr,
    port: u16,
    udp: Arc<UdpSocket>,
    busy: Arc<Mutex<Option<Busy>>>,
    stop: Arc<AtomicBool>,
    record: Option<Recorder>,
    live: Arc<Mutex<ServerLive>>,
    meter: Meter,
    params: Option<Params>,
    udp_thread: Option<std::thread::JoinHandle<()>>,
    udp_stop: Arc<AtomicBool>,
    cpu0: (f64, f64, Instant),
    peer_version: String,
    /// TCP sending streams, accepted, waiting for TEST_RUNNING: (slot index, socket).
    pending: Vec<(usize, TcpStream)>,
    ending: Arc<AtomicBool>,
}

impl Serve {
    #[allow(clippy::too_many_arguments)]
    fn new(s: TcpStream, from: SocketAddr, port: u16, udp: Arc<UdpSocket>, busy: Arc<Mutex<Option<Busy>>>, stop: Arc<AtomicBool>, record: Option<Recorder>, live: Arc<Mutex<ServerLive>>, ending: Arc<AtomicBool>) -> Serve {
        Serve { ctrl: Some(s), from: sock::canonical(from), port, udp, busy, stop, record, live, meter: Meter::new(), params: None, udp_thread: None, udp_stop: Arc::new(AtomicBool::new(false)), cpu0: (0.0, 0.0, Instant::now()), peer_version: String::new(), pending: Vec::new(), ending }
    }

    fn run(mut self) -> Option<RunRecord> {
        let time = crate::host::now_unix();
        let s = self.ctrl.take()?;
        let mut ctrl = Ctrl::new(s, self.record.clone());
        let result = self.exchange(&mut ctrl);
        self.ending.store(true, Ordering::SeqCst);
        // The test's connections close without leaving TIME_WAIT on this port.
        sock::abort_on_close(ctrl.stream());
        for s in &self.meter.slots {
            if let Some(i) = &s.info {
                sock::abort_on_close(i);
            }
        }
        for (_, s) in &self.pending {
            sock::abort_on_close(s);
        }
        drop(ctrl);
        self.udp_stop.store(true, Ordering::SeqCst);
        self.meter.stop();
        if let Some(t) = self.udp_thread.take() {
            let _ = t.join();
        }
        let at = self.meter.started().then(|| self.meter.end_t.unwrap_or_else(|| self.meter.elapsed()));
        let (outcome, peer) = match result {
            Ok(peer) => (Outcome::complete(), Some(peer)),
            Err(End::ClientStopped) => (Outcome { kind: "stopped".into(), at, reason: "stopped by the client".into() }, None),
            Err(End::Failed(why)) => (Outcome::failed(why, at), None),
            Err(End::Silent) => return None,
        };
        Some(self.record(time, outcome, peer))
    }

    fn publish_current(&self, phase: Phase) {
        let Some(p) = &self.params else { return };
        let proto_ = p.proto;
        let rows = self.meter.slots.iter().map(|s| client::live_row(s, proto_)).collect();
        let live = Live {
            seq: 0,
            phase,
            addr: sock::show_addr(&self.from),
            elapsed: self.meter.end_t.unwrap_or_else(|| self.meter.elapsed()),
            series: self.meter.series.clone(),
            streams: rows,
            link: netinfo::link_to(&self.from).map(|l| l.text()).unwrap_or_default(),
            ..Live::default()
        };
        let who = self.from.ip().to_string();
        let settings = self.settings();
        publish(&self.live, |l| l.current = Some((who, settings, live)));
    }

    /// The test's settings from the server's side: "reverse" is the client's word for the
    /// server sending, so it is kept as the client asked. The UDP rate is the one the client
    /// asked for, before the 100 Gbit/s cap (Ted, 2026-10-26); a cap applied is a hint.
    fn settings(&self) -> Settings {
        let p = self.params.clone().unwrap_or_default();
        Settings {
            proto: if p.proto == Proto::Udp { "UDP" } else { "TCP" }.into(),
            direction: match p.direction {
                Direction::Normal => "normal",
                Direction::Reverse => "reverse",
                Direction::Both => "both",
            }
            .into(),
            streams: p.parallel,
            seconds: p.time,
            bitrate: if p.proto == Proto::Udp { p.bandwidth_capped_from.unwrap_or(p.bandwidth).saturating_mul(p.parallel as u64) } else { 0 },
            port: self.port,
            window: p.window,
        }
    }

    fn exchange(&mut self, ctrl: &mut Ctrl) -> Result<proto::Results, End> {
        let peer = "client";
        let cookie = ctrl.cookie(Duration::from_secs(5), Some(&self.stop)).map_err(|_| End::Silent)?;
        ctrl.send_state(State::ParamExchange).map_err(|_| End::Silent)?;
        let v = ctrl.json(proto::MAX_PARAMS_JSON, STEP_TIMEOUT, Some(&self.stop)).map_err(|e| match e {
            ProtoError::Cancelled => End::Failed("the server was stopped".into()),
            e => End::Failed(format!("no parameters: {}", e.words(peer))),
        })?;
        let p = match proto::parse_params(&v) {
            Ok(p) => p,
            Err(r) => {
                if ctrl.send(&proto::server_error_bytes(r.code, 0)).is_ok() {
                    ctrl.await_close(REFUSAL_READ, &self.stop);
                }
                return Err(End::Failed(format!("refused: {} ({})", r.why, proto::error_text(r.code))));
            }
        };
        self.peer_version = p.client_version.clone();
        self.params = Some(p.clone());
        let ipv6 = self.from.is_ipv6();
        let len = p.len_or_default(ipv6);
        // Who receives and who sends: the client's sending streams come first (iperf3's order).
        let roles: Vec<Role> = match p.direction {
            Direction::Normal => vec![Role::Recv; p.parallel as usize],
            Direction::Reverse => vec![Role::Send; p.parallel as usize],
            Direction::Both => [vec![Role::Recv; p.parallel as usize], vec![Role::Send; p.parallel as usize]].concat(),
        };
        for (i, r) in roles.iter().enumerate() {
            self.meter.slots.push(Slot::new(proto::stream_id(i), *r, None));
        }
        let (tx, rx) = channel::<TcpStream>();
        let mut udp_peers: Option<Arc<Mutex<Vec<SocketAddr>>>> = None;
        match p.proto {
            Proto::Tcp => {
                if let Some(b) = self.busy.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                    b.streams = Some(tx);
                }
            }
            Proto::Udp => {
                let receivers = roles.iter().filter(|r| **r == Role::Recv).count() as u32;
                let _ = sock::set_rcvbuf(&*self.udp, (UDP_RCVBUF.saturating_mul(receivers.max(1))).min(UDP_RCVBUF_MAX));
                drain(&self.udp);
                udp_peers = Some(self.start_udp(&p, len));
            }
        }
        self.publish_current(Phase::Starting);
        ctrl.send_state(State::CreateStreams).map_err(|e| End::Failed(e.words(peer)))?;
        match p.proto {
            Proto::Tcp => self.accept_tcp(ctrl, &rx, &cookie, &p, len)?,
            Proto::Udp => self.wait_udp(ctrl, udp_peers.as_ref().expect("set above"))?,
        }
        if let Some(b) = self.busy.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            b.streams = None;
        }
        ctrl.send_state(State::TestStart).map_err(|e| End::Failed(e.words(peer)))?;
        let (u, k) = crate::host::process_cpu();
        self.cpu0 = (u, k, Instant::now());
        self.meter.begin();
        ctrl.send_state(State::TestRunning).map_err(|e| End::Failed(e.words(peer)))?;
        self.start_senders(&p, len, udp_peers.as_ref());
        self.publish_current(Phase::Running);
        // Running, until the client says TEST_END.
        let limit = if p.time > 0 { p.time as f64 + GRACE_SECS } else { proto::MAX_TIME as f64 };
        let receives = roles.contains(&Role::Recv);
        let mut last_bytes = 0u64;
        let mut last_data = Instant::now();
        loop {
            if self.stop.load(Ordering::SeqCst) {
                let _ = ctrl.send_state(State::ServerTerminate);
                self.meter.finish();
                return Err(End::Failed("the server was stopped".into()));
            }
            if !self.meter.poll() {
                let _ = ctrl.send_state(State::ServerTerminate);
                return Err(End::Failed(format!("this computer slept or stalled for {:.0} s during the test", self.meter.stalled.unwrap_or(0.0))));
            }
            self.publish_current(Phase::Running);
            if let Some(f) = self.meter.failure() {
                self.meter.finish();
                let _ = ctrl.send_state(State::ServerTerminate);
                return Err(End::Failed(f));
            }
            if self.meter.elapsed() > limit {
                self.meter.finish();
                let _ = ctrl.send_state(State::ServerTerminate);
                return Err(End::Failed("the client never ended the test".into()));
            }
            if receives {
                let b: u64 = self.meter.slots.iter().filter(|s| s.role == Role::Recv).map(|s| s.bytes()).sum();
                if b != last_bytes {
                    (last_bytes, last_data) = (b, Instant::now());
                } else if last_data.elapsed().as_secs_f64() > NO_DATA_SECS {
                    self.meter.finish();
                    let _ = ctrl.send_state(State::ServerTerminate);
                    return Err(End::Failed("no data for 120 s".into()));
                }
            }
            match ctrl.wait(self.meter.until_tick().min(sock::SLICE), None) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) => {
                    self.meter.finish();
                    return Err(End::Failed(e.words(peer)));
                }
            }
            match ctrl.state(Duration::from_millis(1), None) {
                Ok(State::TestEnd) => break,
                Ok(State::ClientTerminate) => {
                    self.meter.stop_senders();
                    self.meter.finish();
                    return Err(End::ClientStopped);
                }
                Ok(s) => {
                    self.meter.finish();
                    return Err(End::Failed(format!("the client sent {} in the middle of the test", s.name())));
                }
                Err(e) => {
                    self.meter.finish();
                    return Err(End::Failed(e.words(peer)));
                }
            }
        }
        // TEST_END: stop, count, close the streams (as iperf3's server does here: a client
        // before 3.16 drains its streams with blocking reads of a whole block after TEST_END,
        // and only the end of the stream lets the last one return), then exchange results,
        // the client's first.
        self.meter.stop_senders();
        self.meter.finish();
        for s in &self.meter.slots {
            if let Some(i) = &s.info {
                let _ = i.shutdown(std::net::Shutdown::Write);
            }
        }
        self.publish_current(Phase::Finishing);
        ctrl.send_state(State::ExchangeResults).map_err(|e| End::Failed(e.words(peer)))?;
        let theirs = match ctrl.json(proto::MAX_RESULTS_JSON, STEP_TIMEOUT, Some(&self.stop)) {
            Ok(v) => proto::parse_results(&v).map_err(|e| End::Failed(format!("the client's results were not iperf3's: {e}")))?,
            Err(ProtoError::Cancelled) => return Err(End::Failed("the server was stopped".into())),
            Err(e) => return Err(End::Failed(format!("no results from the client: {}", e.words(peer)))),
        };
        let ours = client::results_for(&self.meter, p.proto == Proto::Udp, self.cpu0);
        ctrl.send_json(&proto::results_json(&ours)).map_err(|e| End::Failed(e.words(peer)))?;
        // From here a new client waits for this one's goodbye instead of hearing "busy".
        self.ending.store(true, Ordering::SeqCst);
        ctrl.send_state(State::DisplayResults).map_err(|e| End::Failed(e.words(peer)))?;
        // IPERF_DONE is the client's last word; the test is complete either way.
        let _ = ctrl.state(Duration::from_secs(5), None);
        Ok(theirs)
    }

    /// TCP data streams from the listener: each must open with the test's cookie (a wrong one
    /// gets ACCESS_DENIED and is closed, as iperf3 does), within 10 s in all. The cookies are
    /// read without blocking, every connection's within that same deadline, so a stray or slow
    /// connection holds up neither the others nor the test (IN-VibePerf-3).
    fn accept_tcp(&mut self, ctrl: &mut Ctrl, rx: &Receiver<TcpStream>, cookie: &[u8; proto::COOKIE_SIZE], p: &Params, len: u32) -> Result<(), End> {
        let deadline = Instant::now() + STEP_TIMEOUT;
        let mut next = 0;
        // Connections still sending their cookie: (socket, cookie so far, bytes of it, accepted),
        // oldest first.
        let mut unproven: Vec<(TcpStream, [u8; proto::COOKIE_SIZE], usize, Instant)> = Vec::new();
        let refuse = |s: TcpStream| {
            let _ = s.set_nonblocking(false);
            deny(s);
        };
        let result = loop {
            if next >= self.meter.slots.len() {
                break Ok(());
            }
            if self.stop.load(Ordering::SeqCst) {
                break Err(End::Failed("the server was stopped".into()));
            }
            if let Err(e) = client_left(ctrl) {
                break Err(e);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(End::Failed(format!("the client opened {next} of {} streams", self.meter.slots.len())));
            }
            let mut progress = false;
            let mut i = 0;
            while i < unproven.len() && next < self.meter.slots.len() {
                let (s, c, got, since) = &mut unproven[i];
                if since.elapsed() >= COOKIE_WAIT {
                    // Silent, or dripping its cookie: it makes way (RIN1-10).
                    let (s, ..) = unproven.remove(i);
                    refuse(s);
                    continue;
                }
                use std::io::Read;
                match s.read(&mut c[*got..]) {
                    Ok(0) => {
                        unproven.remove(i);
                        continue;
                    }
                    Ok(n) => {
                        *got += n;
                        progress = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        unproven.remove(i);
                        continue;
                    }
                }
                if *got < proto::COOKIE_SIZE {
                    i += 1;
                    continue;
                }
                let (s, c, ..) = unproven.remove(i);
                if c != *cookie {
                    refuse(s);
                    continue;
                }
                let _ = s.set_nonblocking(false);
                self.take_stream(next, s, p, len);
                next += 1;
            }
            let wait = if progress { Duration::ZERO } else if unproven.is_empty() { left.min(sock::SLICE) } else { Duration::from_millis(5) };
            let mut admit = |s: TcpStream| {
                if s.set_nonblocking(true).is_err() {
                    refuse(s);
                    return;
                }
                if unproven.len() >= MAX_UNPROVEN {
                    // All taken: the oldest makes way, so strays never keep out a stream that
                    // sends its cookie at once (RIN1-10).
                    let (old, ..) = unproven.remove(0);
                    refuse(old);
                }
                unproven.push((s, [0u8; proto::COOKIE_SIZE], 0, Instant::now()));
            };
            if let Ok(s) = rx.recv_timeout(wait) {
                admit(s);
            }
            while let Ok(s) = rx.try_recv() {
                admit(s);
            }
        };
        // Connections the step no longer needs (strays): told, as iperf3 tells a wrong cookie.
        for (s, ..) in unproven {
            refuse(s);
        }
        result
    }

    /// An accepted data stream with the right cookie, as the test's `next` stream.
    fn take_stream(&mut self, next: usize, s: TcpStream, p: &Params, len: u32) {
        if p.window > 0 {
            let _ = sock::set_buffers(&s, p.window);
        }
        if p.nodelay {
            let _ = s.set_nodelay(true);
        }
        let slot = &mut self.meter.slots[next];
        slot.info = s.try_clone().ok();
        if slot.role == Role::Recv {
            let (stop, counting, c, id) = (self.meter.stop_all.clone(), self.meter.counting.clone(), slot.c.clone(), slot.id);
            slot.thread = std::thread::Builder::new().name(format!("vibeperf-srx-{id}")).spawn(move || tcp::run_receiver(s, len, stop, counting, c)).ok();
        } else {
            self.pending.push((next, s));
        }
    }

    /// The UDP thread: during CREATE_STREAMS a 4-byte datagram from the client's address is a
    /// stream's hello (answered, numbered in order); after that, datagrams from a receiving
    /// stream's address count for it, everything else is dropped.
    fn start_udp(&mut self, p: &Params, len: u32) -> Arc<Mutex<Vec<SocketAddr>>> {
        let peers: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let n = self.meter.slots.len();
        let roles: Vec<Role> = self.meter.slots.iter().map(|s| s.role).collect();
        let counters: Vec<_> = self.meter.slots.iter().map(|s| s.c.clone()).collect();
        let (sock_, stop, counting, wide, client_ip) = (self.udp.clone(), self.udp_stop.clone(), self.meter.counting.clone(), p.udp64, self.from.ip());
        let pr = peers.clone();
        self.udp_thread = std::thread::Builder::new()
            .name("vibeperf-sudp".into())
            .spawn(move || {
                let _ = sock_.set_nonblocking(true);
                let mut buf = vec![0u8; (len as usize).max(65_536)];
                let mut index: HashMap<SocketAddr, usize> = HashMap::new();
                let mut rx: Vec<RxStats> = vec![RxStats::default(); n];
                while !stop.load(Ordering::Relaxed) {
                    match sock_.recv_from(&mut buf) {
                        Ok((k, from)) => {
                            let from = sock::canonical(from);
                            match index.get(&from) {
                                Some(&i) => {
                                    if roles[i] == Role::Recv && counting.load(Ordering::Relaxed) {
                                        udp::take(&mut rx[i], &buf[..k], wide, &counters[i]);
                                    }
                                }
                                None if k == 4 && index.len() < n && from.ip() == client_ip => {
                                    index.insert(from, index.len());
                                    pr.lock().unwrap_or_else(|e| e.into_inner()).push(from);
                                    let _ = sock_.send_to(&proto::UDP_CONNECT_REPLY, from);
                                }
                                None => {}
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            let _ = sock::wait_readable(&*sock_, sock::SLICE);
                        }
                        Err(_) => {}
                    }
                }
            })
            .ok();
        peers
    }

    fn wait_udp(&mut self, ctrl: &mut Ctrl, peers: &Arc<Mutex<Vec<SocketAddr>>>) -> Result<(), End> {
        let deadline = Instant::now() + STEP_TIMEOUT;
        let n = self.meter.slots.len();
        loop {
            client_left(ctrl)?;
            let got = peers.lock().unwrap_or_else(|e| e.into_inner()).len();
            if got >= n {
                return Ok(());
            }
            if self.stop.load(Ordering::SeqCst) {
                return Err(End::Failed("the server was stopped".into()));
            }
            if Instant::now() >= deadline {
                return Err(End::Failed(format!("the client opened {got} of {n} UDP streams (a firewall may block UDP)")));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn start_senders(&mut self, p: &Params, len: u32, udp_peers: Option<&Arc<Mutex<Vec<SocketAddr>>>>) {
        let stop = self.meter.stop_send.clone();
        for (i, s) in std::mem::take(&mut self.pending) {
            let (st, c, id) = (stop.clone(), self.meter.slots[i].c.clone(), self.meter.slots[i].id);
            self.meter.slots[i].thread = std::thread::Builder::new().name(format!("vibeperf-stx-{id}")).spawn(move || tcp::run_sender(s, len, st, c)).ok();
        }
        if let Some(peers) = udp_peers {
            let peers = peers.lock().unwrap_or_else(|e| e.into_inner()).clone();
            for (i, slot) in self.meter.slots.iter_mut().enumerate() {
                if slot.role != Role::Send {
                    continue;
                }
                let Some(to) = peers.get(i).copied() else { continue };
                if p.dont_fragment && to.is_ipv4() {
                    let _ = sock::set_dont_fragment(&*self.udp);
                }
                let (st, c, id, u) = (stop.clone(), slot.c.clone(), slot.id, self.udp.clone());
                let (rate, wide) = (p.bandwidth, p.udp64);
                slot.thread = std::thread::Builder::new().name(format!("vibeperf-stx-{id}")).spawn(move || udp::run_sender(udp::Target::Shared(u, to), len, rate, wide, st, c)).ok();
            }
        }
    }

    fn record(&self, time: u64, outcome: Outcome, peer: Option<proto::Results>) -> RunRecord {
        let p = self.params.clone().unwrap_or_default();
        let secs = self.meter.end_t.unwrap_or_else(|| self.meter.elapsed());
        let (dirs, mut hints) = if self.meter.started() { run::directions(p.proto, &client::sides(&self.meter), secs, peer.as_ref()) } else { (Vec::new(), Vec::new()) };
        if p.proto == Proto::Tcp {
            hints.extend(client::window_hints(&self.meter));
        }
        if p.window > 0 {
            hints.push(format!("The client asked for socket buffers of {}: Windows' auto-tuning was off for this test.", run::bytes_text(p.window as u64)));
        }
        // Only a UDP sender paces (R-PERF-1): TCP takes no rate, so nothing was paced there.
        if let (Some(asked), true) = (p.bandwidth_capped_from, p.proto == Proto::Udp && p.direction != Direction::Normal) {
            hints.push(format!("The client asked for {} per stream; this server sends at most {} per stream, so it paced to that.", run::rate_text(asked as f64 / 1e6), run::rate_text(crate::MAX_BITRATE as f64 / 1e6)));
        }
        RunRecord {
            id: client::new_id(),
            time,
            label: String::new(),
            host: self.from.ip().to_string(),
            addr: sock::show_addr(&self.from),
            settings: self.settings(),
            outcome,
            dirs,
            latency: None,
            link: netinfo::link_to(&self.from).map(|l| l.text()).unwrap_or_default(),
            series: self.meter.series.clone(),
            streams: client::final_rows(&self.meter, p.proto, secs, peer.as_ref()),
            hints,
            peer_version: self.peer_version.clone(),
            served: true,
        }
    }
}

/// While the streams open: a client that said CLIENT_TERMINATE or left ends the test at once.
fn client_left(ctrl: &mut Ctrl) -> Result<(), End> {
    if !ctrl.wait(Duration::ZERO, None).unwrap_or(true) {
        return Ok(());
    }
    match ctrl.state(Duration::from_millis(1), None) {
        Ok(State::ClientTerminate) => Err(End::ClientStopped),
        Ok(s) => Err(End::Failed(format!("the client sent {} while opening its streams", s.name()))),
        Err(e) => Err(End::Failed(e.words("client"))),
    }
}

/// Datagrams left from an earlier test (late arrivals) are not a new test's hellos.
fn drain(u: &UdpSocket) {
    let _ = u.set_nonblocking(true);
    let mut b = [0u8; 2048];
    for _ in 0..100_000 {
        if u.recv_from(&mut b).is_err() {
            break;
        }
    }
}

/// The server's log line: "941 Mbit/s received", "941 Mbit/s sent, 938 Mbit/s received".
pub fn result_words(r: &RunRecord) -> String {
    let mut parts: Vec<String> = r
        .dirs
        .iter()
        .map(|d| match d.headline() {
            Some((m, true)) => format!("{} {}", run::rate_text(m), if d.up { "sent" } else { "received" }),
            Some((m, false)) => format!("{} {} (receiver unknown)", run::rate_text(m), if d.up { "sent" } else { "received" }),
            None => "no data".into(),
        })
        .collect();
    if r.settings.is_udp()
        && let Some(p) = r.dirs.iter().filter_map(|d| d.loss_percent()).reduce(f64::max)
    {
        parts.push(format!("{} lost", run::percent_text(p)));
    }
    let mut s = parts.join(", ");
    if !r.outcome.is_complete() {
        if s.is_empty() {
            s = r.outcome.words();
        } else {
            s.push_str(&format!(" ({})", r.outcome.words()));
        }
    }
    s
}
