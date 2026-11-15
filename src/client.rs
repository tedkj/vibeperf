//! The client: one test against an iperf3 server (or a VibePerf), on its own thread. It
//! resolves and connects, takes the idle latency baseline, asks for the test, opens the
//! streams, measures every second while pinging under load, ends the test, exchanges results
//! and builds the record. The window reads `Live` (a snapshot it polls); every live value and
//! the final record carry the test's epoch.

use crate::ctrl::{Ctrl, Recorder};
use crate::latency::{self, PingNet, Pings};
use crate::meter::{Meter, Role, Slot};
use crate::netinfo::{self, Target};
use crate::proto::{self, Direction, Params, ProtoError, Proto, State};
use crate::run::{self, Outcome, RunRecord, Settings, Side, StreamRow};
use crate::{sock, tcp, tcpinfo, udp};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The receive buffer of a receiving UDP socket (UDP has no auto-tuning).
pub const UDP_RCVBUF: u32 = 4 << 20;
/// How long to wait for the server at each step before calling it gone.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one address may take to connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct Request {
    pub target: Target,
    pub port: u16,
    pub proto: Proto,
    pub direction: Direction,
    /// Streams each way.
    pub streams: u32,
    pub seconds: u32,
    /// UDP: bits per second each way, shared by that way's streams.
    pub bitrate: u64,
    /// A fixed socket buffer (`-w`); 0: Windows' auto-tuning (always, from the window).
    pub window: u32,
    /// Ping for latency under load.
    pub latency: bool,
    /// 64-bit UDP sequence numbers (iperf3's `--udp-counters-64bit`; the window never asks).
    pub udp64: bool,
    /// Tests: record the control conversation.
    pub record: Option<Recorder>,
}

impl Request {
    pub fn settings(&self) -> Settings {
        Settings {
            proto: if self.proto == Proto::Udp { "UDP" } else { "TCP" }.into(),
            direction: match self.direction {
                Direction::Normal => "normal",
                Direction::Reverse => "reverse",
                Direction::Both => "both",
            }
            .into(),
            streams: self.streams,
            seconds: self.seconds,
            bitrate: if self.proto == Proto::Udp { self.bitrate } else { 0 },
            port: self.port,
            window: self.window,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Resolving,
    Connecting,
    Pinging,
    Starting,
    Running,
    Finishing,
    Done,
}

/// What the window shows while a test runs (and its record once it is done).
#[derive(Clone, Debug, Default)]
pub struct Live {
    /// Bumped on every change.
    pub seq: u64,
    pub phase: Phase,
    pub addr: String,
    pub elapsed: f64,
    pub series: Vec<crate::meter::Point>,
    pub streams: Vec<StreamRow>,
    pub idle: Pings,
    pub loaded: Pings,
    pub target: Option<latency::Target>,
    pub link: String,
    pub record: Option<RunRecord>,
}

pub struct Client {
    pub live: Arc<Mutex<Live>>,
    pub cancel: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Client {
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// The test has its record (the thread's last act).
    pub fn finished(&self) -> bool {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).phase == Phase::Done
    }

    /// A test run by something else (the window tests' scripted engine): its live state and
    /// its stop flag.
    pub fn from_parts(live: Arc<Mutex<Live>>, cancel: Arc<AtomicBool>) -> Client {
        Client { live, cancel, thread: None }
    }

    /// Wait for the thread (tests, and exit).
    pub fn join(mut self) -> Option<RunRecord> {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.live.lock().unwrap_or_else(|e| e.into_inner()).record.clone()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

pub fn start(req: Request, ping: Arc<dyn PingNet>) -> Client {
    let live = Arc::new(Mutex::new(Live::default()));
    let cancel = Arc::new(AtomicBool::new(false));
    let (l, c) = (live.clone(), cancel.clone());
    let thread = std::thread::Builder::new()
        .name("vibeperf-client".into())
        .spawn(move || {
            let rec = Test::new(req, ping, l.clone(), c).run();
            let mut g = l.lock().unwrap_or_else(|e| e.into_inner());
            g.phase = Phase::Done;
            g.record = Some(rec);
            g.seq += 1;
        })
        .ok();
    Client { live, cancel, thread }
}

/// Why a test did not complete.
enum End {
    Stopped,
    Failed(String),
}

struct Test {
    req: Request,
    ping: Arc<dyn PingNet>,
    live: Arc<Mutex<Live>>,
    cancel: Arc<AtomicBool>,
    meter: Meter,
    addr: Option<SocketAddr>,
    peer_version: String,
    link: String,
    idle: Pings,
    target: Option<(latency::Target, std::net::IpAddr, u32)>,
    loaded: Arc<Mutex<Pings>>,
    ping_stop: Arc<AtomicBool>,
    ping_thread: Option<std::thread::JoinHandle<()>>,
    hints: Vec<String>,
    cpu0: (f64, f64, Instant),
    /// Sending streams, connected, waiting for TEST_RUNNING: (slot index, socket).
    pending_tcp: Vec<(usize, std::net::TcpStream)>,
    pending_udp: Vec<(usize, std::net::UdpSocket)>,
}

fn stopped_or(e: ProtoError, peer: &str) -> End {
    match e {
        ProtoError::Cancelled => End::Stopped,
        e => End::Failed(e.words(peer)),
    }
}

impl Test {
    fn new(req: Request, ping: Arc<dyn PingNet>, live: Arc<Mutex<Live>>, cancel: Arc<AtomicBool>) -> Test {
        Test {
            req,
            ping,
            live,
            cancel,
            meter: Meter::new(),
            addr: None,
            peer_version: String::new(),
            link: String::new(),
            idle: Pings::default(),
            target: None,
            loaded: Arc::new(Mutex::new(Pings::default())),
            ping_stop: Arc::new(AtomicBool::new(false)),
            ping_thread: None,
            hints: Vec::new(),
            cpu0: (0.0, 0.0, Instant::now()),
            pending_tcp: Vec::new(),
            pending_udp: Vec::new(),
        }
    }

    fn publish(&self, f: impl FnOnce(&mut Live)) {
        let mut g = self.live.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g);
        g.seq += 1;
    }

    fn stopped(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    fn run(mut self) -> RunRecord {
        let time = crate::host::now_unix();
        let result = self.exchange();
        self.ping_stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.ping_thread.take() {
            let _ = t.join();
        }
        self.meter.stop();
        let at = self.meter.started().then(|| self.meter.end_t.unwrap_or_else(|| self.meter.elapsed()));
        let (outcome, peer) = match result {
            Ok(peer) => (Outcome::complete(), peer),
            Err(End::Stopped) => (Outcome::stopped(at.unwrap_or(0.0)), None),
            Err(End::Failed(why)) => (Outcome::failed(why, at), None),
        };
        self.record(time, outcome, peer)
    }

    /// The whole conversation; Ok with the server's results.
    fn exchange(&mut self) -> Result<Option<proto::Results>, End> {
        let peer = "server";
        // Where.
        let addrs = netinfo::resolve(&self.req.target, self.req.port).map_err(End::Failed)?;
        if self.stopped() {
            return Err(End::Stopped);
        }
        self.publish(|l| l.phase = Phase::Connecting);
        let mut last = String::new();
        let mut ctrl = None;
        for a in &addrs {
            match sock::connect_tcp(a, CONNECT_TIMEOUT, &self.cancel, None) {
                Ok(s) => {
                    self.addr = Some(*a);
                    ctrl = Some(Ctrl::new(s, self.req.record.clone()));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Err(End::Stopped),
                Err(e) => last = connect_words(a, &e),
            }
        }
        let mut ctrl = ctrl.ok_or(End::Failed(last))?;
        let addr = self.addr.unwrap_or(addrs[0]);
        self.link = netinfo::link_to(&addr).map(|l| l.text()).unwrap_or_default();
        let shown = sock::show_addr(&addr);
        let link = self.link.clone();
        self.publish(|l| {
            l.addr = shown;
            l.link = link;
        });
        // Who we are, then what the server says to that.
        let cookie = proto::new_cookie();
        ctrl.send(&cookie).map_err(|e| stopped_or(e, peer))?;
        match ctrl.state(STEP_TIMEOUT, Some(&self.cancel)).map_err(|e| stopped_or(e, peer))? {
            State::ParamExchange => {}
            State::AccessDenied => return Err(End::Failed("the server is busy with another test; try again in a moment".into())),
            s => return Err(End::Failed(format!("the server answered {} instead of asking for parameters", s.name()))),
        }
        // The idle baseline, before any data.
        if self.req.latency {
            self.publish(|l| l.phase = Phase::Pinging);
            self.baseline(addr);
            if self.stopped() {
                let _ = ctrl.send_state(State::ClientTerminate);
                return Err(End::Stopped);
            }
        }
        // The test.
        let len = match self.req.proto {
            Proto::Tcp => proto::TCP_LEN,
            Proto::Udp => udp_len(sock::mss(ctrl.stream()), addr.is_ipv6()),
        };
        let streams = self.req.streams.clamp(1, proto::MAX_STREAMS);
        let params = Params {
            proto: self.req.proto,
            time: self.req.seconds,
            parallel: streams,
            direction: self.req.direction,
            len,
            bandwidth: if self.req.proto == Proto::Udp { (self.req.bitrate / streams as u64).max(1) } else { 0 },
            window: self.req.window,
            udp64: self.req.udp64,
            client_version: run::APP.into(),
            ..Params::default()
        };
        self.publish(|l| l.phase = Phase::Starting);
        ctrl.send_json(&params.to_json()).map_err(|e| stopped_or(e, peer))?;
        match ctrl.state(STEP_TIMEOUT, Some(&self.cancel)).map_err(|e| stopped_or(e, peer))? {
            State::CreateStreams => {}
            State::ServerError => {
                let (code, errno) = ctrl.codes().map_err(|e| stopped_or(e, peer))?;
                let os = if errno != 0 { format!(" (system error {errno})") } else { String::new() };
                return Err(End::Failed(format!("the server refused: {}{os}", proto::error_text(code))));
            }
            State::AccessDenied => return Err(End::Failed("the server is busy with another test; try again in a moment".into())),
            s => return Err(End::Failed(format!("the server answered {} instead of CREATE_STREAMS", s.name()))),
        }
        self.open_streams(&addr, &cookie, &params)?;
        // TEST_START: the clock and the receivers start. TEST_RUNNING: the senders.
        match ctrl.state(STEP_TIMEOUT, Some(&self.cancel)) {
            Ok(State::TestStart) => {}
            Ok(State::ServerError) => {
                let (code, _) = ctrl.codes().map_err(|e| stopped_or(e, peer))?;
                return Err(End::Failed(format!("the server refused: {}", proto::error_text(code))));
            }
            Ok(s) => return Err(End::Failed(format!("the server answered {} instead of TEST_START", s.name()))),
            Err(ProtoError::Cancelled) => {
                let _ = ctrl.send_state(State::ClientTerminate);
                return Err(End::Stopped);
            }
            Err(ProtoError::TimedOut) => return Err(End::Failed("the server did not start the test (are its data ports blocked?)".into())),
            Err(e) => return Err(End::Failed(e.words(peer))),
        }
        let (u, k) = crate::host::process_cpu();
        self.cpu0 = (u, k, Instant::now());
        self.meter.begin();
        match ctrl.state(STEP_TIMEOUT, Some(&self.cancel)) {
            Ok(State::TestRunning) => {}
            Ok(s) => return Err(End::Failed(format!("the server answered {} instead of TEST_RUNNING", s.name()))),
            Err(ProtoError::Cancelled) => return Err(self.give_up(&mut ctrl, End::Stopped)),
            Err(e) => return Err(End::Failed(e.words(peer))),
        }
        self.start_senders(&params);
        self.start_loaded_pings();
        self.publish(|l| l.phase = Phase::Running);
        // Running: a sample every second, the server watched in between.
        let secs = self.req.seconds as f64;
        loop {
            if self.stopped() {
                return Err(self.give_up(&mut ctrl, End::Stopped));
            }
            if !self.meter.poll() {
                let away = self.meter.stalled.unwrap_or(0.0);
                return Err(self.give_up(&mut ctrl, End::Failed(format!("the computer slept or stalled for {away:.0} s during the test"))));
            }
            self.publish_running();
            if self.meter.elapsed() >= secs {
                break;
            }
            if let Some(f) = self.meter.failure() {
                return Err(self.give_up(&mut ctrl, End::Failed(f)));
            }
            if let Some(id) = self.meter.closed_early() {
                return Err(self.give_up(&mut ctrl, End::Failed(format!("the server closed stream {id}"))));
            }
            let left = Duration::from_secs_f64((secs - self.meter.elapsed()).max(0.0));
            let wait = self.meter.until_tick().min(left).min(sock::SLICE);
            match ctrl.wait(wait, None) {
                Ok(false) => {}
                Ok(true) => {
                    let why = match ctrl.state(Duration::from_millis(1), None) {
                        Ok(State::ServerTerminate) => "the server stopped the test".to_string(),
                        Ok(s) => format!("the server sent {} in the middle of the test", s.name()),
                        Err(e) => e.words(peer),
                    };
                    return Err(self.give_up(&mut ctrl, End::Failed(why)));
                }
                Err(e) => return Err(self.give_up(&mut ctrl, End::Failed(e.words(peer)))),
            }
        }
        // The end: senders stop, the last part-second is counted, TEST_END.
        self.meter.stop_senders();
        self.meter.finish();
        self.ping_stop.store(true, Ordering::SeqCst);
        self.publish(|l| l.phase = Phase::Finishing);
        self.publish_running();
        ctrl.send_state(State::TestEnd).map_err(|e| End::Failed(e.words(peer)))?;
        // Results: ours first, then the server's.
        match ctrl.state(STEP_TIMEOUT, Some(&self.cancel)) {
            Ok(State::ExchangeResults) => {}
            Ok(s) => return Err(End::Failed(format!("the server answered {} instead of EXCHANGE_RESULTS", s.name()))),
            Err(ProtoError::TimedOut) => return Err(End::Failed("the server sent no results within 10 s".into())),
            Err(ProtoError::Cancelled) => {
                // Stop while waiting for results: the data part is done; leave politely.
                let _ = ctrl.send_state(State::ClientTerminate);
                return Err(End::Stopped);
            }
            Err(e) => return Err(End::Failed(e.words(peer))),
        }
        ctrl.send_json(&proto::results_json(&results_for(&self.meter, self.req.proto == Proto::Udp, self.cpu0))).map_err(|e| End::Failed(e.words(peer)))?;
        let theirs = match ctrl.json(proto::MAX_RESULTS_JSON, STEP_TIMEOUT, Some(&self.cancel)) {
            Ok(v) => proto::parse_results(&v).map_err(|e| End::Failed(format!("the server's results were not iperf3's: {e}")))?,
            Err(ProtoError::TimedOut) => return Err(End::Failed("the server sent no results within 10 s".into())),
            Err(ProtoError::Cancelled) => {
                let _ = ctrl.send_state(State::ClientTerminate);
                return Err(End::Stopped);
            }
            Err(e) => return Err(End::Failed(e.words(peer))),
        };
        match ctrl.state(STEP_TIMEOUT, None) {
            Ok(State::DisplayResults) => {
                let _ = ctrl.send_state(State::IperfDone);
            }
            // The numbers are in; a server that leaves without the last word does not undo them.
            Ok(_) | Err(_) => self.hints.push("The server did not finish the conversation (no DISPLAY_RESULTS); its results arrived.".into()),
        }
        Ok(Some(theirs))
    }

    /// Stop what runs, count what was measured, tell the server (CLIENT_TERMINATE).
    fn give_up(&mut self, ctrl: &mut Ctrl, end: End) -> End {
        self.meter.stop_senders();
        self.meter.finish();
        let _ = ctrl.send_state(State::ClientTerminate);
        end
    }

    fn baseline(&mut self, addr: SocketAddr) {
        let scope = match addr {
            SocketAddr::V6(v6) => v6.scope_id(),
            _ => 0,
        };
        let gw = netinfo::gateway_for(&addr);
        let peer = series_thread(self.ping.clone(), addr.ip(), scope, self.cancel.clone());
        let gwt = gw.map(|(g, s)| series_thread(self.ping.clone(), g, s, self.cancel.clone()));
        let peer_pings = peer.join().unwrap_or_default();
        let gw_pings = gwt.map(|t| t.join().unwrap_or_default());
        let peer_text = addr.ip().to_string();
        let gw_text = gw.map(|(g, _)| g.to_string()).unwrap_or_default();
        let choice = latency::choose(&peer_pings, gw_pings.as_ref().map(|p| (gw_text.as_str(), p)), &peer_text);
        self.idle = match &choice {
            Some(latency::Target::Gateway(_)) => gw_pings.clone().unwrap_or_default(),
            _ => peer_pings,
        };
        self.target = choice.map(|t| match t {
            latency::Target::Gateway(_) => (t, gw.map(|g| g.0).unwrap_or(addr.ip()), gw.map(|g| g.1).unwrap_or(0)),
            latency::Target::Peer(_) => (t, addr.ip(), scope),
        });
        let (idle, target) = (self.idle.clone(), self.target.as_ref().map(|t| t.0.clone()));
        self.publish(|l| {
            l.idle = idle;
            l.target = target;
        });
    }

    fn start_loaded_pings(&mut self) {
        let Some((_, ip, scope)) = self.target.clone() else { return };
        let (net, stop, out) = (self.ping.clone(), self.ping_stop.clone(), self.loaded.clone());
        self.ping_thread = std::thread::Builder::new()
            .name("vibeperf-ping".into())
            .spawn(move || {
                let Ok(mut p) = net.open(ip, scope) else { return };
                let mut next = Instant::now();
                while !stop.load(Ordering::SeqCst) {
                    let r = p.ping();
                    if stop.load(Ordering::SeqCst) {
                        break; // a ping that ended after the test is not "under load"
                    }
                    {
                        let mut o = out.lock().unwrap_or_else(|e| e.into_inner());
                        o.sent += 1;
                        if let Some(us) = r {
                            o.rtts.push(us);
                        }
                    }
                    next += Duration::from_millis(latency::GAP_MS);
                    let now = Instant::now();
                    if next > now {
                        // Sleep in slices so the end is noticed at once.
                        while Instant::now() < next && !stop.load(Ordering::SeqCst) {
                            std::thread::sleep((next - Instant::now()).min(Duration::from_millis(20)));
                        }
                    } else {
                        next = now;
                    }
                }
            })
            .ok();
    }

    fn open_streams(&mut self, addr: &SocketAddr, cookie: &[u8; proto::COOKIE_SIZE], p: &Params) -> Result<(), End> {
        let roles: Vec<Role> = match p.direction {
            Direction::Normal => vec![Role::Send; p.parallel as usize],
            Direction::Reverse => vec![Role::Recv; p.parallel as usize],
            Direction::Both => [vec![Role::Send; p.parallel as usize], vec![Role::Recv; p.parallel as usize]].concat(),
        };
        let window = (p.window > 0).then_some(p.window);
        for (i, role) in roles.into_iter().enumerate() {
            if self.stopped() {
                return Err(End::Stopped);
            }
            let id = proto::stream_id(i);
            match p.proto {
                Proto::Tcp => {
                    let mut s = match sock::connect_tcp(addr, CONNECT_TIMEOUT, &self.cancel, window) {
                        Ok(s) => s,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Err(End::Stopped),
                        Err(e) => return Err(End::Failed(format!("stream {id} did not connect ({e})"))),
                    };
                    use std::io::Write;
                    let _ = s.set_write_timeout(Some(STEP_TIMEOUT));
                    s.write_all(cookie).map_err(|e| End::Failed(format!("stream {id} did not open ({e})")))?;
                    let info = s.try_clone().ok();
                    let mut slot = Slot::new(id, role, info);
                    if role == Role::Recv {
                        let (stop, counting, c, len) = (self.meter.stop_all.clone(), self.meter.counting.clone(), slot.c.clone(), p_len(p));
                        slot.thread = std::thread::Builder::new().name(format!("vibeperf-rx-{id}")).spawn(move || tcp::run_receiver(s, len, stop, counting, c)).ok();
                    } else {
                        // Senders start at TEST_RUNNING; the socket waits in the slot's thread.
                        slot.thread = None;
                        self.pending_tcp.push((self.meter.slots.len(), s));
                    }
                    self.meter.slots.push(slot);
                }
                Proto::Udp => {
                    let src = netinfo::source_for(addr).ok_or_else(|| End::Failed(format!("this computer has no route to {}", sock::show_addr(addr))))?;
                    let u = sock::udp_connected(addr, src, (role == Role::Recv).then_some(UDP_RCVBUF), window).map_err(|e| End::Failed(format!("stream {id}: {e}")))?;
                    udp_hello(&u, &self.cancel).map_err(|e| match e {
                        ProtoError::Cancelled => End::Stopped,
                        _ => End::Failed(format!("the server did not answer stream {id} on UDP port {} (a firewall may block UDP)", addr.port())),
                    })?;
                    let mut slot = Slot::new(id, role, None);
                    if role == Role::Recv {
                        let (stop, counting, c) = (self.meter.stop_all.clone(), self.meter.counting.clone(), slot.c.clone());
                        let (len, wide) = (p.len, p.udp64);
                        slot.thread = std::thread::Builder::new().name(format!("vibeperf-rx-{id}")).spawn(move || udp::run_receiver(u, len, wide, stop, counting, c)).ok();
                    } else {
                        self.pending_udp.push((self.meter.slots.len(), u));
                    }
                    self.meter.slots.push(slot);
                }
            }
        }
        Ok(())
    }
}

impl Test {
    /// The senders go at TEST_RUNNING, all at once.
    fn start_senders(&mut self, p: &Params) {
        let stop = self.meter.stop_send.clone();
        for (i, s) in std::mem::take(&mut self.pending_tcp) {
            let (st, c, id) = (stop.clone(), self.meter.slots[i].c.clone(), self.meter.slots[i].id);
            let len = p_len(p);
            self.meter.slots[i].thread = std::thread::Builder::new().name(format!("vibeperf-tx-{id}")).spawn(move || tcp::run_sender(s, len, st, c)).ok();
        }
        for (i, u) in std::mem::take(&mut self.pending_udp) {
            let (st, c, id) = (stop.clone(), self.meter.slots[i].c.clone(), self.meter.slots[i].id);
            let (len, rate, wide) = (p.len, p.bandwidth, p.udp64);
            self.meter.slots[i].thread = std::thread::Builder::new().name(format!("vibeperf-tx-{id}")).spawn(move || udp::run_sender(udp::Target::Connected(u), len, rate, wide, st, c)).ok();
        }
    }

    fn publish_running(&self) {
        let rows: Vec<StreamRow> = self.meter.slots.iter().map(|s| live_row(s, self.req.proto)).collect();
        let (series, elapsed) = (self.meter.series.clone(), self.meter.end_t.unwrap_or_else(|| self.meter.elapsed()));
        let loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner()).clone();
        self.publish(|l| {
            l.streams = rows;
            l.series = series;
            l.elapsed = elapsed;
            l.loaded = loaded;
        });
    }

    fn record(&mut self, time: u64, outcome: Outcome, peer: Option<proto::Results>) -> RunRecord {
        let proto_ = self.req.proto;
        let secs = self.meter.end_t.unwrap_or_else(|| self.meter.elapsed());
        let (dirs, mut hints) = if self.meter.started() { run::directions(proto_, &sides(&self.meter), secs, peer.as_ref()) } else { (Vec::new(), Vec::new()) };
        hints.append(&mut self.hints);
        if proto_ == Proto::Tcp {
            hints.extend(window_hints(&self.meter));
        }
        if self.req.window > 0 {
            hints.push(format!("Socket buffers were fixed at {} for this test: Windows' auto-tuning was off.", run::bytes_text(self.req.window as u64)));
        }
        let loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let latency = (self.req.latency && self.meter.started()).then(|| latency::Summary::build(self.target.as_ref().map(|t| t.0.clone()), &self.idle, &loaded));
        RunRecord {
            id: new_id(),
            time,
            label: String::new(),
            host: self.req.target.text(),
            addr: self.addr.map(|a| sock::show_addr(&a)).unwrap_or_else(|| format!("{}:{}", self.req.target.text(), self.req.port)),
            settings: self.req.settings(),
            outcome,
            dirs,
            latency,
            link: self.link.clone(),
            series: self.meter.series.clone(),
            streams: final_rows(&self.meter, proto_, secs, peer.as_ref()),
            hints,
            peer_version: self.peer_version.clone(),
            served: false,
        }
    }
}

/// One side's results as iperf3 sends them (the client's or the server's).
pub(crate) fn results_for(meter: &Meter, udp: bool, cpu0: (f64, f64, Instant)) -> proto::Results {
    let (u, k) = crate::host::process_cpu();
    let wall = cpu0.2.elapsed().as_secs_f64().max(1e-6);
    let (du, dk) = ((u - cpu0.0).max(0.0), (k - cpu0.1).max(0.0));
    let end = meter.end_t.unwrap_or_else(|| meter.elapsed());
    let streams = meter
        .slots
        .iter()
        .map(|s| {
            let recv_udp = udp && s.role == Role::Recv;
            proto::StreamResult {
                id: s.id,
                bytes: s.bytes(),
                retransmits: -1,
                jitter: if recv_udp { s.c.jitter() } else { 0.0 },
                errors: if recv_udp { s.c.lost.load(Ordering::Relaxed) as i64 } else { 0 },
                packets: if udp { s.c.packets.load(Ordering::Relaxed) as i64 } else { 0 },
                omitted: Some((0, 0)),
                start_time: Some(0.0),
                end_time: Some(end),
            }
        })
        .collect();
    let sends = meter.slots.iter().any(|s| s.role == Role::Send);
    proto::Results {
        cpu_total: (du + dk) / wall * 100.0,
        cpu_user: du / wall * 100.0,
        cpu_system: dk / wall * 100.0,
        // Windows counts retransmitted bytes, not segments: none to report (0); a side that
        // only received has no sender count at all (-1), as iperf3 says it.
        sender_has_retransmits: if sends { 0 } else { -1 },
        streams,
    }
}

/// This side's streams at the end, for `run::directions`.
pub(crate) fn sides(meter: &Meter) -> Vec<Side> {
    meter
        .slots
        .iter()
        .map(|s| Side {
            id: s.id,
            send: s.role == Role::Send,
            bytes: s.bytes(),
            packets: s.c.packets.load(Ordering::Relaxed),
            lost: s.c.lost.load(Ordering::Relaxed),
            ooo: s.c.ooo.load(Ordering::Relaxed),
            jitter: s.c.jitter(),
            retrans: s.retrans_bytes(),
        })
        .collect()
}

/// The final rows: each stream's average over the test, and for a UDP sender the receiver's
/// loss and jitter from the peer's results.
pub(crate) fn final_rows(meter: &Meter, proto_: Proto, secs: f64, peer: Option<&proto::Results>) -> Vec<StreamRow> {
    meter
        .slots
        .iter()
        .map(|s| {
            let mut r = live_row(s, proto_);
            r.mbps = if secs > 0.0 { s.bytes() as f64 * 8.0 / secs / 1e6 } else { 0.0 };
            if proto_ == Proto::Udp
                && s.role == Role::Send
                && let Some(p) = peer.and_then(|p| p.streams.iter().find(|x| x.id == s.id))
            {
                r.jitter_ms = Some(p.jitter * 1000.0);
                r.lost = Some(p.errors.max(0) as u64);
            }
            r
        })
        .collect()
}

/// TCP hints from the windows seen during a test.
pub(crate) fn window_hints(meter: &Meter) -> Vec<String> {
    let mut hints = Vec::new();
    if meter.slots.iter().filter(|s| s.role == Role::Recv).any(|s| tcpinfo::window_stuck(&s.rcv_wnds)) {
        hints.push("Receive window stuck at 64 KB: is auto-tuning disabled? (netsh int tcp show global)".into());
    }
    if meter.slots.iter().filter(|s| s.role == Role::Send).any(|s| tcpinfo::window_stuck(&s.snd_wnds)) {
        hints.push("The receiver's window stayed at 64 KB or less: its TCP auto-tuning may be off.".into());
    }
    hints
}

/// A fresh record id (16 hex digits).
pub(crate) fn new_id() -> String {
    let mut id = [0u8; 8];
    crate::host::random_bytes(&mut id);
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// A stream's row as it stands (live: the last interval's rate).
pub(crate) fn live_row(s: &Slot, proto_: Proto) -> StreamRow {
    let up = s.role == Role::Send;
    let mut r = StreamRow { id: s.id, up, bytes: s.bytes(), mbps: s.last_mbps, ..StreamRow::default() };
    match proto_ {
        Proto::Tcp => {
            if up {
                r.retrans_bytes = s.retrans_bytes();
                r.rtt_us = s.latest.map(|i| i.rtt_us);
                r.cwnd = s.latest.map(|i| i.cwnd);
            }
        }
        Proto::Udp => {
            r.total = Some(s.c.packets.load(Ordering::Relaxed));
            if !up {
                r.jitter_ms = Some(s.c.jitter() * 1000.0);
                r.lost = Some(s.c.lost.load(Ordering::Relaxed));
            }
        }
    }
    r
}

/// The UDP payload: the control connection's MSS, so nothing fragments (iperf3's rule), within
/// what a real link carries: 536 to 8960 bytes (a 9000-byte jumbo frame). Loopback's MSS of
/// nearly 64 KiB, or none at all, gives 1460 (IPv4) or 1440 (IPv6) bytes.
pub fn udp_len(mss: Option<u32>, ipv6: bool) -> u32 {
    match mss {
        Some(m) if (536..=8960).contains(&m) => m,
        _ if ipv6 => proto::UDP_LEN_V6,
        _ => proto::UDP_LEN_V4,
    }
}

fn p_len(p: &Params) -> u32 {
    p.len.max(1)
}

/// The UDP "connect": send iperf3's hello, wait for the reply (a few tries a second apart; in
/// a reverse test data may come first, as iperf3 allows).
fn udp_hello(u: &std::net::UdpSocket, cancel: &AtomicBool) -> Result<(), ProtoError> {
    let mut buf = vec![0u8; 65_536];
    for _ in 0..3 {
        u.send(&proto::UDP_CONNECT_MSG).map_err(ProtoError::from_io)?;
        let until = Instant::now() + Duration::from_secs(1);
        while Instant::now() < until {
            if cancel.load(Ordering::SeqCst) {
                return Err(ProtoError::Cancelled);
            }
            if sock::wait_readable(u, sock::SLICE).map_err(ProtoError::from_io)? {
                match u.recv(&mut buf) {
                    Ok(n) if proto::is_connect_reply(&buf[..n]) => return Ok(()),
                    Ok(_) => {}
                    // A port-unreachable for the hello: keep trying until the time is up.
                    Err(_) => {}
                }
            }
        }
    }
    Err(ProtoError::TimedOut)
}

/// One series of idle pings on its own thread.
fn series_thread(net: Arc<dyn PingNet>, ip: std::net::IpAddr, scope: u32, cancel: Arc<AtomicBool>) -> std::thread::JoinHandle<Pings> {
    std::thread::spawn(move || {
        let mut out = Pings::default();
        let Ok(mut p) = net.open(ip, scope) else { return out };
        let start = Instant::now();
        for i in 0..latency::IDLE_PINGS {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            let due = start + Duration::from_millis(latency::GAP_MS * i as u64);
            while Instant::now() < due && !cancel.load(Ordering::SeqCst) {
                std::thread::sleep((due - Instant::now()).min(Duration::from_millis(20)));
            }
            out.sent += 1;
            if let Some(us) = p.ping() {
                out.rtts.push(us);
            }
        }
        out
    })
}

fn connect_words(a: &SocketAddr, e: &std::io::Error) -> String {
    let at = sock::show_addr(a);
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => format!("nothing is listening on {at} (connection refused)"),
        std::io::ErrorKind::TimedOut => format!("no answer from {at} within 5 s (a firewall may drop it, or the host is down)"),
        _ => format!("could not connect to {at} ({e})"),
    }
}
