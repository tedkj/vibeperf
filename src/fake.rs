//! A scripted engine for the window tests and their snapshots: tests and servers that do
//! exactly what the test says, second by second, so every run looks the same. Also believable
//! records for the snapshots (a powerline link, a busy Wi-Fi, a 10G loopback).

use crate::client::{Client, Live, Phase, Request};
use crate::latency::{self, Pings};
use crate::meter::Point;
use crate::proto::{Direction, Proto};
use crate::run::{DirResult, Outcome, RunRecord, StreamRow};
use crate::server::{Opts, Server, ServerLive};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub struct FakeTest {
    pub req: Request,
    pub live: Arc<Mutex<Live>>,
    pub cancel: Arc<AtomicBool>,
}

pub struct FakeServer {
    pub opts: Opts,
    pub live: Arc<Mutex<ServerLive>>,
    pub stop: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
pub struct Engine {
    pub tests: Arc<Mutex<Vec<FakeTest>>>,
    pub servers: Arc<Mutex<Vec<FakeServer>>>,
}

impl Engine {
    pub fn start_test(&self, req: Request) -> Client {
        let live = Arc::new(Mutex::new(Live { phase: Phase::Connecting, ..Live::default() }));
        let cancel = Arc::new(AtomicBool::new(false));
        self.tests.lock().unwrap().push(FakeTest { req, live: live.clone(), cancel: cancel.clone() });
        Client::from_parts(live, cancel)
    }

    pub fn start_server(&self, opts: Opts) -> Server {
        let live = Arc::new(Mutex::new(ServerLive { listening: true, ..ServerLive::default() }));
        let stop = Arc::new(AtomicBool::new(false));
        self.servers.lock().unwrap().push(FakeServer { opts, live: live.clone(), stop: stop.clone() });
        Server::from_parts(live, stop)
    }

    /// The newest test's live state.
    pub fn live(&self) -> Arc<Mutex<Live>> {
        self.tests.lock().unwrap().last().expect("a test was started").live.clone()
    }

    pub fn request(&self) -> Request {
        self.tests.lock().unwrap().last().expect("a test was started").req.clone()
    }

    pub fn stop_asked(&self) -> bool {
        self.tests.lock().unwrap().last().is_some_and(|t| t.cancel.load(std::sync::atomic::Ordering::SeqCst))
    }

    pub fn set(&self, f: impl FnOnce(&mut Live)) {
        let l = self.live();
        let mut g = l.lock().unwrap();
        f(&mut g);
        g.seq += 1;
    }

    /// The test runs: its streams, its link, its idle latency.
    pub fn running(&self, link: &str, idle_ms: &[f64]) {
        let req = self.request();
        self.set(|l| {
            l.phase = Phase::Running;
            l.addr = format!("{}:{}", req.target.text(), req.port);
            l.link = link.into();
            l.idle = Pings { rtts: idle_ms.iter().map(|m| (m * 1000.0) as u32).collect(), sent: 20 };
            l.target = (!idle_ms.is_empty()).then(|| latency::Target::Peer(req.target.text()));
            l.streams = rows(&req, 0.0, 0);
        });
    }

    /// One more second at these rates (Mbit/s, all streams of that way).
    pub fn second(&self, send: Option<f64>, recv: Option<f64>, loaded_ms: f64) {
        let req = self.request();
        self.set(|l| {
            let t = l.series.len() as f64 + 1.0;
            l.series.push(Point { t, send, recv });
            l.elapsed = t;
            for _ in 0..10 {
                l.loaded.rtts.push((loaded_ms * 1000.0) as u32);
                l.loaded.sent += 1;
            }
            let rate = send.or(recv).unwrap_or(0.0);
            l.streams = rows(&req, rate, t as u64);
        });
    }

    /// The test ends with this record.
    pub fn finish(&self, r: RunRecord) {
        self.set(|l| {
            l.phase = Phase::Done;
            l.record = Some(r);
        });
    }

    pub fn server_live(&self) -> Arc<Mutex<ServerLive>> {
        self.servers.lock().unwrap().last().expect("a server was started").live.clone()
    }

    pub fn server_set(&self, f: impl FnOnce(&mut ServerLive)) {
        let l = self.server_live();
        let mut g = l.lock().unwrap();
        f(&mut g);
        g.seq += 1;
    }
}

fn rows(req: &Request, rate: f64, secs: u64) -> Vec<StreamRow> {
    let ways: Vec<bool> = match req.direction {
        Direction::Normal => vec![true],
        Direction::Reverse => vec![false],
        Direction::Both => vec![true, false],
    };
    let mut out = Vec::new();
    let mut i = 0;
    for up in ways {
        for _ in 0..req.streams {
            let per = rate / req.streams as f64;
            let mut r = StreamRow { id: crate::proto::stream_id(i), up, bytes: (per * 1e6 / 8.0) as u64 * secs, mbps: per, ..StreamRow::default() };
            if req.proto == Proto::Udp {
                r.total = Some(secs * 8560 / req.streams as u64);
                if !up {
                    r.jitter_ms = Some(0.031 + i as f64 * 0.004);
                    r.lost = Some(i as u64);
                }
            } else if up {
                r.retrans_bytes = Some(secs * 1460 * (i as u64 + 1));
                r.rtt_us = Some(2100 + i as u32 * 130);
                r.cwnd = Some(262_144 + i as u32 * 16_384);
            }
            out.push(r);
            i += 1;
        }
    }
    out
}

/// A believable finished test of `req`: `mbps` received each way over `secs`, with the
/// outcome given.
pub fn record(req: &Request, id: &str, time: u64, mbps: f64, outcome: Outcome) -> RunRecord {
    let secs = req.seconds as f64;
    let ran = outcome.at.unwrap_or(secs).min(secs);
    let ways: Vec<bool> = match req.direction {
        Direction::Normal => vec![true],
        Direction::Reverse => vec![false],
        Direction::Both => vec![true, false],
    };
    let udp = req.proto == Proto::Udp;
    let dirs: Vec<DirResult> = ways
        .iter()
        .map(|up| {
            let recv = (mbps * 1e6 / 8.0 * ran) as u64;
            let sent = recv + recv / 400;
            let mut d = DirResult { up: *up, streams: req.streams, sent_bytes: Some(sent), sent_secs: Some(ran), recv_bytes: Some(recv), recv_secs: Some(ran + 0.04), ..DirResult::default() };
            if udp {
                d.udp_total = Some((ran * 8560.0) as u64);
                d.udp_lost = Some(12);
                d.jitter_ms = Some(0.042);
            } else if *up {
                d.retrans_bytes = Some(sent / 2000);
            } else {
                d.peer_retrans = Some(37);
            }
            d
        })
        .collect();
    let series: Vec<Point> = (1..=(ran as u64))
        .map(|t| {
            let wob = ((t * 7) % 5) as f64 * 0.004;
            let v = mbps * (0.97 + wob);
            Point { t: t as f64, send: ways.contains(&true).then_some(v), recv: ways.contains(&false).then_some(v * 0.995) }
        })
        .collect();
    let mut streams = rows(req, mbps, ran as u64);
    for s in &mut streams {
        s.mbps = mbps / req.streams as f64;
    }
    RunRecord {
        id: id.into(),
        time,
        label: String::new(),
        host: req.target.text(),
        addr: format!("{}:{}", req.target.text(), req.port),
        settings: req.settings(),
        outcome,
        dirs,
        latency: Some(latency::Summary {
            target: Some(latency::Target::Peer(req.target.text())),
            idle_ms: Some(0.62),
            loaded_ms: Some(3.4),
            loaded_p95_ms: Some(6.1),
            idle_sent: 20,
            idle_lost: 0,
            loaded_sent: (ran * 10.0) as usize,
            loaded_lost: 0,
        }),
        link: "Ethernet, 1 Gbps link".into(),
        series,
        streams,
        hints: Vec::new(),
        peer_version: "3.16".into(),
        served: false,
    }
}

/// A request for the snapshots and tests.
pub fn request(host: &str, proto: Proto, direction: Direction, streams: u32, seconds: u32) -> Request {
    Request { target: crate::netinfo::parse_target(host).expect("a host"), port: 5201, proto, direction, streams, seconds, bitrate: 100_000_000, window: 0, latency: true, udp64: false, record: None }
}

// ---------- the firewall and its helper, in memory ----------

use crate::firewall::{Firewall, NewRule, Rule};
use crate::helper::{Launch, Launcher};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;

/// A firewall in memory: what the helper added and removed.
#[derive(Default, Clone)]
pub struct MemFirewall(pub Arc<Mutex<Vec<Rule>>>);

impl Firewall for MemFirewall {
    fn add(&self, r: &NewRule) -> Result<(), String> {
        self.0.lock().unwrap().push(Rule {
            name: r.name.clone(),
            app: r.app.clone(),
            inbound: true,
            allow: true,
            enabled: true,
            grouping: crate::firewall::GROUP.into(),
            protocol: r.protocol,
            ports: r.port.to_string(),
            remote: "LocalSubnet".into(),
            profiles: 0x7fff_ffff,
            description: r.description.clone(),
        });
        Ok(())
    }

    fn remove(&self, pick: &dyn Fn(&Rule) -> bool) -> Result<usize, String> {
        let mut v = self.0.lock().unwrap();
        let before = v.len();
        v.retain(|r| !pick(r));
        Ok(before - v.len())
    }
}

impl MemFirewall {
    pub fn ours(&self) -> usize {
        self.0.lock().unwrap().iter().filter(|r| crate::firewall::is_ours(r)).count()
    }
}

/// What the user does at the (pretend) UAC prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uac {
    Accept,
    Decline,
}

/// A helper on a thread of this process, speaking the real pipe protocol to the app, with a
/// firewall in memory; the "UAC prompt" answers as told.
#[derive(Clone)]
pub struct ThreadLauncher {
    pub fw: MemFirewall,
    pub uac: Arc<Mutex<Uac>>,
    pub launches: Arc<std::sync::atomic::AtomicUsize>,
}

impl ThreadLauncher {
    pub fn new() -> ThreadLauncher {
        ThreadLauncher { fw: MemFirewall::default(), uac: Arc::new(Mutex::new(Uac::Accept)), launches: Default::default() }
    }
}

impl Default for ThreadLauncher {
    fn default() -> Self {
        ThreadLauncher::new()
    }
}

/// A real handle to this process (a thread helper's stand-in for both the helper and its parent).
pub fn this_process() -> OwnedHandle {
    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: duplicating this process's pseudo handle into a real one we own.
    unsafe {
        let mut dup: HANDLE = std::ptr::null_mut();
        DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &mut dup, 0, 0, DUPLICATE_SAME_ACCESS);
        OwnedHandle::from_raw_handle(dup as RawHandle)
    }
}

impl Launcher for ThreadLauncher {
    fn launch(&self, exe: &Path, args: &str) -> Result<OwnedHandle, Launch> {
        self.launches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if *self.uac.lock().unwrap() == Uac::Decline {
            return Err(Launch::Declined);
        }
        let a: Vec<String> = args.split(' ').map(String::from).collect();
        let (path, fw, exe) = (crate::helper::pipe_path(&a[1]), self.fw.clone(), exe.to_path_buf());
        std::thread::spawn(move || {
            let Some(pipe) = crate::helper::open_pipe(&path, std::time::Duration::from_secs(5)) else { return };
            let parent = this_process();
            crate::helper::serve(pipe, parent.as_raw_handle(), crate::firewall::me(), crate::firewall::user_sid(), &fw, &exe, std::time::Duration::from_secs(120));
        });
        Ok(this_process())
    }
}
