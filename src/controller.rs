//! The window's brain. It lives on the UI thread: it starts and stops tests and the server, asks
//! about the firewall, keeps the prefs (in memory, saved on the prefs thread) and the history
//! (in memory, saved on the history thread), and on a 250 ms timer (only while something is
//! running or pending) copies what the workers measured into the window. The .slint files lay
//! out what it hands them; every word and number is made here or in `view`.
//!
//! Nothing here blocks: name lookups, connects, firewall reads, the UAC prompt and the helper's
//! pipe all run on workers whose results land in slots the timer looks at. Every result carries
//! the epoch it was asked for; a result for an older one does nothing.

use crate::check::{Dot, Fetched, Local as CheckLocal, Release, Rows};
use crate::client::{self, Client, Live, Phase, Request};
use crate::firewall;
use crate::helper::{self, Launch, Launcher};
use crate::history::{self, Event, HistoryChange};
use crate::netinfo::{self, Local};
use crate::prefs::{Change, Store};
use crate::proto::{Direction, Proto};
use crate::run::{self, RunRecord};
use crate::server::{self, Server};
use crate::view;
use crate::{AppWindow, ChartInfo, CheckDot, CheckRow, Prefs, ReachLine, RunLine, StreamLine, Theme, TileInfo, ToastItem, ToastKind};
use slint::platform::Key;
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Where the server listens: every address, IPv6 and IPv4.
pub const SERVER_BIND: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
/// How often the window looks at what runs.
pub const POLL_MS: u64 = 250;

/// What the firewall says before Start server (read on a worker, no admin needed).
#[derive(Clone, Debug, PartialEq)]
pub struct FwCheck {
    pub status: Result<firewall::Status, String>,
    /// Inbound block rules for this exe, listed in the question before anything is removed.
    pub blocks: Vec<BlockRule>,
    /// An allow rule of someone else's already covers TCP and UDP on the port.
    pub allowed: bool,
}

/// An inbound block rule for this exe: Windows makes one when its "allow access?" prompt is
/// dismissed, but someone may have made it on purpose; the two cannot be told apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRule {
    pub name: String,
    /// The profiles it applies to, in words ("Public", "Domain, Private, Public").
    pub profiles: String,
}

/// The system's firewall check for this exe and port.
pub fn system_fw_check(exe: &Path, port: u16) -> FwCheck {
    fw_check_from(firewall::status(), &firewall::rules().unwrap_or_default(), firewall::active_profiles(), exe, port)
}

/// The check from what was read. `active` None: the active profiles could not be read, so no
/// rule is known to cover them and the question is asked (never "an allow rule is already in
/// place" on a guess).
fn fw_check_from(status: Result<firewall::Status, String>, rules: &[firewall::Rule], active: Option<i32>, exe: &Path, port: u16) -> FwCheck {
    let blocks = rules.iter().filter(|r| firewall::blocks_this_exe(r, exe)).map(|r| BlockRule { name: r.name.clone(), profiles: firewall::profile_names(r.profiles) }).collect();
    let allowed = active.is_some_and(|a| firewall::allowed_already(rules, exe, port, 6, a) && firewall::allowed_already(rules, exe, port, 17, a));
    FwCheck { status, blocks, allowed }
}

/// The start-up count of `rules`: this user's VibePerf rules whose window is gone (or an older
/// VibePerf's, untagged). A second running window's are not left over.
fn leftovers_in(rules: &[firewall::Rule]) -> usize {
    firewall::leftovers(rules, firewall::user_sid(), &firewall::alive)
}

/// The question's words about this exe's block rules: what they do, that where they came from
/// is unknown, and each one by name and profiles (at most 8 named; the names are untrusted).
fn block_list(blocks: &[BlockRule]) -> String {
    if blocks.is_empty() {
        return String::new();
    }
    let n = blocks.len();
    let mut s = format!(
        "\n\nThe firewall also has {n} inbound block rule{} for VibePerf.exe, and a block rule beats any allow rule. Windows makes such a rule when its own prompt about a program is dismissed, but someone may also have made {} on purpose:",
        if n == 1 { "" } else { "s" },
        if n == 1 { "it" } else { "them" }
    );
    for b in blocks.iter().take(8) {
        let name: String = netinfo::clean(&b.name).chars().take(80).collect();
        s.push_str(&format!("\n• {name} ({})", b.profiles));
    }
    if n > 8 {
        s.push_str(&format!("\n• and {} more", n - 8));
    }
    s
}

/// What the controller needs from the outside world; the tests hand it fakes.
pub struct Services {
    pub copy: Box<dyn Fn(&str) -> bool>,
    pub start_test: Box<dyn Fn(Request) -> Client>,
    pub start_server: Box<dyn Fn(server::Opts) -> Server>,
    pub fw_check: Arc<dyn Fn(u16) -> FwCheck + Send + Sync>,
    /// VibePerf's own rules left in the firewall by a window that is gone (read at start).
    pub stale_rules: Arc<dyn Fn() -> usize + Send + Sync>,
    pub launcher: Arc<dyn Launcher>,
    pub exe: PathBuf,
    pub locals: Arc<dyn Fn() -> Vec<Local> + Send + Sync>,
    /// history.json's path.
    pub history: PathBuf,
    pub bind: IpAddr,
    pub now: Box<dyn Fn() -> u64>,
    /// A web page in the browser (About's link).
    pub open_url: Box<dyn Fn(&str)>,
    /// The install check's offline half, on its worker: this copy's files, their signatures and
    /// hashes (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, CheckLocal>,
    /// The install check's online half, on its worker: the release list at a path on the site,
    /// waited for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `net::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

impl Services {
    /// The real services. `fetch` is the release-list fetcher: `main` hands in the exe's
    /// `net::fetch_release_list`, and is the only place that names it.
    pub fn system(paths: &crate::host::Paths, fetch: Fetcher<str, Fetched>) -> Services {
        // The exe's identity as this process started from it, taken now, before an install
        // could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        let exe = crate::host::own_exe().unwrap_or_default();
        let e2 = exe.clone();
        Services {
            copy: Box::new(|t| crate::host::copy_text(t).is_ok()),
            start_test: Box::new(|r| client::start(r, Arc::new(crate::latency::Icmp))),
            start_server: Box::new(server::start),
            fw_check: Arc::new(move |port| system_fw_check(&e2, port)),
            stale_rules: Arc::new(|| firewall::rules().map(|r| leftovers_in(&r)).unwrap_or(0)),
            launcher: Arc::new(helper::Elevated),
            exe,
            locals: Arc::new(|| netinfo::locals().unwrap_or_default()),
            history: paths.local_data.join("history.json"),
            bind: SERVER_BIND,
            now: Box::new(crate::host::now_unix),
            // The shell can take a moment: never on the window's thread.
            open_url: Box::new(|u| {
                let u = u.to_string();
                std::thread::spawn(move || {
                    let _ = crate::host::open_url(&u);
                });
            }),
            inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)),
            fetch,
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

/// One change to the prefs, applied by the prefs thread onto the newest saved ones.
type PrefsChange = Change<Prefs>;

/// After a change, when the window looks whether the prefs thread met a garbled file.
const PREFS_TELL_MS: u64 = 500;

/// The thread that saves prefs changes, in order: the store keeps each until it is written, and
/// puts every unwritten one onto the file as read right before the write (another instance's
/// changes included), onto this window's own when the file is garbled or missing, and writes
/// nothing while the file cannot be read. Reading prefs.json is the disk too: never on the
/// window's thread (a profile on a dead share froze it).
fn prefs_writer(store: Store<Prefs>, pending: Arc<AtomicUsize>) -> Sender<PrefsChange> {
    let (tx, rx) = channel::<PrefsChange>();
    std::thread::spawn(move || {
        while let Ok(f) = rx.recv() {
            store.change(Arc::new(move |p: &mut Prefs| {
                *p = std::mem::take(p).sanitized();
                f(p);
            }));
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}

/// A worker's answer, when it has one.
type Slot<T> = Arc<Mutex<Option<T>>>;
/// A helper launch on its worker: the server start it is for, the port, its answer.
type HelperJob = (u64, u16, Slot<Result<helper::Session, Launch>>);

fn spawn_job<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> Slot<T> {
    let slot: Slot<T> = Arc::new(Mutex::new(None));
    let s = slot.clone();
    let _ = std::thread::Builder::new().name(name.into()).spawn(move || {
        let v = f();
        *s.lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
    });
    slot
}

fn take<T>(s: &Slot<T>) -> Option<T> {
    s.lock().unwrap_or_else(|e| e.into_inner()).take()
}

// ---------- the client's inputs (one way in: the field, Enter, the button, the command line) ----------

/// Seconds as typed: "10", "10 s", "10s", "2 min". 1 to 300.
pub fn parse_seconds(t: &str) -> Result<u32, String> {
    let s = t.trim().to_lowercase();
    let (num, mult) = if let Some(m) = s.strip_suffix("min").or_else(|| s.strip_suffix('m')) {
        (m.trim().to_string(), 60)
    } else {
        (s.trim_end_matches("sec").trim_end_matches('s').trim().to_string(), 1)
    };
    match num.parse::<u32>() {
        Ok(n) if (1..=crate::MAX_SECONDS).contains(&(n.saturating_mul(mult))) => Ok(n * mult),
        _ => Err(format!("A test lasts 1 to {} seconds.", crate::MAX_SECONDS)),
    }
}

pub fn seconds_text(s: u32) -> String {
    format!("{s} s")
}

/// The note after Stop server, counted: the helper may have found no rule left (removed from
/// outside) or one (its twin already gone).
fn stopped_note(removed: u32) -> String {
    match removed {
        0 => "Stopped. No firewall rules were left to remove.".into(),
        1 => "Stopped. The firewall rule was removed.".into(),
        n => format!("Stopped. The {n} firewall rules were removed."),
    }
}

/// A rate as typed, iperf3's way or in words: "100M", "100 Mbit/s", "1G", "500k", "2.5 Gbit/s",
/// "100" (Mbit/s). 1 kbit/s to 100 Gbit/s.
pub fn parse_rate(t: &str) -> Result<u64, String> {
    let s = t.trim().to_lowercase().replace(' ', "");
    let s = s.trim_end_matches("/s").trim_end_matches("ps").trim_end_matches("bit").trim_end_matches('b');
    let (num, mult) = match s.chars().last() {
        Some('k') => (&s[..s.len() - 1], 1e3),
        Some('m') => (&s[..s.len() - 1], 1e6),
        Some('g') => (&s[..s.len() - 1], 1e9),
        _ => (s, 1e6),
    };
    let bad = || "A rate is 1 kbit/s to 100 Gbit/s (\"100M\", \"1G\", \"500k\").".to_string();
    let v: f64 = num.parse().map_err(|_| bad())?;
    let bps = (v * mult).round();
    if !bps.is_finite() || bps < crate::MIN_BITRATE as f64 || bps > crate::MAX_BITRATE as f64 {
        return Err(bad());
    }
    Ok(bps as u64)
}

/// "100 Mbit/s", "1 Gbit/s", "2.5 Gbit/s", "500 kbit/s": the exact rate, in its largest unit.
pub fn rate_field_text(bps: u64) -> String {
    let trim = |x: f64| {
        let s = format!("{x:.3}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    };
    if bps >= 1_000_000_000 {
        format!("{} Gbit/s", trim(bps as f64 / 1e9))
    } else if bps >= 1_000_000 {
        format!("{} Mbit/s", trim(bps as f64 / 1e6))
    } else {
        format!("{} kbit/s", trim(bps as f64 / 1e3))
    }
}

fn direction_of(p: &Prefs) -> Direction {
    match p.direction.as_str() {
        "reverse" => Direction::Reverse,
        "both" => Direction::Both,
        _ => Direction::Normal,
    }
}

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

fn key_is(text: &str, k: Key) -> bool {
    let k: SharedString = k.into();
    text == k.as_str()
}

/// What the window shows in the main area.
#[derive(Clone, Debug)]
enum Shown {
    Nothing,
    Live { live: Box<Live>, kind: String, host: String, seconds: u32, udp: bool },
    Record(Box<RunRecord>),
}

#[derive(Default)]
struct State {
    prefs: Prefs,
    // The fields as last committed (Escape puts these back; work uses only these).
    host: String,
    port: String,
    duration: String,
    rate: String,
    server_port: String,
    label: String,
    // The client's test.
    test: Option<(u64, Client, Request)>,
    test_epoch: u64,
    test_seen: u64,
    live: Option<Live>,
    // History.
    runs: Vec<RunRecord>,
    history_loaded: bool,
    history_note: String,
    selected: Option<String>,
    scroll_seq: i32,
    /// The record on screen (its label field is filled when it changes).
    shown_id: Option<String>,
    // The server.
    server: Option<Server>,
    server_seen: u64,
    served: Vec<RunRecord>,
    served_selected: Option<String>,
    served_scroll_seq: i32,
    current: Option<(String, run::Settings, Live)>,
    srv_epoch: u64,
    fw_job: Option<(u64, u16, Slot<FwCheck>)>,
    helper_job: Option<HelperJob>,
    clean_job: Option<Slot<Result<helper::Reply, String>>>,
    stop_job: Option<Slot<String>>,
    stale_job: Option<Slot<usize>>,
    reach_job: Option<Slot<Vec<Local>>>,
    /// The question on screen: its server start, port and how many block rules it listed.
    consent: Option<(u64, u16, usize)>,
    /// Block rules for this exe the user chose to keep at the last Start server.
    blocks_kept: usize,
    stale: usize,
    note: (String, i32),
    serving_port: u16,
    // Toasts.
    toast_seq: i32,
    /// Each toast's timer generation (only the newest timer counts) and its full time in ms.
    toast_time: HashMap<i32, (u64, u64)>,
    /// The install check: its number (an answer for another one does nothing), and while it
    /// runs, where its answer comes from.
    check_seq: u64,
    check_rx: Option<Receiver<(u64, Rows)>>,
}

pub struct App {
    ui: Weak<AppWindow>,
    svc: Services,
    store: Store<Prefs>,
    st: RefCell<State>,
    prefs_tx: Sender<PrefsChange>,
    /// Changes sent to the prefs thread and not yet handed to the store.
    prefs_pending: Arc<AtomicUsize>,
    history_tx: RefCell<Option<Sender<HistoryChange>>>,
    history_thread: RefCell<Option<std::thread::JoinHandle<()>>>,
    history_events: Arc<Mutex<Vec<Event>>>,
    history_pending: Arc<AtomicUsize>,
    /// The firewall helper while the server's rules exist (closed on a worker).
    session: Arc<Mutex<Option<helper::Session>>>,
    toasts: Rc<VecModel<ToastItem>>,
    tiles: Rc<VecModel<TileInfo>>,
    streams: Rc<VecModel<StreamLine>>,
    history_rows: Rc<VecModel<RunLine>>,
    served_rows: Rc<VecModel<RunLine>>,
    reach: Rc<VecModel<ReachLine>>,
    recent: Rc<VecModel<SharedString>>,
    hints: Rc<VecModel<SharedString>>,
    timer: Timer,
    /// The graph's plot size in pixels (reported by the window).
    chart_size: Cell<(f32, f32)>,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
    me: RefCell<std::rc::Weak<App>>,
}

impl App {
    /// Wire the controller to a window made by `crate::window`.
    pub fn attach(ui: &AppWindow, store: Store<Prefs>, svc: Services) -> Rc<App> {
        let prefs = store.load().sanitized();
        let prefs_pending = Arc::new(AtomicUsize::new(0));
        let prefs_tx = prefs_writer(store.clone(), prefs_pending.clone());
        let history_events = Arc::new(Mutex::new(Vec::new()));
        let history_pending = Arc::new(AtomicUsize::new(0));
        let (htx, hthread) = history::thread(svc.history.clone(), history_events.clone(), history_pending.clone());
        let app = Rc::new(App {
            ui: ui.as_weak(),
            svc,
            store,
            st: RefCell::new(State { prefs, ..State::default() }),
            prefs_tx,
            prefs_pending,
            history_tx: RefCell::new(Some(htx)),
            history_thread: RefCell::new(Some(hthread)),
            history_events,
            history_pending,
            session: Arc::new(Mutex::new(None)),
            toasts: Rc::new(VecModel::default()),
            tiles: Rc::new(VecModel::default()),
            streams: Rc::new(VecModel::default()),
            history_rows: Rc::new(VecModel::default()),
            served_rows: Rc::new(VecModel::default()),
            reach: Rc::new(VecModel::default()),
            recent: Rc::new(VecModel::default()),
            hints: Rc::new(VecModel::default()),
            timer: Timer::default(),
            chart_size: Cell::new((0.0, 0.0)),
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
            me: RefCell::new(std::rc::Weak::new()),
        });
        *app.me.borrow_mut() = Rc::downgrade(&app);
        ui.set_toasts(ModelRc::from(app.toasts.clone()));
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&Rows::idle());
        // About's version line (no portable mode: always the installed copy).
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        ui.set_about_line(s(format!("version {} · {bits} · installed for you", crate::VERSION)));
        ui.set_tiles(ModelRc::from(app.tiles.clone()));
        ui.set_stream_rows(ModelRc::from(app.streams.clone()));
        ui.set_history(ModelRc::from(app.history_rows.clone()));
        ui.set_served(ModelRc::from(app.served_rows.clone()));
        ui.set_reach(ModelRc::from(app.reach.clone()));
        ui.set_recent(ModelRc::from(app.recent.clone()));
        ui.set_hints(ModelRc::from(app.hints.clone()));
        app.wire(ui);
        app.load_fields();
        if app.store.broken() {
            app.toast("prefs.json could not be read: the settings are back to their defaults, and the old file will be kept as prefs.json.broken.", ToastKind::Error);
        }
        app.check_stale_rules();
        app.refresh_all();
        app.ensure_poll();
        app
    }

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$a:ident $(, $arg:ident)*| $body:expr) => {{
                let w = Rc::downgrade(self);
                ui.$setter(move |$($arg),*| {
                    let Some($a) = w.upgrade() else { return Default::default() };
                    $body
                });
            }};
        }
        on!(on_toggle_theme, |a| a.toggle_theme());
        on!(on_copy_text, |a, t| (a.svc.copy)(&t));
        on!(on_toast_dismissed, |a, id| a.drop_toast(id));
        on!(on_toast_action, |a, id| a.drop_toast(id));
        on!(on_dialogs_closed, |a| a.dialogs_closed());
        on!(on_mode_picked, |a, i| a.set_mode(i));
        on!(on_host_edited, |a, _t| a.field_edited());
        on!(on_host_accepted, |a| a.start_clicked());
        on!(on_host_escaped, |a| a.escape_field(3));
        on!(on_recent_picked, |a, i| a.recent_picked(i));
        on!(on_field_edited, |a, _i, _t| a.field_edited());
        on!(on_field_escaped, |a, i| a.escape_field(i));
        on!(on_proto_picked, |a, i| a.pick(0, i));
        on!(on_direction_picked, |a, i| a.pick(1, i));
        on!(on_streams_picked, |a, i| a.pick(2, i));
        on!(on_start_clicked, |a| a.start_clicked());
        on!(on_server_port_edited, |a, _t| a.field_edited());
        on!(on_server_port_escaped, |a| a.escape_field(4));
        on!(on_server_clicked, |a| a.server_clicked());
        on!(on_server_note_clicked, |a| a.clean_stale());
        on!(on_fw_continue, |a| a.fw_continue());
        on!(on_fw_cancel, |a| a.fw_cancel());
        on!(on_label_edited, |a, _t| { let _ = a; });
        on!(on_label_accepted, |a| a.label_commit());
        on!(on_label_escaped, |a| a.label_escape());
        on!(on_copy_line, |a| a.copy_shown(false));
        on!(on_copy_block, |a| a.copy_shown(true));
        on!(on_history_clicked, |a, id| a.select_run(Some(id.to_string())));
        on!(on_history_opened, |a, id| a.repeat_settings(&id));
        on!(on_history_key, |a, t, _c, _s| a.list_key(&t, false));
        on!(on_served_clicked, |a, id| a.select_served(Some(id.to_string())));
        on!(on_served_key, |a, t, _c, _s| a.list_key(&t, true));
        on!(on_chart_resized, |a, w, h| a.chart_resized(w, h));
        on!(on_check_install, |a| a.check_install());
        on!(on_open_site, |a| (a.svc.open_url)(crate::check::SITE));
    }

    fn ui(&self) -> Option<AppWindow> {
        self.ui.upgrade()
    }

    // ---------- About's install check ----------

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    fn check_install(&self) {
        let Some(ui) = self.ui() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.svc.inspect.clone(), self.svc.fetch.clone(), self.svc.release.clone());
        // No portable mode: always the installed copy, so the uninstaller is checked too.
        let installed = true;
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = self.me.borrow().clone();
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: s(name), text: s(&r.text), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }

    fn now(&self) -> u64 {
        (self.svc.now)()
    }

    // ---------- prefs ----------

    /// The prefs as this window has them (its own choices, in memory).
    pub fn prefs(&self) -> Prefs {
        self.st.borrow().prefs.clone()
    }

    /// One change to the prefs: at once in memory (this window's own choices), and by the prefs
    /// thread onto the newest saved ones, which may hold another instance's changes. A file
    /// found garbled on the way is told shortly after.
    pub fn save_prefs(&self, change: impl Fn(&mut Prefs) + Send + Sync + 'static) {
        let f: PrefsChange = Arc::new(change);
        f(&mut self.st.borrow_mut().prefs);
        self.prefs_pending.fetch_add(1, Ordering::SeqCst);
        if self.prefs_tx.send(f).is_err() {
            self.prefs_pending.fetch_sub(1, Ordering::SeqCst);
        }
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(PREFS_TELL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.tell_garbled();
            }
        });
    }

    fn tell_garbled(&self) {
        if self.store.take_garbled() {
            self.toast("prefs.json was damaged: it is kept as prefs.json.broken, and this window's settings are saved in its place.", ToastKind::Error);
        }
    }

    /// At exit (and in tests): let the prefs thread hand its last change to the store (at most
    /// two seconds), then write what is unwritten onto the file as it is now, on a thread of its
    /// own, waited for at most two seconds too: a prefs file on a share that stopped answering
    /// never holds the window's thread for good (VibePing PING-8, review X15CON-4). A prefs
    /// thread still busy then is not waited for: at exit the process ends it, and the changes it
    /// had not written are lost, unsaid.
    pub fn finish_prefs(&self) {
        let start = Instant::now();
        let limit = Duration::from_secs(2);
        while self.prefs_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.prefs_pending.load(Ordering::SeqCst) > 0 {
            return;
        }
        let store = self.store.clone();
        let (tx, rx) = channel::<()>();
        std::thread::spawn(move || {
            store.flush();
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(limit);
    }

    /// At exit (and in tests): history's last changes onto the file (at most two seconds).
    pub fn finish_history(&self) {
        let start = Instant::now();
        while self.history_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.history_tx.borrow_mut().take();
        if let Some(t) = self.history_thread.borrow_mut().take() {
            let until = Instant::now() + Duration::from_secs(2);
            while !t.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(2));
            }
            if t.is_finished() {
                let _ = t.join();
            }
        }
    }

    /// At exit: the test stops, the server stops and its firewall rules go (the helper is told;
    /// a helper that cannot be told sees the pipe close and removes them itself), then the last
    /// prefs and history changes are written.
    pub fn finish(&self) {
        let (test, server) = {
            let mut st = self.st.borrow_mut();
            (st.test.take(), st.server.take())
        };
        if let Some((_, c, _)) = test {
            c.stop();
            let until = Instant::now() + Duration::from_secs(3);
            while !c.finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(srv) = server {
            srv.shutdown();
        }
        if let Some(s) = self.session.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = s.close();
        }
        self.finish_prefs();
        self.finish_history();
    }

    fn toggle_theme(&self) {
        let Some(ui) = self.ui() else { return };
        let theme = ui.global::<Theme>();
        let dark = !theme.get_dark();
        theme.set_dark(dark);
        self.save_prefs(move |p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
    }

    // ---------- fields ----------

    /// The prefs into the fields (at start).
    fn load_fields(&self) {
        let Some(ui) = self.ui() else { return };
        let p = self.prefs();
        let host = p.recent.first().cloned().unwrap_or_default();
        let (port, dur, rate, sport) = (p.port.to_string(), seconds_text(p.seconds), rate_field_text(p.bitrate), p.server_port.to_string());
        {
            let mut st = self.st.borrow_mut();
            st.host = host.clone();
            st.port = port.clone();
            st.duration = dur.clone();
            st.rate = rate.clone();
            st.server_port = sport.clone();
        }
        ui.set_host(s(&host));
        ui.set_port(s(&port));
        ui.set_duration(s(&dur));
        ui.set_bitrate(s(&rate));
        ui.set_server_port(s(&sport));
        ui.set_mode(if p.mode == "server" { 1 } else { 0 });
        ui.set_proto(if p.proto == "udp" { 1 } else { 0 });
        ui.set_direction(match p.direction.as_str() {
            "reverse" => 1,
            "both" => 2,
            _ => 0,
        });
        ui.set_streams(p.streams as i32 - 1);
        self.recent.set_vec(p.recent.iter().map(s).collect::<Vec<_>>());
    }

    /// A field was typed in: its error mark goes (the next Start checks it again).
    fn field_edited(&self) {
        let Some(ui) = self.ui() else { return };
        ui.set_host_invalid(false);
        ui.set_port_invalid(false);
        ui.set_duration_invalid(false);
        ui.set_bitrate_invalid(false);
        ui.set_server_port_invalid(false);
    }

    /// Escape in a field: its committed text back (true), or nothing to put back (false: the
    /// key goes on). 0 port, 1 time, 2 rate, 3 host, 4 server port.
    fn escape_field(&self, i: i32) -> bool {
        let Some(ui) = self.ui() else { return false };
        let st = self.st.borrow();
        let (now, was) = match i {
            0 => (ui.get_port(), st.port.clone()),
            1 => (ui.get_duration(), st.duration.clone()),
            2 => (ui.get_bitrate(), st.rate.clone()),
            3 => (ui.get_host(), st.host.clone()),
            _ => (ui.get_server_port(), st.server_port.clone()),
        };
        drop(st);
        if now.as_str() == was {
            return false;
        }
        match i {
            0 => ui.set_port(s(&was)),
            1 => ui.set_duration(s(&was)),
            2 => ui.set_bitrate(s(&was)),
            3 => ui.set_host(s(&was)),
            _ => ui.set_server_port(s(&was)),
        }
        self.field_edited();
        true
    }

    fn recent_picked(&self, i: i32) {
        let Some(ui) = self.ui() else { return };
        if let Some(h) = self.prefs().recent.get(i as usize).cloned() {
            ui.set_host(s(&h));
            ui.set_host_invalid(false);
        }
    }

    /// A Segmented or Select pick: 0 protocol, 1 direction, 2 streams.
    fn pick(&self, what: i32, i: i32) {
        let Some(ui) = self.ui() else { return };
        if self.st.borrow().test.is_some() {
            return;
        }
        match what {
            0 => {
                let udp = i == 1;
                ui.set_proto(i);
                self.save_prefs(move |p| p.proto = if udp { "udp" } else { "tcp" }.into());
            }
            1 => {
                let d = match i {
                    1 => "reverse",
                    2 => "both",
                    _ => "normal",
                };
                ui.set_direction(i);
                self.save_prefs(move |p| p.direction = d.into());
            }
            _ => {
                let n = (i + 1).clamp(1, crate::MAX_STREAMS as i32) as u32;
                ui.set_streams(n as i32 - 1);
                self.save_prefs(move |p| p.streams = n);
            }
        }
    }

    fn set_mode(&self, i: i32) {
        let Some(ui) = self.ui() else { return };
        ui.set_mode(i);
        let server = i == 1;
        self.save_prefs(move |p| p.mode = if server { "server" } else { "client" }.into());
        if server && self.st.borrow().reach_job.is_none() && self.reach.row_count() == 0 {
            self.load_reach();
        }
        self.refresh_all();
    }

    // ---------- the client ----------

    /// Start (Enter in a field, the button, the command line), or Stop while a test runs.
    pub fn start_clicked(&self) {
        let Some(ui) = self.ui() else { return };
        if let Some((_, c, _)) = &self.st.borrow().test {
            c.stop();
            return;
        }
        // Every field through its one normaliser; a bad one is marked and nothing starts.
        let target = netinfo::parse_target(ui.get_host().as_str());
        let port = netinfo::parse_port(ui.get_port().as_str());
        let secs = parse_seconds(ui.get_duration().as_str());
        let udp = ui.get_proto() == 1;
        let rate = if udp { parse_rate(ui.get_bitrate().as_str()).map(Some) } else { Ok(None) };
        ui.set_host_invalid(target.is_err());
        ui.set_port_invalid(port.is_err());
        ui.set_duration_invalid(secs.is_err());
        ui.set_bitrate_invalid(rate.is_err());
        let (target, port, secs, rate) = match (target, port, secs, rate) {
            (Ok(t), Ok(p), Ok(s), Ok(r)) => (t, p, s, r),
            (t, p, s, r) => {
                let why = [t.err(), p.err(), s.err(), r.err()].into_iter().flatten().next().unwrap_or_default();
                self.toast(&why, ToastKind::Error);
                return;
            }
        };
        // A port in the host ("nas:5202") wins over the field, and goes there.
        let port = target.port.unwrap_or(port);
        let host = target.text();
        let p = self.prefs();
        let rate = rate.unwrap_or(p.bitrate);
        let (dur_t, rate_t, port_t) = (seconds_text(secs), rate_field_text(rate), port.to_string());
        ui.set_host(s(&host));
        ui.set_port(s(&port_t));
        ui.set_duration(s(&dur_t));
        if udp {
            ui.set_bitrate(s(&rate_t));
        }
        let req = Request {
            target: netinfo::Target { port: None, ..target },
            port,
            proto: if udp { Proto::Udp } else { Proto::Tcp },
            direction: direction_of(&p),
            streams: p.streams,
            seconds: secs,
            bitrate: rate,
            window: 0,
            latency: true,
            udp64: false,
            record: None,
        };
        {
            let mut st = self.st.borrow_mut();
            st.host = host.clone();
            st.port = port_t;
            st.duration = dur_t;
            if udp {
                st.rate = rate_t;
            }
        }
        let h2 = host.clone();
        self.save_prefs(move |p| {
            p.remember(&h2);
            p.port = port;
            p.seconds = secs;
            if udp {
                p.bitrate = rate;
            }
        });
        let mut recent = self.prefs().recent;
        recent.truncate(crate::RECENT);
        self.recent.set_vec(recent.iter().map(s).collect::<Vec<_>>());
        let client = (self.svc.start_test)(req.clone());
        {
            let mut st = self.st.borrow_mut();
            st.test_epoch += 1;
            let e = st.test_epoch;
            st.test = Some((e, client, req));
            st.test_seen = u64::MAX;
            st.live = None;
            st.selected = None;
        }
        ui.set_running(true);
        self.refresh_all();
        self.ensure_poll();
    }

    /// The running test's news: the live view, and at the end its record into the history.
    fn poll_test(&self) {
        let (epoch, live) = {
            let st = self.st.borrow();
            let Some((e, c, _)) = &st.test else { return };
            let l = c.live.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if l.seq == st.test_seen {
                return;
            }
            (*e, l)
        };
        // Only the newest test's news counts.
        if self.st.borrow().test_epoch != epoch {
            return;
        }
        let done = live.phase == Phase::Done;
        {
            let mut st = self.st.borrow_mut();
            st.test_seen = live.seq;
            st.live = Some(live.clone());
        }
        if done {
            self.st.borrow_mut().test = None;
            if let Some(ui) = self.ui() {
                ui.set_running(false);
            }
            if let Some(r) = live.record {
                if r.outcome.kind == "failed" {
                    self.toast(&format!("The test failed: {}", netinfo::clean(&r.outcome.reason)), ToastKind::Error);
                }
                self.add_run(r);
            }
        }
        self.refresh_all();
    }

    /// A finished test to the front of the history (this window at once, the file by its
    /// thread), and on screen.
    fn add_run(&self, r: RunRecord) {
        let id = r.id.clone();
        {
            let mut st = self.st.borrow_mut();
            let mut h = history::History { version: 1, runs: std::mem::take(&mut st.runs) };
            history::add(&mut h, r.clone());
            st.runs = h.runs;
            st.selected = Some(id);
            st.label = String::new();
        }
        self.history_change(Arc::new(move |h: &mut history::History| history::add(h, r.clone())));
    }

    fn history_change(&self, f: HistoryChange) {
        if let Some(tx) = self.history_tx.borrow().as_ref() {
            self.history_pending.fetch_add(1, Ordering::SeqCst);
            if tx.send(f).is_err() {
                self.history_pending.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    fn poll_history(&self) {
        let events: Vec<Event> = std::mem::take(&mut *self.history_events.lock().unwrap_or_else(|e| e.into_inner()));
        if events.is_empty() {
            return;
        }
        for e in events {
            match e {
                Event::Loaded(file) => {
                    let mut st = self.st.borrow_mut();
                    st.runs = history::merge(&file, &st.runs);
                    st.history_loaded = true;
                    st.history_note = String::new();
                }
                Event::Fresh => {
                    let mut st = self.st.borrow_mut();
                    st.history_loaded = true;
                    st.history_note = String::new();
                }
                Event::Garbled => {
                    self.st.borrow_mut().history_loaded = true;
                    self.toast("history.json could not be read: a new history starts, and the old file will be kept as history.json.broken.", ToastKind::Error);
                }
                Event::Blind(why) => {
                    let mut st = self.st.borrow_mut();
                    st.history_loaded = true;
                    st.history_note = format!("history.json cannot be read right now ({}): new tests are kept here and saved once it can be read.", netinfo::clean(&why));
                }
                Event::KeptAside => self.toast("history.json was damaged: it is kept as history.json.broken, and this window's history is saved in its place.", ToastKind::Error),
            }
        }
        self.refresh_all();
    }

    fn select_run(&self, id: Option<String>) {
        let label = {
            let mut st = self.st.borrow_mut();
            st.selected = id.clone();
            id.and_then(|i| st.runs.iter().find(|r| r.id == i).map(|r| r.label.clone())).unwrap_or_default()
        };
        self.st.borrow_mut().label = label;
        self.refresh_all();
        self.scroll_to_selected(false);
    }

    fn select_served(&self, id: Option<String>) {
        self.st.borrow_mut().served_selected = id;
        self.refresh_all();
        self.scroll_to_selected(true);
    }

    fn scroll_to_selected(&self, served: bool) {
        let Some(ui) = self.ui() else { return };
        let (idx, seq) = {
            let mut st = self.st.borrow_mut();
            let idx = if served {
                let sel = st.served_selected.clone();
                // The served list is newest first, like the history.
                sel.and_then(|k| st.served.iter().rev().position(|r| r.id == k))
            } else {
                let sel = st.selected.clone();
                sel.and_then(|k| st.runs.iter().position(|r| r.id == k))
            };
            let seq = if served {
                st.served_scroll_seq += 1;
                st.served_scroll_seq
            } else {
                st.scroll_seq += 1;
                st.scroll_seq
            };
            (idx, seq)
        };
        let Some(i) = idx else { return };
        if served {
            ui.set_served_scroll_to(i as i32);
            ui.set_served_scroll_seq(seq);
        } else {
            ui.set_history_scroll_to(i as i32);
            ui.set_history_scroll_seq(seq);
        }
    }

    /// Up/Down/Home/End in a list; Escape lets the selection go.
    fn list_key(&self, text: &str, served: bool) -> bool {
        let ids: Vec<String> = {
            let st = self.st.borrow();
            if served { st.served.iter().rev().map(|r| r.id.clone()).collect() } else { st.runs.iter().map(|r| r.id.clone()).collect() }
        };
        if ids.is_empty() {
            return false;
        }
        let sel = if served { self.st.borrow().served_selected.clone() } else { self.st.borrow().selected.clone() };
        let at = sel.as_ref().and_then(|k| ids.iter().position(|x| x == k));
        let n = ids.len();
        let to = if key_is(text, Key::Home) {
            0
        } else if key_is(text, Key::End) {
            n - 1
        } else if key_is(text, Key::UpArrow) {
            at.map_or(n - 1, |i| i.saturating_sub(1))
        } else if key_is(text, Key::DownArrow) {
            at.map_or(0, |i| (i + 1).min(n - 1))
        } else {
            return false;
        };
        if served {
            self.select_served(Some(ids[to].clone()));
        } else {
            self.select_run(Some(ids[to].clone()));
        }
        true
    }

    /// A double-click on a history row: that test's settings into the fields (the row stays
    /// selected); Start runs it again.
    fn repeat_settings(&self, id: &str) {
        let Some(ui) = self.ui() else { return };
        if self.st.borrow().test.is_some() {
            return;
        }
        let Some(r) = self.st.borrow().runs.iter().find(|r| r.id == id).cloned() else { return };
        let set = &r.settings;
        let (udp, dir, streams, secs, rate, port) = (set.is_udp(), set.direction.clone(), set.streams.clamp(1, crate::MAX_STREAMS), set.seconds.clamp(1, crate::MAX_SECONDS), set.bitrate, set.port);
        ui.set_host(s(netinfo::clean(&r.host)));
        ui.set_port(s(port.to_string()));
        ui.set_proto(if udp { 1 } else { 0 });
        ui.set_direction(match dir.as_str() {
            "reverse" => 1,
            "both" => 2,
            _ => 0,
        });
        ui.set_streams(streams as i32 - 1);
        ui.set_duration(s(seconds_text(secs)));
        if udp && rate > 0 {
            ui.set_bitrate(s(rate_field_text(rate)));
        }
        self.field_edited();
        self.save_prefs(move |p| {
            p.proto = if udp { "udp" } else { "tcp" }.into();
            p.direction = dir.clone();
            p.streams = streams;
        });
        self.toast("That test's settings are in the fields: Start runs it again.", ToastKind::Info);
    }

    fn label_commit(&self) {
        let Some(ui) = self.ui() else { return };
        let Some(id) = self.st.borrow().selected.clone() else { return };
        let label = history::clean_label(ui.get_run_label().as_str());
        if label == self.st.borrow().label {
            return;
        }
        {
            let mut st = self.st.borrow_mut();
            st.label = label.clone();
            if let Some(r) = st.runs.iter_mut().find(|r| r.id == id) {
                r.label = label.clone();
            }
        }
        let (i2, l2) = (id, label);
        self.history_change(Arc::new(move |h: &mut history::History| history::set_label(h, &i2, &l2)));
        self.refresh_lists();
    }

    fn label_escape(&self) -> bool {
        let Some(ui) = self.ui() else { return false };
        let was = self.st.borrow().label.clone();
        if ui.get_run_label().as_str() == was {
            return false;
        }
        ui.set_run_label(s(&was));
        true
    }

    /// The record on screen as one line or iperf3's text block.
    fn copy_shown(&self, block: bool) -> bool {
        let r = match self.shown() {
            Shown::Record(r) => r,
            _ => return false,
        };
        let text = if block { run::text_block(&r) } else { run::one_line(&r) };
        (self.svc.copy)(&text)
    }

    // ---------- the server ----------

    fn server_clicked(&self) {
        let Some(ui) = self.ui() else { return };
        if self.st.borrow().server.is_some() {
            self.stop_server();
            return;
        }
        if self.server_busy() {
            return;
        }
        match netinfo::parse_port(ui.get_server_port().as_str()) {
            Ok(p) => {
                ui.set_server_port_invalid(false);
                ui.set_server_port(s(p.to_string()));
                self.st.borrow_mut().server_port = p.to_string();
                self.save_prefs(move |x| x.server_port = p);
                self.start_server_flow(p);
            }
            Err(e) => {
                ui.set_server_port_invalid(true);
                self.toast(&e, ToastKind::Error);
            }
        }
    }

    fn server_busy(&self) -> bool {
        let st = self.st.borrow();
        st.fw_job.is_some() || st.helper_job.is_some() || st.consent.is_some() || st.stop_job.is_some() || st.clean_job.is_some()
    }

    /// Start server: first what the firewall says (a worker), then maybe the question. A
    /// server on loopback only (live checks) needs no rule.
    pub fn start_server_flow(&self, port: u16) {
        if self.svc.bind.is_loopback() && self.svc.bind != SERVER_BIND {
            self.st.borrow_mut().srv_epoch += 1;
            return self.launch_server(port, ("Serving on this computer only (loopback): no firewall rule needed.".into(), 0));
        }
        let check = self.svc.fw_check.clone();
        {
            let mut st = self.st.borrow_mut();
            st.srv_epoch += 1;
            let e = st.srv_epoch;
            st.fw_job = Some((e, port, spawn_job("vibeperf-fw-check", move || check(port))));
            st.note = ("Checking Windows Firewall…".into(), 0);
        }
        self.refresh_server_controls();
        self.ensure_poll();
    }

    fn poll_firewall(&self) {
        // The firewall's answer.
        let got = {
            let st = self.st.borrow();
            st.fw_job.as_ref().and_then(|(e, p, slot)| take(slot).map(|c| (*e, *p, c)))
        };
        if let Some((epoch, port, check)) = got {
            self.st.borrow_mut().fw_job = None;
            if self.st.borrow().srv_epoch == epoch {
                self.firewall_answer(epoch, port, check);
            }
        }
        // The helper's answer (after the UAC prompt).
        let got = {
            let st = self.st.borrow();
            st.helper_job.as_ref().and_then(|(e, p, slot)| take(slot).map(|r| (*e, *p, r)))
        };
        if let Some((epoch, port, r)) = got {
            self.st.borrow_mut().helper_job = None;
            if self.st.borrow().srv_epoch != epoch {
                // Asked for an older start: its rules go again at once.
                if let Ok(sess) = r {
                    spawn_job("vibeperf-fw-close", move || sess.close().map(|_| ()));
                }
            } else {
                match r {
                    Ok(sess) => {
                        let reply = sess.reply.clone();
                        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(sess);
                        let blocks = if reply.blocks_removed > 0 { format!("; {} block rule{} removed", reply.blocks_removed, if reply.blocks_removed == 1 { "" } else { "s" }) } else { String::new() };
                        let kept = std::mem::take(&mut self.st.borrow_mut().blocks_kept);
                        self.st.borrow_mut().stale = 0;
                        let note = if kept > 0 {
                            (format!("Firewall: inbound TCP and UDP {port} allowed from the local subnet while serving, but the {kept} block rule{} for VibePerf {} kept, and a block rule wins: other PCs may still be refused.", if kept == 1 { "" } else { "s" }, if kept == 1 { "was" } else { "were" }), 2)
                        } else {
                            (format!("Firewall: inbound TCP and UDP {port} open to the local subnet while serving{blocks}."), 1)
                        };
                        self.launch_server(port, note);
                    }
                    Err(Launch::Declined) => self.set_note("Client only. Another PC can still serve; or run the server where you have admin.", 2),
                    Err(Launch::Failed(e)) => {
                        let e = netinfo::clean(&e);
                        self.toast(&format!("The firewall could not be opened: {e}"), ToastKind::Error);
                        self.set_note(&format!("The firewall could not be opened: {e}"), 3);
                    }
                }
            }
        }
        // Stopped: the server down and its rules gone.
        let got = self.st.borrow().stop_job.as_ref().and_then(take);
        if let Some(words) = got {
            self.st.borrow_mut().stop_job = None;
            self.set_note(&words, 0);
        }
        // The rules left from before, removed (or not).
        let got = self.st.borrow().clean_job.as_ref().and_then(take);
        if let Some(r) = got {
            self.st.borrow_mut().clean_job = None;
            match r {
                Ok(reply) => {
                    self.st.borrow_mut().stale = 0;
                    self.set_note(&format!("Removed {} firewall rule{} left from before.", reply.removed, if reply.removed == 1 { "" } else { "s" }), 1);
                }
                Err(e) => self.set_note(&netinfo::clean(&e), 2),
            }
        }
        let got = self.st.borrow().stale_job.as_ref().and_then(take);
        if let Some(n) = got {
            let mut st = self.st.borrow_mut();
            st.stale_job = None;
            st.stale = n;
        }
        let got = self.st.borrow().reach_job.as_ref().and_then(take);
        if let Some(locals) = got {
            self.st.borrow_mut().reach_job = None;
            self.reach.set_vec(locals.iter().map(|l| ReachLine { addr: s(l.ip.to_string()), adapter: s(&l.adapter) }).collect::<Vec<_>>());
            self.refresh_server_controls();
        }
    }

    fn firewall_answer(&self, epoch: u64, port: u16, c: FwCheck) {
        match &c.status {
            Ok(st) if !st.enabled => return self.launch_server(port, ("Windows Firewall is off on this network: no rule needed.".into(), 0)),
            Ok(st) if st.block_all => {
                return self.launch_server(port, ("Windows Firewall blocks all incoming connections on this network (Windows Security > Firewall): other PCs cannot reach this server.".into(), 2));
            }
            Ok(_) if c.allowed && c.blocks.is_empty() => return self.launch_server(port, ("An allow rule for VibePerf is already in place.".into(), 0)),
            _ => {}
        }
        let profiles = c.status.as_ref().map(|s| s.profiles.clone()).unwrap_or_default();
        let on = if profiles.is_empty() { "Windows Firewall is on".to_string() } else { format!("Windows Firewall is on for this network ({profiles})") };
        let blocks = block_list(&c.blocks);
        let unknown = if c.status.is_err() { "Windows Firewall's state could not be read. ".to_string() } else { String::new() };
        let body = format!("{unknown}{on}: other PCs cannot reach the server without a rule. VibePerf adds two inbound rules, TCP and UDP {port}, for VibePerf.exe only and from your local subnet only (on any kind of network, public Wi-Fi too), and removes them when the server stops or VibePerf closes.{blocks}");
        self.st.borrow_mut().consent = Some((epoch, port, c.blocks.len()));
        if let Some(ui) = self.ui() {
            ui.set_fw_body(s(&body));
            ui.set_fw_has_blocks(!c.blocks.is_empty());
            // Off unless the user ticks it: a block rule may be someone's deliberate choice.
            ui.set_fw_remove_blocks(false);
            ui.set_fw_open(true);
        }
        self.set_note("", 0);
    }

    fn fw_continue(&self) {
        let Some(ui) = self.ui() else { return };
        let Some((epoch, port, listed)) = self.st.borrow_mut().consent.take() else { return };
        let remove_blocks = ui.get_fw_has_blocks() && ui.get_fw_remove_blocks();
        self.st.borrow_mut().blocks_kept = if remove_blocks { 0 } else { listed };
        ui.set_fw_open(false);
        let (launcher, exe) = (self.svc.launcher.clone(), self.svc.exe.clone());
        let req = helper::Request { op: "open".into(), port, remove_blocks };
        self.st.borrow_mut().helper_job = Some((epoch, port, spawn_job("vibeperf-fw-helper", move || helper::start(&*launcher, &exe, &req))));
        self.set_note("Waiting for Windows' permission…", 0);
        self.ensure_poll();
    }

    fn fw_cancel(&self) {
        self.st.borrow_mut().consent = None;
        if let Some(ui) = self.ui() {
            ui.set_fw_open(false);
        }
        self.set_note("", 0);
    }

    fn launch_server(&self, port: u16, note: (String, i32)) {
        let srv = (self.svc.start_server)(server::Opts { bind: self.svc.bind, port, record: None });
        {
            let mut st = self.st.borrow_mut();
            st.server = Some(srv);
            st.server_seen = u64::MAX;
            st.serving_port = port;
            st.note = note;
        }
        self.load_reach();
        self.refresh_all();
        self.ensure_poll();
    }

    fn load_reach(&self) {
        let locals = self.svc.locals.clone();
        self.st.borrow_mut().reach_job = Some(spawn_job("vibeperf-reach", move || locals()));
        self.ensure_poll();
    }

    /// Stop server: down at once in the window; the listener and the firewall rules go on a
    /// worker (the helper's answer can take a moment).
    fn stop_server(&self) {
        let Some(srv) = self.st.borrow_mut().server.take() else { return };
        let session = self.session.clone();
        let job = spawn_job("vibeperf-stop", move || {
            srv.shutdown();
            match session.lock().unwrap_or_else(|e| e.into_inner()).take() {
                Some(s) => match s.close() {
                    Ok(r) => stopped_note(r.removed),
                    Err(e) => format!("Stopped. The firewall helper did not answer ({}): its rules go when it notices VibePerf left, or at the next Start server.", netinfo::clean(&e)),
                },
                None => "Stopped.".into(),
            }
        });
        {
            let mut st = self.st.borrow_mut();
            st.stop_job = Some(job);
            st.current = None;
            st.note = ("Stopping…".into(), 0);
        }
        self.refresh_all();
        self.ensure_poll();
    }

    /// "Remove" next to the note: VibePerf's rules left from before, through the helper.
    fn clean_stale(&self) {
        if self.server_busy() {
            return;
        }
        let (launcher, exe) = (self.svc.launcher.clone(), self.svc.exe.clone());
        let job = spawn_job("vibeperf-fw-clean", move || match helper::start(&*launcher, &exe, &helper::Request { op: "clean".into(), port: 0, remove_blocks: false }) {
            Ok(s) => Ok(s.reply.clone()),
            Err(Launch::Declined) => Err("Declined: the rule stays (it lets nothing in while VibePerf does not listen).".into()),
            Err(Launch::Failed(e)) => Err(e),
        });
        self.st.borrow_mut().clean_job = Some(job);
        self.set_note("Waiting for Windows' permission…", 0);
        self.ensure_poll();
    }

    fn poll_server(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(srv) = &st.server else { return };
            let l = srv.live.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if l.seq == st.server_seen { None } else { Some(l) }
        };
        // The helper ended from outside while serving.
        let helper_gone = {
            let mut g = self.session.lock().unwrap_or_else(|e| e.into_inner());
            if g.as_ref().is_some_and(|s| !s.alive()) {
                g.take();
                true
            } else {
                false
            }
        };
        if helper_gone {
            self.set_note("The firewall helper stopped: other PCs may not reach this server, and its rules may stay until the next Start server.", 2);
        }
        let Some(l) = got else { return };
        let mut new_runs = false;
        {
            let mut st = self.st.borrow_mut();
            st.server_seen = l.seq;
            st.current = l.current.clone();
            if st.served.len() != l.log.len() || st.served.last().map(|r| &r.id) != l.log.last().map(|r| &r.id) {
                new_runs = l.log.len() > st.served.len();
                st.served = l.log.clone();
            }
        }
        if new_runs && self.st.borrow().current.is_none() {
            // The newest served test on screen, unless the user picked one.
            let newest = self.st.borrow().served.last().map(|r| r.id.clone());
            let picked = self.st.borrow().served_selected.clone();
            if picked.is_none() || picked == self.st.borrow().served.iter().rev().nth(1).map(|r| r.id.clone()) {
                self.st.borrow_mut().served_selected = newest;
            }
        }
        if let Some(e) = l.error {
            // It could not listen: no server, and its rules go.
            self.st.borrow_mut().server = None;
            let session = self.session.clone();
            spawn_job("vibeperf-fw-close", move || session.lock().unwrap_or_else(|e| e.into_inner()).take().map(|s| s.close().map(|_| ())));
            self.toast(&e, ToastKind::Error);
            self.set_note(&e, 3);
            return;
        }
        self.refresh_all();
    }

    fn set_note(&self, text: &str, state: i32) {
        self.st.borrow_mut().note = (text.to_string(), state);
        self.refresh_server_controls();
    }

    // ---------- polling ----------

    fn needs_poll(&self) -> bool {
        let st = self.st.borrow();
        st.test.is_some()
            || st.server.is_some()
            || st.fw_job.is_some()
            || st.helper_job.is_some()
            || st.stop_job.is_some()
            || st.clean_job.is_some()
            || st.stale_job.is_some()
            || st.reach_job.is_some()
            || !st.history_loaded
            || !st.history_note.is_empty()
    }

    fn ensure_poll(&self) {
        if self.timer.running() || !self.needs_poll() {
            return;
        }
        let w = self.me.borrow().clone();
        self.timer.start(TimerMode::Repeated, Duration::from_millis(POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll();
            }
        });
    }

    /// One look at everything that runs (also called by the tests).
    pub fn poll(&self) {
        self.poll_history();
        self.poll_test();
        self.poll_firewall();
        self.poll_server();
        if !self.needs_poll() {
            self.timer.stop();
        }
    }

    // ---------- the view ----------

    fn shown(&self) -> Shown {
        let st = self.st.borrow();
        let server = st.prefs.mode == "server";
        if server {
            if let Some((who, settings, live)) = &st.current {
                return Shown::Live { live: Box::new(live.clone()), kind: settings.kind(), host: who.clone(), seconds: settings.seconds, udp: settings.is_udp() };
            }
            if let Some(r) = st.served_selected.as_ref().and_then(|k| st.served.iter().find(|r| &r.id == k)) {
                return Shown::Record(Box::new(r.clone()));
            }
            return Shown::Nothing;
        }
        if let Some((_, _, req)) = &st.test {
            let live = st.live.clone().unwrap_or_default();
            return Shown::Live { live: Box::new(live), kind: req.settings().kind(), host: req.target.text(), seconds: req.seconds, udp: req.proto == Proto::Udp };
        }
        if let Some(r) = st.selected.as_ref().and_then(|k| st.runs.iter().find(|r| &r.id == k)) {
            return Shown::Record(Box::new(r.clone()));
        }
        Shown::Nothing
    }

    fn refresh_all(&self) {
        self.refresh_view();
        self.refresh_lists();
        self.refresh_server_controls();
        self.refresh_status();
    }

    fn chart_resized(&self, w: f32, h: f32) {
        if self.chart_size.get() != (w, h) {
            self.chart_size.set((w, h));
            self.refresh_view();
        }
    }

    fn refresh_view(&self) {
        let Some(ui) = self.ui() else { return };
        let shown = self.shown();
        let (w, h) = self.chart_size.get();
        let server = self.prefs().mode == "server";
        let (tiles, chart, rows, udp, title, outcome, done, label_shown, hints) = match &shown {
            Shown::Nothing => (Vec::new(), view::Chart::default(), Vec::new(), false, String::new(), (String::new(), 0), false, false, Vec::new()),
            Shown::Live { live, kind, host, seconds, udp } => {
                let ups = live.streams.iter().any(|s| s.up);
                let downs = live.streams.iter().any(|s| !s.up);
                let chart = view::chart(&live.series, *seconds, w, h, ups || !downs, downs, true);
                let phase = match live.phase {
                    Phase::Resolving => "looking up the name…".to_string(),
                    Phase::Connecting => "connecting…".into(),
                    Phase::Pinging => "measuring idle latency…".into(),
                    Phase::Starting => "opening the streams…".into(),
                    Phase::Running => format!("{} s of {seconds}", live.elapsed.floor() as u64),
                    Phase::Finishing | Phase::Done => "finishing…".into(),
                };
                let title = if server { format!("Serving {} · {kind}", netinfo::clean(host)) } else { format!("Testing {} · {kind}", netinfo::clean(host)) };
                (view::live_tiles(live, *udp, server), chart, live.streams.clone(), *udp, title, (phase, 0), false, false, Vec::new())
            }
            Shown::Record(r) => {
                let ups = r.dirs.iter().any(|d| d.up);
                let downs = r.dirs.iter().any(|d| !d.up);
                let mut chart = view::chart(&r.series, r.settings.seconds, w, h, ups || !downs, downs, true);
                if r.series.is_empty() {
                    chart.empty = "No seconds measured".into();
                }
                let hints: Vec<String> = r.hints.iter().map(|h| netinfo::clean(h)).collect();
                (view::record_tiles(r, server), chart, r.streams.clone(), r.settings.is_udp(), view::run_title(r), view::outcome(r), true, !server, hints)
            }
        };
        self.tiles.set_vec(tiles.into_iter().map(|t| TileInfo { shown: true, caption: s(t.caption), value: s(t.value), sub: s(t.sub), state: t.state, tip: s(t.tip) }).collect::<Vec<_>>());
        ui.set_chart(ChartInfo {
            grid: s(chart.grid),
            up: s(chart.up),
            down: s(chart.down),
            y_top: s(chart.y_top),
            y_mid: s(chart.y_mid),
            y_top_at: chart.y_top_at,
            y_mid_at: chart.y_mid_at,
            x_left: s(chart.x_left),
            x_right: s(chart.x_right),
            empty: s(chart.empty),
            legend_up: s(chart.legend_up),
            legend_down: s(chart.legend_down),
            a11y: s(chart.a11y),
        });
        let heads = view::stream_heads(udp);
        ui.set_head_a(s(heads[0]));
        ui.set_head_b(s(heads[1]));
        ui.set_head_c(s(heads[2]));
        self.streams.set_vec(
            rows.iter()
                .map(|r| {
                    let t = view::stream_text(r, udp);
                    StreamLine { id: s(t.id), dir: s(t.dir), bytes: s(t.bytes), rate: s(t.rate), col_a: s(t.a), col_b: s(t.b), col_c: s(t.c), a11y: s(t.a11y) }
                })
                .collect::<Vec<_>>(),
        );
        self.hints.set_vec(hints.iter().map(s).collect::<Vec<_>>());
        ui.set_run_title(s(&title));
        ui.set_run_outcome(s(&outcome.0));
        ui.set_run_outcome_state(outcome.1);
        ui.set_run_done(done);
        ui.set_run_label_shown(label_shown);
        // The label field gets the kept label only when another test comes on screen: a poll
        // (the server running behind) must not wipe what is being typed.
        let id = match &shown {
            Shown::Record(r) => Some(r.id.clone()),
            _ => None,
        };
        let changed = self.st.borrow().shown_id != id;
        if changed {
            let label = self.st.borrow().label.clone();
            self.st.borrow_mut().shown_id = id;
            ui.set_run_label(s(&label));
        }
        // Before any test: what to do.
        if server {
            ui.set_hint_before(s(""));
            ui.set_hint_key(s(""));
            ui.set_hint_after(s(""));
        } else {
            ui.set_hint_before(s("Type a host running iperf3 -s (or VibePerf's server) and press"));
            ui.set_hint_key(s("Enter"));
            ui.set_hint_after(s("to measure what the network carries, with latency under load."));
        }
    }

    fn refresh_lists(&self) {
        let Some(ui) = self.ui() else { return };
        let now = self.now();
        let st = self.st.borrow();
        let sel = st.selected.clone();
        let rows: Vec<RunLine> = st
            .runs
            .iter()
            .map(|r| {
                let t = view::history_row(r, now);
                RunLine { selected: sel.as_deref() == Some(&t.id), id: s(t.id), time: s(t.time), title: s(t.title), line: s(t.line), state: t.state, a11y: s(t.a11y) }
            })
            .collect();
        let count = if st.runs.is_empty() { String::new() } else { st.runs.len().to_string() };
        let empty = if st.history_loaded { "Every test you run is kept here: its numbers, its graph, your label for it." } else { "Reading the history…" };
        let note = st.history_note.clone();
        let ssel = st.served_selected.clone();
        let served: Vec<RunLine> = st
            .served
            .iter()
            .rev()
            .map(|r| {
                let t = view::served_row(r, now);
                RunLine { selected: ssel.as_deref() == Some(&t.id), id: s(t.id), time: s(t.time), title: s(t.title), line: s(t.line), state: t.state, a11y: s(t.a11y) }
            })
            .collect();
        let scount = if st.served.is_empty() { String::new() } else { st.served.len().to_string() };
        drop(st);
        self.history_rows.set_vec(rows);
        self.served_rows.set_vec(served);
        ui.set_history_count(s(count));
        ui.set_history_empty(s(empty));
        ui.set_history_note(s(note));
        ui.set_served_count(s(scount));
    }

    fn refresh_server_controls(&self) {
        let Some(ui) = self.ui() else { return };
        let busy = self.server_busy();
        let st = self.st.borrow();
        let serving = st.server.is_some();
        let (mut note, mut state) = st.note.clone();
        let mut action = String::new();
        if note.is_empty() && st.stale > 0 && !serving {
            let one = st.stale == 1;
            note = format!(
                "{} firewall rule{} from an earlier VibePerf {} still there ({} nothing in while VibePerf does not listen).",
                st.stale,
                if one { "" } else { "s" },
                if one { "is" } else { "are" },
                if one { "it lets" } else { "they let" }
            );
            state = 2;
            action = "Remove".into();
        }
        let button = if serving {
            "Stop server"
        } else if st.helper_job.is_some() || st.clean_job.is_some() {
            "Waiting for Windows…"
        } else if st.fw_job.is_some() {
            "Checking…"
        } else if st.stop_job.is_some() {
            "Stopping…"
        } else {
            "Start server"
        };
        let port = st.serving_port;
        let first = self.reach.row_data(0).map(|r| r.addr.to_string());
        drop(st);
        ui.set_serving(serving);
        ui.set_server_busy(busy && !serving);
        ui.set_server_button(s(button));
        ui.set_server_note(s(netinfo::clean(&note)));
        ui.set_server_note_state(state);
        ui.set_server_note_action(s(action));
        ui.set_reach_empty(s(if self.st.borrow().reach_job.is_some() { "Reading this computer's addresses…" } else { "No network adapter is up." }));
        if serving {
            ui.set_server_hint(s("Serving. On another computer, run iperf3 or VibePerf against this one:"));
            let host = first.unwrap_or_else(|| "this-pc".into());
            let host = if host.contains(':') { format!("[{host}]") } else { host };
            let p = if port == crate::proto::DEFAULT_PORT { String::new() } else { format!(" -p {port}") };
            ui.set_server_command(s(format!("iperf3 -c {host}{p}")));
        } else {
            ui.set_server_hint(s("Start the server to let another computer test against this one: iperf3 clients and VibePerf's own, TCP and UDP, one test at a time."));
            ui.set_server_command(s(""));
        }
    }

    fn refresh_status(&self) {
        let Some(ui) = self.ui() else { return };
        let st = self.st.borrow();
        let server_mode = st.prefs.mode == "server";
        let (left, right) = if server_mode {
            match (&st.server, &st.current) {
                (Some(_), Some((who, set, live))) => (format!("Serving {} · {} · {} s of {}", netinfo::clean(who), set.kind(), live.elapsed.floor() as u64, set.seconds), live.link.clone()),
                (Some(_), None) => (format!("Serving on port {} · {} test{} served", st.serving_port, st.served.len(), if st.served.len() == 1 { "" } else { "s" }), String::new()),
                (None, _) => ("Server stopped".into(), String::new()),
            }
        } else if let Some((_, _, req)) = &st.test {
            let live = st.live.clone().unwrap_or_default();
            let addr = if live.addr.is_empty() { format!("{}:{}", req.target.text(), req.port) } else { live.addr.clone() };
            let set = req.settings();
            let mut kind = set.kind();
            kind = kind.rsplit_once(" · ").map(|(a, _)| a.to_string()).unwrap_or(kind);
            let when = match live.phase {
                Phase::Running => format!("{} s of {}", live.elapsed.floor() as u64, req.seconds),
                Phase::Resolving => "looking up the name".into(),
                Phase::Connecting => "connecting".into(),
                Phase::Pinging => "measuring idle latency".into(),
                Phase::Starting => "opening the streams".into(),
                Phase::Finishing | Phase::Done => "exchanging results".into(),
            };
            (format!("{kind} · {when} · {}", netinfo::clean(&addr)), live.link.clone())
        } else {
            let n = st.runs.len();
            (if n == 0 { "Ready".to_string() } else { format!("Ready · {n} test{} in the history", if n == 1 { "" } else { "s" }) }, String::new())
        };
        drop(st);
        ui.set_status_left(s(left));
        ui.set_status_right(s(netinfo::clean(&right)));
    }

    // ---------- the command line ----------

    /// `VibePerf.exe <host>` fills the client; `VibePerf.exe --server` starts serving.
    pub fn command_line(&self, args: &[String]) {
        let Some(ui) = self.ui() else { return };
        if args.iter().any(|a| a == "--server") {
            self.set_mode(1);
            let port = self.prefs().server_port;
            self.start_server_flow(port);
            return;
        }
        if let Some(a) = args.first() {
            match netinfo::parse_target(a) {
                Ok(t) => {
                    if self.prefs().mode != "client" {
                        self.set_mode(0);
                    }
                    ui.set_host(s(t.text()));
                    if let Some(p) = t.port {
                        ui.set_port(s(p.to_string()));
                    }
                }
                Err(e) => self.toast(&format!("The command line's host: {e}"), ToastKind::Error),
            }
        }
    }

    // ---------- toasts ----------

    /// A toast, bottom right: errors stay 10 s, the rest 5 s.
    pub fn toast(&self, text: &str, kind: ToastKind) {
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            st.toast_seq
        };
        while self.toasts.row_count() >= 3 {
            let old = self.toasts.row_data(0).map(|t| t.id).unwrap_or(0);
            self.drop_toast(old);
        }
        self.toasts.push(ToastItem { id, text: s(netinfo::clean(text)), kind, action: s("") });
        self.arm_toast(id, if kind == ToastKind::Error { 10_000 } else { 5_000 });
    }

    /// A toast's timer, `ms` from now. Only its newest timer counts, and while a dialog is open
    /// it waits: the toast is in sight but out of reach there (`dialogs_closed` gives it its
    /// full time again).
    fn arm_toast(&self, id: i32, ms: u64) {
        let generation = {
            let mut st = self.st.borrow_mut();
            let t = st.toast_time.entry(id).or_insert((0, ms));
            t.0 += 1;
            t.0
        };
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(ms), move || {
            let Some(a) = w.upgrade() else { return };
            let current = a.st.borrow().toast_time.get(&id).is_some_and(|t| t.0 == generation);
            let blocked = a.ui().is_some_and(|ui| ui.get_about_open() || ui.get_fw_open());
            if current && !blocked {
                a.drop_toast(id);
            }
        });
    }

    /// A dialog closed: every toast gets its full time again.
    fn dialogs_closed(&self) {
        let all: Vec<(i32, u64)> = self.st.borrow().toast_time.iter().map(|(id, t)| (*id, t.1)).collect();
        for (id, ms) in all {
            self.arm_toast(id, ms);
        }
    }

    fn drop_toast(&self, id: i32) {
        if let Some(i) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(i);
        }
        self.st.borrow_mut().toast_time.remove(&id);
    }

    /// VibePerf's rules left in the firewall (a helper killed, a power cut): read on a worker,
    /// told in server mode.
    pub fn check_stale_rules(&self) {
        let check = self.svc.stale_rules.clone();
        self.st.borrow_mut().stale_job = Some(spawn_job("vibeperf-stale", move || check()));
        self.ensure_poll();
    }

    // ---------- for the tests ----------

    /// Tests: the helper's end of the pipe goes, as when the helper is killed.
    #[doc(hidden)]
    pub fn disconnect_helper_for_tests(&self) {
        if let Some(s) = self.session.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            s.disconnect();
        }
    }

    /// Tests: a start-up worker (the history file, the stale-rules check, the addresses) has
    /// not answered yet, or its answer is not taken in yet.
    #[doc(hidden)]
    pub fn workers_pending_for_tests(&self) -> bool {
        let st = self.st.borrow();
        !st.history_loaded || st.stale_job.is_some() || st.reach_job.is_some()
    }

    /// The history as this window has it, newest first.
    pub fn runs(&self) -> Vec<RunRecord> {
        self.st.borrow().runs.clone()
    }

    pub fn has_session(&self) -> bool {
        self.session.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    pub fn serving(&self) -> bool {
        self.st.borrow().server.is_some()
    }
}
