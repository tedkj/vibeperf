//! Every finished test, kept (`%LOCALAPPDATA%\com.tedkj.vibeperf\history.json`): the last 200,
//! newest first, each with its settings, summary, per-second series and your label. It follows
//! the prefs rules (it is prefs.json's sibling, through the same `Store`): changes are kept as
//! changes and put onto the file as read right before each write (another VibePerf's runs
//! stay); a file that cannot be read right now is never written ("start blind", read again
//! every 10 s); a garbled one is kept aside as history.json.broken and the user is told.

use crate::prefs::{Change, Loaded, Store};
use crate::run::RunRecord;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Runs kept.
pub const MAX_RUNS: usize = 200;
/// A label is at most this long.
pub const MAX_LABEL: usize = 80;
/// While the file cannot be read, how often it is tried again.
pub const RETRY: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct History {
    pub version: u32,
    /// Newest first.
    pub runs: Vec<RunRecord>,
}

/// A run to the front (once by id), the oldest beyond 200 gone.
pub fn add(h: &mut History, r: RunRecord) {
    h.version = 1;
    h.runs.retain(|x| x.id != r.id);
    h.runs.insert(0, r);
    h.runs.truncate(MAX_RUNS);
}

/// Your label as it is kept: no control characters, trimmed, at most 80 characters. Your own
/// text: the marks right-to-left text and emoji need stay (they are stripped when shown).
pub fn clean_label(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).take(MAX_LABEL).collect();
    s.trim().to_string()
}

pub fn set_label(h: &mut History, id: &str, label: &str) {
    if let Some(r) = h.runs.iter_mut().find(|r| r.id == id) {
        r.label = clean_label(label);
    }
}

/// Runs from two sources (the file read late, this window's own since): newest first, each
/// once (the file's copy wins: it already carries this window's changes once written).
pub fn merge(file: &[RunRecord], mine: &[RunRecord]) -> Vec<RunRecord> {
    let mut all: Vec<RunRecord> = file.to_vec();
    for r in mine {
        if !all.iter().any(|x| x.id == r.id) {
            all.push(r.clone());
        }
    }
    // Newest first, a total order (time, then id).
    all.sort_by(|a, b| b.time.cmp(&a.time).then_with(|| a.id.cmp(&b.id)));
    all.truncate(MAX_RUNS);
    all
}

/// What the history thread tells the window.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// The file as read (at start, or once a file that could not be read can be).
    Loaded(Vec<RunRecord>),
    /// No file yet.
    Fresh,
    /// The file does not parse: it will be kept as history.json.broken.
    Garbled,
    /// It cannot be read right now (the system's words); tried again every 10 s.
    Blind(String),
    /// A file that went bad while the window was open was kept aside and replaced.
    KeptAside,
}

pub type HistoryChange = Change<History>;

/// The history's thread: loads the file, then writes each change onto the newest file, in
/// order; while the file cannot be read it tries again every 10 s. Its news lands in `events`
/// (the window polls it).
pub fn thread(path: PathBuf, events: Arc<Mutex<Vec<Event>>>, pending: Arc<std::sync::atomic::AtomicUsize>) -> (Sender<HistoryChange>, std::thread::JoinHandle<()>) {
    let (tx, rx) = channel::<HistoryChange>();
    let h = std::thread::Builder::new()
        .name("vibeperf-history".into())
        .spawn(move || run(Store::new(path), rx, events, pending))
        .expect("a thread");
    (tx, h)
}

fn tell(events: &Mutex<Vec<Event>>, e: Event) {
    events.lock().unwrap_or_else(|e| e.into_inner()).push(e);
}

fn run(store: Store<History>, rx: Receiver<HistoryChange>, events: Arc<Mutex<Vec<Event>>>, pending: Arc<std::sync::atomic::AtomicUsize>) {
    let mut blind = false;
    match store.try_load() {
        Loaded::Read(h) => tell(&events, Event::Loaded(h.runs)),
        Loaded::Missing => tell(&events, Event::Fresh),
        Loaded::Garbled => tell(&events, Event::Garbled),
        Loaded::Unreadable(e) => {
            blind = true;
            tell(&events, Event::Blind(e));
        }
    }
    loop {
        match rx.recv_timeout(if blind { RETRY } else { Duration::from_secs(3600) }) {
            Ok(f) => {
                store.change(f);
                pending.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                if store.take_garbled() {
                    tell(&events, Event::KeptAside);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if blind {
            match store.try_load() {
                Loaded::Read(h) => {
                    blind = false;
                    store.flush();
                    let now = match store.try_load() {
                        Loaded::Read(n) => n.runs,
                        _ => h.runs,
                    };
                    tell(&events, Event::Loaded(now));
                }
                Loaded::Missing => {
                    blind = false;
                    store.flush();
                    tell(&events, Event::Fresh);
                }
                Loaded::Garbled => {
                    blind = false;
                    tell(&events, Event::Garbled);
                }
                Loaded::Unreadable(_) => {}
            }
        }
    }
    store.flush();
}
