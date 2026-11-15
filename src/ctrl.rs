//! The control connection of one test, either side: state bytes, the cookie, JSON messages,
//! each read with one deadline for the whole of it (and, where a person may be waiting, a way
//! to give up within 100 ms). Optionally records both directions' bytes (the transcripts in
//! tests/fixtures).

use crate::proto::{self, COOKIE_SIZE, ProtoError, State};
use crate::sock;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Both directions of a control conversation, as bytes.
#[derive(Clone, Debug, Default)]
pub struct Transcript {
    pub sent: Vec<u8>,
    pub got: Vec<u8>,
}

pub type Recorder = Arc<Mutex<Transcript>>;

pub struct Ctrl {
    s: TcpStream,
    log: Option<Recorder>,
}

/// How long a write to the control connection may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// The control connection as one message reads it: one deadline for the whole message, and
/// the stop looked at between reads (IN-VibePerf-1), so a peer that sends a byte now and then
/// holds nothing past either.
struct Logged<'a> {
    s: &'a mut TcpStream,
    log: &'a Option<Recorder>,
    until: Instant,
    cancel: Option<&'a AtomicBool>,
}

impl Read for Logged<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.cancel.is_some_and(|c| c.load(Ordering::SeqCst)) {
                // Not Interrupted: read_exact would try again.
                return Err(std::io::Error::other("stopped"));
            }
            let left = self.until.saturating_duration_since(Instant::now());
            if sock::wait_readable(&*self.s, left.min(sock::SLICE))? {
                // Urgent (out-of-band) data counts as readable too, with nothing to read: the
                // read waits at most a slice and never past the deadline, then the stop and the
                // deadline are looked at again (RIN1-12).
                let left = self.until.saturating_duration_since(Instant::now());
                let _ = self.s.set_read_timeout(Some(left.min(sock::SLICE).max(Duration::from_millis(1))));
                match self.s.read(buf) {
                    Ok(n) => {
                        if let Some(l) = self.log {
                            l.lock().unwrap_or_else(|e| e.into_inner()).got.extend_from_slice(&buf[..n]);
                        }
                        return Ok(n);
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                    Err(e) => return Err(e),
                }
            }
            if self.until <= Instant::now() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
        }
    }
}

impl Ctrl {
    pub fn new(s: TcpStream, log: Option<Recorder>) -> Ctrl {
        // Control messages are tiny and wait for each other: no Nagle delay (as iperf3).
        let _ = s.set_nodelay(true);
        let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
        Ctrl { s, log }
    }

    pub fn stream(&self) -> &TcpStream {
        &self.s
    }

    pub fn send(&mut self, b: &[u8]) -> Result<(), ProtoError> {
        self.s.write_all(b).map_err(ProtoError::from_io)?;
        if let Some(l) = &self.log {
            l.lock().unwrap_or_else(|e| e.into_inner()).sent.extend_from_slice(b);
        }
        Ok(())
    }

    pub fn send_state(&mut self, s: State) -> Result<(), ProtoError> {
        self.send(&[s.byte()])
    }

    pub fn send_json(&mut self, v: &Value) -> Result<(), ProtoError> {
        self.send(&proto::frame_json(v))
    }

    /// Wait until something can be read, at most `timeout`; with `cancel`, give up within 100 ms
    /// of it being set. Ok(false): nothing yet.
    pub fn wait(&self, timeout: Duration, cancel: Option<&AtomicBool>) -> Result<bool, ProtoError> {
        let start = Instant::now();
        loop {
            if cancel.is_some_and(|c| c.load(Ordering::SeqCst)) {
                return Err(ProtoError::Cancelled);
            }
            let left = timeout.saturating_sub(start.elapsed());
            if sock::wait_readable(&self.s, left.min(sock::SLICE)).map_err(ProtoError::from_io)? {
                return Ok(true);
            }
            if start.elapsed() >= timeout {
                return Ok(false);
            }
        }
    }

    /// One message, all of it within `timeout` (waiting for its first byte included); with
    /// `cancel`, given up within 100 ms of it being set.
    fn read_msg<T>(&mut self, timeout: Duration, cancel: Option<&AtomicBool>, f: impl FnOnce(&mut Logged<'_>) -> Result<T, ProtoError>) -> Result<T, ProtoError> {
        let _ = self.s.set_read_timeout(Some(timeout.max(Duration::from_millis(1))));
        let mut r = Logged { s: &mut self.s, log: &self.log, until: Instant::now() + timeout, cancel };
        f(&mut r).map_err(|e| if cancel.is_some_and(|c| c.load(Ordering::SeqCst)) { ProtoError::Cancelled } else { e })
    }

    /// The next state byte, within `timeout`.
    pub fn state(&mut self, timeout: Duration, cancel: Option<&AtomicBool>) -> Result<State, ProtoError> {
        self.read_msg(timeout, cancel, |r| proto::read_state(r))
    }

    /// The next JSON message, of at most `max` bytes, all of it within `timeout`.
    pub fn json(&mut self, max: usize, timeout: Duration, cancel: Option<&AtomicBool>) -> Result<Value, ProtoError> {
        self.read_msg(timeout, cancel, |r| proto::read_json(r, max))
    }

    pub fn codes(&mut self) -> Result<(i32, i32), ProtoError> {
        self.read_msg(Duration::from_secs(5), None, |r| proto::read_error_codes(r))
    }

    pub fn cookie(&mut self, timeout: Duration, cancel: Option<&AtomicBool>) -> Result<[u8; COOKIE_SIZE], ProtoError> {
        self.read_msg(timeout, cancel, |r| {
            let mut c = [0u8; COOKIE_SIZE];
            r.read_exact(&mut c).map_err(ProtoError::from_io)?;
            Ok(c)
        })
    }

    /// After a last word the peer must still read (a refusal): wait for the peer to close
    /// first, reading and dropping what it sends, at most `limit` or until `cancel`. The
    /// connection then closes with a reset (no TIME_WAIT on the port), and a reset that comes
    /// before the peer has read the last word would destroy it.
    pub fn await_close(&mut self, limit: Duration, cancel: &AtomicBool) {
        let until = Instant::now() + limit;
        let mut b = [0u8; 4096];
        while Instant::now() < until && !cancel.load(Ordering::SeqCst) {
            match sock::wait_readable(&self.s, sock::SLICE.min(until.saturating_duration_since(Instant::now()))) {
                Ok(true) => match self.s.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                },
                Ok(false) => {}
                Err(_) => return,
            }
        }
    }

    /// Whether the peer has closed (or reset) the connection, without waiting.
    pub fn closed(&mut self) -> bool {
        match sock::wait_readable(&self.s, Duration::ZERO) {
            Ok(true) => {
                let mut b = [0u8; 1];
                matches!(self.s.peek(&mut b), Ok(0) | Err(_))
            }
            Ok(false) => false,
            Err(_) => true,
        }
    }
}
