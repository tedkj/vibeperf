//! TCP streams: write or read `len`-byte blocks (iperf3's 128 KiB by default) as fast as the
//! connection takes them. The sockets are non-blocking with waits of at most 100 ms, so a
//! stream notices its stop flag in time even when the peer stopped reading or sending. No
//! buffer sizes are set here: Windows' auto-tuning decides (unless a peer asked, in `sock`).

use crate::meter::Counters;
use crate::sock;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long a sender may take to finish its last block after the stop.
const LAST_BLOCK: Duration = Duration::from_secs(2);

/// Write until `stop`, whole blocks only: a stop in the middle of a block finishes the block
/// first (iperf3 reads whole blocks, and a receiver left waiting for the rest of one would
/// never read its control connection again). Every byte the system took counts (as iperf3's
/// sender counts).
pub fn run_sender(mut s: TcpStream, len: u32, stop: Arc<AtomicBool>, c: Arc<Counters>) {
    if let Err(e) = s.set_nonblocking(true) {
        c.fail(format!("the socket did not switch to non-blocking ({e})"));
        return;
    }
    let w = s.try_clone();
    let mut wait = || {
        if let Ok(w) = &w {
            let _ = sock::wait_writable(w, sock::SLICE);
        }
    };
    send_blocks(&mut s, &mut wait, len, &stop, &c);
}

/// The sender's loop over any writer that may take a write in parts (`wait`: until it can take
/// more): whole blocks only, as `run_sender` promises.
pub fn send_blocks(w: &mut impl Write, wait: &mut dyn FnMut(), len: u32, stop: &AtomicBool, c: &Counters) {
    let len = len.max(1) as usize;
    let buf: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let mut off = 0;
    let mut stopped_at: Option<Instant> = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            let t = *stopped_at.get_or_insert_with(Instant::now);
            if off == 0 || t.elapsed() > LAST_BLOCK {
                return;
            }
        }
        match w.write(&buf[off..]) {
            Ok(0) => wait(),
            Ok(n) => {
                c.add_bytes(n as u64);
                off = (off + n) % len;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => wait(),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                if !stop.load(Ordering::Relaxed) {
                    c.fail(format!("sending failed: {e}"));
                }
                return;
            }
        }
    }
}

/// Read until `stop` or the peer closes, counting while `counting` is set. The peer closing is
/// recorded (`closed`): before the end it is a failure, after it the normal goodbye.
pub fn run_receiver(mut s: TcpStream, len: u32, stop: Arc<AtomicBool>, counting: Arc<AtomicBool>, c: Arc<Counters>) {
    let mut buf = vec![0u8; len.clamp(1, 1 << 20) as usize];
    if let Err(e) = s.set_nonblocking(true) {
        c.fail(format!("the socket did not switch to non-blocking ({e})"));
        return;
    }
    while !stop.load(Ordering::Relaxed) {
        match s.read(&mut buf) {
            Ok(0) => {
                c.closed.store(true, Ordering::SeqCst);
                return;
            }
            Ok(n) => {
                if counting.load(Ordering::Relaxed) {
                    c.add_bytes(n as u64);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                let _ = sock::wait_readable(&s, sock::SLICE);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                if !stop.load(Ordering::Relaxed) {
                    if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted) {
                        c.closed.store(true, Ordering::SeqCst);
                    }
                    c.fail(format!("receiving failed: {e}"));
                }
                return;
            }
        }
    }
}
