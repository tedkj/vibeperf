//! The sockets, set up the way the measurement needs them, through WinSock where std has no
//! word for it: dual-stack listeners with `SO_EXCLUSIVEADDRUSE`, connects that can be cancelled,
//! buffer sizes only when a peer asks for them (never by default: Windows' receive-window
//! auto-tuning and send-buffer autotuning do better than any fixed value), the UDP receive
//! buffer, and waits that never block a thread for more than a moment, so every worker can
//! notice a stop within 100 ms.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Networking::WinSock::*;

/// How long a worker waits for its socket before it looks at its stop flag again.
pub const SLICE: Duration = Duration::from_millis(100);

fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: WSAStartup with an out struct; std calls it too (it is reference counted).
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        unsafe { WSAStartup(0x0202, &mut data) };
    });
}

fn last_error() -> io::Error {
    // SAFETY: no arguments.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

/// A raw socket that closes itself unless handed on to a std type.
struct Raw(SOCKET);

impl Raw {
    fn new(family: i32, kind: i32, proto: i32) -> io::Result<Raw> {
        init();
        // SAFETY: plain arguments; the handle is closed by Drop (or owned by a std type later).
        let s = unsafe { WSASocketW(family, kind, proto, std::ptr::null(), 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT) };
        if s == INVALID_SOCKET { Err(last_error()) } else { Ok(Raw(s)) }
    }

    fn into_raw(self) -> RawSocket {
        let s = self.0;
        std::mem::forget(self);
        s as RawSocket
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: our own handle, closed once.
        unsafe { closesocket(self.0) };
    }
}

fn setopt<T>(s: SOCKET, level: i32, name: i32, value: T) -> io::Result<()> {
    // SAFETY: a value of the size we say, read during the call only.
    let r = unsafe { setsockopt(s, level, name, (&value as *const T).cast(), std::mem::size_of::<T>() as i32) };
    if r == 0 { Ok(()) } else { Err(last_error()) }
}

fn getopt_u32(s: SOCKET, level: i32, name: i32) -> io::Result<u32> {
    let mut v: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as i32;
    // SAFETY: an out value of the size we say.
    let r = unsafe { getsockopt(s, level, name, (&mut v as *mut u32).cast(), &mut len) };
    if r == 0 { Ok(v) } else { Err(last_error()) }
}

/// A socket address as WinSock takes it.
fn sockaddr(a: &SocketAddr) -> (SOCKADDR_INET, i32) {
    // SAFETY: a plain union, zeroed, then the family's fields set.
    let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match a {
        SocketAddr::V4(v4) => {
            s.Ipv4.sin_family = AF_INET;
            s.Ipv4.sin_port = v4.port().to_be();
            s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.ip().octets());
            (s, std::mem::size_of::<SOCKADDR_IN>() as i32)
        }
        SocketAddr::V6(v6) => {
            s.Ipv6.sin6_family = AF_INET6;
            s.Ipv6.sin6_port = v6.port().to_be();
            s.Ipv6.sin6_addr.u.Byte = v6.ip().octets();
            s.Ipv6.Anonymous.sin6_scope_id = v6.scope_id();
            s.Ipv6.sin6_flowinfo = v6.flowinfo();
            (s, std::mem::size_of::<SOCKADDR_IN6>() as i32)
        }
    }
}

fn family(a: &SocketAddr) -> i32 {
    if a.is_ipv6() { AF_INET6 as i32 } else { AF_INET as i32 }
}

fn bind_raw(s: SOCKET, a: &SocketAddr) -> io::Result<()> {
    let (sa, len) = sockaddr(a);
    // SAFETY: an address of `len` bytes.
    if unsafe { bind(s, (&sa as *const SOCKADDR_INET).cast(), len) } == 0 { Ok(()) } else { Err(last_error()) }
}

/// A socket of `kind` bound to `bind`:`port`, that no other program can take over
/// (`SO_EXCLUSIVEADDRUSE`). `::` is every address of this computer, IPv6 and IPv4 on one socket
/// (`IPV6_V6ONLY` off), falling back to IPv4's `0.0.0.0` where the system has no IPv6. (Tests
/// bind loopback only: a program listening on every address makes Windows Defender Firewall
/// ask the user about it.)
fn bound(bind: IpAddr, port: u16, kind: i32, proto: i32) -> io::Result<Raw> {
    let v6_any = bind == IpAddr::from([0u16; 8]);
    let first = Raw::new(if bind.is_ipv6() { AF_INET6 as i32 } else { AF_INET as i32 }, kind, proto);
    let (s, at) = match first {
        Ok(s) => (s, bind),
        Err(_) if v6_any => (Raw::new(AF_INET as i32, kind, proto)?, IpAddr::from([0u8; 4])),
        Err(e) => return Err(e),
    };
    if at.is_ipv6() {
        setopt(s.0, IPPROTO_IPV6, IPV6_V6ONLY, if v6_any { 0u32 } else { 1u32 })?;
    }
    setopt(s.0, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1u32)?;
    bind_raw(s.0, &SocketAddr::new(at, port))?;
    Ok(s)
}

/// The server's TCP listener (control connections and TCP data streams).
pub fn listen_tcp(bind: IpAddr, port: u16) -> io::Result<TcpListener> {
    let s = bound(bind, port, SOCK_STREAM, IPPROTO_TCP)?;
    // SAFETY: a bound socket of ours.
    if unsafe { listen(s.0, SOMAXCONN as i32) } != 0 {
        return Err(last_error());
    }
    // SAFETY: the handle goes to the listener, which closes it.
    Ok(unsafe { TcpListener::from_raw_socket(s.into_raw()) })
}

/// The server's UDP socket, with a receive buffer of `rcvbuf` bytes (UDP has no auto-tuning:
/// Windows' small default drops datagrams the network delivered and calls it loss).
pub fn bind_udp(bind: IpAddr, port: u16, rcvbuf: u32) -> io::Result<UdpSocket> {
    let s = bound(bind, port, SOCK_DGRAM, IPPROTO_UDP)?;
    setopt(s.0, SOL_SOCKET, SO_RCVBUF, rcvbuf)?;
    no_connreset(s.0);
    // SAFETY: the handle goes to the socket, which closes it.
    Ok(unsafe { UdpSocket::from_raw_socket(s.into_raw()) })
}

/// Windows reports an ICMP port-unreachable for an earlier datagram as an error on the next
/// receive (WSAECONNRESET) and so ends a UDP receive loop for nothing: switched off.
fn no_connreset(s: SOCKET) {
    let off: u32 = 0;
    let mut ret = 0u32;
    // SAFETY: a 4-byte input, no output.
    unsafe { WSAIoctl(s, SIO_UDP_CONNRESET, (&off as *const u32).cast(), 4, std::ptr::null_mut(), 0, &mut ret, std::ptr::null_mut(), None) };
}

/// Wait until `s` can be read (or accepted), at most `timeout`. Ok(false) when it cannot yet.
pub fn wait_readable(s: &impl AsRawSocket, timeout: Duration) -> io::Result<bool> {
    wait(s.as_raw_socket() as SOCKET, timeout, false)
}

pub fn wait_writable(s: &impl AsRawSocket, timeout: Duration) -> io::Result<bool> {
    wait(s.as_raw_socket() as SOCKET, timeout, true)
}

fn wait(s: SOCKET, timeout: Duration, write: bool) -> io::Result<bool> {
    let mut set = FD_SET { fd_count: 1, fd_array: [0; 64] };
    set.fd_array[0] = s;
    let mut ex = FD_SET { fd_count: 1, fd_array: [0; 64] };
    ex.fd_array[0] = s;
    let tv = TIMEVAL { tv_sec: timeout.as_secs() as i32, tv_usec: timeout.subsec_micros() as i32 };
    let (r, w) = if write { (std::ptr::null_mut(), &mut set as *mut FD_SET) } else { (&mut set as *mut FD_SET, std::ptr::null_mut()) };
    // SAFETY: sets of one socket each, and a timeout, alive for the call.
    let n = unsafe { select(0, r, w, &mut ex, &tv) };
    if n == SOCKET_ERROR {
        return Err(last_error());
    }
    // A failed connect shows in the exception set: the caller reads SO_ERROR (or the read fails).
    Ok(n > 0)
}

/// Connect with a deadline, giving up within 100 ms of `cancel` being set. `window` sets both
/// socket buffers before the connect (so the window scale fits it): only when a test asks.
pub fn connect_tcp(addr: &SocketAddr, timeout: Duration, cancel: &AtomicBool, window: Option<u32>) -> io::Result<TcpStream> {
    let s = Raw::new(family(addr), SOCK_STREAM, IPPROTO_TCP)?;
    if let Some(w) = window {
        setopt(s.0, SOL_SOCKET, SO_SNDBUF, w)?;
        setopt(s.0, SOL_SOCKET, SO_RCVBUF, w)?;
    }
    set_nonblocking_raw(s.0, true)?;
    let (sa, len) = sockaddr(addr);
    // SAFETY: an address of `len` bytes.
    if unsafe { connect(s.0, (&sa as *const SOCKADDR_INET).cast(), len) } != 0 {
        let e = last_error();
        if e.raw_os_error() != Some(WSAEWOULDBLOCK) {
            return Err(e);
        }
        let start = Instant::now();
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "stopped"));
            }
            if start.elapsed() >= timeout {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no answer in time"));
            }
            if wait(s.0, SLICE, true)? {
                break;
            }
        }
        let err = getopt_u32(s.0, SOL_SOCKET, SO_ERROR)?;
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
    }
    set_nonblocking_raw(s.0, false)?;
    // SAFETY: a connected socket of ours, handed to the stream.
    Ok(unsafe { TcpStream::from_raw_socket(s.into_raw()) })
}

fn set_nonblocking_raw(s: SOCKET, on: bool) -> io::Result<()> {
    let mut v: u32 = on as u32;
    // SAFETY: an in/out u32.
    if unsafe { ioctlsocket(s, FIONBIO, &mut v) } == 0 { Ok(()) } else { Err(last_error()) }
}

/// A UDP socket bound to `src` (the address this computer sends to `addr` from: never the
/// wildcard, which would make Windows Defender Firewall ask about a "server") on any port, and
/// connected to `addr` (so it only hears that peer), with `rcvbuf` as its receive buffer.
pub fn udp_connected(addr: &SocketAddr, src: IpAddr, rcvbuf: Option<u32>, window: Option<u32>) -> io::Result<UdpSocket> {
    let s = Raw::new(family(addr), SOCK_DGRAM, IPPROTO_UDP)?;
    if let Some(w) = window {
        setopt(s.0, SOL_SOCKET, SO_SNDBUF, w)?;
        setopt(s.0, SOL_SOCKET, SO_RCVBUF, w)?;
    }
    if let Some(b) = rcvbuf {
        setopt(s.0, SOL_SOCKET, SO_RCVBUF, b)?;
    }
    no_connreset(s.0);
    let from = match (src, addr) {
        (IpAddr::V6(v6), SocketAddr::V6(a)) => SocketAddr::V6(std::net::SocketAddrV6::new(v6, 0, 0, a.scope_id())),
        _ => SocketAddr::new(src, 0),
    };
    bind_raw(s.0, &from)?;
    // SAFETY: the handle goes to the socket, which closes it.
    let u = unsafe { UdpSocket::from_raw_socket(s.into_raw()) };
    u.connect(addr)?;
    Ok(u)
}

/// Both buffers of an accepted or connected socket (a peer's `window` on the server side).
pub fn set_buffers(s: &impl AsRawSocket, bytes: u32) -> io::Result<()> {
    let raw = s.as_raw_socket() as SOCKET;
    setopt(raw, SOL_SOCKET, SO_SNDBUF, bytes)?;
    setopt(raw, SOL_SOCKET, SO_RCVBUF, bytes)
}

pub fn set_rcvbuf(s: &impl AsRawSocket, bytes: u32) -> io::Result<()> {
    setopt(s.as_raw_socket() as SOCKET, SOL_SOCKET, SO_RCVBUF, bytes)
}

pub fn rcvbuf(s: &impl AsRawSocket) -> io::Result<u32> {
    getopt_u32(s.as_raw_socket() as SOCKET, SOL_SOCKET, SO_RCVBUF)
}

/// Close without TIME_WAIT (SO_LINGER 0): the server's side of a finished test, so a listener
/// with SO_EXCLUSIVEADDRUSE can bind its port again at once after Stop server (lingering
/// accepted connections would block it for minutes).
pub fn abort_on_close(s: &impl AsRawSocket) {
    let l = LINGER { l_onoff: 1, l_linger: 0 };
    let _ = setopt(s.as_raw_socket() as SOCKET, SOL_SOCKET, SO_LINGER, l);
}

/// IP "don't fragment" on an IPv4 UDP socket (IPv6 routers never fragment anyway).
pub fn set_dont_fragment(s: &impl AsRawSocket) -> io::Result<()> {
    setopt(s.as_raw_socket() as SOCKET, IPPROTO_IP, IP_DONTFRAGMENT, 1u32)
}

/// The TCP maximum segment size of a connected socket, when Windows says.
pub fn mss(s: &impl AsRawSocket) -> Option<u32> {
    getopt_u32(s.as_raw_socket() as SOCKET, IPPROTO_TCP, TCP_MAXSEG).ok().filter(|m| (1..=65_535).contains(m))
}

/// A peer address as people read it: an IPv4 client of the dual-stack listener arrives as
/// ::ffff:a.b.c.d and is shown as a.b.c.d.
pub fn canonical(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => a,
        },
        _ => a,
    }
}

/// "192.168.1.20:5201", "[fe80::1%12]:5201".
pub fn show_addr(a: &SocketAddr) -> String {
    match canonical(*a) {
        SocketAddr::V4(v4) => v4.to_string(),
        SocketAddr::V6(v6) if v6.scope_id() != 0 => format!("[{}%{}]:{}", v6.ip(), v6.scope_id(), v6.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}
