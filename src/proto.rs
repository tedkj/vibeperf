//! iperf3's control protocol, as the wire carries it (clean-room from iperf3 3.20's
//! `iperf_api.c`, `iperf_api.h`, `iperf.h`, `iperf_udp.c`). Pure: bytes and
//! JSON in, typed values out, every limit checked. No sockets here.
//!
//! The control connection is TCP to the server's port: the client sends a 37-byte cookie, the
//! server answers with one-byte states (signed), parameters and results travel as JSON behind a
//! 4-byte big-endian length. Data streams open with the same cookie (TCP) or a 4-byte connect
//! datagram (UDP); UDP datagrams carry the sender's seconds, microseconds and a sequence number.

use serde_json::{Map, Value, json};
use std::io::Read;

pub const DEFAULT_PORT: u16 = 5201;
/// 36 characters and a NUL ("an ascii uuid" in iperf3's words).
pub const COOKIE_SIZE: usize = 37;
/// The characters a cookie is made of (`make_cookie`): 32 of them, so a random byte maps evenly.
pub const COOKIE_CHARS: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// iperf3's limit on the parameters a server reads (MAX_PARAMS_JSON_STRING).
pub const MAX_PARAMS_JSON: usize = 8 * 1024;
/// iperf3 reads results of any size; VibePerf stops at 1 MiB (a results object with 256 streams
/// is under 64 KiB, server output text included it rarely passes 100 KiB).
pub const MAX_RESULTS_JSON: usize = 1 << 20;
pub const MAX_STREAMS: u32 = 128;
pub const MAX_TIME: u32 = 86_400;
pub const MAX_BLOCKSIZE: u32 = 1 << 20;
pub const MIN_UDP_BLOCKSIZE: u32 = 16;
pub const MAX_UDP_BLOCKSIZE: u32 = 65_535 - 8 - 20;
pub const MAX_TCP_BUFFER: u64 = 512 << 20;
/// Both socket buffers of every TCP stream of a served test, at most (IN-VibePerf-2; iperf3
/// has no such cap): one stream at the largest window still fits. More is refused.
pub const MAX_TEST_BUFFERS: u64 = 2 * MAX_TCP_BUFFER;
/// iperf3's TCP read and write size (DEFAULT_TCP_BLKSIZE).
pub const TCP_LEN: u32 = 128 * 1024;
/// iperf3's UDP size when the control connection's MSS is unknown (DEFAULT_UDP_BLKSIZE).
pub const UDP_LEN_V4: u32 = 1460;
/// The same for IPv6: 20 bytes more header, so 20 fewer of payload (1500-byte MTU).
pub const UDP_LEN_V6: u32 = 1440;

/// The UDP connect datagram as it is on the wire ("9876"; iperf3 writes 0x36373839 in host
/// order, and every iperf3 host it runs on that writes these bytes).
pub const UDP_CONNECT_MSG: [u8; 4] = *b"9876";
/// The server's reply ("6789").
pub const UDP_CONNECT_REPLY: [u8; 4] = *b"6789";
/// What servers before 3.? replied (987654321 little-endian); clients still accept it.
pub const UDP_LEGACY_REPLY: [u8; 4] = [0xB1, 0x68, 0xDE, 0x3A];
/// What clients before then sent (123456789 little-endian): any datagram counts as a connect.
pub const UDP_LEGACY_MSG: [u8; 4] = [0x15, 0xCD, 0x5B, 0x07];

/// The states (one signed byte each). iperf3 also defines 3, 5, 6, 7, 8 and 15, which never
/// travel on the wire: an unknown byte is a protocol error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    TestStart,
    TestRunning,
    TestEnd,
    ParamExchange,
    CreateStreams,
    ServerTerminate,
    ClientTerminate,
    ExchangeResults,
    DisplayResults,
    IperfDone,
    AccessDenied,
    ServerError,
}

impl State {
    pub const ALL: [State; 12] = [
        State::TestStart,
        State::TestRunning,
        State::TestEnd,
        State::ParamExchange,
        State::CreateStreams,
        State::ServerTerminate,
        State::ClientTerminate,
        State::ExchangeResults,
        State::DisplayResults,
        State::IperfDone,
        State::AccessDenied,
        State::ServerError,
    ];

    pub fn value(self) -> i8 {
        match self {
            State::TestStart => 1,
            State::TestRunning => 2,
            State::TestEnd => 4,
            State::ParamExchange => 9,
            State::CreateStreams => 10,
            State::ServerTerminate => 11,
            State::ClientTerminate => 12,
            State::ExchangeResults => 13,
            State::DisplayResults => 14,
            State::IperfDone => 16,
            State::AccessDenied => -1,
            State::ServerError => -2,
        }
    }

    pub fn byte(self) -> u8 {
        self.value() as u8
    }

    pub fn from_byte(b: u8) -> Option<State> {
        State::ALL.into_iter().find(|s| s.byte() == b)
    }

    /// iperf3's name for it (its `state_to_text`), for logs and transcripts.
    pub fn name(self) -> &'static str {
        match self {
            State::TestStart => "TEST_START",
            State::TestRunning => "TEST_RUNNING",
            State::TestEnd => "TEST_END",
            State::ParamExchange => "PARAM_EXCHANGE",
            State::CreateStreams => "CREATE_STREAMS",
            State::ServerTerminate => "SERVER_TERMINATE",
            State::ClientTerminate => "CLIENT_TERMINATE",
            State::ExchangeResults => "EXCHANGE_RESULTS",
            State::DisplayResults => "DISPLAY_RESULTS",
            State::IperfDone => "IPERF_DONE",
            State::AccessDenied => "ACCESS_DENIED",
            State::ServerError => "SERVER_ERROR",
        }
    }
}

/// A cookie from 36 random bytes: each picks one of the 32 characters, then a NUL.
pub fn cookie_from(random: &[u8; COOKIE_SIZE - 1]) -> [u8; COOKIE_SIZE] {
    let mut c = [0u8; COOKIE_SIZE];
    for (o, r) in c.iter_mut().zip(random) {
        *o = COOKIE_CHARS[(*r % 32) as usize];
    }
    c
}

/// A fresh cookie from the system's random numbers.
pub fn new_cookie() -> [u8; COOKIE_SIZE] {
    let mut r = [0u8; COOKIE_SIZE - 1];
    crate::host::random_bytes(&mut r);
    cookie_from(&r)
}

// ---------- errors ----------

/// What went wrong reading the control connection.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// The peer closed the connection.
    Closed,
    /// Nothing arrived in time.
    TimedOut,
    /// The socket failed (the system's words).
    Io(String),
    /// A JSON length of 0 or above the limit.
    BadLength(u32),
    /// The JSON did not parse, or was not an object.
    BadJson,
    /// A state byte iperf3 does not send.
    UnknownState(u8),
    /// This side stopped waiting (the user pressed Stop).
    Cancelled,
}

impl ProtoError {
    pub fn from_io(e: std::io::Error) -> ProtoError {
        use std::io::ErrorKind::*;
        match e.kind() {
            UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => ProtoError::Closed,
            TimedOut | WouldBlock => ProtoError::TimedOut,
            _ => ProtoError::Io(e.to_string()),
        }
    }

    /// In words, for the window ("the server closed the connection").
    pub fn words(&self, peer: &str) -> String {
        match self {
            ProtoError::Closed => format!("the {peer} closed the connection"),
            ProtoError::TimedOut => format!("the {peer} stopped answering"),
            ProtoError::Io(e) => format!("the connection to the {peer} failed ({e})"),
            ProtoError::BadLength(n) => format!("the {peer} sent a message of {n} bytes, which is not iperf3's"),
            ProtoError::BadJson => format!("the {peer} sent a message that is not iperf3's (not JSON)"),
            ProtoError::UnknownState(b) => format!("the {peer} sent state {}, which iperf3 does not have (is it iperf2?)", *b as i8),
            ProtoError::Cancelled => "stopped".into(),
        }
    }
}

/// iperf3's error codes (`iperf_api.h`) a server may send after SERVER_ERROR, in iperf3's own
/// words (`iperf_error.c`), so a refusal reads the same as it would in iperf3.
pub mod code {
    pub const IEDURATION: i32 = 5;
    pub const IENUMSTREAMS: i32 = 6;
    pub const IEBLOCKSIZE: i32 = 7;
    pub const IEBUFSIZE: i32 = 8;
    pub const IEUNIMP: i32 = 13;
    pub const IENOSCTP: i32 = 18;
    pub const IEUDPBLOCKSIZE: i32 = 20;
    pub const IEREVERSEBIDIR: i32 = 25;
    pub const IERECVPARAMS: i32 = 114;
    pub const IEACCESSDENIED: i32 = 121;
    pub const IESETMSS: i32 = 123;
    pub const IESETBUF: i32 = 124;
    pub const IESETTOS: i32 = 125;
    pub const IESETFLOW: i32 = 127;
    pub const IEPROTOCOL: i32 = 131;
    pub const IESETPACING: i32 = 140;
    pub const IEAUTHTEST: i32 = 142;
    pub const IESTREAMLISTEN: i32 = 202;
}

pub fn error_text(code: i32) -> String {
    let t = match code {
        0 => "no error",
        1 => "cannot be both server and client",
        2 => "must either be a client (-c) or server (-s)",
        3 => "some option you are trying to set is server only",
        4 => "some option you are trying to set is client only",
        5 => "test duration valid values are 0 to 86400 seconds",
        6 => "number of parallel streams too large (maximum = 128)",
        7 => "block size too large (maximum = 1048576 bytes)",
        8 => "socket buffer size too large (maximum = 536870912 bytes)",
        9 => "invalid report interval",
        10 => "TCP MSS too large (maximum = 9216 bytes)",
        11 => "this OS does not support sendfile",
        12 => "bogus value for --omit (maximum = 600 seconds)",
        13 => "an option you are trying to set is not implemented yet",
        14 => "unable to open -F file",
        15 => "invalid burst count (maximum = 1000)",
        16 => "only one test end condition (-t, -n, -k) may be specified",
        18 => "no SCTP support available",
        20 => "block size invalid (minimum = 16 bytes, maximum = 65507 bytes)",
        21 => "bad TOS value (must be between 0 and 255 inclusive)",
        25 => "cannot be both reverse and bidirectional",
        26 => "port number must be between 1 and 65535 inclusive",
        27 => "total required bandwidth is larger than server limit",
        34 => "cannot transfer file using UDP",
        37 => "client's requested duration exceeds the server's maximum permitted limit",
        100 => "unable to create a new test",
        101 => "test initialization failed",
        102 => "unable to start listener for connections",
        103 => "unable to connect to server",
        104 => "unable to accept connection from client",
        105 => "unable to send cookie to server",
        106 => "unable to receive cookie at server",
        107 => "unable to write to the control socket",
        108 => "unable to read from the control socket",
        109 => "control socket has closed unexpectedly",
        110 => "received an unknown control message",
        111 => "unable to send control message",
        112 => "unable to receive control message",
        113 => "unable to send parameters to server",
        114 => "unable to receive parameters from client",
        115 => "unable to package results",
        116 => "unable to send results",
        117 => "unable to receive results",
        118 => "select failed",
        119 => "the client has terminated",
        120 => "the server has terminated",
        121 => "the server is busy running a test. try again later",
        122 => "unable to set TCP/SCTP NODELAY",
        123 => "unable to set TCP/SCTP MSS",
        124 => "unable to set socket buffer size",
        125 => "unable to set IP TOS",
        126 => "unable to set IPv6 traffic class",
        127 => "unable to set IPv6 flow label",
        128 => "unable to reuse address on socket",
        129 => "unable to set socket to non-blocking",
        130 => "unable to set socket window size",
        131 => "protocol does not exist",
        132 => "unable to set CPU affinity",
        134 => "unable to set TCP_CONGESTION",
        136 => "unable to set/reset IPV6_V6ONLY",
        140 => "unable to set socket pacing",
        141 => "socket buffer size not set correctly",
        142 => "test authorization failed",
        143 => "unable to bind-to-device",
        144 => "idle timeout for receiving data",
        145 => "unable to set IP Do-Not-Fragment flag",
        200 => "unable to create a new stream",
        201 => "unable to initialize stream",
        202 => "unable to start stream listener",
        203 => "unable to connect stream",
        204 => "unable to accept stream connection",
        205 => "unable to write to stream socket",
        206 => "unable to read from stream socket",
        207 => "stream socket has closed unexpectedly",
        208 => "stream has an invalid id",
        _ => "",
    };
    if t.is_empty() { format!("iperf3 error {code}") } else { t.to_string() }
}

// ---------- JSON framing ----------

/// A JSON message as iperf3 sends it: the compact text behind its length (4 bytes, big-endian).
pub fn frame_json(v: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Read one JSON message of at most `max` bytes. Its length is checked before anything is
/// allocated; a zero length, a longer one, text that does not parse or is not an object are
/// refused.
pub fn read_json(r: &mut impl Read, max: usize) -> Result<Value, ProtoError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).map_err(ProtoError::from_io)?;
    let n = u32::from_be_bytes(len);
    if n == 0 || n as usize > max {
        return Err(ProtoError::BadLength(n));
    }
    let mut body = vec![0u8; n as usize];
    r.read_exact(&mut body).map_err(ProtoError::from_io)?;
    parse_json(&body)
}

pub fn parse_json(body: &[u8]) -> Result<Value, ProtoError> {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) if v.is_object() => Ok(v),
        _ => Err(ProtoError::BadJson),
    }
}

/// Read one state byte.
pub fn read_state(r: &mut impl Read) -> Result<State, ProtoError> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).map_err(ProtoError::from_io)?;
    State::from_byte(b[0]).ok_or(ProtoError::UnknownState(b[0]))
}

/// The two codes behind SERVER_ERROR: iperf3's error number and the server's errno, each a
/// 4-byte big-endian integer.
pub fn read_error_codes(r: &mut impl Read) -> Result<(i32, i32), ProtoError> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(ProtoError::from_io)?;
    Ok((i32::from_be_bytes([b[0], b[1], b[2], b[3]]), i32::from_be_bytes([b[4], b[5], b[6], b[7]])))
}

pub fn server_error_bytes(code: i32, errno: i32) -> Vec<u8> {
    let mut v = vec![State::ServerError.byte()];
    v.extend_from_slice(&code.to_be_bytes());
    v.extend_from_slice(&errno.to_be_bytes());
    v
}

// ---------- typed fields (iperf3's iperf_cJSON_GetObjectItemType: a wrong type is absent) ----------

fn num(m: &Map<String, Value>, k: &str) -> Option<f64> {
    m.get(k).and_then(Value::as_f64).filter(|v| v.is_finite())
}

/// A number as cJSON's `valueint` reads it (truncated), clamped into i64.
fn int(m: &Map<String, Value>, k: &str) -> Option<i64> {
    num(m, k).map(|v| v.trunc().clamp(i64::MIN as f64, i64::MAX as f64) as i64)
}

fn is_true(m: &Map<String, Value>, k: &str) -> bool {
    matches!(m.get(k), Some(Value::Bool(true)))
}

fn string<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

// ---------- parameters ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

/// Which way the data flows, as the client sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Direction {
    /// Client sends, server receives.
    #[default]
    Normal,
    /// Server sends, client receives (`-R`).
    Reverse,
    /// Both at once (`--bidir`): `parallel` streams each way.
    Both,
}

/// What a test asks for: the parameters a client sends, as VibePerf uses them.
#[derive(Clone, Debug, PartialEq)]
pub struct Params {
    pub proto: Proto,
    /// Seconds; 0 means the test ends by bytes or blocks (`num`, `blockcount`).
    pub time: u32,
    pub parallel: u32,
    pub direction: Direction,
    /// Bytes per write (TCP) or per datagram (UDP); 0: the receiver's default.
    pub len: u32,
    /// Bits per second per stream (UDP pacing); 0: unpaced. At most `MAX_BITRATE`.
    pub bandwidth: u64,
    /// The rate the client asked for when it was above `MAX_BITRATE` (and so capped).
    pub bandwidth_capped_from: Option<u64>,
    /// Socket buffer size asked for (`-w`); 0: the system's own (auto-tuning).
    pub window: u32,
    /// 64-bit UDP sequence numbers.
    pub udp64: bool,
    pub nodelay: bool,
    /// IP Do-Not-Fragment on UDP.
    pub dont_fragment: bool,
    pub num: u64,
    pub blockcount: u64,
    pub client_version: String,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            proto: Proto::Tcp,
            time: 10,
            parallel: 1,
            direction: Direction::Normal,
            len: 0,
            bandwidth: 0,
            bandwidth_capped_from: None,
            window: 0,
            udp64: false,
            nodelay: false,
            dont_fragment: false,
            num: 0,
            blockcount: 0,
            client_version: String::new(),
        }
    }
}

impl Params {
    /// The streams opened in all (both directions count).
    pub fn stream_count(&self) -> u32 {
        if self.direction == Direction::Both { self.parallel * 2 } else { self.parallel }
    }

    /// What a client sends: the keys iperf3's client always sends, and the optional ones only
    /// when they are set (as iperf3 does). Never `window` unless asked: Windows' auto-tuning
    /// does better than any fixed value.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert(if self.proto == Proto::Udp { "udp" } else { "tcp" }.into(), Value::Bool(true));
        m.insert("omit".into(), json!(0));
        m.insert("time".into(), json!(self.time));
        m.insert("num".into(), json!(self.num));
        m.insert("blockcount".into(), json!(self.blockcount));
        if self.nodelay {
            m.insert("nodelay".into(), Value::Bool(true));
        }
        m.insert("parallel".into(), json!(self.parallel));
        match self.direction {
            Direction::Reverse => {
                m.insert("reverse".into(), Value::Bool(true));
            }
            Direction::Both => {
                m.insert("bidirectional".into(), Value::Bool(true));
            }
            Direction::Normal => {}
        }
        if self.window > 0 {
            m.insert("window".into(), json!(self.window));
        }
        if self.len > 0 {
            m.insert("len".into(), json!(self.len));
        }
        if self.bandwidth > 0 {
            m.insert("bandwidth".into(), json!(self.bandwidth));
        }
        m.insert("pacing_timer".into(), json!(1000));
        if self.udp64 {
            m.insert("udp_counters_64bit".into(), json!(1));
        }
        if self.dont_fragment {
            m.insert("dont_fragment".into(), json!(1));
        }
        m.insert("client_version".into(), json!(self.client_version));
        Value::Object(m)
    }

    /// The length a receiver uses for its reads when the client gave none.
    pub fn len_or_default(&self, ipv6: bool) -> u32 {
        match (self.len, self.proto) {
            (0, Proto::Tcp) => TCP_LEN,
            (0, Proto::Udp) => {
                if ipv6 {
                    UDP_LEN_V6
                } else {
                    UDP_LEN_V4
                }
            }
            (n, _) => n,
        }
    }
}

/// A request the server will not serve: iperf3's code for it (sent after SERVER_ERROR) and
/// what VibePerf says about it in its own log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: i32,
    pub why: String,
}

fn refuse(code: i32, why: &str) -> Refusal {
    Refusal { code, why: why.to_string() }
}

/// A client's parameters as a server reads them: typed as iperf3 reads them (a key of the wrong
/// type is as good as absent), unknown keys ignored, and anything VibePerf cannot honestly
/// serve refused with iperf3's own error code for it.
pub fn parse_params(v: &Value) -> Result<Params, Refusal> {
    let m = v.as_object().ok_or_else(|| refuse(code::IERECVPARAMS, "the parameters are not a JSON object"))?;
    let mut p = Params { time: 0, ..Params::default() };
    if is_true(m, "udp") {
        p.proto = Proto::Udp;
    } else if is_true(m, "tcp") {
        p.proto = Proto::Tcp;
    }
    if is_true(m, "sctp") {
        return Err(refuse(code::IENOSCTP, "SCTP was asked for"));
    }
    if is_true(m, "mptcp") {
        return Err(refuse(code::IEPROTOCOL, "MPTCP was asked for (Windows has none)"));
    }
    if string(m, "authtoken").is_some() {
        return Err(refuse(code::IEAUTHTEST, "authentication was asked for (VibePerf serves without it)"));
    }
    if int(m, "omit").unwrap_or(0) != 0 {
        return Err(refuse(code::IEUNIMP, "omitting the first seconds (-O) was asked for"));
    }
    if let Some(t) = int(m, "time") {
        if !(0..=MAX_TIME as i64).contains(&t) {
            return Err(refuse(code::IEDURATION, "the duration is out of range"));
        }
        p.time = t as u32;
    }
    p.num = int(m, "num").unwrap_or(0).max(0) as u64;
    p.blockcount = int(m, "blockcount").unwrap_or(0).max(0) as u64;
    if p.time == 0 && p.num == 0 && p.blockcount == 0 {
        // iperf3's client always sends a time; nothing at all is its default of 10 s.
        p.time = 10;
    }
    if int(m, "MSS").unwrap_or(0) > 0 {
        return Err(refuse(code::IESETMSS, "a TCP MSS was asked for (Windows cannot set one)"));
    }
    p.nodelay = is_true(m, "nodelay");
    match int(m, "parallel") {
        Some(n) if (1..=MAX_STREAMS as i64).contains(&n) => p.parallel = n as u32,
        Some(_) => return Err(refuse(code::IENUMSTREAMS, "the number of streams is out of range")),
        None => p.parallel = 1,
    }
    let reverse = is_true(m, "reverse");
    let bidir = is_true(m, "bidirectional");
    p.direction = match (reverse, bidir) {
        (true, true) => return Err(refuse(code::IEREVERSEBIDIR, "both reverse and bidirectional were asked for")),
        (true, false) => Direction::Reverse,
        (false, true) => Direction::Both,
        (false, false) => Direction::Normal,
    };
    if let Some(w) = int(m, "window").filter(|w| *w != 0) {
        if w < 0 || w as u64 > MAX_TCP_BUFFER {
            return Err(refuse(code::IEBUFSIZE, "the socket buffer size is out of range"));
        }
        p.window = w as u32;
        if p.proto == Proto::Tcp && 2 * p.window as u64 * p.stream_count() as u64 > MAX_TEST_BUFFERS {
            return Err(refuse(code::IEBUFSIZE, "the socket buffers asked for come to more than 1 GiB for the test"));
        }
    }
    if let Some(l) = int(m, "len").filter(|l| *l != 0) {
        let ok = match p.proto {
            Proto::Tcp => (1..=MAX_BLOCKSIZE as i64).contains(&l),
            Proto::Udp => (MIN_UDP_BLOCKSIZE as i64..=MAX_UDP_BLOCKSIZE as i64).contains(&l),
        };
        if !ok {
            let c = if p.proto == Proto::Udp { code::IEUDPBLOCKSIZE } else { code::IEBLOCKSIZE };
            return Err(refuse(c, "the block size is out of range"));
        }
        p.len = l as u32;
    }
    // A server that sends paces to the client's rate: never above the window's own cap.
    let asked = int(m, "bandwidth").unwrap_or(0).max(0) as u64;
    p.bandwidth = asked.min(crate::MAX_BITRATE);
    p.bandwidth_capped_from = (asked > crate::MAX_BITRATE).then_some(asked);
    p.udp64 = num(m, "udp_counters_64bit").is_some();
    p.dont_fragment = int(m, "dont_fragment").unwrap_or(0) != 0;
    // Options that change how a sender sends: refused only when this server sends.
    let server_sends = p.direction != Direction::Normal;
    if server_sends {
        if int(m, "fqrate").unwrap_or(0) > 0 {
            return Err(refuse(code::IESETPACING, "fair-queue pacing was asked for (Linux only)"));
        }
        if int(m, "burst").unwrap_or(0) > 0 {
            return Err(refuse(code::IEUNIMP, "burst sending was asked for"));
        }
        if int(m, "TOS").unwrap_or(0) != 0 {
            return Err(refuse(code::IESETTOS, "a TOS / DSCP value was asked for (Windows needs a QoS policy for that)"));
        }
        if int(m, "flowlabel").unwrap_or(0) != 0 {
            return Err(refuse(code::IESETFLOW, "an IPv6 flow label was asked for"));
        }
    }
    p.client_version = string(m, "client_version").unwrap_or("").chars().take(64).collect();
    Ok(p)
}

// ---------- results ----------

/// One stream's results as exchanged at the end (`send_results` / `get_results`).
#[derive(Clone, Debug, PartialEq)]
pub struct StreamResult {
    pub id: i64,
    /// Sender: bytes sent; receiver: bytes received.
    pub bytes: u64,
    /// Retransmitted segments (a Linux sender), -1 when not known.
    pub retransmits: i64,
    /// Seconds (UDP receiver).
    pub jitter: f64,
    /// Datagrams lost (UDP receiver).
    pub errors: i64,
    /// Datagrams sent (sender) or the highest sequence number seen (receiver).
    pub packets: i64,
    /// `omitted_errors` and `omitted_packets` (3.12 and later send both; older ones neither).
    pub omitted: Option<(i64, i64)>,
    /// Seconds since the stream's start; absent from servers before 3.2.
    pub start_time: Option<f64>,
    pub end_time: Option<f64>,
}

impl StreamResult {
    /// The time the stream's bytes were measured over (end minus start), when both are known.
    pub fn duration(&self) -> Option<f64> {
        match (self.start_time, self.end_time) {
            (Some(s), Some(e)) if e > s => Some(e - s),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Results {
    pub cpu_total: f64,
    pub cpu_user: f64,
    pub cpu_system: f64,
    /// 1: the sender's `retransmits` are segment counts; 0: it has none (VibePerf: Windows
    /// counts bytes); -1: this side only received.
    pub sender_has_retransmits: i64,
    pub streams: Vec<StreamResult>,
}

/// More streams than this in a results object is not iperf3's (128 each way).
pub const MAX_RESULT_STREAMS: usize = 2 * MAX_STREAMS as usize;

pub fn results_json(r: &Results) -> Value {
    let streams: Vec<Value> = r
        .streams
        .iter()
        .map(|s| {
            let mut m = Map::new();
            m.insert("id".into(), json!(s.id));
            m.insert("bytes".into(), json!(s.bytes));
            m.insert("retransmits".into(), json!(s.retransmits));
            m.insert("jitter".into(), json!(s.jitter));
            m.insert("errors".into(), json!(s.errors));
            let (oe, op) = s.omitted.unwrap_or((0, 0));
            m.insert("omitted_errors".into(), json!(oe));
            m.insert("packets".into(), json!(s.packets));
            m.insert("omitted_packets".into(), json!(op));
            m.insert("start_time".into(), json!(s.start_time.unwrap_or(0.0)));
            m.insert("end_time".into(), json!(s.end_time.unwrap_or(0.0)));
            Value::Object(m)
        })
        .collect();
    json!({
        "cpu_util_total": r.cpu_total,
        "cpu_util_user": r.cpu_user,
        "cpu_util_system": r.cpu_system,
        "sender_has_retransmits": r.sender_has_retransmits,
        "streams": streams,
    })
}

/// Results as iperf3's `get_results` takes them: the CPU figures and `sender_has_retransmits`
/// must be there, every stream needs id, bytes, retransmits, jitter, errors and packets, the
/// omitted pair comes both or neither. Anything else is refused whole (never half-read).
pub fn parse_results(v: &Value) -> Result<Results, String> {
    let m = v.as_object().ok_or("the results are not a JSON object")?;
    let need = |k: &str| num(m, k).ok_or(format!("the results have no {k}"));
    let cpu_total = need("cpu_util_total")?;
    let cpu_user = need("cpu_util_user")?;
    let cpu_system = need("cpu_util_system")?;
    let sender_has_retransmits = int(m, "sender_has_retransmits").ok_or("the results have no sender_has_retransmits")?;
    let list = m.get("streams").and_then(Value::as_array).ok_or("the results have no streams")?;
    if list.len() > MAX_RESULT_STREAMS {
        return Err(format!("the results list {} streams", list.len()));
    }
    let mut streams = Vec::with_capacity(list.len());
    for s in list {
        let s = s.as_object().ok_or("a stream's results are not an object")?;
        let field = |k: &str| int(s, k).ok_or(format!("a stream's results have no {k}"));
        let id = field("id")?;
        let bytes = num(s, "bytes").ok_or("a stream's results have no bytes")?;
        let retransmits = field("retransmits")?;
        let jitter = num(s, "jitter").ok_or("a stream's results have no jitter")?;
        let errors = field("errors")?;
        let packets = field("packets")?;
        let omitted = match (int(s, "omitted_errors"), int(s, "omitted_packets")) {
            (Some(e), Some(p)) => Some((e, p)),
            (None, None) => None,
            _ => return Err("a stream's results have one of omitted_errors and omitted_packets".into()),
        };
        if bytes < 0.0 {
            return Err("a stream's byte count is negative".into());
        }
        streams.push(StreamResult {
            id,
            bytes: bytes.trunc().min(u64::MAX as f64) as u64,
            retransmits,
            jitter: jitter.max(0.0),
            errors,
            packets,
            omitted,
            start_time: num(s, "start_time"),
            end_time: num(s, "end_time"),
        });
    }
    Ok(Results { cpu_total, cpu_user, cpu_system, sender_has_retransmits, streams })
}

/// Stream ids as iperf3 numbers them, in the order the streams are made: 1, then 3, 4, 5...
/// (iperf3 skips 2, and keeps doing so so old and new versions agree).
pub fn stream_id(index: usize) -> i64 {
    if index == 0 { 1 } else { index as i64 + 2 }
}

// ---------- UDP datagrams ----------

/// The header a UDP datagram starts with: the sender's seconds and microseconds (any clock:
/// only differences matter), and its sequence number, 32 or 64 bits, all big-endian.
pub fn udp_header_len(wide: bool) -> usize {
    if wide { 16 } else { 12 }
}

pub fn put_udp_header(buf: &mut [u8], sec: u32, usec: u32, seq: u64, wide: bool) {
    buf[0..4].copy_from_slice(&sec.to_be_bytes());
    buf[4..8].copy_from_slice(&usec.to_be_bytes());
    if wide {
        buf[8..16].copy_from_slice(&seq.to_be_bytes());
    } else {
        buf[8..12].copy_from_slice(&(seq as u32).to_be_bytes());
    }
}

/// The header of a received datagram, or None when it is too short to carry one.
pub fn parse_udp_header(buf: &[u8], wide: bool) -> Option<(u32, u32, u64)> {
    if buf.len() < udp_header_len(wide) {
        return None;
    }
    let sec = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let usec = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let seq = if wide {
        u64::from_be_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]])
    } else {
        u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64
    };
    Some((sec, usec, seq))
}

/// Whether a datagram is a server's answer to a UDP connect (the current or the old value).
pub fn is_connect_reply(buf: &[u8]) -> bool {
    buf == UDP_CONNECT_REPLY || buf == UDP_LEGACY_REPLY
}

// ---------- transcripts ----------

/// One message of a recorded control conversation.
#[derive(Clone, Debug, PartialEq)]
pub enum Msg {
    Cookie(Vec<u8>),
    State(State),
    Json(Value),
    /// The two codes after SERVER_ERROR.
    Codes(i32, i32),
}

/// One side of a recorded control conversation, decoded: the client's side starts with the
/// cookie. A JSON length starts with a zero byte (messages are far below 16 MiB) and no state is
/// zero, which tells the two apart; SERVER_ERROR carries its two codes.
pub fn decode_side(bytes: &[u8], client: bool) -> Result<Vec<Msg>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    if client {
        if bytes.len() < COOKIE_SIZE {
            return Err("shorter than a cookie".into());
        }
        out.push(Msg::Cookie(bytes[..COOKIE_SIZE].to_vec()));
        i = COOKIE_SIZE;
    }
    while i < bytes.len() {
        if bytes[i] == 0 {
            let len = bytes.get(i..i + 4).ok_or("a cut JSON length")?;
            let n = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
            let body = bytes.get(i + 4..i + 4 + n).ok_or("a cut JSON message")?;
            out.push(Msg::Json(parse_json(body).map_err(|_| "a JSON message that does not parse")?));
            i += 4 + n;
            continue;
        }
        let s = State::from_byte(bytes[i]).ok_or(format!("unknown state byte {}", bytes[i]))?;
        out.push(Msg::State(s));
        i += 1;
        if s == State::ServerError {
            let c = bytes.get(i..i + 8).ok_or("SERVER_ERROR without its codes")?;
            out.push(Msg::Codes(i32::from_be_bytes([c[0], c[1], c[2], c[3]]), i32::from_be_bytes([c[4], c[5], c[6], c[7]])));
            i += 8;
        }
    }
    Ok(out)
}
