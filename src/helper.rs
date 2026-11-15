//! The one step that needs admin (inbound firewall rules for the server) runs in a short-lived
//! helper: this same exe relaunched elevated (`ShellExecuteExW` "runas": one UAC prompt, which
//! the user may decline) as `VibePerf.exe --firewall <pipe id> <parent pid>`.
//!
//! The app makes a named pipe with a random name and a DACL for the current user only (plus
//! elevated Administrators: an over-the-shoulder admin's helper runs as that admin), and takes
//! as its client only the process it launched, running this very exe. The helper works only for
//! its own app (SOL-PERF-1): it opens the pipe at identification level (`SECURITY_SQOS_PRESENT |
//! SECURITY_IDENTIFICATION`: the server cannot act as it) and serves only if the pipe's server
//! is the parent named on its command line and runs this very exe (`QueryFullProcessImageNameW`,
//! compared by file identity, `FILE_ID_INFO`, never by path). The helper takes one value from the pipe, the
//! port (1-65535), and one flag (remove this exe's block rules); everything else (its own
//! path, the rules' names, scope and group) it decides itself. It adds the rules, answers, and
//! stays while the app serves; it removes the rules when told, when the pipe closes or when the
//! parent exits (it waits on the parent's handle, so a crash cleans up too), and after 24 h at
//! the most. Each rule names its app (the parent's id, start time and user): the helper removes
//! only its own app's rules and the ones whose app is gone, never a second running VibePerf's.
//! Its answers are untrusted input to the app: one line of at most 4 KiB, strict JSON.

use crate::firewall::{self, Firewall, NewRule, Owner};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED};
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;

/// The command-line switch the helper runs under.
pub const ARG: &str = "--firewall";
/// A message on the pipe: one JSON line of at most this many bytes.
pub const MAX_LINE: usize = 4096;
/// The helper's hard limit while serving.
pub const MAX_LIFE: Duration = Duration::from_secs(24 * 3600);
/// How long the app waits for the helper to connect once the user said yes.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// "open" (add the rules and stay), "clean" (remove rules left from before and leave),
    /// "close" (remove the rules and leave).
    pub op: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub remove_blocks: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Reply {
    pub ok: bool,
    pub added: u32,
    /// VibePerf's own rules removed (left from before, or at close).
    pub removed: u32,
    pub blocks_removed: u32,
    pub error: String,
}

/// A line read from a pipe, at most `MAX_LINE` bytes, or why not.
fn read_line(r: &mut impl Read) -> Result<String, String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match r.read(&mut b) {
            Ok(0) => return Err("the pipe closed".into()),
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) => {
                out.push(b[0]);
                if out.len() > MAX_LINE {
                    return Err("a message longer than 4 KiB".into());
                }
            }
            Err(e) => return Err(format!("the pipe failed ({e})")),
        }
    }
    String::from_utf8(out).map_err(|_| "a message that is not text".into())
}

fn line(v: &impl Serialize) -> Vec<u8> {
    let mut s = serde_json::to_vec(v).unwrap_or_default();
    s.push(b'\n');
    s
}

/// The reply as the app takes it: strict, bounded, and an ok without its counts is no ok.
pub fn parse_reply(s: &str) -> Result<Reply, String> {
    if s.len() > MAX_LINE {
        return Err("the helper's answer is too long".into());
    }
    let r: Reply = serde_json::from_str(s).map_err(|_| "the helper's answer is not one it gives".to_string())?;
    if r.ok && !r.error.is_empty() {
        return Err("the helper's answer contradicts itself".into());
    }
    if r.added > 2 || r.removed > 1000 || r.blocks_removed > 1000 {
        return Err("the helper's answer has impossible counts".into());
    }
    Ok(Reply { error: crate::netinfo::clean(&r.error), ..r })
}

/// A request as the helper takes it: strict, the port in range.
pub fn parse_request(s: &str) -> Result<Request, String> {
    let r: Request = serde_json::from_str(s).map_err(|_| "not a request".to_string())?;
    match r.op.as_str() {
        "open" if (1..=65_535).contains(&r.port) => Ok(r),
        "open" => Err("a port outside 1-65535".into()),
        "clean" | "close" => Ok(r),
        _ => Err("an unknown request".into()),
    }
}

// ---------- the helper (elevated) ----------

/// The helper's whole job on an open pipe: one request, then (for "open") stay until told to
/// close, the pipe closes, the parent exits, or `life` passes; the rules go in every case.
/// `owner` is the app (the parent) and `user` its SID: the rules added name both, only a gone
/// owner's rules are left from a crash, and only the owner's own go at the end.
pub fn serve(pipe: std::fs::File, parent: RawHandle, owner: Owner, user: &str, fw: &dyn Firewall, exe: &Path, life: Duration) -> i32 {
    serve_with_reader(pipe, parent, owner, user, fw, exe, life).0
}

/// `serve`, and the stay phase's pipe reader (detached in `serve`; it may outlive the wait,
/// when the parent's exit or the time limit ends it): `true` when its wake-up reached the
/// event. Tests join it.
fn serve_with_reader(mut pipe: std::fs::File, parent: RawHandle, owner: Owner, user: &str, fw: &dyn Firewall, exe: &Path, life: Duration) -> (i32, Option<std::thread::JoinHandle<bool>>) {
    let done = |code| (code, None);
    let req = match read_line(&mut pipe).and_then(|l| parse_request(&l)) {
        Ok(r) => r,
        Err(e) => {
            let _ = pipe.write_all(&line(&Reply { error: e, ..Reply::default() }));
            return done(2);
        }
    };
    let exe_owned = exe.to_path_buf();
    // Rules left from a crash: this user's whose owner is gone (or names none). Another running
    // VibePerf's are never among them.
    let stale = |r: &firewall::Rule| firewall::stale_for(r, user, &firewall::alive);
    let own = |r: &firewall::Rule| firewall::mine(r, owner);
    if req.op == "clean" || req.op == "close" {
        let pick: &dyn Fn(&firewall::Rule) -> bool = if req.op == "clean" { &stale } else { &own };
        let r = match fw.remove(pick) {
            Ok(n) => Reply { ok: true, removed: n as u32, ..Reply::default() },
            Err(e) => Reply { error: e, ..Reply::default() },
        };
        let _ = pipe.write_all(&line(&r));
        return done(if r.ok { 0 } else { 1 });
    }
    // Open: rules left from a crash go first, and this app's own (a fresh session owns none yet:
    // they are a helper's that was ended from outside while the window stayed open), then (if
    // asked) Windows' block rules for this exe.
    let mut reply = Reply::default();
    match fw.remove(&|r| stale(r) || own(r)) {
        Ok(n) => reply.removed = n as u32,
        Err(e) => reply.error = e,
    }
    if reply.error.is_empty() && req.remove_blocks {
        match fw.remove(&|r| firewall::blocks_this_exe(r, &exe_owned)) {
            Ok(n) => reply.blocks_removed = n as u32,
            Err(e) => reply.error = e,
        }
    }
    if reply.error.is_empty() {
        for tcp in [true, false] {
            match fw.add(&NewRule::server(exe, tcp, req.port, owner, user)) {
                Ok(()) => reply.added += 1,
                Err(e) => {
                    reply.error = e;
                    break;
                }
            }
        }
    }
    reply.ok = reply.error.is_empty();
    if !reply.ok {
        let _ = fw.remove(&own); // half done is undone
        reply.added = 0;
    }
    if pipe.write_all(&line(&reply)).is_err() || !reply.ok {
        let _ = fw.remove(&own);
        return done(1);
    }
    // Stay: a thread reads the pipe (a "close" or its end wakes the wait); the parent's exit
    // or the hard limit do too.
    // The event is shared with the reader: it closes when both are done with it, so the
    // reader's wake-up never meets a closed (or reused) handle when the parent's exit or the
    // time limit ended the wait first.
    // SAFETY: an unnamed manual-reset event, closed by the OwnedHandle.
    let event = std::sync::Arc::new(unsafe { OwnedHandle::from_raw_handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) as RawHandle) });
    let ev = event.clone();
    let mut reader = match pipe.try_clone() {
        Ok(p) => p,
        Err(_) => {
            let _ = fw.remove(&own);
            return done(1);
        }
    };
    let told = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let t = told.clone();
    let reader_thread = std::thread::spawn(move || {
        // Anything but a well-formed "close" (garbage, the end, an error) counts as the end too.
        if let Ok(r) = read_line(&mut reader).and_then(|l| parse_request(&l)) {
            t.store(r.op == "close", std::sync::atomic::Ordering::SeqCst);
        }
        // SAFETY: this thread holds its own reference to the event, so the handle is open.
        unsafe { SetEvent(ev.as_raw_handle() as HANDLE) != 0 }
    });
    let handles = [parent as HANDLE, event.as_raw_handle() as HANDLE];
    let ms = life.as_millis().min(u32::MAX as u128 - 1) as u32;
    // SAFETY: two handles; a bounded wait. A parent handle the wait refuses still leaves the
    // pipe and the time limit.
    unsafe {
        if WaitForMultipleObjects(2, handles.as_ptr(), 0, ms) == WAIT_FAILED {
            WaitForSingleObject(handles[1], ms);
        }
    }
    let removed = fw.remove(&own);
    if told.load(std::sync::atomic::Ordering::SeqCst) {
        let r = match removed {
            Ok(n) => Reply { ok: true, removed: n as u32, ..Reply::default() },
            Err(e) => Reply { error: e, ..Reply::default() },
        };
        let _ = pipe.write_all(&line(&r));
    }
    (0, Some(reader_thread))
}

/// `VibePerf.exe --firewall <32 hex> <parent pid>` (taken apart by `command_line`, lib.rs):
/// connect to the parent's pipe and serve. The exit code is for the record only (nobody waits
/// for it but the parent).
pub fn run(id: &str, pid: u32) -> i32 {
    let Some(exe) = crate::host::own_exe() else { return 3 };
    run_with(id, pid, &exe, &firewall::System, MAX_LIFE)
}

/// `run` with this exe's path and the firewall given: the tests' seam. The helper works only
/// for its own app (SOL-PERF-1): the pipe's server must be the parent named on the command line
/// and run this very exe, compared by file identity; otherwise no firewall call is made.
fn run_with(id: &str, pid: u32, exe: &Path, fw: &dyn Firewall, life: Duration) -> i32 {
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return 2;
    }
    // The parent first, then its pipe: the PID cannot be reused while this handle is held, and
    // the pipe's server PID is the PID of the process that made the pipe (RP-2).
    // SAFETY: plain arguments; the handle is closed by the OwnedHandle.
    let parent = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if parent.is_null() {
        return 4;
    }
    let parent = unsafe { OwnedHandle::from_raw_handle(parent as RawHandle) };
    // The app the rules belong to: its id and start time, and the user it runs as.
    let Some(started) = firewall::started(pid) else { return 4 };
    let Some(pipe) = open_pipe(&pipe_path(id), Duration::from_secs(10)) else { return 5 };
    if !server_is(&pipe, pid, exe) {
        return 6;
    }
    let user = firewall::process_user(std::os::windows::io::AsHandle::as_handle(&parent)).unwrap_or_default();
    serve(pipe, parent.as_raw_handle(), Owner { pid, started }, &user, fw, exe, life)
}

/// The pipe's server is process `pid`, running `exe` (the same file, by identity).
fn server_is(pipe: &std::fs::File, pid: u32, exe: &Path) -> bool {
    let mut server = 0u32;
    // SAFETY: our pipe handle and an out value.
    let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut server) } != 0;
    ok && server == pid && runs(server, exe)
}

/// The app's pipe's client is process `pid` (the one the app launched), running `exe`.
fn client_is(pipe: HANDLE, pid: u32, exe: &Path) -> bool {
    let mut client = 0u32;
    // SAFETY: our pipe handle and an out value.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut client) } != 0;
    ok && client == pid && runs(client, exe)
}

// ---------- who is at the other end: file identity, not names ----------

/// A file identity: the volume serial and the 128-bit file id.
pub(crate) type FileIdent = (u64, [u8; 16]);

/// Two identities are one file: equal, and neither the serial nor the id is zero (a zero is
/// "unknown", never "the same": VIBEWARE "Identity, not names").
pub(crate) fn same_id(a: FileIdent, b: FileIdent) -> bool {
    a == b && a.0 != 0 && a.1 != [0; 16]
}

/// The identity where a file system has no `FILE_ID_INFO` (FAT, exFAT): the 32-bit serial and
/// the 64-bit index in the low 8 bytes, the high 8 bytes zero.
pub(crate) fn fallback_id(serial: u32, index_high: u32, index_low: u32) -> FileIdent {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&((u64::from(index_high) << 32) | u64::from(index_low)).to_le_bytes());
    (u64::from(serial), id)
}

/// A file's identity (`FILE_ID_INFO`, else the serial and 64-bit index); None when the file
/// cannot be opened or asked.
fn file_id(path: &Path) -> Option<FileIdent> {
    use windows_sys::Win32::Storage::FileSystem::*;
    let p = crate::host::wide_path(path);
    // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
    let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: plain structs filled by the calls, sizes given; the handle just opened.
    let id = unsafe {
        let mut info: FILE_ID_INFO = std::mem::zeroed();
        if GetFileInformationByHandleEx(h, FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
            Some((info.VolumeSerialNumber, info.FileId.Identifier))
        } else {
            let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
            (GetFileInformationByHandle(h, &mut bh) != 0).then(|| fallback_id(bh.dwVolumeSerialNumber, bh.nFileIndexHigh, bh.nFileIndexLow))
        }
    };
    unsafe { CloseHandle(h) };
    id
}

/// Two paths name the same file: by identity, never by name (a subst or mapped drive, a
/// junction, a hard link or an 8.3 name of the very same exe still match; a zero id never does).
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (file_id(a), file_id(b)) {
        (Some(x), Some(y)) => same_id(x, y),
        _ => false,
    }
}

/// The image path of process `pid` (None when it cannot be opened or asked).
fn image_of(pid: u32) -> Option<std::path::PathBuf> {
    // SAFETY: a query-only open of a process by id; closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 32_768];
    let mut n = buf.len() as u32;
    // SAFETY: a buffer and its length in units.
    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) } != 0;
    unsafe { CloseHandle(h) };
    ok.then(|| crate::host::path_from_wide(&buf[..n as usize]))
}

/// Process `pid` is a real one and runs `exe`.
fn runs(pid: u32, exe: &Path) -> bool {
    pid != 0 && image_of(pid).is_some_and(|img| same_file(&img, exe))
}

pub fn pipe_path(id: &str) -> String {
    format!(r"\\.\pipe\vibeperf-fw-{id}")
}

/// The client end of a pipe, waiting (at most `wait`) while it is busy or not there yet.
/// Identification level only: the pipe's server may learn who we are, never act as us.
pub fn open_pipe(path: &str, wait: Duration) -> Option<std::fs::File> {
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};
    let w = crate::host::wide(path);
    let start = std::time::Instant::now();
    while start.elapsed() < wait {
        // SAFETY: a NUL-terminated path; the handle goes to the File.
        let h = unsafe { CreateFileW(w.as_ptr(), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut()) };
        if h != INVALID_HANDLE_VALUE {
            return Some(unsafe { std::fs::File::from_raw_handle(h as RawHandle) });
        }
        // SAFETY: no arguments.
        match unsafe { GetLastError() } {
            ERROR_PIPE_BUSY => unsafe {
                WaitNamedPipeW(w.as_ptr(), 500);
            },
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    None
}

// ---------- the app's side ----------

/// How the helper is started: elevated for real, a plain process or thread in tests.
pub trait Launcher: Send + Sync {
    /// Start the helper with these arguments; the process handle, or Declined.
    fn launch(&self, exe: &Path, args: &str) -> Result<OwnedHandle, Launch>;
}

/// Why there is no helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launch {
    /// The user said no at the UAC prompt.
    Declined,
    Failed(String),
}

/// `ShellExecuteExW` with the "runas" verb: one UAC prompt.
pub struct Elevated;

impl Launcher for Elevated {
    fn launch(&self, exe: &Path, args: &str) -> Result<OwnedHandle, Launch> {
        use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
        use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
        let verb = crate::host::wide("runas");
        let file = crate::host::wide_path(exe);
        let params = crate::host::wide(args);
        // SAFETY: COM for the shell on this (worker) thread; a filled-in struct; the process
        // handle comes back ours to close.
        unsafe {
            CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                let e = GetLastError();
                return Err(if e == ERROR_CANCELLED { Launch::Declined } else { Launch::Failed(format!("Windows did not start the firewall helper ({})", std::io::Error::from_raw_os_error(e as i32))) });
            }
            if info.hProcess.is_null() {
                return Err(Launch::Failed("Windows started the firewall helper without a handle to it".into()));
            }
            Ok(OwnedHandle::from_raw_handle(info.hProcess as RawHandle))
        }
    }
}

/// The helper at work for the app (the server's rules exist while this lives).
pub struct Session {
    pipe: OwnedHandle,
    process: OwnedHandle,
    pub reply: Reply,
}

/// The app's end of the pipe: a random name, the current user (and elevated admins) only, one
/// instance, local clients only, overlapped (every wait has a deadline).
fn make_pipe() -> Result<(OwnedHandle, String), String> {
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
    let sid = firewall::user_sid();
    if sid.is_empty() {
        return Err("this account's identity could not be read".into());
    }
    let sddl = crate::host::wide(&format!("D:P(A;;GA;;;{sid})(A;;GA;;;BA)"));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string; the descriptor is freed with LocalFree below.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
        return Err("the pipe's permissions could not be made".into());
    }
    let mut id = [0u8; 16];
    crate::host::random_bytes(&mut id);
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let name = crate::host::wide(&pipe_path(&id));
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    // SAFETY: a NUL-terminated name and the attributes above; the handle is ours.
    let h = unsafe {
        CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, &sa)
    };
    // SAFETY: allocated by the conversion above.
    unsafe { LocalFree(sd as HLOCAL) };
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("the helper's pipe could not be made ({})", std::io::Error::last_os_error()));
    }
    Ok((unsafe { OwnedHandle::from_raw_handle(h as RawHandle) }, id))
}

/// One overlapped read or write on the app's pipe, done within `timeout` or cancelled.
fn ov_io(h: HANDLE, buf: &mut [u8], write: bool, timeout: Duration) -> Result<usize, String> {
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    // SAFETY: an event for this operation, closed by the OwnedHandle; the OVERLAPPED and the
    // buffer outlive the operation (it is complete or cancelled-and-complete before return).
    unsafe {
        let ev = OwnedHandle::from_raw_handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) as RawHandle);
        let mut ov: OVERLAPPED = std::mem::zeroed();
        ov.hEvent = ev.as_raw_handle() as HANDLE;
        let mut n = 0u32;
        let ok = if write { WriteFile(h, buf.as_ptr(), buf.len() as u32, &mut n, &mut ov) } else { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, &mut ov) };
        if ok == 0 && GetLastError() != ERROR_IO_PENDING {
            return Err(format!("the pipe failed ({})", std::io::Error::last_os_error()));
        }
        if GetOverlappedResultEx(h, &ov, &mut n, timeout.as_millis().min(u32::MAX as u128 - 1) as u32, 0) == 0 {
            let e = GetLastError();
            if e == WAIT_TIMEOUT || e == ERROR_IO_INCOMPLETE {
                CancelIoEx(h, &ov);
                GetOverlappedResultEx(h, &ov, &mut n, INFINITE, 0);
                return Err("the helper did not answer in time".into());
            }
            return Err(format!("the pipe failed ({})", std::io::Error::from_raw_os_error(e as i32)));
        }
        Ok(n as usize)
    }
}

fn read_reply(h: HANDLE, timeout: Duration) -> Result<Reply, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut out = Vec::new();
    let mut b = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err("the helper did not answer in time".into());
        }
        let n = ov_io(h, &mut b, false, left)?;
        if n == 0 {
            return Err("the helper closed the pipe".into());
        }
        out.extend_from_slice(&b[..n]);
        if let Some(i) = out.iter().position(|c| *c == b'\n') {
            return parse_reply(std::str::from_utf8(&out[..i]).map_err(|_| "the helper's answer is not text")?);
        }
        if out.len() > MAX_LINE {
            return Err("the helper's answer is too long".into());
        }
    }
}

/// Start the helper and give it its job: the session when the rules are in, else why not.
/// Blocks (the UAC prompt, then up to 15 s): call it on a worker.
pub fn start(launcher: &dyn Launcher, exe: &Path, req: &Request) -> Result<Session, Launch> {
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let (pipe, id) = make_pipe().map_err(Launch::Failed)?;
    let h = pipe.as_raw_handle() as HANDLE;
    // Listen before launching: the helper may connect at once.
    // SAFETY: an event for the connect, closed by the OwnedHandle; the OVERLAPPED lives until
    // the connect completed or was cancelled.
    let ev = unsafe { OwnedHandle::from_raw_handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) as RawHandle) };
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = ev.as_raw_handle() as HANDLE;
    let pending = unsafe {
        if ConnectNamedPipe(h, &mut ov) != 0 {
            false
        } else {
            match GetLastError() {
                ERROR_IO_PENDING => true,
                ERROR_PIPE_CONNECTED => false,
                e => return Err(Launch::Failed(format!("the helper's pipe failed ({})", std::io::Error::from_raw_os_error(e as i32)))),
            }
        }
    };
    let process = match launcher.launch(exe, &format!("{ARG} {id} {}", std::process::id())) {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: cancel our own pending connect and let it complete.
            unsafe {
                CancelIoEx(h, &ov);
                let mut n = 0;
                GetOverlappedResultEx(h, &ov, &mut n, INFINITE, 0);
            }
            return Err(e);
        }
    };
    if pending {
        let handles = [ev.as_raw_handle() as HANDLE, process.as_raw_handle() as HANDLE];
        // SAFETY: two valid handles; a bounded wait.
        let w = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, CONNECT_TIMEOUT.as_millis() as u32) };
        if w != WAIT_OBJECT_0 {
            unsafe {
                CancelIoEx(h, &ov);
                let mut n = 0;
                GetOverlappedResultEx(h, &ov, &mut n, INFINITE, 0);
            }
            return Err(Launch::Failed(if w == WAIT_OBJECT_0 + 1 { "the firewall helper ended before it connected".into() } else { "the firewall helper did not connect in time".into() }));
        }
    }
    // Only the process we launched, running this very exe, may be the client.
    // SAFETY: our process handle.
    let theirs = unsafe { GetProcessId(process.as_raw_handle() as HANDLE) };
    let own = crate::host::own_exe().unwrap_or_default();
    if !client_is(h, theirs, &own) {
        return Err(Launch::Failed("something other than the firewall helper connected to its pipe".into()));
    }
    let mut msg = line(req);
    ov_io(h, &mut msg, true, Duration::from_secs(5)).map_err(Launch::Failed)?;
    let reply = read_reply(h, Duration::from_secs(30)).map_err(Launch::Failed)?;
    if !reply.ok {
        return Err(Launch::Failed(if reply.error.is_empty() { "the firewall helper could not change the rules".into() } else { reply.error.clone() }));
    }
    Ok(Session { pipe, process, reply })
}

impl Session {
    /// Whether the helper is still there (it may have been ended from outside).
    pub fn alive(&self) -> bool {
        let mut avail = 0u32;
        // SAFETY: our handles; peek reads nothing.
        unsafe {
            WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 0) == WAIT_TIMEOUT
                && PeekNamedPipe(self.pipe.as_raw_handle() as HANDLE, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) != 0
        }
    }

    /// Tests: drop the helper's end of the pipe (what the app sees of a killed helper).
    #[doc(hidden)]
    pub fn disconnect(&self) {
        // SAFETY: our own pipe handle.
        unsafe { DisconnectNamedPipe(self.pipe.as_raw_handle() as HANDLE) };
    }

    /// Tell the helper to remove the rules and leave; its answer (or why there is none).
    pub fn close(self) -> Result<Reply, String> {
        let h = self.pipe.as_raw_handle() as HANDLE;
        let mut msg = line(&Request { op: "close".into(), port: 0, remove_blocks: false });
        ov_io(h, &mut msg, true, Duration::from_secs(5))?;
        let r = read_reply(h, Duration::from_secs(15));
        // SAFETY: our process handle; a bounded wait for the helper to leave.
        unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 5000) };
        r
    }
}
