//! What Windows' TCP stack knows about a connection (`WSAIoctl(SIO_TCP_INFO)`, version 0,
//! Windows 10 1703 and later): round trip, congestion window, the windows both ways, and the
//! bytes it sent again. Windows counts retransmitted *bytes*, not segments, so that is what
//! VibePerf shows (never a made-up segment count).

use std::os::windows::io::AsRawSocket;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpInfo {
    pub mss: u32,
    pub rtt_us: u32,
    pub cwnd: u32,
    /// The peer's receive window, as this side sends into it.
    pub snd_wnd: u32,
    /// This side's receive window, as it advertises it.
    pub rcv_wnd: u32,
    pub bytes_out: u64,
    pub bytes_retrans: u32,
    pub fast_retrans: u32,
    pub timeout_episodes: u32,
}

/// The connection's numbers now, or None where Windows does not say (older Windows, a socket
/// already closed).
pub fn read(s: &impl AsRawSocket) -> Option<TcpInfo> {
    use windows_sys::Win32::Networking::WinSock::{SIO_TCP_INFO, SOCKET, TCP_INFO_v0, WSAIoctl};
    let version: u32 = 0;
    // SAFETY: a zeroed plain struct as the output.
    let mut info: TCP_INFO_v0 = unsafe { std::mem::zeroed() };
    let mut got = 0u32;
    // SAFETY: input and output buffers of the sizes given; a synchronous call (no overlapped).
    let r = unsafe {
        WSAIoctl(
            s.as_raw_socket() as SOCKET,
            SIO_TCP_INFO,
            (&version as *const u32).cast(),
            4,
            (&mut info as *mut TCP_INFO_v0).cast(),
            std::mem::size_of::<TCP_INFO_v0>() as u32,
            &mut got,
            std::ptr::null_mut(),
            None,
        )
    };
    if r != 0 || (got as usize) < std::mem::size_of::<TCP_INFO_v0>() {
        return None;
    }
    Some(TcpInfo {
        mss: info.Mss,
        rtt_us: info.RttUs,
        cwnd: info.Cwnd,
        snd_wnd: info.SndWnd,
        rcv_wnd: info.RcvWnd,
        bytes_out: info.BytesOut,
        bytes_retrans: info.BytesRetrans,
        fast_retrans: info.FastRetrans,
        timeout_episodes: info.TimeoutEpisodes,
    })
}

/// Retransmitted bytes between two readings (the counter is 32 bits wide and may wrap).
pub fn retrans_since(before: u32, now: u32) -> u64 {
    now.wrapping_sub(before) as u64
}

/// A receive window that stayed at 64 KiB or less in every reading of a test is the sign of
/// auto-tuning switched off (`netsh int tcp set global autotuninglevel=disabled`). Needs a few
/// readings: one at the very start says nothing.
pub fn window_stuck(readings: &[u32]) -> bool {
    readings.len() >= 3 && readings.iter().all(|w| *w > 0 && *w <= 65_535)
}
