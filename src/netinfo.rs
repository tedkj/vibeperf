//! What this computer's network looks like from here: the addresses to tell a client ("Reach
//! me at"), the adapter and link speed a peer is reached through, the gateway on the way, and
//! the target a user typed (host, IPv4, IPv6 with a zone, an optional port), resolved off the
//! window's thread.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET};

/// Text from the system or the network as it may be shown: no control characters, no
/// bidirectional controls or invisible characters (they make a name read as another), at most
/// 255 characters. U+200C and U+200D stay (emoji and many scripts need them).
pub fn clean(s: &str) -> String {
    s.chars().filter(|c| !invisible(*c)).take(255).collect::<String>().trim().to_string()
}

/// Characters that change how the text around them reads without showing themselves: controls,
/// bidirectional embeddings, overrides, isolates and marks, zero-width spaces and line
/// separators, the soft hyphen and the Unicode tag characters (U+E0000..U+E007F). The joiners
/// U+200C (ZWNJ) and U+200D (ZWJ) are not among them: emoji sequences and Persian, Arabic and
/// Indic names need them (family rule, 2026-10-20). VibeTemplate's text.rs, as is.
pub fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

// ---------- the target as typed ----------

/// A target from the host field or the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The host or address, without brackets, zone or port.
    pub host: String,
    /// An IPv6 zone ("12" or "Ethernet").
    pub zone: Option<String>,
    /// A port written with the host ("host:5202", "[::1]:5202").
    pub port: Option<u16>,
}

impl Target {
    /// As it is shown and remembered: "server.lan", "192.168.1.20", "fe80::1%12".
    pub fn text(&self) -> String {
        match &self.zone {
            Some(z) => format!("{}%{z}", self.host),
            None => self.host.clone(),
        }
    }
}

/// The one way in for a target (field, recent list, command line): trims spaces and quotes,
/// takes "[v6]:port", "[v6]", "v6%zone", "host:port", and refuses what cannot be a host.
pub fn parse_target(text: &str) -> Result<Target, String> {
    let t = text.trim().trim_matches('"').trim();
    if t.is_empty() {
        return Err("Type a host name or an address.".into());
    }
    let (body, port) = if let Some(rest) = t.strip_prefix('[') {
        let end = rest.find(']').ok_or("A [ without its ].")?;
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(parse_port(p)?),
            None if after.is_empty() => None,
            None => return Err(format!("\"{}\" after the address is not a port.", clean(after))),
        };
        (&rest[..end], port)
    } else if t.matches(':').count() == 1 {
        let (h, p) = t.split_once(':').unwrap_or((t, ""));
        (h, Some(parse_port(p)?))
    } else {
        (t, None)
    };
    let (host, zone) = match body.split_once('%') {
        Some((h, z)) if !z.is_empty() => (h, Some(z.to_string())),
        Some(_) => return Err("A % without a zone after it.".into()),
        None => (body, None),
    };
    if host.is_empty() {
        return Err("Type a host name or an address.".into());
    }
    if zone.is_some() && host.parse::<Ipv6Addr>().is_err() {
        return Err("Only an IPv6 address takes a zone (%).".into());
    }
    if host.contains(':') && host.parse::<Ipv6Addr>().is_err() {
        return Err(format!("{} is not an IPv6 address.", clean(host)));
    }
    let ok = |c: char| c.is_alphanumeric() || "-._:".contains(c);
    if !host.chars().all(ok) || host.len() > 253 {
        return Err(format!("{} is not a host name or an address.", clean(host)));
    }
    Ok(Target { host: host.to_string(), zone, port })
}

pub fn parse_port(p: &str) -> Result<u16, String> {
    match p.trim().parse::<u32>() {
        Ok(n) if (1..=65_535).contains(&n) => Ok(n as u16),
        _ => Err(format!("\"{}\" is not a port (1 to 65535).", clean(p))),
    }
}

/// An interface zone ("12" or "Ethernet") as its index.
fn zone_index(zone: &str) -> Result<u32, String> {
    if let Ok(n) = zone.parse::<u32>() {
        return Ok(n);
    }
    let w = crate::host::wide(zone);
    // SAFETY: a NUL-terminated alias and out values.
    let mut luid: windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH = unsafe { std::mem::zeroed() };
    let mut index = 0u32;
    let ok = unsafe { ConvertInterfaceAliasToLuid(w.as_ptr(), &mut luid) == 0 && ConvertInterfaceLuidToIndex(&luid, &mut index) == 0 };
    if ok { Ok(index) } else { Err(format!("This computer has no network adapter called {}.", clean(zone))) }
}

/// The addresses a target stands for, in the order the system prefers them. Blocks (DNS): call
/// it on a worker.
pub fn resolve(t: &Target, port: u16) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = t.host.parse::<IpAddr>() {
        let a = match (ip, &t.zone) {
            (IpAddr::V6(v6), Some(z)) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, zone_index(z)?)),
            _ => SocketAddr::new(ip, port),
        };
        return Ok(vec![a]);
    }
    match (t.host.as_str(), port).to_socket_addrs() {
        Ok(list) => {
            let v: Vec<SocketAddr> = list.collect();
            if v.is_empty() { Err(format!("{} has no address.", clean(&t.host))) } else { Ok(v) }
        }
        Err(_) => Err(format!("{} was not found (DNS).", clean(&t.host))),
    }
}

// ---------- socket addresses ----------

/// An address from a SOCKADDR the system wrote.
///
/// # Safety
/// `p` is null or points at a SOCKADDR of its family's length.
pub unsafe fn sockaddr_ip(p: *const SOCKADDR) -> Option<(IpAddr, u32)> {
    if p.is_null() {
        return None;
    }
    // SAFETY: as the caller promises.
    unsafe {
        match (*p).sa_family {
            AF_INET => {
                let a = &*(p as *const SOCKADDR_IN);
                Some((IpAddr::from(a.sin_addr.S_un.S_addr.to_ne_bytes()), 0))
            }
            AF_INET6 => {
                let a = &*(p as *const SOCKADDR_IN6);
                Some((IpAddr::from(a.sin6_addr.u.Byte), a.Anonymous.sin6_scope_id))
            }
            _ => None,
        }
    }
}

fn inet(a: &SocketAddr) -> SOCKADDR_INET {
    // SAFETY: a plain union, zeroed, then the family's fields set.
    let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match a {
        SocketAddr::V4(v4) => {
            s.Ipv4.sin_family = AF_INET;
            s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            s.Ipv6.sin6_family = AF_INET6;
            s.Ipv6.sin6_addr.u.Byte = v6.ip().octets();
            s.Ipv6.Anonymous.sin6_scope_id = v6.scope_id();
        }
    }
    s
}

// ---------- adapters ----------

/// One address of an adapter that is up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Local {
    pub index: u32,
    /// "Ethernet", "Wi-Fi".
    pub adapter: String,
    pub ip: IpAddr,
    pub gateway: Option<IpAddr>,
}

/// Every address of every adapter that is up (no loopback, no IPv6 link-local or temporary
/// address: a client cannot use those without more help).
pub fn locals() -> Result<Vec<Local>, String> {
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::IpSuffixOriginRandom;
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: an 8-byte aligned buffer of `size` bytes; the API fills a linked list inside it.
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast(), &mut size) };
        match r {
            0 => break,
            111 if tries < 4 => tries += 1,
            232 => return Ok(Vec::new()),
            e => return Err(format!("Windows did not list the network adapters (error {e}).")),
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        // SAFETY: a node of the list GetAdaptersAddresses wrote into `buf`, alive in this loop.
        let a = unsafe { &*p };
        p = a.Next;
        if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        let adapter = clean(&unsafe { wide_str(a.FriendlyName) });
        let mut gw4 = None;
        let mut gw6 = None;
        let mut g = a.FirstGatewayAddress;
        while !g.is_null() {
            // SAFETY: as above.
            let ga = unsafe { &*g };
            match unsafe { sockaddr_ip(ga.Address.lpSockaddr) } {
                Some((ip @ IpAddr::V4(_), _)) => {
                    gw4.get_or_insert(ip);
                }
                Some((ip @ IpAddr::V6(_), _)) => {
                    gw6.get_or_insert(ip);
                }
                None => {}
            }
            g = ga.Next;
        }
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: as above.
            let ua = unsafe { &*u };
            u = ua.Next;
            let Some((ip, _)) = (unsafe { sockaddr_ip(ua.Address.lpSockaddr) }) else { continue };
            let skip = match ip {
                IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || ua.SuffixOrigin == IpSuffixOriginRandom,
            };
            if !skip {
                let gateway = if ip.is_ipv4() { gw4 } else { gw6 };
                out.push(Local { index, adapter: adapter.clone(), ip, gateway });
            }
        }
    }
    // IPv4 first, then IPv6; within each the system's order.
    out.sort_by_key(|l| l.ip.is_ipv6());
    Ok(out)
}

/// # Safety
/// `p` is null or a NUL-terminated UTF-16 string.
unsafe fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: as the caller promises.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// The adapter a peer is reached through, and its link.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    /// "Ethernet", "Wi-Fi" (the kind), or the adapter's name for other kinds.
    pub kind: String,
    pub tx_bps: u64,
    pub rx_bps: u64,
    /// The next hop toward the peer (None: the peer is on this link).
    pub next_hop: Option<(IpAddr, u32)>,
}

impl Link {
    /// "Ethernet, 1 Gbps link"; "Wi-Fi, 866 / 1201 Mbps link" (send / receive) when they differ.
    pub fn text(&self) -> String {
        if self.kind == "Loopback" {
            return "Loopback (this computer)".into();
        }
        let known = |b: u64| b > 0 && b != u64::MAX;
        match (known(self.tx_bps), known(self.rx_bps)) {
            (true, true) if self.tx_bps != self.rx_bps => format!("{}, {} / {} link", self.kind, speed(self.tx_bps), speed(self.rx_bps)),
            (true, _) => format!("{}, {} link", self.kind, speed(self.tx_bps)),
            (false, true) => format!("{}, {} link", self.kind, speed(self.rx_bps)),
            _ => format!("{}, link speed unknown", self.kind),
        }
    }
}

/// "1 Gbps", "2.5 Gbps", "100 Mbps", "866.7 Mbps": the link's own figure, never rounded up.
pub fn speed(bps: u64) -> String {
    // Whole numbers only: `units` of 10^-`places` of the unit, cut (never rounded) and shown
    // without trailing zeros.
    let fixed = |units: u64, places: u32| {
        let p = 10u64.pow(places);
        let (whole, frac) = (units / p, units % p);
        if frac == 0 {
            whole.to_string()
        } else {
            let f = format!("{frac:0width$}", width = places as usize);
            format!("{whole}.{}", f.trim_end_matches('0'))
        }
    };
    if bps >= 1_000_000_000 {
        format!("{} Gbps", fixed(bps / 10_000_000, 2))
    } else if bps >= 1_000_000 {
        format!("{} Mbps", fixed(bps / 100_000, 1))
    } else {
        format!("{} kbps", bps / 1000)
    }
}

/// The interface and link a peer is reached through (`GetBestRoute2`, `GetIfEntry2`): no
/// packet is sent.
pub fn link_to(peer: &SocketAddr) -> Option<Link> {
    if peer.ip().is_loopback() {
        return Some(Link { kind: "Loopback".into(), ..Link::default() });
    }
    let dst = inet(peer);
    // SAFETY: plain out structs; null source and LUID (the system picks).
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut src: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    let r = unsafe { GetBestRoute2(std::ptr::null(), 0, std::ptr::null(), &dst, 0, &mut route, &mut src) };
    if r != 0 {
        return None;
    }
    // SAFETY: a plain struct with its index set, filled by the call.
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = route.InterfaceIndex;
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return None;
    }
    let alias = clean(&String::from_utf16_lossy(&row.Alias[..row.Alias.iter().position(|c| *c == 0).unwrap_or(row.Alias.len())]));
    let kind = match row.Type {
        IF_TYPE_ETHERNET_CSMACD => "Ethernet".to_string(),
        IF_TYPE_IEEE80211 => "Wi-Fi".to_string(),
        IF_TYPE_SOFTWARE_LOOPBACK => "Loopback".to_string(),
        _ if alias.is_empty() => "Network adapter".to_string(),
        _ => alias,
    };
    // SAFETY: the union's family says which member the call wrote.
    let hop = unsafe { sockaddr_ip((&route.NextHop as *const SOCKADDR_INET).cast()) }.filter(|(ip, _)| !ip.is_unspecified());
    Some(Link { index: route.InterfaceIndex, kind, tx_bps: row.TransmitLinkSpeed, rx_bps: row.ReceiveLinkSpeed, next_hop: hop })
}

/// The address this computer sends to `peer` from (`GetBestRoute2`'s source address).
pub fn source_for(peer: &SocketAddr) -> Option<IpAddr> {
    let dst = inet(peer);
    // SAFETY: plain out structs; null source and LUID (the system picks).
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut src: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    if unsafe { GetBestRoute2(std::ptr::null(), 0, std::ptr::null(), &dst, 0, &mut route, &mut src) } != 0 {
        return None;
    }
    // SAFETY: the union's family says which member the call wrote.
    unsafe { sockaddr_ip((&src as *const SOCKADDR_INET).cast()) }.map(|(ip, _)| ip).filter(|ip| !ip.is_unspecified())
}

/// The gateway to ping when the peer does not answer: the next hop toward the peer, or (for a
/// peer on the same link) that adapter's default gateway. Never the peer itself.
pub fn gateway_for(peer: &SocketAddr) -> Option<(IpAddr, u32)> {
    let link = link_to(peer)?;
    let gw = match link.next_hop {
        Some(h) => Some(h),
        None => locals().ok()?.into_iter().find(|l| l.index == link.index && l.ip.is_ipv4() == peer.is_ipv4()).and_then(|l| l.gateway).map(|g| (g, link.index)),
    };
    gw.filter(|(g, _)| *g != peer.ip())
}
