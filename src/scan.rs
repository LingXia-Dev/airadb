use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::error::Result;
use crate::packet::{read_packet, write_packet, AdbPacket, A_AUTH, A_CNXN, A_VERSION_SKIP_CHECKSUM};

/// Default TCP port for standard ADB daemon.
pub const DEFAULT_ADB_PORT: u16 = 5555;

/// Default list of TCP ports probed during network scan.
/// 5555 is standard Android adbd; 9527 is commonly used on Smart TV / OTT boxes (e.g. Hisilicon);
/// 5566 is commonly used for secondary debug ports / emulator / cloud devices (aligned with mukeinstall).
pub const DEFAULT_ADB_PORTS: &[u16] = &[5555, 9527, 5566];

/// Information about a discovered ADB device on the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    /// The target network address (IP and port).
    pub addr: SocketAddr,
    /// Product model name (if reported in banner without authentication), e.g. "MiTV" or "Nexus 5".
    pub model: Option<String>,
    /// Product name (if reported in banner).
    pub product: Option<String>,
    /// Device hardware name (if reported in banner).
    pub device: Option<String>,
    /// Raw banner string returned by the device.
    pub banner: String,
    /// Whether the device is already authorized or needs key authentication.
    pub authorized: bool,
}

/// Options controlling network scanning for ADB devices.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Subnet or IP prefix to scan (e.g. "192.168.1" or "192.168.1.0/24").
    /// If None, automatically detects the local IPv4 subnet.
    pub subnet: Option<String>,
    /// Explicit list of candidate IP addresses to probe. Overrides `subnet` if provided.
    pub candidates: Option<Vec<Ipv4Addr>>,
    /// Ports to probe on each candidate IP. Defaults to `[5555, 9527]`.
    pub ports: Vec<u16>,
    /// Timeout for each connection and probe attempt. Defaults to 800ms.
    pub timeout: Duration,
    /// Maximum concurrent TCP probes to run simultaneously. Defaults to 96.
    pub concurrency: usize,
    /// Whether to perform mDNS multicast discovery (`_adb._tcp.local`). Defaults to true.
    pub mdns: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            subnet: None,
            candidates: None,
            ports: DEFAULT_ADB_PORTS.to_vec(),
            timeout: Duration::from_millis(800),
            concurrency: 96,
            mdns: true,
        }
    }
}

/// Detects the local host's IPv4 address by querying the routing table via a dummy UDP socket.
///
/// This does NOT send any packets on the wire, making it completely non-intrusive
/// and compatible with iOS, Android, HarmonyOS, macOS, and Linux sandboxes.
pub fn detect_local_ipv4() -> Option<Ipv4Addr> {
    // 1. First probe multicast (224.0.0.1:80), which routes to the physical Wi-Fi/LAN interface
    //    and correctly bypasses point-to-point VPN/TUN tunnels (which don't handle multicast).
    for probe in &["224.0.0.1:80", "239.255.255.250:80", "8.8.8.8:80"] {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(probe).is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    if let IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                            return Some(ipv4);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Parses an IP prefix string (e.g. "192.168.1", "192.168.1.0/24", "192.168.1.5")
/// and returns the list of 254 candidate host IPs (1..=254) or a single IP.
pub fn parse_subnet_candidates(prefix_or_cidr: &str) -> Option<Vec<Ipv4Addr>> {
    let trimmed = prefix_or_cidr.trim().trim_end_matches('/');
    // Check if it's a CIDR like "192.168.1.0/24"
    let base = if let Some((cidr_ip, mask)) = trimmed.split_once('/') {
        if mask != "24" {
            // For now, support /24 subnets which are standard in home/office Wi-Fi
            return None;
        }
        cidr_ip
    } else {
        trimmed
    };

    let parts: Vec<&str> = base.split('.').collect();
    match parts.len() {
        3 => {
            let a: u8 = parts[0].parse().ok()?;
            let b: u8 = parts[1].parse().ok()?;
            let c: u8 = parts[2].parse().ok()?;
            Some((1..=254).map(|d| Ipv4Addr::new(a, b, c, d)).collect())
        }
        4 => {
            let a: u8 = parts[0].parse().ok()?;
            let b: u8 = parts[1].parse().ok()?;
            let c: u8 = parts[2].parse().ok()?;
            let d: u8 = parts[3].parse().ok()?;
            if d == 0 {
                // e.g. "192.168.1.0"
                Some((1..=254).map(|host| Ipv4Addr::new(a, b, c, host)).collect())
            } else {
                // Exact single IP
                Some(vec![Ipv4Addr::new(a, b, c, d)])
            }
        }
        _ => None,
    }
}

/// Helper to parse ADB banner properties such as `ro.product.model=...`.
fn parse_banner_props(banner: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut model = None;
    let mut product = None;
    let mut device = None;

    let props_str = banner.split_once("::").map(|(_, rest)| rest).unwrap_or(banner);

    for part in props_str.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            match k {
                "ro.product.model" => model = Some(v.to_string()),
                "ro.product.name" => product = Some(v.to_string()),
                "ro.product.device" => device = Some(v.to_string()),
                _ => {}
            }
        }
    }

    (model, product, device)
}

/// Probes a single target `addr` over TCP, sending an ADB `A_CNXN` handshake packet
/// to verify whether an actual ADB daemon is listening.
///
/// Returns `Some(DiscoveredDevice)` if the target responds with `A_CNXN` or `A_AUTH`.
pub async fn probe_adb_device(addr: SocketAddr, timeout_dur: Duration) -> Option<DiscoveredDevice> {
    // 1. Establish TCP connection with timeout
    let mut stream = timeout(timeout_dur, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let _ = stream.set_nodelay(true);

    // 2. Send initial A_CNXN packet
    let connect_banner = b"host::features=cmd\0".to_vec();
    let init_packet = AdbPacket::new(
        A_CNXN,
        A_VERSION_SKIP_CHECKSUM,
        256 * 1024,
        connect_banner,
    );

    timeout(timeout_dur, write_packet(&mut stream, &init_packet))
        .await
        .ok()?
        .ok()?;

    // 3. Await ADB response packet
    let response = timeout(timeout_dur, read_packet(&mut stream, false))
        .await
        .ok()?
        .ok()?;

    if response.command == A_CNXN {
        let banner = String::from_utf8_lossy(&response.payload).to_string();
        let (model, product, device) = parse_banner_props(&banner);
        Some(DiscoveredDevice {
            addr,
            model,
            product,
            device,
            banner,
            authorized: true,
        })
    } else if response.command == A_AUTH {
        Some(DiscoveredDevice {
            addr,
            model: None,
            product: None,
            device: None,
            banner: String::new(),
            authorized: false,
        })
    } else {
        None
    }
}

/// Builds a DNS PTR query packet for an mDNS service name (e.g. `_adb._tcp.local`).
fn build_mdns_ptr_query(service_name: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&[0x00, 0x00]); // ID 0
    packet.extend_from_slice(&[0x00, 0x00]); // Standard query
    packet.extend_from_slice(&[0x00, 0x01]); // 1 Question
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Answers/Auth/Add = 0

    for label in service_name.split('.') {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0x00); // Root label

    packet.extend_from_slice(&[0x00, 0x0c]); // Type: PTR (12)
    packet.extend_from_slice(&[0x00, 0x01]); // Class: IN (1)
    packet
}

/// Helper to advance past a DNS name label sequence (supporting DNS compression pointers).
fn skip_dns_name(buf: &[u8], mut idx: usize) -> Option<usize> {
    let mut jumped = false;
    let mut ret_idx = idx;
    let mut count = 0;
    while idx < buf.len() && count < 64 {
        count += 1;
        let len = buf[idx];
        if len == 0 {
            if !jumped {
                ret_idx = idx + 1;
            }
            return Some(ret_idx);
        } else if (len & 0xc0) == 0xc0 {
            if idx + 2 > buf.len() {
                return None;
            }
            if !jumped {
                ret_idx = idx + 2;
            }
            jumped = true;
            let ptr = (((len as u16 & 0x3f) << 8) | buf[idx + 1] as u16) as usize;
            idx = ptr;
        } else {
            let label_len = len as usize;
            idx += 1 + label_len;
            if !jumped {
                ret_idx = idx;
            }
        }
    }
    None
}

/// Parses an mDNS response packet, extracting SRV ports and A record IPv4 addresses.
pub fn parse_mdns_response(buf: &[u8], peer_ip: Ipv4Addr) -> Vec<SocketAddr> {
    if buf.len() < 12 {
        return Vec::new();
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut idx = 12;
    for _ in 0..qdcount {
        idx = match skip_dns_name(buf, idx) {
            Some(i) => i,
            None => return Vec::new(),
        };
        if idx + 4 > buf.len() {
            return Vec::new();
        }
        idx += 4;
    }

    let total_rrs = ancount + nscount + arcount;
    let mut srv_ports = Vec::new();
    let mut a_ips = Vec::new();

    for _ in 0..total_rrs {
        if idx >= buf.len() {
            break;
        }
        idx = match skip_dns_name(buf, idx) {
            Some(i) => i,
            None => break,
        };
        if idx + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let rdlen = u16::from_be_bytes([buf[idx + 8], buf[idx + 9]]) as usize;
        idx += 10;
        if idx + rdlen > buf.len() {
            break;
        }
        let rdata = &buf[idx..idx + rdlen];
        idx += rdlen;

        if rtype == 33 && rdlen >= 6 {
            // SRV record: priority(2), weight(2), port(2)
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            if port > 0 && !srv_ports.contains(&port) {
                srv_ports.push(port);
            }
        } else if rtype == 1 && rdlen == 4 {
            // A record
            let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            if !a_ips.contains(&ip) {
                a_ips.push(ip);
            }
        }
    }

    let ips = if !a_ips.is_empty() {
        a_ips
    } else {
        vec![peer_ip]
    };

    let mut endpoints = Vec::new();
    for ip in ips {
        for &port in &srv_ports {
            endpoints.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    endpoints
}

/// Discovers ADB device endpoints on the local network via mDNS multicast (`224.0.0.251:5353`).
pub async fn discover_mdns_adb_endpoints(timeout_dur: Duration) -> Vec<SocketAddr> {
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let multicast_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    let query_plain = build_mdns_ptr_query("_adb._tcp.local");
    let query_tls = build_mdns_ptr_query("_adb-tls-connect._tcp.local");

    let _ = socket.send_to(&query_plain, multicast_addr).await;
    let _ = socket.send_to(&query_tls, multicast_addr).await;

    let mut discovered = HashSet::new();
    let deadline = tokio::time::Instant::now() + timeout_dur;
    let mut buf = [0u8; 4096];

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, peer_addr))) => {
                if let IpAddr::V4(ipv4) = peer_addr.ip() {
                    let endpoints = parse_mdns_response(&buf[..len], ipv4);
                    for ep in endpoints {
                        discovered.insert(ep);
                    }
                }
            }
            _ => break,
        }
    }

    discovered.into_iter().collect()
}

/// Scans the network for active ADB devices according to `options`.
///
/// Combines mDNS multicast discovery with concurrent TCP probing bounded by `options.concurrency`
/// and returns all responsive ADB devices.
pub async fn scan_devices(options: ScanOptions) -> Result<Vec<DiscoveredDevice>> {
    let mut candidate_addrs = HashSet::new();

    // 1. Run mDNS discovery if enabled and candidates is not explicitly constrained
    if options.mdns && options.candidates.is_none() {
        let mdns_endpoints = discover_mdns_adb_endpoints(Duration::from_millis(500)).await;
        for ep in mdns_endpoints {
            // If subnet is specified, only include endpoints matching that subnet
            if let Some(ref subnet_str) = options.subnet {
                if let Some(valid_ips) = parse_subnet_candidates(subnet_str) {
                    if let IpAddr::V4(ipv4) = ep.ip() {
                        if !valid_ips.contains(&ipv4) {
                            continue;
                        }
                    }
                }
            }
            candidate_addrs.insert(ep);
        }
    }

    // 2. Add candidates from subnet / IP candidate list
    let candidate_ips = if let Some(candidates) = options.candidates {
        candidates
    } else if let Some(ref subnet_str) = options.subnet {
        parse_subnet_candidates(subnet_str).unwrap_or_default()
    } else if let Some(local_ip) = detect_local_ipv4() {
        let octets = local_ip.octets();
        (1..=254)
            .map(|host| Ipv4Addr::new(octets[0], octets[1], octets[2], host))
            .collect()
    } else {
        Vec::new()
    };

    let ports = if options.ports.is_empty() {
        DEFAULT_ADB_PORTS.to_vec()
    } else {
        options.ports
    };

    for ip in candidate_ips {
        for &port in &ports {
            candidate_addrs.insert(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }

    if candidate_addrs.is_empty() {
        return Ok(Vec::new());
    }

    let semaphore = Arc::new(Semaphore::new(options.concurrency));
    let mut tasks = Vec::with_capacity(candidate_addrs.len());

    for addr in candidate_addrs {
        let sem = semaphore.clone();
        let timeout_dur = options.timeout;

        tasks.push(tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return None,
            };
            probe_adb_device(addr, timeout_dur).await
        }));
    }

    let mut discovered = Vec::new();
    for task in tasks {
        if let Ok(Some(device)) = task.await {
            discovered.push(device);
        }
    }

    // Sort by IP address and port for deterministic output
    discovered.sort_by_key(|d| d.addr);
    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subnet_candidates() {
        let ips = parse_subnet_candidates("192.168.1").unwrap();
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));

        let ips2 = parse_subnet_candidates("192.168.2.0/24").unwrap();
        assert_eq!(ips2.len(), 254);
        assert_eq!(ips2[0], Ipv4Addr::new(192, 168, 2, 1));

        let single = parse_subnet_candidates("10.0.0.15").unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0], Ipv4Addr::new(10, 0, 0, 15));
    }

    #[test]
    fn test_parse_banner_props() {
        let banner = "device::ro.product.name=hammerhead;ro.product.model=Nexus 5;ro.product.device=hammerhead;features=cmd";
        let (model, product, device) = parse_banner_props(banner);
        assert_eq!(model.as_deref(), Some("Nexus 5"));
        assert_eq!(product.as_deref(), Some("hammerhead"));
        assert_eq!(device.as_deref(), Some("hammerhead"));
    }
}
