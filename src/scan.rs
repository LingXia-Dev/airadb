use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::error::Result;
use crate::packet::{read_packet, write_packet, AdbPacket, A_AUTH, A_CNXN, A_VERSION_SKIP_CHECKSUM};

/// Default TCP port for ADB daemon.
pub const DEFAULT_ADB_PORT: u16 = 5555;

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
    /// Ports to probe on each candidate IP. Defaults to `[5555]`.
    pub ports: Vec<u16>,
    /// Timeout for each connection and probe attempt. Defaults to 800ms.
    pub timeout: Duration,
    /// Maximum concurrent TCP probes to run simultaneously. Defaults to 96.
    pub concurrency: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            subnet: None,
            candidates: None,
            ports: vec![DEFAULT_ADB_PORT],
            timeout: Duration::from_millis(800),
            concurrency: 96,
        }
    }
}

/// Detects the local host's IPv4 address by querying the routing table via a dummy UDP socket.
///
/// This does NOT send any packets on the wire, making it completely non-intrusive
/// and compatible with iOS, Android, HarmonyOS, macOS, and Linux sandboxes.
pub fn detect_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // Connect to a public IP to determine default route interface (no packet sent)
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() || ipv4.is_unspecified() {
                None
            } else {
                Some(ipv4)
            }
        }
        _ => None,
    }
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

/// Scans the network for active ADB devices according to `options`.
///
/// Runs concurrent TCP probes bounded by `options.concurrency` and returns all
/// responsive ADB devices.
pub async fn scan_devices(options: ScanOptions) -> Result<Vec<DiscoveredDevice>> {
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

    if candidate_ips.is_empty() {
        return Ok(Vec::new());
    }

    let ports = if options.ports.is_empty() {
        vec![DEFAULT_ADB_PORT]
    } else {
        options.ports
    };

    let semaphore = Arc::new(Semaphore::new(options.concurrency));
    let mut tasks = Vec::with_capacity(candidate_ips.len() * ports.len());

    for ip in candidate_ips {
        for &port in &ports {
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
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
    }

    let mut discovered = Vec::new();
    for task in tasks {
        if let Ok(Some(device)) = task.await {
            discovered.push(device);
        }
    }

    // Sort by IP address for clean output
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
