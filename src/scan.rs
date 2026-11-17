use std::collections::{BTreeSet, HashSet};
use std::future::{Future, IntoFuture};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::error::{Error, ErrorKind, Result};
use crate::packet::{
    read_packet, write_packet, AdbPacket, A_AUTH, A_CNXN, A_VERSION_SKIP_CHECKSUM,
};
use crate::types::Subnet;

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
    /// The device answered with an auth challenge (it may still trust our
    /// key); `false` means it accepted the connection without one, or this
    /// client already holds a connection to it.
    pub auth_required: bool,
}

/// Helper to parse ADB banner properties such as `ro.product.model=...`.
fn parse_banner_props(banner: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut model = None;
    let mut product = None;
    let mut device = None;

    let props_str = banner
        .split_once("::")
        .map(|(_, rest)| rest)
        .unwrap_or(banner);

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
pub(crate) async fn probe_adb_device(
    addr: SocketAddr,
    timeout_dur: Duration,
) -> Option<DiscoveredDevice> {
    // 1. Establish TCP connection with timeout.
    // On lossy 2.4GHz WiFi (e.g. Android 5 TV boxes with 20% packet loss),
    // allowing at least ~1000-1200ms lets the OS kernel perform a native SYN retransmission
    // without flooding the wireless driver.
    let mut stream = timeout(timeout_dur, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let _ = stream.set_nodelay(true);

    // 2. Send initial A_CNXN packet
    let connect_banner = b"host::features=cmd\0".to_vec();
    let init_packet = AdbPacket::new(A_CNXN, A_VERSION_SKIP_CHECKSUM, 256 * 1024, connect_banner);

    let rw_timeout = Duration::from_millis(600).max(timeout_dur);
    timeout(rw_timeout, write_packet(&mut stream, &init_packet))
        .await
        .ok()?
        .ok()?;

    // 3. Await ADB response packet
    let response = timeout(rw_timeout, read_packet(&mut stream, false))
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
            auth_required: false,
        })
    } else if response.command == A_AUTH {
        Some(DiscoveredDevice {
            addr,
            model: None,
            product: None,
            device: None,
            banner: String::new(),
            auth_required: true,
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
    packet.extend_from_slice(&[0x80, 0x01]); // Class: IN (1) with QU (unicast-response) bit set
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
pub(crate) fn parse_mdns_response(buf: &[u8], peer_ip: Ipv4Addr) -> Vec<SocketAddr> {
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

    let ports = if !srv_ports.is_empty() {
        srv_ports
    } else {
        vec![DEFAULT_ADB_PORT]
    };

    let mut endpoints = Vec::new();
    for ip in ips {
        for &port in &ports {
            endpoints.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    endpoints
}

/// Discovery options. `.await` for the full list, or [`start`](Discover::start)
/// to receive devices as they answer. Probing sends a CNXN and reads the
/// reply; it never offers a key, so no device shows a dialog.
#[must_use = "discovery does nothing until awaited or started"]
pub struct Discover {
    subnets: BTreeSet<Subnet>,
    hosts: BTreeSet<Ipv4Addr>,
    ports: Vec<u16>,
    duration: Duration,
    probe_timeout: Duration,
    concurrency: usize,
    mdns: bool,
    /// Devices this client is connected to: reported once that connection
    /// answers, never probed (a single-client adbd would refuse the probe).
    live: Vec<crate::Device>,
}

impl Default for Discover {
    fn default() -> Self {
        Self::new()
    }
}

impl Discover {
    pub fn new() -> Self {
        Self {
            subnets: BTreeSet::new(),
            hosts: BTreeSet::new(),
            ports: DEFAULT_ADB_PORTS.to_vec(),
            duration: Duration::from_millis(5000),
            probe_timeout: Duration::from_millis(1200),
            concurrency: 256,
            mdns: true,
            live: Vec::new(),
        }
    }

    /// Sweep this subnet; may be repeated. Without subnets or hosts, the
    /// subnet of the default-route interface is swept.
    pub fn subnet(mut self, subnet: Subnet) -> Self {
        self.subnets.insert(subnet);
        self
    }

    /// Probe exactly these addresses (on every port).
    pub fn hosts(mut self, hosts: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        self.hosts.extend(hosts);
        self
    }

    /// Ports to probe on each host. Default 5555, 9527, 5566.
    pub fn ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.ports = ports.into_iter().collect();
        self
    }

    /// Upper bound for the whole discovery. Default 5.0s.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Per-address connect + reply timeout. Default 1200ms.
    ///
    /// Setting this to at least 1100-1200ms gives the OS kernel enough time
    /// to perform its native RFC 6298 SYN retransmission (at 1000ms) on lossy
    /// 2.4GHz Wi-Fi networks (common on older Android 5 TV boxes).
    pub fn probe_timeout(mut self, duration: Duration) -> Self {
        self.probe_timeout = duration;
        self
    }

    /// Probes in flight at once. Default 256.
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = n.max(1);
        self
    }

    /// Also ask mDNS for `_adb._tcp.local` (default on).
    pub fn mdns(mut self, enabled: bool) -> Self {
        self.mdns = enabled;
        self
    }

    pub(crate) fn live(mut self, devices: Vec<crate::Device>) -> Self {
        self.live = devices;
        self
    }

    /// Begin. Fails with [`ErrorKind::NoNetwork`] when nothing was given and
    /// no local IPv4 interface exists.
    pub fn start(self) -> Result<Discovery> {
        if self.ports.is_empty() {
            return Err(Error::invalid_arg("no ports to probe"));
        }
        let mut ips: BTreeSet<Ipv4Addr> = self.hosts;
        let mut subnets = self.subnets;
        if ips.is_empty() && subnets.is_empty() {
            subnets.insert(Subnet::detect().ok_or_else(|| {
                Error::new(ErrorKind::NoNetwork, "no local IPv4 network to discover on")
            })?);
        }
        for subnet in &subnets {
            ips.extend(subnet.hosts());
        }
        let mdns_socket = if self.mdns {
            std::net::UdpSocket::bind("0.0.0.0:0")
                .and_then(|s| {
                    s.set_nonblocking(true)?;
                    tokio::net::UdpSocket::from_std(s)
                })
                .map_err(|e| tracing::debug!("mDNS unavailable: {e}"))
                .ok()
        } else {
            None
        };

        let shared = Arc::new(Shared {
            probe_timeout: self.probe_timeout,
            seen: Mutex::new(HashSet::new()),
            discovered_ips: Mutex::new(HashSet::new()),
            limit: Semaphore::new(self.concurrency),
            subnets,
            explicit: ips.clone(),
        });
        let (tx, rx) = mpsc::channel(64);
        let mut tasks = JoinSet::new();

        if let Some(socket) = mdns_socket {
            tasks.spawn(mdns_query(
                shared.clone(),
                socket,
                self.duration,
                tx.clone(),
            ));
        }

        let ports = self.ports.clone();
        // Devices this client is connected to answer over that connection;
        // a probe would be refused by a single-client adbd.
        for d in self.live {
            let addr = d.addr();
            let Some(conn) = d.live_connection() else { continue };
            if !matches!(addr.ip(), IpAddr::V4(ip) if shared.wanted(ip)) {
                continue;
            }
            let (shared, tx, limit) = (shared.clone(), tx.clone(), self.probe_timeout);
            tasks.spawn(async move {
                if !conn.answers(limit).await || !shared.seen.lock().unwrap().insert(addr) {
                    return;
                }
                shared.discovered_ips.lock().unwrap().insert(addr.ip());
                let banner = conn.device_banner().to_string();
                let (model, product, device) = parse_banner_props(&banner);
                let _ = tx.send(DiscoveredDevice { addr, model, product, device, banner, auth_required: false }).await;
            });
        }
        let ips_vec: Vec<Ipv4Addr> = ips.into_iter().collect();
        let driver_shared = shared.clone();
        let driver_tx = tx.clone();

        // Staged scanning coordinator task:
        tasks.spawn(async move {
            // Phase 1: Probe default primary port (5555) on all targets in parallel.
            if ports.contains(&DEFAULT_ADB_PORT) {
                let mut phase1 = JoinSet::new();
                for &ip in &ips_vec {
                    phase1.spawn(probe(
                        driver_shared.clone(),
                        SocketAddr::new(IpAddr::V4(ip), DEFAULT_ADB_PORT),
                        driver_tx.clone(),
                    ));
                }
                while phase1.join_next().await.is_some() {}

                // Phase 2: Second-chance retry on port 5555 ONLY for targets not yet discovered.
                // This specifically handles lossy 2.4GHz WiFi (e.g. Android 5 TV boxes) where initial SYNs dropped.
                let missing: Vec<Ipv4Addr> = {
                    let disc = driver_shared.discovered_ips.lock().unwrap();
                    ips_vec
                        .iter()
                        .filter(|ip| !disc.contains(&IpAddr::V4(**ip)))
                        .copied()
                        .collect()
                };
                if !missing.is_empty() {
                    let mut phase2 = JoinSet::new();
                    for ip in missing {
                        phase2.spawn(probe(
                            driver_shared.clone(),
                            SocketAddr::new(IpAddr::V4(ip), DEFAULT_ADB_PORT),
                            driver_tx.clone(),
                        ));
                    }
                    while phase2.join_next().await.is_some() {}
                }
            }

            // Phase 3: Secondary ports (e.g. 9527, 5566) ONLY for targets not yet discovered.
            let missing: Vec<Ipv4Addr> = {
                let disc = driver_shared.discovered_ips.lock().unwrap();
                ips_vec
                    .iter()
                    .filter(|ip| !disc.contains(&IpAddr::V4(**ip)))
                    .copied()
                    .collect()
            };
            if !missing.is_empty() {
                let mut phase3 = JoinSet::new();
                for &port in &ports {
                    if port != DEFAULT_ADB_PORT {
                        for &ip in &missing {
                            phase3.spawn(probe(
                                driver_shared.clone(),
                                SocketAddr::new(IpAddr::V4(ip), port),
                                driver_tx.clone(),
                            ));
                        }
                    }
                }
                while phase3.join_next().await.is_some() {}
            }
        });

        drop(tx);
        Ok(Discovery {
            rx,
            _tasks: tasks,
            deadline: Box::pin(tokio::time::sleep(self.duration)),
            finished: false,
        })
    }
}

impl IntoFuture for Discover {
    type Output = Result<Vec<DiscoveredDevice>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut discovery = self.start()?;
            let mut all = Vec::new();
            while let Some(d) = discovery.next().await {
                all.push(d);
            }
            all.sort_by_key(|d| d.addr);
            Ok(all)
        })
    }
}

/// A running discovery. Yields each endpoint once; dropping it stops all probes.
pub struct Discovery {
    rx: mpsc::Receiver<DiscoveredDevice>,
    _tasks: JoinSet<()>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
}

impl Discovery {
    /// The next device, or `None` when every probe finished or the timeout passed.
    pub async fn next(&mut self) -> Option<DiscoveredDevice> {
        std::future::poll_fn(|cx| self.poll_next_device(cx)).await
    }

    fn poll_next_device(&mut self, cx: &mut Context<'_>) -> Poll<Option<DiscoveredDevice>> {
        if self.finished {
            return Poll::Ready(None);
        }
        if let Poll::Ready(item) = self.rx.poll_recv(cx) {
            self.finished = item.is_none();
            return Poll::Ready(item);
        }
        if self.deadline.as_mut().poll(cx).is_ready() {
            self.finished = true;
            self.rx.close();
            return Poll::Ready(None);
        }
        Poll::Pending
    }
}

impl futures_core::Stream for Discovery {
    type Item = DiscoveredDevice;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<DiscoveredDevice>> {
        self.get_mut().poll_next_device(cx)
    }
}

struct Shared {
    probe_timeout: Duration,
    seen: Mutex<HashSet<SocketAddr>>,
    discovered_ips: Mutex<HashSet<IpAddr>>,
    limit: Semaphore,
    subnets: BTreeSet<Subnet>,
    explicit: BTreeSet<Ipv4Addr>,
}

impl Shared {
    /// mDNS answers from outside what was asked for are ignored.
    fn wanted(&self, ip: Ipv4Addr) -> bool {
        self.explicit.contains(&ip) || self.subnets.iter().any(|s| s.contains(ip))
    }
}

async fn probe(shared: Arc<Shared>, addr: SocketAddr, tx: mpsc::Sender<DiscoveredDevice>) {
    // If an ADB device has already responded on this IP (e.g. standard port 5555),
    // skip probing secondary ports on the same host to avoid redundant load and duplicate reports.
    if shared.discovered_ips.lock().unwrap().contains(&addr.ip()) {
        return;
    }
    let Ok(_permit) = shared.limit.acquire().await else {
        return;
    };
    if shared.seen.lock().unwrap().contains(&addr) {
        return;
    }
    if shared.discovered_ips.lock().unwrap().contains(&addr.ip()) {
        return;
    }
    let Some(found) = probe_adb_device(addr, shared.probe_timeout).await else {
        return;
    };
    if shared.seen.lock().unwrap().insert(addr) {
        shared.discovered_ips.lock().unwrap().insert(addr.ip());
        let _ = tx.send(found).await;
    }
}

async fn mdns_query(
    shared: Arc<Shared>,
    socket: tokio::net::UdpSocket,
    duration: Duration,
    tx: mpsc::Sender<DiscoveredDevice>,
) {
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    if let Err(e) = socket
        .send_to(&build_mdns_ptr_query("_adb._tcp.local"), group)
        .await
    {
        tracing::debug!("mDNS query not sent: {e}");
        return;
    }
    let mut probes = JoinSet::new();
    let mut buf = [0u8; 4096];
    // mDNS responses arrive within tens to hundreds of milliseconds.
    // Cap listener window so Discovery finishes promptly once TCP probes complete.
    let mdns_deadline = tokio::time::Instant::now() + Duration::from_millis(1500).min(duration);
    while let Ok(Ok((len, peer))) =
        tokio::time::timeout_at(mdns_deadline, socket.recv_from(&mut buf)).await
    {
        let IpAddr::V4(peer_ip) = peer.ip() else {
            continue;
        };
        for endpoint in parse_mdns_response(&buf[..len], peer_ip) {
            if let IpAddr::V4(ip) = endpoint.ip() {
                if shared.wanted(ip) {
                    probes.spawn(probe(shared.clone(), endpoint, tx.clone()));
                }
            }
        }
    }
    while probes.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_banner_props() {
        let banner = "device::ro.product.name=hammerhead;ro.product.model=Nexus 5;ro.product.device=hammerhead;features=cmd";
        let (model, product, device) = parse_banner_props(banner);
        assert_eq!(model.as_deref(), Some("Nexus 5"));
        assert_eq!(product.as_deref(), Some("hammerhead"));
        assert_eq!(device.as_deref(), Some("hammerhead"));
    }
}
