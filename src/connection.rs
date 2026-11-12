use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tracing::{debug, error, trace};

use crate::crypto::{load_or_generate_default_key, AdbKeyPair};
use crate::error::{AdbError, Result};
use crate::packet::{
    read_packet, write_packet, AdbPacket, ADB_AUTH_RSAPUBLICKEY, ADB_AUTH_SIGNATURE,
    ADB_AUTH_TOKEN, A_AUTH, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_VERSION_SKIP_CHECKSUM,
    A_WRTE, MAX_PAYLOAD_V1,
};
use crate::stream::AdbStream;

const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

struct StreamEntry {
    open_tx: Option<oneshot::Sender<std::result::Result<u32, String>>>,
    data_tx: mpsc::Sender<Vec<u8>>,
    write_ack_tx: mpsc::Sender<()>,
    closed: Arc<AtomicBool>,
}

/// A persistent multiplexed ADB connection to an Android device over TCP.
pub struct AdbConnection {
    max_payload: usize,
    device_banner: String,
    protocol_version: u32,
    next_stream_id: AtomicU32,
    streams: Arc<Mutex<HashMap<u32, StreamEntry>>>,
    writer_tx: mpsc::Sender<AdbPacket>,
    connected: Arc<AtomicBool>,
}

impl AdbConnection {
    /// Connects to an ADB daemon at `addr` over TCP, performing handshake and authentication.
    ///
    /// If `key` is `None`, attempts to load `~/.android/adbkey` or generates a persistent key.
    pub async fn connect<A: ToSocketAddrs>(addr: A, key: Option<&AdbKeyPair>) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let _ = stream.set_nodelay(true);

        // Configure TCP keepalive to maintain the long-lived connection through NAT/routers
        // and quickly detect broken links.
        let sock_ref = socket2::SockRef::from(&stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(15))
            .with_interval(std::time::Duration::from_secs(5));
        let _ = sock_ref.set_tcp_keepalive(&keepalive);

        Self::connect_with_stream(stream, key).await
    }

    /// Internal handshake and demux startup over an already-connected TCP stream.
    pub async fn connect_with_stream(
        mut stream: TcpStream,
        key: Option<&AdbKeyPair>,
    ) -> Result<Self> {
        let default_key;
        let auth_key = match key {
            Some(k) => k,
            None => {
                default_key = load_or_generate_default_key()?;
                &default_key
            }
        };

        // Step 1: Send initial A_CNXN
        // Android 5 adbd expects version 0x01000000 or 0x01000001
        let connect_banner = b"host::features=cmd\0".to_vec();
        let init_packet = AdbPacket::new(
            A_CNXN,
            A_VERSION_SKIP_CHECKSUM,
            256 * 1024,
            connect_banner,
        );
        write_packet(&mut stream, &init_packet).await?;

        // Step 2: Read response (A_AUTH or A_CNXN)
        let mut response = read_packet(&mut stream, false).await?;

        let (max_payload, device_banner, protocol_version) = if response.command == A_AUTH {
            // Authentication challenge
            if response.arg0 != ADB_AUTH_TOKEN {
                return Err(AdbError::AuthFailed(format!(
                    "Unexpected auth sub-type: {}",
                    response.arg0
                )));
            }

            // Sign token with private key
            let token = response.payload;
            debug!("Signing 20-byte auth token from device");
            let signature = auth_key.sign_token(&token)?;

            let sig_packet = AdbPacket::new(A_AUTH, ADB_AUTH_SIGNATURE, 0, signature);
            write_packet(&mut stream, &sig_packet).await?;

            // Read response to signature
            response = read_packet(&mut stream, false).await?;

            if response.command == A_AUTH && response.arg0 == ADB_AUTH_TOKEN {
                // Device does not recognize the key, send public key
                debug!("Signature rejected; sending public key for authorization");
                let pubkey_str = auth_key.android_pubkey_string("airadb@client")?;
                let pubkey_packet = AdbPacket::new(
                    A_AUTH,
                    ADB_AUTH_RSAPUBLICKEY,
                    0,
                    pubkey_str.into_bytes(),
                );
                write_packet(&mut stream, &pubkey_packet).await?;

                // Wait for user confirmation and A_CNXN response
                debug!("Waiting for user authorization on device...");
                response = timeout(DEFAULT_AUTH_TIMEOUT, read_packet(&mut stream, false))
                    .await
                    .map_err(|_| {
                        AdbError::Timeout("Timed out waiting for device authorization".into())
                    })??;
            }

            if response.command != A_CNXN {
                return Err(AdbError::AuthFailed(format!(
                    "Expected A_CNXN after authentication, got {}",
                    response.command_name()
                )));
            }

            let version = response.arg0;
            let max_data = if response.arg1 == 0 {
                MAX_PAYLOAD_V1
            } else {
                response.arg1 as usize
            };
            let banner = String::from_utf8_lossy(&response.payload).to_string();
            (max_data, banner, version)
        } else if response.command == A_CNXN {
            // No auth required
            let version = response.arg0;
            let max_data = if response.arg1 == 0 {
                MAX_PAYLOAD_V1
            } else {
                response.arg1 as usize
            };
            let banner = String::from_utf8_lossy(&response.payload).to_string();
            (max_data, banner, version)
        } else {
            return Err(AdbError::Protocol(format!(
                "Unexpected initial packet from device: {}",
                response.command_name()
            )));
        };

        debug!(
            "Connected to ADB device: banner='{}', max_payload={}, version={:#x}",
            device_banner, max_payload, protocol_version
        );

        let (mut tcp_reader, mut tcp_writer) = stream.into_split();
        let (writer_tx, mut writer_rx) = mpsc::channel::<AdbPacket>(128);

        let streams: Arc<Mutex<HashMap<u32, StreamEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let connected = Arc::new(AtomicBool::new(true));

        // Background Writer Task
        let connected_clone = connected.clone();
        tokio::spawn(async move {
            while let Some(packet) = writer_rx.recv().await {
                trace!("Sending ADB packet: {:?}", packet);
                if let Err(e) = write_packet(&mut tcp_writer, &packet).await {
                    error!("Error writing packet to TCP: {}", e);
                    connected_clone.store(false, Ordering::SeqCst);
                    break;
                }
            }
        });

        // Background Demux Reader Task
        let streams_clone = streams.clone();
        let writer_tx_clone = writer_tx.clone();
        let connected_clone2 = connected.clone();
        let skip_checksum = protocol_version >= A_VERSION_SKIP_CHECKSUM;

        tokio::spawn(async move {
            loop {
                match read_packet(&mut tcp_reader, skip_checksum).await {
                    Ok(packet) => {
                        trace!("Received ADB packet: {:?}", packet);
                        match packet.command {
                            A_OKAY => {
                                let remote_id = packet.arg0;
                                let local_id = packet.arg1;
                                let mut lock = streams_clone.lock().await;
                                if let Some(entry) = lock.get_mut(&local_id) {
                                    if let Some(open_tx) = entry.open_tx.take() {
                                        let _ = open_tx.send(Ok(remote_id));
                                    } else {
                                        let _ = entry.write_ack_tx.try_send(());
                                    }
                                } else {
                                    debug!(
                                        "Received A_OKAY for unknown or closed local_id={}",
                                        local_id
                                    );
                                }
                            }
                            A_WRTE => {
                                let remote_id = packet.arg0;
                                let local_id = packet.arg1;
                                let mut found = false;
                                {
                                    let mut lock = streams_clone.lock().await;
                                    if let Some(entry) = lock.get_mut(&local_id) {
                                        found = true;
                                        let _ = entry.data_tx.send(packet.payload).await;
                                    }
                                }
                                if found {
                                    // Must respond immediately with A_OKAY for flow control
                                    let ack = AdbPacket::new(A_OKAY, local_id, remote_id, Vec::new());
                                    let _ = writer_tx_clone.send(ack).await;
                                } else {
                                    // Stream doesn't exist, tell device to close it
                                    let clse = AdbPacket::new(A_CLSE, local_id, remote_id, Vec::new());
                                    let _ = writer_tx_clone.send(clse).await;
                                }
                            }
                            A_CLSE => {
                                let _remote_id = packet.arg0;
                                let local_id = packet.arg1;
                                let mut lock = streams_clone.lock().await;
                                if let Some(mut entry) = lock.remove(&local_id) {
                                    entry.closed.store(true, Ordering::SeqCst);
                                    if let Some(open_tx) = entry.open_tx.take() {
                                        let _ = open_tx.send(Err("Stream closed by device".into()));
                                    }
                                }
                            }
                            _ => {
                                debug!(
                                    "Unhandled packet in demux: command={}",
                                    packet.command_name()
                                );
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Demux reader terminated: {}", e);
                        connected_clone2.store(false, Ordering::SeqCst);
                        let mut lock = streams_clone.lock().await;
                        for (_, mut entry) in lock.drain() {
                            entry.closed.store(true, Ordering::SeqCst);
                            if let Some(open_tx) = entry.open_tx.take() {
                                let _ = open_tx.send(Err("Connection lost".into()));
                            }
                        }
                        break;
                    }
                }
            }
        });

        Ok(Self {
            max_payload,
            device_banner,
            protocol_version,
            next_stream_id: AtomicU32::new(1),
            streams,
            writer_tx,
            connected,
        })
    }

    /// Maximum payload allowed per packet for this device.
    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// Device banner string returned during connection (e.g. `device::ro.product.model=...`).
    pub fn device_banner(&self) -> &str {
        &self.device_banner
    }

    /// ADB protocol version negotiated with the device.
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Checks if the connection to the device is alive.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Opens a multiplexed stream to a destination service (e.g. `shell:...`, `sync:`, `exec:...`).
    ///
    /// This uses the SAME persistent TCP connection without reconnecting!
    pub async fn open_stream(&self, destination: &str) -> Result<AdbStream> {
        if !self.is_connected() {
            return Err(AdbError::ConnectionClosed);
        }

        let local_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
        let (open_tx, open_rx) = oneshot::channel();
        let (data_tx, data_rx) = mpsc::channel(64);
        let (write_ack_tx, write_ack_rx) = mpsc::channel(32);
        let closed = Arc::new(AtomicBool::new(false));

        {
            let mut lock = self.streams.lock().await;
            lock.insert(
                local_id,
                StreamEntry {
                    open_tx: Some(open_tx),
                    data_tx,
                    write_ack_tx,
                    closed: closed.clone(),
                },
            );
        }

        // Android 5 adbd expects null-terminated destination string
        let mut dest_bytes = destination.as_bytes().to_vec();
        if !dest_bytes.ends_with(b"\0") {
            dest_bytes.push(0);
        }

        let open_packet = AdbPacket::new(A_OPEN, local_id, 0, dest_bytes);
        self.writer_tx
            .send(open_packet)
            .await
            .map_err(|_| AdbError::ConnectionClosed)?;

        let remote_id = match timeout(DEFAULT_OPEN_TIMEOUT, open_rx).await {
            Ok(Ok(Ok(id))) => id,
            Ok(Ok(Err(err_msg))) => {
                let mut lock = self.streams.lock().await;
                lock.remove(&local_id);
                return Err(AdbError::CommandFailed(err_msg));
            }
            Ok(Err(_)) => {
                let mut lock = self.streams.lock().await;
                lock.remove(&local_id);
                return Err(AdbError::ConnectionClosed);
            }
            Err(_) => {
                let mut lock = self.streams.lock().await;
                lock.remove(&local_id);
                return Err(AdbError::Timeout(format!(
                    "Timed out waiting for service '{}' to open",
                    destination
                )));
            }
        };

        Ok(AdbStream::new(
            local_id,
            remote_id,
            self.max_payload,
            self.writer_tx.clone(),
            data_rx,
            write_ack_rx,
            closed,
        ))
    }
}
