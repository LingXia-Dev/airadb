use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::crypto::KeyPair;
use crate::error::{Error, Result};
use crate::packet::{
    read_packet, write_packet, AdbPacket, ADB_AUTH_RSAPUBLICKEY, ADB_AUTH_SIGNATURE, ADB_AUTH_TOKEN, A_AUTH,
    A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_VERSION_SKIP_CHECKSUM, A_WRTE, MAX_PAYLOAD_V1,
};
use crate::stream::AdbStream;

/// Timeouts for establishing a connection.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// TCP connect.
    pub connect: Duration,
    /// Each handshake reply (CNXN/AUTH) and each service open.
    pub reply: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { connect: Duration::from_secs(3), reply: Duration::from_secs(5) }
    }
}

struct StreamEntry {
    open_tx: Option<oneshot::Sender<std::result::Result<u32, String>>>,
    data_tx: mpsc::Sender<Vec<u8>>,
    write_ack_tx: mpsc::Sender<()>,
    closed: Arc<AtomicBool>,
}

/// A persistent multiplexed ADB connection to an Android device over TCP.
///
/// Dropping it (or calling [`shutdown`](Self::shutdown)) stops its reader
/// and writer tasks and closes the socket.
pub struct AdbConnection {
    max_payload: usize,
    device_banner: String,
    protocol_version: u32,
    open_timeout: Duration,
    next_stream_id: AtomicU32,
    streams: Arc<Mutex<HashMap<u32, StreamEntry>>>,
    writer_tx: mpsc::Sender<AdbPacket>,
    connected: Arc<AtomicBool>,
    tasks: [JoinHandle<()>; 2],
}

/// The first stage of a connection: TCP is up, CNXN sent, our key's
/// signature offered once.
pub(crate) enum Hello {
    Connected(AdbConnection),
    /// The device does not recognise the key. Offering the public key makes
    /// it show the "Allow USB debugging?" dialog.
    UnknownKey(PendingAuth),
}

pub(crate) struct PendingAuth {
    stream: TcpStream,
    timeouts: Timeouts,
}

/// The public key was offered; the device is showing its dialog.
pub(crate) struct AwaitingUser {
    stream: TcpStream,
    timeouts: Timeouts,
}

async fn read_reply(stream: &mut TcpStream, limit: Duration, what: &str) -> Result<AdbPacket> {
    timeout(limit, read_packet(stream, false))
        .await
        .map_err(|_| Error::timeout(format!("no {what} from device within {limit:?}")))?
}

fn keepalive(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(15)).with_interval(Duration::from_secs(5));
    let _ = sock.set_tcp_keepalive(&ka);
}

/// Connect, send CNXN and answer one AUTH challenge with a signature.
pub(crate) async fn hello(addr: SocketAddr, key: &KeyPair, timeouts: Timeouts) -> Result<Hello> {
    let mut stream = timeout(timeouts.connect, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::timeout(format!("connecting to {addr} took longer than {:?}", timeouts.connect)))?
        .map_err(|e| Error::connect(addr, e))?;
    keepalive(&stream);

    // Android 5 adbd expects version 0x01000000 or 0x01000001.
    let banner = b"host::features=cmd\0".to_vec();
    write_packet(&mut stream, &AdbPacket::new(A_CNXN, A_VERSION_SKIP_CHECKSUM, 256 * 1024, banner)).await?;

    let reply = read_reply(&mut stream, timeouts.reply, "handshake reply").await?;
    match reply.command {
        A_CNXN => Ok(Hello::Connected(AdbConnection::start(stream, reply, timeouts)?)),
        A_AUTH if reply.arg0 == ADB_AUTH_TOKEN => {
            let signature = key.sign_token(&reply.payload)?;
            write_packet(&mut stream, &AdbPacket::new(A_AUTH, ADB_AUTH_SIGNATURE, 0, signature)).await?;
            let reply = read_reply(&mut stream, timeouts.reply, "reply to the key signature").await?;
            match reply.command {
                A_CNXN => Ok(Hello::Connected(AdbConnection::start(stream, reply, timeouts)?)),
                A_AUTH if reply.arg0 == ADB_AUTH_TOKEN => {
                    Ok(Hello::UnknownKey(PendingAuth { stream, timeouts }))
                }
                _ => Err(Error::protocol(format!("unexpected {} after signature", reply.command_name()))),
            }
        }
        A_AUTH => Err(Error::protocol(format!("unexpected auth type {}", reply.arg0))),
        _ => Err(Error::protocol(format!("unexpected {} as handshake reply", reply.command_name()))),
    }
}

impl PendingAuth {
    /// Offer the public key; the device shows its authorization dialog.
    pub(crate) async fn offer_key(mut self, key: &KeyPair) -> Result<AwaitingUser> {
        let public = key.android_pubkey_string("airadb@client")?;
        write_packet(&mut self.stream, &AdbPacket::new(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, public.into_bytes()))
            .await?;
        Ok(AwaitingUser { stream: self.stream, timeouts: self.timeouts })
    }
}

impl AwaitingUser {
    /// Wait for the user to allow the key. A refusal looks exactly like
    /// silence to the client: both end in a timeout.
    pub(crate) async fn wait(mut self, limit: Duration) -> Result<AdbConnection> {
        let reply = match timeout(limit, read_packet(&mut self.stream, false)).await {
            Err(_) => {
                return Err(Error::unauthorized(format!(
                    "the device was not authorized within {limit:?} (dialog dismissed or not answered)"
                )))
            }
            Ok(Err(e)) if e.kind() == crate::ErrorKind::Disconnected => {
                return Err(Error::unauthorized("the device closed the connection while authorizing"))
            }
            Ok(r) => r?,
        };
        if reply.command != A_CNXN {
            return Err(Error::protocol(format!("expected CNXN after authorization, got {}", reply.command_name())));
        }
        AdbConnection::start(self.stream, reply, self.timeouts)
    }
}

impl AdbConnection {
    fn start(stream: TcpStream, cnxn: AdbPacket, timeouts: Timeouts) -> Result<Self> {
        let protocol_version = cnxn.arg0;
        let max_payload = if cnxn.arg1 == 0 { MAX_PAYLOAD_V1 } else { cnxn.arg1 as usize };
        let device_banner = String::from_utf8_lossy(&cnxn.payload).trim_end_matches('\0').to_string();
        debug!("connected: banner='{device_banner}', max_payload={max_payload}, version={protocol_version:#x}");

        let (mut tcp_reader, mut tcp_writer) = stream.into_split();
        let (writer_tx, mut writer_rx) = mpsc::channel::<AdbPacket>(128);
        let streams: Arc<Mutex<HashMap<u32, StreamEntry>>> = Arc::new(Mutex::new(HashMap::new()));
        let connected = Arc::new(AtomicBool::new(true));

        let writer_connected = connected.clone();
        let writer = tokio::spawn(async move {
            while let Some(packet) = writer_rx.recv().await {
                trace!("send {packet:?}");
                if let Err(e) = write_packet(&mut tcp_writer, &packet).await {
                    debug!("writer stopped: {e}");
                    break;
                }
            }
            writer_connected.store(false, Ordering::SeqCst);
        });

        let reader_streams = streams.clone();
        let reader_tx = writer_tx.clone();
        let reader_connected = connected.clone();
        let skip_checksum = protocol_version >= A_VERSION_SKIP_CHECKSUM;
        let reader = tokio::spawn(async move {
            loop {
                let packet = match read_packet(&mut tcp_reader, skip_checksum).await {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("reader stopped: {e}");
                        break;
                    }
                };
                trace!("recv {packet:?}");
                let (remote_id, local_id) = (packet.arg0, packet.arg1);
                match packet.command {
                    A_OKAY => {
                        let mut lock = reader_streams.lock().await;
                        if let Some(entry) = lock.get_mut(&local_id) {
                            match entry.open_tx.take() {
                                Some(open_tx) => {
                                    let _ = open_tx.send(Ok(remote_id));
                                }
                                None => {
                                    let _ = entry.write_ack_tx.try_send(());
                                }
                            }
                        }
                    }
                    A_WRTE => {
                        // Clone the sender and release the map before a
                        // possibly slow send: one stalled reader must not
                        // block other streams from opening or closing.
                        let tx = reader_streams.lock().await.get(&local_id).map(|e| e.data_tx.clone());
                        let delivered = match tx {
                            Some(tx) => tx.send(packet.payload).await.is_ok(),
                            None => false,
                        };
                        let reply = if delivered { A_OKAY } else { A_CLSE };
                        let _ = reader_tx.send(AdbPacket::new(reply, local_id, remote_id, Vec::new())).await;
                    }
                    A_CLSE => {
                        if let Some(mut entry) = reader_streams.lock().await.remove(&local_id) {
                            entry.closed.store(true, Ordering::SeqCst);
                            if let Some(open_tx) = entry.open_tx.take() {
                                let _ = open_tx.send(Err("stream closed by device".into()));
                            }
                        }
                    }
                    _ => debug!("unhandled packet: {}", packet.command_name()),
                }
            }
            reader_connected.store(false, Ordering::SeqCst);
            fail_all(&reader_streams, "connection lost").await;
        });

        Ok(Self {
            max_payload,
            device_banner,
            protocol_version,
            open_timeout: timeouts.reply,
            next_stream_id: AtomicU32::new(1),
            streams,
            writer_tx,
            connected,
            tasks: [writer, reader],
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

    /// Whether the connection is still up.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Stop both I/O tasks and close the socket. Open streams read EOF.
    pub async fn shutdown(&self) {
        self.connected.store(false, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
        fail_all(&self.streams, "connection shut down").await;
    }

    /// Opens a multiplexed stream to a destination service (e.g. `shell:...`, `sync:`, `exec:...`).
    pub async fn open_stream(&self, destination: &str) -> Result<AdbStream> {
        if !self.is_connected() {
            return Err(Error::disconnected());
        }

        let local_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
        let (open_tx, open_rx) = oneshot::channel();
        let (data_tx, data_rx) = mpsc::channel(64);
        let (write_ack_tx, write_ack_rx) = mpsc::channel(32);
        let closed = Arc::new(AtomicBool::new(false));
        self.streams.lock().await.insert(
            local_id,
            StreamEntry { open_tx: Some(open_tx), data_tx, write_ack_tx, closed: closed.clone() },
        );

        // Android 5 adbd expects a NUL-terminated destination.
        let mut dest = destination.as_bytes().to_vec();
        if !dest.ends_with(b"\0") {
            dest.push(0);
        }
        self.writer_tx
            .send(AdbPacket::new(A_OPEN, local_id, 0, dest))
            .await
            .map_err(|_| Error::disconnected())?;

        let outcome = timeout(self.open_timeout, open_rx).await;
        let remote_id = match outcome {
            Ok(Ok(Ok(id))) => id,
            other => {
                self.streams.lock().await.remove(&local_id);
                let service = destination.split(':').next().unwrap_or(destination);
                return Err(match other {
                    Ok(Ok(Err(msg))) => Error::rejected(format!("service '{service}:' refused: {msg}")),
                    Err(_) => Error::timeout(format!("service '{service}:' did not open within {:?}", self.open_timeout)),
                    _ => Error::disconnected(),
                });
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

async fn fail_all(streams: &Mutex<HashMap<u32, StreamEntry>>, why: &str) {
    for (_, mut entry) in streams.lock().await.drain() {
        entry.closed.store(true, Ordering::SeqCst);
        if let Some(open_tx) = entry.open_tx.take() {
            let _ = open_tx.send(Err(why.into()));
        }
    }
}

impl AdbConnection {
    /// Whether any stream is still open (used to avoid reaping a busy link).
    pub(crate) fn has_open_streams(&self) -> bool {
        self.streams.try_lock().map(|m| !m.is_empty()).unwrap_or(true)
    }
}

impl Drop for AdbConnection {
    fn drop(&mut self) {
        self.connected.store(false, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
        // Readers of still-open streams see EOF instead of hanging.
        if let Ok(mut streams) = self.streams.try_lock() {
            for (_, entry) in streams.drain() {
                entry.closed.store(true, Ordering::SeqCst);
            }
        }
    }
}
