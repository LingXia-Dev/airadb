use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate::connection::Timeouts;
use crate::crypto::KeyPair;
use crate::device::{Device, DeviceInner};
use crate::scan::Discover;

/// Shared configuration and the connection table. Cheap to clone.
///
/// The client holds the one key every device sees. It never reads
/// `~/.android/adbkey` by itself: load one with
/// [`KeyPair::load_or_create`] and pass it in.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

pub(crate) struct ClientInner {
    pub key: Arc<KeyPair>,
    pub timeouts: Timeouts,
    pub auth_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    devices: Mutex<HashMap<SocketAddr, Weak<DeviceInner>>>,
}

pub struct ClientBuilder {
    key: Arc<KeyPair>,
    timeouts: Timeouts,
    auth_timeout: Duration,
    idle_timeout: Option<Duration>,
}

impl ClientBuilder {
    /// TCP connect timeout. Default 3s.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.connect = timeout;
        self
    }

    /// Timeout for each handshake reply and each service open. Default 5s.
    pub fn reply_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.reply = timeout;
        self
    }

    /// Default wait for the user in [`AuthPrompt::wait`](crate::AuthPrompt::wait). Default 30s.
    pub fn auth_timeout(mut self, timeout: Duration) -> Self {
        self.auth_timeout = timeout;
        self
    }

    /// Close a connection after this long without use and without open
    /// streams; the next call reconnects. Default 60s; `None` keeps
    /// connections until [`Device::close`] or drop.
    pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.idle_timeout = timeout;
        self
    }

    pub fn build(self) -> Client {
        Client {
            inner: Arc::new(ClientInner {
                key: self.key,
                timeouts: self.timeouts,
                auth_timeout: self.auth_timeout,
                idle_timeout: self.idle_timeout,
                devices: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl Client {
    /// Start configuring a client that authenticates with `key`.
    pub fn builder(key: KeyPair) -> ClientBuilder {
        ClientBuilder {
            key: Arc::new(key),
            timeouts: Timeouts::default(),
            auth_timeout: Duration::from_secs(30),
            idle_timeout: Some(Duration::from_secs(60)),
        }
    }

    /// A client with default settings.
    pub fn new(key: KeyPair) -> Self {
        Self::builder(key).build()
    }

    /// The handle for the device at `addr`. Sends nothing. Handles for the
    /// same address share one connection.
    pub fn device(&self, addr: SocketAddr) -> Device {
        let mut devices = self.inner.devices.lock().unwrap();
        if let Some(inner) = devices.get(&addr).and_then(Weak::upgrade) {
            return Device { inner };
        }
        devices.retain(|_, weak| weak.strong_count() > 0);
        let inner = Arc::new(DeviceInner::new(self.clone(), addr));
        devices.insert(addr, Arc::downgrade(&inner));
        Device { inner }
    }

    /// Find ADB endpoints on the local network. See [`Discover`].
    pub fn discover(&self) -> Discover {
        Discover::new()
    }

    pub fn key(&self) -> &KeyPair {
        &self.inner.key
    }
}
