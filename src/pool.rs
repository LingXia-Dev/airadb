use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::crypto::AdbKeyPair;
use crate::device::{AdbDevice, ShellOutput};
use crate::error::Result;

/// A connection pool caching persistent `AdbDevice` connections across commands.
///
/// Ensures that multiple operations on the same target device reuse the existing
/// TCP connection and authentication handshake, avoiding reconnection overhead.
#[derive(Clone, Default)]
pub struct DevicePool {
    devices: Arc<Mutex<HashMap<SocketAddr, Arc<AdbDevice>>>>,
}

impl DevicePool {
    /// Creates a new empty `DevicePool`.
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Gets an existing active connection or establishes a new connection to `addr`.
    pub async fn get_or_connect(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
    ) -> Result<Arc<AdbDevice>> {
        let mut map = self.devices.lock().await;

        if let Some(dev) = map.get(&addr) {
            if dev.is_connected() {
                return Ok(dev.clone());
            }
        }

        // Establish new connection
        let dev = if let Some(k) = key {
            AdbDevice::connect_with_key(addr, k).await?
        } else {
            AdbDevice::connect(addr).await?
        };

        let dev_arc = Arc::new(dev);
        map.insert(addr, dev_arc.clone());
        Ok(dev_arc)
    }

    /// Executes a shell command on `addr`, reusing the existing connection if alive.
    pub async fn shell(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        command: &str,
    ) -> Result<String> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.shell(command).await
    }

    /// Executes a shell command on `addr` and validates its exit code.
    pub async fn shell_checked(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        command: &str,
    ) -> Result<String> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.shell_checked(command).await
    }

    /// Checks if a command exists in PATH on `addr`.
    pub async fn has_command(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        cmd: &str,
    ) -> bool {
        if let Ok(dev) = self.get_or_connect(addr, key).await {
            dev.has_command(cmd).await
        } else {
            false
        }
    }

    /// Executes a shell command on `addr` returning `ShellOutput` (stdout & stderr).
    pub async fn shell_output(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        command: &str,
    ) -> Result<ShellOutput> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.shell_output(command).await
    }

    /// Pushes in-memory bytes to `remote_path` on `addr`.
    pub async fn push_bytes(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        bytes: &[u8],
        remote_path: &str,
    ) -> Result<u64> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.push_bytes(bytes, remote_path).await
    }

    /// Pumps stdin into a remote `exec:` daemon and streams stdout back.
    pub async fn exec_pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        command: &str,
        stdin: &mut R,
        stdout: &mut W,
    ) -> Result<()> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.exec_pump(command, stdin, stdout).await
    }

    /// Captures a screenshot from `addr` as PNG bytes, reusing the connection.
    pub async fn screencap(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
    ) -> Result<Vec<u8>> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.screencap().await
    }

    /// Pulls a remote file from `addr` directly into memory.
    pub async fn pull_bytes(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        remote_path: &str,
    ) -> Result<Vec<u8>> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.pull_bytes(remote_path).await
    }

    /// Installs an APK on `addr` from a local file path.
    pub async fn install_apk<P: AsRef<std::path::Path>>(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        local_apk_path: P,
    ) -> Result<()> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.install_apk(local_apk_path).await
    }

    /// Installs an APK on `addr` directly from in-memory bytes.
    pub async fn install_apk_bytes(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
        apk_bytes: &[u8],
    ) -> Result<()> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.install_apk_bytes(apk_bytes).await
    }

    /// Queries detailed device hardware info from `addr`.
    pub async fn get_hardware_info(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
    ) -> Result<crate::info::DeviceHardwareInfo> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.get_hardware_info().await
    }

    /// Queries the 64-bit unique Android ID from `addr`.
    pub async fn get_android_id(
        &self,
        addr: SocketAddr,
        key: Option<&AdbKeyPair>,
    ) -> Result<Option<String>> {
        let dev = self.get_or_connect(addr, key).await?;
        dev.get_android_id().await
    }

    /// Closes all active connections in the pool.
    pub async fn clear(&self) {
        let mut map = self.devices.lock().await;
        map.clear();
    }
}
