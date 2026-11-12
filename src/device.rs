use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::ToSocketAddrs;

use crate::connection::AdbConnection;
use crate::crypto::AdbKeyPair;
use crate::error::{AdbError, Result};
use crate::stream::AdbStream;
use crate::sync::{AdbSync, SyncDent, SyncStat};

/// Reboot target modes for ADB device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootMode {
    /// Normal system reboot.
    System,
    /// Reboot into bootloader / fastboot.
    Bootloader,
    /// Reboot into recovery mode.
    Recovery,
    /// Reboot into sideload mode.
    Sideload,
}

impl fmt::Display for RebootMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(f, ""),
            Self::Bootloader => write!(f, "bootloader"),
            Self::Recovery => write!(f, "recovery"),
            Self::Sideload => write!(f, "sideload"),
        }
    }
}

/// High-level client interface representing a connected Android device.
///
/// An `AdbDevice` maintains a persistent TCP connection to `adbd`, multiplexing
/// multiple commands and file transfers over that single connection without reconnecting.
#[derive(Clone)]
pub struct AdbDevice {
    connection: Arc<AdbConnection>,
}

impl AdbDevice {
    /// Connects to an ADB device at `addr` using default or auto-generated keys.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let conn = AdbConnection::connect(addr, None).await?;
        Ok(Self {
            connection: Arc::new(conn),
        })
    }

    /// Connects to an ADB device at `addr` using the specified `AdbKeyPair`.
    pub async fn connect_with_key<A: ToSocketAddrs>(
        addr: A,
        key: &AdbKeyPair,
    ) -> Result<Self> {
        let conn = AdbConnection::connect(addr, Some(key)).await?;
        Ok(Self {
            connection: Arc::new(conn),
        })
    }

    /// Creates an `AdbDevice` from an existing `AdbConnection`.
    pub fn from_connection(connection: AdbConnection) -> Self {
        Self {
            connection: Arc::new(connection),
        }
    }

    /// Returns a reference to the underlying `AdbConnection`.
    pub fn connection(&self) -> &AdbConnection {
        &self.connection
    }

    /// Maximum payload allowed by the connected device.
    pub fn max_payload(&self) -> usize {
        self.connection.max_payload()
    }

    /// Device banner string (e.g. `device::ro.product.model=...`).
    pub fn banner(&self) -> &str {
        self.connection.device_banner()
    }

    /// Checks if the connection to the device is alive.
    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    /// Opens an arbitrary multiplexed service stream (e.g. `shell:...`, `sync:`, `exec:...`).
    pub async fn open_stream(&self, destination: &str) -> Result<AdbStream> {
        self.connection.open_stream(destination).await
    }

    /// Executes a shell command on the device and returns its combined output.
    ///
    /// Uses the persistent TCP connection without reconnecting.
    pub async fn shell(&self, command: &str) -> Result<String> {
        let dest = format!("shell:{}", command);
        let mut stream = self.open_stream(&dest).await?;
        stream.read_string_lossy().await
    }

    /// Starts a shell command and returns an `AdbStream` for streaming input and output.
    pub async fn shell_stream(&self, command: &str) -> Result<AdbStream> {
        let dest = format!("shell:{}", command);
        self.open_stream(&dest).await
    }

    /// Opens an interactive shell session stream.
    pub async fn interactive_shell(&self) -> Result<AdbStream> {
        self.open_stream("shell:").await
    }

    /// Executes a raw command using the `exec:` service (no PTY mangling), returning raw bytes.
    ///
    /// Ideal for pulling binary output such as `screencap -p`.
    pub async fn exec(&self, command: &str) -> Result<Vec<u8>> {
        let dest = format!("exec:{}", command);
        let mut stream = self.open_stream(&dest).await?;
        stream.read_all().await
    }

    /// Starts an exec command and returns an `AdbStream`.
    pub async fn exec_stream(&self, command: &str) -> Result<AdbStream> {
        let dest = format!("exec:{}", command);
        self.open_stream(&dest).await
    }

    /// Retrieves an Android system property using `getprop`.
    pub async fn get_prop(&self, prop_name: &str) -> Result<String> {
        let cmd = format!("getprop {}", prop_name);
        let out = self.shell(&cmd).await?;
        Ok(out.trim().to_string())
    }

    /// Convenience: gets device model name (`ro.product.model`).
    pub async fn get_model(&self) -> Result<String> {
        self.get_prop("ro.product.model").await
    }

    /// Convenience: gets Android OS version (`ro.build.version.release`).
    pub async fn get_android_version(&self) -> Result<String> {
        self.get_prop("ro.build.version.release").await
    }

    /// Convenience: gets Android SDK API level (`ro.build.version.sdk`).
    pub async fn get_sdk_version(&self) -> Result<u32> {
        let val = self.get_prop("ro.build.version.sdk").await?;
        val.parse::<u32>()
            .map_err(|e| AdbError::Protocol(format!("Failed to parse SDK version '{}': {}", val, e)))
    }

    /// Reboots the device into the specified `RebootMode`.
    pub async fn reboot(&self, mode: RebootMode) -> Result<()> {
        let mode_str = mode.to_string();
        let dest = if mode_str.is_empty() {
            "reboot:".to_string()
        } else {
            format!("reboot:{}", mode_str)
        };
        let mut stream = self.open_stream(&dest).await?;
        let _ = stream.read_all().await;
        Ok(())
    }

    /// Remounts device partitions in read-write mode.
    pub async fn remount(&self) -> Result<String> {
        let mut stream = self.open_stream("remount:").await?;
        stream.read_string_lossy().await
    }

    /// Restarts `adbd` listening on the specified TCP port (e.g. 5555).
    pub async fn tcpip(&self, port: u16) -> Result<String> {
        let dest = format!("tcpip:{}", port);
        let mut stream = self.open_stream(&dest).await?;
        stream.read_string_lossy().await
    }

    /// Restarts `adbd` with root privileges.
    pub async fn root(&self) -> Result<String> {
        let mut stream = self.open_stream("root:").await?;
        stream.read_string_lossy().await
    }

    /// Restarts `adbd` without root privileges.
    pub async fn unroot(&self) -> Result<String> {
        let mut stream = self.open_stream("unroot:").await?;
        stream.read_string_lossy().await
    }

    /// Opens a file synchronization session (`sync:` service).
    pub async fn sync(&self) -> Result<AdbSync> {
        let stream = self.open_stream("sync:").await?;
        Ok(AdbSync::new(stream))
    }

    /// Pushes a local file to a remote path on the device.
    pub async fn push_file<P: AsRef<Path>>(
        &self,
        local_path: P,
        remote_path: &str,
    ) -> Result<u64> {
        let mut sync = self.sync().await?;
        let bytes = sync.push_file(local_path, remote_path).await?;
        let _ = sync.quit().await;
        Ok(bytes)
    }

    /// Pulls a remote file from the device to a local path.
    pub async fn pull_file<P: AsRef<Path>>(
        &self,
        remote_path: &str,
        local_path: P,
    ) -> Result<u64> {
        let mut sync = self.sync().await?;
        let bytes = sync.pull_file(remote_path, local_path).await?;
        let _ = sync.quit().await;
        Ok(bytes)
    }

    /// Gets metadata for a file on the device.
    pub async fn stat(&self, remote_path: &str) -> Result<SyncStat> {
        let mut sync = self.sync().await?;
        let stat = sync.stat(remote_path).await?;
        let _ = sync.quit().await;
        Ok(stat)
    }

    /// Lists directory contents on the device.
    pub async fn list(&self, remote_path: &str) -> Result<Vec<SyncDent>> {
        let mut sync = self.sync().await?;
        let entries = sync.list(remote_path).await?;
        let _ = sync.quit().await;
        Ok(entries)
    }

    /// Installs an APK on the device.
    ///
    /// Pushes the APK to `/data/local/tmp/` via the sync service, executes `pm install`,
    /// and cleans up the temporary APK file.
    pub async fn install_apk<P: AsRef<Path>>(&self, local_apk_path: P) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let remote_tmp_apk = format!("/data/local/tmp/radb_pkg_{}.apk", now);

        self.push_file(local_apk_path, &remote_tmp_apk).await?;

        let install_cmd = format!("pm install -r \"{}\"", remote_tmp_apk);
        let output = self.shell(&install_cmd).await;

        // Cleanup temporary APK file
        let _ = self.shell(&format!("rm -f \"{}\"", remote_tmp_apk)).await;

        let output = output?;
        if output.contains("Success") {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(format!(
                "pm install failed: {}",
                output.trim()
            )))
        }
    }

    /// Uninstalls an application package from the device.
    pub async fn uninstall(&self, package_name: &str) -> Result<()> {
        let cmd = format!("pm uninstall \"{}\"", package_name);
        let output = self.shell(&cmd).await?;
        if output.contains("Success") {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(format!(
                "pm uninstall failed: {}",
                output.trim()
            )))
        }
    }
}
