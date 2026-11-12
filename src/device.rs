use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::ToSocketAddrs;
use tokio::time::timeout;

use crate::connection::AdbConnection;
use crate::crypto::AdbKeyPair;
use crate::error::{AdbError, Result};
use crate::stream::AdbStream;
use crate::sync::{AdbSync, SyncDent, SyncStat, DEFAULT_FILE_MODE};

/// Output of an ADB shell command, providing stdout and stderr buffers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShellOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ShellOutput {
    pub fn stdout_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    pub fn stderr_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

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

/// Pads command with a trailing space if missing.
///
/// Workaround for older Android adbd transports (specifically on Android 5)
/// that sometimes drop the last byte of a command payload.
fn format_padded_cmd(prefix: &str, command: &str) -> String {
    let trimmed = command.trim_end_matches('\0');
    if !trimmed.ends_with(char::is_whitespace) {
        format!("{}{} \0", prefix, trimmed)
    } else {
        format!("{}{}\0", prefix, trimmed)
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

    /// Executes a shell command on the device and returns its combined output as a String.
    ///
    /// Automatically applies Android 5 command padding safety to prevent last-byte truncation.
    pub async fn shell(&self, command: &str) -> Result<String> {
        let dest = format_padded_cmd("shell:", command);
        let mut stream = self.open_stream(&dest).await?;
        stream.read_string_lossy().await
    }

    /// Executes a shell command and returns raw output bytes.
    pub async fn shell_bytes(&self, command: &str) -> Result<Vec<u8>> {
        let dest = format_padded_cmd("shell:", command);
        let mut stream = self.open_stream(&dest).await?;
        stream.read_all().await
    }

    /// Executes a shell command and returns `ShellOutput` (stdout + stderr).
    ///
    /// Note: On Android < 7 without `shell_v2`, adbd sends combined stdout and stderr
    /// over the PTY, returned here in `stdout`.
    pub async fn shell_output(&self, command: &str) -> Result<ShellOutput> {
        let stdout = self.shell_bytes(command).await?;
        Ok(ShellOutput {
            stdout,
            stderr: Vec::new(),
        })
    }

    /// Executes a shell command with a timeout duration.
    pub async fn shell_timeout(&self, command: &str, duration: Duration) -> Result<String> {
        timeout(duration, self.shell(command)).await.map_err(|_| {
            AdbError::Timeout(format!(
                "Command '{}' timed out after {:?}",
                command, duration
            ))
        })?
    }

    /// Executes a shell command and validates its exit code.
    ///
    /// Since Android 5.0 (ADB v1) does not separate stdout/stderr/exitcode in `shell:`,
    /// this appends an exit code probe marker to detect command failures, unknown commands,
    /// and non-zero exit statuses.
    pub async fn shell_checked(&self, command: &str) -> Result<String> {
        let marker = "__AIRADB_EXIT_STATUS__";
        let wrapped_cmd = format!("{}; echo \"\n{}:$?\"", command.trim(), marker);
        let raw_output = self.shell(&wrapped_cmd).await?;

        if let Some(pos) = raw_output.rfind(marker) {
            let output_part = raw_output[..pos].trim_end();
            let exit_part = raw_output[pos + marker.len()..]
                .trim()
                .trim_start_matches(':');
            let exit_code: i32 = exit_part
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .parse()
                .unwrap_or(0);

            if exit_code != 0 {
                return Err(AdbError::CommandFailed(format!(
                    "Command exited with code {}: {}",
                    exit_code,
                    output_part.trim()
                )));
            }
            Ok(output_part.to_string())
        } else {
            Ok(raw_output)
        }
    }

    /// Checks if a specific executable command exists in PATH on the target device.
    pub async fn has_command(&self, cmd: &str) -> bool {
        let probe = format!(
            "command -v \"{}\" >/dev/null 2>&1 || which \"{}\" >/dev/null 2>&1",
            cmd, cmd
        );
        self.shell_checked(&probe).await.is_ok()
    }

    /// Starts a shell command and returns an `AdbStream` for streaming input and output.
    pub async fn shell_stream(&self, command: &str) -> Result<AdbStream> {
        let dest = format_padded_cmd("shell:", command);
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
        let dest = format_padded_cmd("exec:", command);
        let mut stream = self.open_stream(&dest).await?;
        stream.read_all().await
    }

    /// Starts an exec command and returns an `AdbStream`.
    pub async fn exec_stream(&self, command: &str) -> Result<AdbStream> {
        let dest = format_padded_cmd("exec:", command);
        self.open_stream(&dest).await
    }

    /// Pumps asynchronous `stdin` into a remote `exec:` command and writes remote output into `stdout`.
    ///
    /// Perfect for running long-running daemons with NDJSON / streaming RPC.
    pub async fn exec_pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        command: &str,
        stdin: &mut R,
        stdout: &mut W,
    ) -> Result<()> {
        let stream = self.exec_stream(command).await?;
        let (mut stream_r, mut stream_w) = tokio::io::split(stream);

        tokio::select! {
            res1 = tokio::io::copy(stdin, &mut stream_w) => {
                let _ = res1?;
                let _ = stream_w.shutdown().await;
                let _ = tokio::io::copy(&mut stream_r, stdout).await?;
            }
            res2 = tokio::io::copy(&mut stream_r, stdout) => {
                let _ = res2?;
            }
        }
        Ok(())
    }

    /// Pumps asynchronous `stdin` into a remote `shell:` command and writes remote output into `stdout`.
    pub async fn shell_pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        command: &str,
        stdin: &mut R,
        stdout: &mut W,
    ) -> Result<()> {
        let stream = self.shell_stream(command).await?;
        let (mut stream_r, mut stream_w) = tokio::io::split(stream);

        tokio::select! {
            res1 = tokio::io::copy(stdin, &mut stream_w) => {
                let _ = res1?;
                let _ = stream_w.shutdown().await;
                let _ = tokio::io::copy(&mut stream_r, stdout).await?;
            }
            res2 = tokio::io::copy(&mut stream_r, stdout) => {
                let _ = res2?;
            }
        }
        Ok(())
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

    /// Queries detailed device hardware info (CPU, memory, storage, Android version, Android ID).
    pub async fn get_hardware_info(&self) -> Result<crate::info::DeviceHardwareInfo> {
        crate::info::query_device_hardware_info(self).await
    }

    /// Queries the 64-bit unique Android ID (`settings get secure android_id`).
    pub async fn get_android_id(&self) -> Result<Option<String>> {
        let out = self.shell("settings get secure android_id").await?;
        let trimmed = out.trim();
        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("null")
            || trimmed.contains("not found")
        {
            Ok(None)
        } else {
            Ok(Some(trimmed.to_string()))
        }
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

    /// Pushes in-memory bytes directly to a remote path on the device.
    pub async fn push_bytes(&self, bytes: &[u8], remote_path: &str) -> Result<u64> {
        self.push_bytes_with_mode(bytes, remote_path, DEFAULT_FILE_MODE).await
    }

    /// Pushes in-memory bytes with a specific file permission mode to a remote path.
    pub async fn push_bytes_with_mode(
        &self,
        bytes: &[u8],
        remote_path: &str,
        mode: u32,
    ) -> Result<u64> {
        let mut sync = self.sync().await?;
        let n = sync.push_bytes(bytes, remote_path, mode, 0).await?;
        let _ = sync.quit().await;
        Ok(n)
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

    /// Pulls a remote file directly into an in-memory byte buffer.
    pub async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        let mut sync = self.sync().await?;
        let mut buf = Vec::new();
        sync.pull(remote_path, &mut buf).await?;
        let _ = sync.quit().await;
        Ok(buf)
    }

    /// Captures a screenshot from the device as PNG encoded bytes.
    ///
    /// First attempts `exec:screencap -p` for fast direct streaming without disk I/O.
    /// If `exec:` is unsupported on legacy devices (e.g. Android 5.0), falls back to
    /// capturing to a temporary file via `shell:` and pulling it via binary `sync:`.
    pub async fn screencap(&self) -> Result<Vec<u8>> {
        const PNG_HEADER: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

        // Try direct streaming via exec: first (fastest, no disk wear)
        if let Ok(raw_png) = self.exec("screencap -p").await {
            if raw_png.len() >= 8 && &raw_png[..8] == PNG_HEADER {
                return Ok(raw_png);
            }
        }

        // Fallback for Android 5.0 devices lacking exec: service
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let remote_tmp_png = format!("/data/local/tmp/airadb_shot_{}.png", now);

        // Run screencap to temporary remote file
        let _ = self.shell(&format!("screencap -p \"{}\"", remote_tmp_png)).await?;

        // Pull binary file directly into memory
        let png_res = self.pull_bytes(&remote_tmp_png).await;

        // Cleanup temporary remote file
        let _ = self.shell(&format!("rm -f \"{}\"", remote_tmp_png)).await;

        let png_bytes = png_res?;
        if png_bytes.len() >= 8 && &png_bytes[..8] == PNG_HEADER {
            Ok(png_bytes)
        } else {
            Err(AdbError::Protocol("Captured screenshot data is not valid PNG format".into()))
        }
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
        let remote_tmp_apk = format!("/data/local/tmp/airadb_pkg_{}.apk", now);

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

    /// Installs an APK directly from an in-memory byte buffer without local temporary files.
    pub async fn install_apk_bytes(&self, apk_bytes: &[u8]) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let remote_tmp_apk = format!("/data/local/tmp/airadb_pkg_{}.apk", now);

        self.push_bytes(apk_bytes, &remote_tmp_apk).await?;

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
