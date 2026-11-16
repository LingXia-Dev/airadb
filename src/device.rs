use std::fmt;
use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

use crate::client::Client;
use crate::connection::{hello, AdbConnection, AwaitingUser, Hello};
use crate::error::{Error, ErrorKind, Result};
use crate::stream::AdbStream;
use crate::sync::{AdbSync, SyncDent, SyncStat, DEFAULT_FILE_MODE};
use crate::types::{ActivityName, Key, PackageName};

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
        f.write_str(match self {
            Self::System => "",
            Self::Bootloader => "bootloader",
            Self::Recovery => "recovery",
            Self::Sideload => "sideload",
        })
    }
}

/// An installed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// The package name as the device reports it.
    pub package: String,
    pub apk_path: Option<String>,
    pub system: bool,
}

/// The focused app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Foreground {
    pub package: String,
    /// Fully qualified activity class, when the device reports one.
    pub activity: Option<String>,
}

/// The result of [`Device::authorize`].
#[must_use]
pub enum Authorization {
    /// The device already trusts this client's key.
    Authorized,
    /// The device is showing "Allow USB debugging?". Wait for the user.
    Waiting(AuthPrompt),
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized => f.write_str("Authorized"),
            Self::Waiting(_) => f.write_str("Waiting(..)"),
        }
    }
}

/// The device is showing its authorization dialog for our key.
pub struct AuthPrompt {
    device: Device,
    awaiting: AwaitingUser,
}

impl AuthPrompt {
    /// Wait up to the client's auth timeout (default 30s) for the user to
    /// allow. Declining and ignoring the dialog both end in
    /// [`ErrorKind::Unauthorized`]; the device does not say which.
    pub async fn wait(self) -> Result<()> {
        let limit = self.device.inner.client.inner.auth_timeout;
        self.wait_timeout(limit).await
    }

    pub async fn wait_timeout(self, limit: Duration) -> Result<()> {
        let conn = self.awaiting.wait(limit).await?;
        let mut slot = self.device.inner.conn.lock().await;
        self.device.inner.install(&mut slot, conn);
        Ok(())
    }

    pub fn device(&self) -> &Device {
        &self.device
    }
}

/// One Android device reachable over TCP. Cheap to clone; clones (and
/// other handles for the same address from the same [`Client`]) share the
/// connection.
///
/// Creating it sends nothing. The first call connects, authenticating with
/// the client's key **without** offering it: a device that does not trust
/// the key fails fast with [`ErrorKind::Unauthorized`] and shows nothing.
/// Only [`authorize`](Device::authorize) makes the device ask its user.
#[derive(Clone)]
pub struct Device {
    pub(crate) inner: Arc<DeviceInner>,
}

pub(crate) struct DeviceInner {
    client: Client,
    addr: SocketAddr,
    conn: tokio::sync::Mutex<Option<Arc<AdbConnection>>>,
    generation: AtomicU64,
    last_used: Mutex<Instant>,
}

impl DeviceInner {
    pub(crate) fn new(client: Client, addr: SocketAddr) -> Self {
        Self {
            client,
            addr,
            conn: tokio::sync::Mutex::new(None),
            generation: AtomicU64::new(0),
            last_used: Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        *self.last_used.lock().unwrap() = Instant::now();
    }

    /// Put `conn` in the slot and start its idle reaper.
    fn install(self: &Arc<Self>, slot: &mut Option<Arc<AdbConnection>>, conn: AdbConnection) -> Arc<AdbConnection> {
        let conn = Arc::new(conn);
        *slot = Some(conn.clone());
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.touch();
        if let Some(idle) = self.client.inner.idle_timeout {
            let weak = Arc::downgrade(self);
            tokio::spawn(reap_when_idle(weak, generation, idle));
        }
        conn
    }
}

async fn reap_when_idle(device: std::sync::Weak<DeviceInner>, generation: u64, idle: Duration) {
    let tick = (idle / 4).max(Duration::from_millis(50));
    loop {
        tokio::time::sleep(tick).await;
        let Some(device) = device.upgrade() else { return };
        if device.generation.load(Ordering::SeqCst) != generation {
            return; // replaced by a newer connection with its own reaper
        }
        let mut slot = device.conn.lock().await;
        let Some(conn) = slot.as_ref() else { return };
        if !conn.is_connected() {
            *slot = None;
            return;
        }
        let quiet = device.last_used.lock().unwrap().elapsed() >= idle;
        if quiet && !conn.has_open_streams() {
            tracing::debug!("closing idle connection to {}", device.addr);
            if let Some(conn) = slot.take() {
                conn.shutdown().await;
            }
            return;
        }
    }
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device").field("addr", &self.inner.addr).finish()
    }
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

/// Workaround for Android 5 adbd, which can drop the last byte of a
/// service name: end every command with a space.
fn padded_service(prefix: &str, command: &str) -> String {
    let trimmed = command.trim_end_matches('\0');
    if trimmed.ends_with(char::is_whitespace) {
        format!("{prefix}{trimmed}\0")
    } else {
        format!("{prefix}{trimmed} \0")
    }
}

/// Quote one argument for `/system/bin/sh`.
pub fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-./=:,@%+".contains(&b));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

impl Device {
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// The live connection, connecting first if needed (signature only).
    pub async fn connection(&self) -> Result<Arc<AdbConnection>> {
        let mut slot = self.inner.conn.lock().await;
        if let Some(conn) = slot.as_ref() {
            if conn.is_connected() {
                self.inner.touch();
                return Ok(conn.clone());
            }
        }
        *slot = None;
        let client = &self.inner.client.inner;
        match hello(self.inner.addr, &client.key, client.timeouts).await? {
            Hello::Connected(conn) => Ok(self.inner.install(&mut slot, conn)),
            Hello::UnknownKey(_) => Err(Error::unauthorized(format!(
                "{} does not trust this client's key; call authorize() and confirm on the device",
                self.inner.addr
            ))),
        }
    }

    /// Connect now (signature only). Fails with [`ErrorKind::Unauthorized`]
    /// if the device does not trust the key; nothing is shown on it.
    pub async fn connect(&self) -> Result<()> {
        self.connection().await.map(drop)
    }

    /// Connect, offering the public key if the device does not trust it.
    /// This is the only call that makes the device show its dialog.
    pub async fn authorize(&self) -> Result<Authorization> {
        let mut slot = self.inner.conn.lock().await;
        if slot.as_ref().is_some_and(|c| c.is_connected()) {
            return Ok(Authorization::Authorized);
        }
        let client = &self.inner.client.inner;
        match hello(self.inner.addr, &client.key, client.timeouts).await? {
            Hello::Connected(conn) => {
                self.inner.install(&mut slot, conn);
                Ok(Authorization::Authorized)
            }
            Hello::UnknownKey(pending) => {
                drop(slot);
                let awaiting = pending.offer_key(&client.key).await?;
                Ok(Authorization::Waiting(AuthPrompt { device: self.clone(), awaiting }))
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.inner.conn.lock().await.as_ref().is_some_and(|c| c.is_connected())
    }

    /// The banner the device sent on connect (`device::ro.product.model=…`).
    pub async fn banner(&self) -> Result<String> {
        Ok(self.connection().await?.device_banner().to_string())
    }

    /// Close the connection now. The next call reconnects.
    pub async fn close(&self) {
        if let Some(conn) = self.inner.conn.lock().await.take() {
            conn.shutdown().await;
        }
    }

    /// Open a raw service stream (`shell:…`, `exec:…`, `sync:`, …).
    pub async fn open_stream(&self, destination: &str) -> Result<AdbStream> {
        let conn = self.connection().await?;
        self.inner.touch();
        conn.open_stream(destination).await
    }

    // ---------------------------------------------------------------- shell

    /// A shell command. Arguments added with [`ShellCommand::arg`] are
    /// quoted, so values cannot change what runs.
    ///
    /// ```no_run
    /// # async fn demo(dev: airadb::Device) -> airadb::Result<()> {
    /// let model = dev.shell("getprop").arg("ro.product.model").await?;
    /// # Ok(()) }
    /// ```
    pub fn shell(&self, program: &str) -> ShellCommand {
        ShellCommand { device: self.clone(), line: shell_quote(program), checked: false }
    }

    /// Run a whole command line as is. The caller is responsible for
    /// quoting; prefer [`shell`](Device::shell).
    pub async fn shell_raw(&self, command: &str) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.shell_raw_bytes(command).await?).into_owned())
    }

    pub async fn shell_raw_bytes(&self, command: &str) -> Result<Vec<u8>> {
        let mut stream = self.open_stream(&padded_service("shell:", command)).await?;
        stream.read_all().await
    }

    /// An interactive shell (`shell:` without a command).
    pub async fn interactive_shell(&self) -> Result<AdbStream> {
        self.open_stream("shell:").await
    }

    /// A shell command as a stream (for long-running output).
    pub async fn shell_stream(&self, command: &str) -> Result<AdbStream> {
        self.open_stream(&padded_service("shell:", command)).await
    }

    /// `exec:` (no PTY, binary-safe; Android 7+).
    pub async fn exec_raw(&self, command: &str) -> Result<Vec<u8>> {
        let mut stream = self.open_stream(&padded_service("exec:", command)).await?;
        stream.read_all().await
    }

    pub async fn exec_stream(&self, command: &str) -> Result<AdbStream> {
        self.open_stream(&padded_service("exec:", command)).await
    }

    /// Pump `stdin` into an `exec:` command and its output into `stdout`.
    pub async fn exec_pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        command: &str,
        stdin: &mut R,
        stdout: &mut W,
    ) -> Result<()> {
        pump(self.exec_stream(command).await?, stdin, stdout).await
    }

    /// Pump `stdin` into a `shell:` command and its output into `stdout`.
    pub async fn shell_pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        command: &str,
        stdin: &mut R,
        stdout: &mut W,
    ) -> Result<()> {
        pump(self.shell_stream(command).await?, stdin, stdout).await
    }

    /// `getprop <name>`, trimmed.
    pub async fn getprop(&self, name: &str) -> Result<String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
            return Err(Error::invalid_arg(format!("invalid property name '{name}'")));
        }
        Ok(self.shell("getprop").arg(name).await?.trim().to_string())
    }

    /// Whether `cmd` is on the device's `PATH`.
    pub async fn has_command(&self, cmd: &str) -> bool {
        let q = shell_quote(cmd);
        self.shell_raw(&format!("command -v {q} >/dev/null 2>&1 || which {q} >/dev/null 2>&1; echo $?"))
            .await
            .is_ok_and(|out| out.trim().ends_with('0'))
    }

    // ---------------------------------------------------------------- input

    pub async fn press(&self, key: Key) -> Result<()> {
        self.press_code(key.android_keycode()).await
    }

    /// Send any Android `KeyEvent` code.
    pub async fn press_code(&self, keycode: u32) -> Result<()> {
        self.shell("input").arg("keyevent").arg(keycode.to_string()).await.map(drop)
    }

    /// Press keys one after another, stopping at the first failure.
    pub async fn press_seq(&self, keys: impl IntoIterator<Item = Key>) -> Result<()> {
        for key in keys {
            self.press(key).await?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- apps

    /// All installed packages.
    pub async fn apps(&self) -> Result<Vec<Package>> {
        self.list_packages(false).await
    }

    /// Packages the user installed (`pm list packages -3`).
    pub async fn user_apps(&self) -> Result<Vec<Package>> {
        self.list_packages(true).await
    }

    async fn list_packages(&self, third_party: bool) -> Result<Vec<Package>> {
        let mut cmd = self.shell("pm").arg("list").arg("packages").arg("-f");
        if third_party {
            cmd = cmd.arg("-3");
        }
        let mut list: Vec<Package> = cmd
            .await?
            .lines()
            .filter_map(|line| line.trim().strip_prefix("package:"))
            .map(|rest| {
                let (apk_path, package) = match rest.rsplit_once('=') {
                    Some((path, pkg)) => (Some(path.to_string()), pkg.to_string()),
                    None => (None, rest.to_string()),
                };
                let system = match &apk_path {
                    Some(p) => !p.starts_with("/data/"),
                    None => !third_party,
                };
                Package { package, apk_path, system }
            })
            .collect();
        list.sort_by(|a, b| a.package.cmp(&b.package));
        Ok(list)
    }

    /// The focused app, if any.
    pub async fn foreground(&self) -> Result<Option<Foreground>> {
        let output = self.shell_raw("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'").await?;
        Ok(parse_foreground(&output))
    }

    /// Launch the package's launcher activity.
    pub async fn launch(&self, package: &PackageName) -> Result<()> {
        let out = self
            .shell("monkey")
            .args(["-p", package.as_str(), "-c", "android.intent.category.LAUNCHER", "1"])
            .await?;
        if out.contains("No activities found") {
            let out = self
                .shell("am")
                .args(["start", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER"])
                .args(["-p", package.as_str()])
                .await?;
            if out.contains("Error:") {
                return Err(Error::rejected(format!("{package} has no launcher activity")));
            }
        }
        Ok(())
    }

    pub async fn launch_activity(&self, package: &PackageName, activity: &ActivityName) -> Result<()> {
        let component = format!("{}/{}", package, activity.qualified(package));
        let out = self.shell("am").arg("start").arg("-n").arg(&component).await?;
        if out.contains("Error:") {
            return Err(Error::rejected(format!("am start {component}: {}", out.trim())));
        }
        Ok(())
    }

    /// `am force-stop`.
    pub async fn force_stop(&self, package: &PackageName) -> Result<()> {
        self.shell("am").arg("force-stop").arg(package.as_str()).await.map(drop)
    }

    /// `pm clear`: wipe the app's data and cache.
    pub async fn clear_data(&self, package: &PackageName) -> Result<()> {
        let out = self.shell("pm").arg("clear").arg(package.as_str()).await?;
        expect_success(&out, ErrorKind::Rejected, "pm clear")
    }

    pub async fn uninstall(&self, package: &PackageName) -> Result<()> {
        let out = self.shell("pm").arg("uninstall").arg(package.as_str()).await?;
        expect_success(&out, ErrorKind::Rejected, "pm uninstall")
    }

    /// Uninstall but keep data and cache (`pm uninstall -k`).
    pub async fn uninstall_keep_data(&self, package: &PackageName) -> Result<()> {
        let out = self.shell("pm").arg("uninstall").arg("-k").arg(package.as_str()).await?;
        expect_success(&out, ErrorKind::Rejected, "pm uninstall -k")
    }

    /// Install an APK from a local file; `.await` the request.
    pub fn install(&self, apk: impl Into<PathBuf>) -> InstallRequest {
        InstallRequest { device: self.clone(), path: apk.into(), progress: None }
    }

    // ---------------------------------------------------------------- info

    pub async fn hardware_info(&self) -> Result<crate::info::DeviceHardwareInfo> {
        crate::info::query_device_hardware_info(self).await
    }

    /// `settings get secure android_id`, a stable per-device id.
    pub async fn android_id(&self) -> Result<Option<String>> {
        let out = self.shell("settings").args(["get", "secure", "android_id"]).await?;
        let id = out.trim();
        Ok((!id.is_empty() && !id.eq_ignore_ascii_case("null") && !id.contains("not found")).then(|| id.to_string()))
    }

    /// A PNG screenshot. Uses `exec:screencap -p`, falling back to a file
    /// and `sync:` on devices without `exec:` (Android 5/6).
    pub async fn screencap(&self) -> Result<Vec<u8>> {
        const PNG_HEADER: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
        if let Ok(Ok(png)) = timeout(Duration::from_millis(1500), self.exec_raw("screencap -p")).await {
            if png.starts_with(PNG_HEADER) {
                return Ok(png);
            }
        }
        let remote = format!("/data/local/tmp/airadb_shot_{}.png", now_millis());
        let guard = RemoteFile::new(self, &remote);
        self.shell("screencap").arg("-p").arg(&remote).await?;
        let png = self.pull_bytes(&remote).await;
        guard.remove().await;
        let png = png?;
        if png.starts_with(PNG_HEADER) {
            Ok(png)
        } else {
            Err(Error::protocol("screencap did not produce a PNG"))
        }
    }

    // ---------------------------------------------------------------- files

    pub async fn sync(&self) -> Result<AdbSync> {
        Ok(AdbSync::new(self.open_stream("sync:").await?))
    }

    pub async fn push_bytes(&self, bytes: &[u8], remote_path: &str) -> Result<u64> {
        self.push_bytes_with_mode(bytes, remote_path, DEFAULT_FILE_MODE).await
    }

    pub async fn push_bytes_with_mode(&self, bytes: &[u8], remote_path: &str, mode: u32) -> Result<u64> {
        let mut sync = self.sync().await?;
        let n = sync.push_bytes(bytes, remote_path, mode, 0).await?;
        let _ = sync.quit().await;
        Ok(n)
    }

    pub async fn push_file<P: AsRef<Path>>(&self, local_path: P, remote_path: &str) -> Result<u64> {
        let mut sync = self.sync().await?;
        let n = sync.push_file(local_path, remote_path).await?;
        let _ = sync.quit().await;
        Ok(n)
    }

    pub async fn pull_file<P: AsRef<Path>>(&self, remote_path: &str, local_path: P) -> Result<u64> {
        let mut sync = self.sync().await?;
        let n = sync.pull_file(remote_path, local_path).await?;
        let _ = sync.quit().await;
        Ok(n)
    }

    pub async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        let mut sync = self.sync().await?;
        let mut buf = Vec::new();
        sync.pull(remote_path, &mut buf).await?;
        let _ = sync.quit().await;
        Ok(buf)
    }

    pub async fn stat(&self, remote_path: &str) -> Result<SyncStat> {
        let mut sync = self.sync().await?;
        let stat = sync.stat(remote_path).await?;
        let _ = sync.quit().await;
        Ok(stat)
    }

    pub async fn list(&self, remote_path: &str) -> Result<Vec<SyncDent>> {
        let mut sync = self.sync().await?;
        let entries = sync.list(remote_path).await?;
        let _ = sync.quit().await;
        Ok(entries)
    }

    // ---------------------------------------------------------------- adbd

    pub async fn reboot(&self, mode: RebootMode) -> Result<()> {
        let mut stream = self.open_stream(&format!("reboot:{mode}")).await?;
        let _ = stream.read_all().await;
        self.close().await;
        Ok(())
    }

    pub async fn remount(&self) -> Result<String> {
        self.open_stream("remount:").await?.read_string_lossy().await
    }

    /// Restart adbd listening on TCP `port`.
    pub async fn tcpip(&self, port: u16) -> Result<String> {
        self.open_stream(&format!("tcpip:{port}")).await?.read_string_lossy().await
    }

    pub async fn root(&self) -> Result<String> {
        self.open_stream("root:").await?.read_string_lossy().await
    }

    pub async fn unroot(&self) -> Result<String> {
        self.open_stream("unroot:").await?.read_string_lossy().await
    }
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    stream: AdbStream,
    stdin: &mut R,
    stdout: &mut W,
) -> Result<()> {
    let (mut stream_r, mut stream_w) = tokio::io::split(stream);
    tokio::select! {
        res = tokio::io::copy(stdin, &mut stream_w) => {
            res?;
            let _ = stream_w.shutdown().await;
            tokio::io::copy(&mut stream_r, stdout).await?;
        }
        res = tokio::io::copy(&mut stream_r, stdout) => {
            res?;
        }
    }
    Ok(())
}

fn expect_success(output: &str, kind: ErrorKind, what: &str) -> Result<()> {
    if output.contains("Success") {
        Ok(())
    } else {
        Err(Error::new(kind, format!("{what} failed: {}", output.trim())))
    }
}

pub(crate) fn parse_foreground(output: &str) -> Option<Foreground> {
    for line in output.lines() {
        let Some(pos) = line.find(" u0 ") else { continue };
        let rest = &line[pos + 4..];
        let end = rest.find(['}', ' ']).unwrap_or(rest.len());
        let target = rest[..end].trim();
        if target.is_empty() || target == "null" {
            continue;
        }
        return Some(match target.split_once('/') {
            Some((package, activity)) => {
                let activity =
                    if activity.starts_with('.') { format!("{package}{activity}") } else { activity.to_string() };
                Foreground { package: package.to_string(), activity: Some(activity) }
            }
            None => Foreground { package: target.to_string(), activity: None },
        });
    }
    None
}

/// A shell command under construction. `.await` it for its output.
#[must_use = "a shell command does nothing until awaited"]
pub struct ShellCommand {
    device: Device,
    line: String,
    checked: bool,
}

impl ShellCommand {
    /// Append one argument, quoted.
    pub fn arg(mut self, arg: impl AsRef<str>) -> Self {
        self.line.push(' ');
        self.line.push_str(&shell_quote(arg.as_ref()));
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for arg in args {
            self = self.arg(arg);
        }
        self
    }

    /// Fail with [`ErrorKind::Rejected`] when the command exits non-zero.
    /// (Android < 7 has no separate exit status; a marker is echoed.)
    pub fn checked(mut self) -> Self {
        self.checked = true;
        self
    }

    /// The command line that will run.
    pub fn command_line(&self) -> &str {
        &self.line
    }

    pub async fn bytes(self) -> Result<Vec<u8>> {
        self.device.shell_raw_bytes(&self.line).await
    }

    async fn run(self) -> Result<String> {
        if !self.checked {
            return self.device.shell_raw(&self.line).await;
        }
        const MARKER: &str = "__AIRADB_EXIT_STATUS__";
        let raw = self.device.shell_raw(&format!("{}; echo \"\n{MARKER}:$?\"", self.line)).await?;
        let Some(pos) = raw.rfind(MARKER) else { return Ok(raw) };
        let output = raw[..pos].trim_end().to_string();
        let code: i32 = raw[pos + MARKER.len()..].trim().trim_start_matches(':').trim().parse().unwrap_or(0);
        if code == 0 {
            Ok(output)
        } else {
            Err(Error::rejected(format!("`{}` exited with {code}: {}", self.line, output.trim())))
        }
    }
}

impl IntoFuture for ShellCommand {
    type Output = Result<String>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<String>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run())
    }
}

/// A temporary file on the device, removed even if the operation using it
/// is cancelled (dropped) half-way.
struct RemoteFile {
    device: Device,
    path: String,
    armed: bool,
}

impl RemoteFile {
    fn new(device: &Device, path: &str) -> Self {
        Self { device: device.clone(), path: path.to_string(), armed: true }
    }

    async fn remove(mut self) {
        self.armed = false;
        let _ = timeout(Duration::from_secs(10), self.device.shell("rm").arg("-f").arg(&self.path)).await;
    }
}

impl Drop for RemoteFile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let (device, path) = (self.device.clone(), self.path.clone());
            rt.spawn(async move {
                let _ = timeout(Duration::from_secs(10), device.shell("rm").arg("-f").arg(&path)).await;
            });
        }
    }
}

type ProgressFn = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// An APK install; `.await` it. Dropping the future cancels the upload and
/// removes the partial file from the device.
#[must_use = "an install does nothing until awaited"]
pub struct InstallRequest {
    device: Device,
    path: PathBuf,
    progress: Option<ProgressFn>,
}

impl InstallRequest {
    /// Called with `(sent, total)` bytes while uploading.
    pub fn on_progress(mut self, f: impl Fn(u64, u64) + Send + Sync + 'static) -> Self {
        self.progress = Some(Arc::new(f));
        self
    }

    async fn run(self) -> Result<()> {
        let file = tokio::fs::File::open(&self.path)
            .await
            .map_err(|e| Error::invalid_arg(format!("cannot open {}: {e}", self.path.display())))?;
        let total = file.metadata().await?.len();
        let remote = format!("/data/local/tmp/airadb_pkg_{}_{:04x}.apk", now_millis(), rand_u16());
        let tmp = RemoteFile::new(&self.device, &remote);

        let mut sync = self.device.sync().await?;
        let mut reader = ProgressReader { inner: file, sent: 0, total, progress: self.progress.clone() };
        if let Some(cb) = &self.progress {
            cb(0, total);
        }
        sync.push(&mut reader, &remote, DEFAULT_FILE_MODE, 0).await?;
        let _ = sync.quit().await;

        let out = self.device.shell("pm").arg("install").arg("-r").arg(&remote).await;
        tmp.remove().await;
        expect_success(&out?, ErrorKind::InstallFailed, "pm install")
    }
}

impl IntoFuture for InstallRequest {
    type Output = Result<()>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run())
    }
}

fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    u16::from_le_bytes(b)
}

struct ProgressReader<R> {
    inner: R,
    sent: u64,
    total: u64,
    progress: Option<ProgressFn>,
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressReader<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            self.sent += n;
            if let Some(cb) = &self.progress {
                cb(self.sent, self.total);
            }
        }
        poll
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("com.example.app"), "com.example.app");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("$(reboot)"), "'$(reboot)'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("x;rm -rf /"), "'x;rm -rf /'");
        assert_eq!(shell_quote("Main$Inner"), "'Main$Inner'");
    }

    #[test]
    fn foreground_parsing() {
        let out = "  mCurrentFocus=Window{4a1 u0 com.mitv.tvhome/com.mitv.tvhome.MainActivity}\n";
        assert_eq!(
            parse_foreground(out),
            Some(Foreground {
                package: "com.mitv.tvhome".into(),
                activity: Some("com.mitv.tvhome.MainActivity".into())
            })
        );
        let out = "  mFocusedApp=AppWindowToken{x token=Token{y ActivityRecord{z u0 com.a/.Main t5}}}";
        assert_eq!(parse_foreground(out).unwrap().activity.as_deref(), Some("com.a.Main"));
        assert_eq!(parse_foreground("mCurrentFocus=null"), None);
    }
}
