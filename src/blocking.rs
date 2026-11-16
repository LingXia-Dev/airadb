//! A synchronous wrapper for callers without an async runtime
//! (`blocking` feature). Each call runs on a small private runtime.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use tokio::runtime::Runtime;

use crate::{Client, Device, DeviceHardwareInfo, DiscoveredDevice, Key, PackageName, Result};

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("airadb-blocking")
            .build()
            .expect("cannot start the airadb runtime")
    })
}

/// Blocking counterpart of [`Client`]. Must not be used from inside an
/// async runtime.
#[derive(Clone)]
pub struct BlockingClient {
    client: Client,
}

impl BlockingClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn device(&self, addr: SocketAddr) -> BlockingDevice {
        // The device's reaper task must live on the runtime that drives it.
        let _guard = runtime().enter();
        BlockingDevice { device: Arc::new(self.client.device(addr)) }
    }

    pub fn discover(&self) -> Result<Vec<DiscoveredDevice>> {
        let discover = self.client.discover();
        runtime().block_on(async move { discover.await })
    }
}

/// Blocking counterpart of [`Device`].
#[derive(Clone)]
pub struct BlockingDevice {
    device: Arc<Device>,
}

impl BlockingDevice {
    pub fn device(&self) -> &Device {
        &self.device
    }

    pub fn connect(&self) -> Result<()> {
        runtime().block_on(self.device.connect())
    }

    /// Run a command line as is (caller quotes).
    pub fn shell_raw(&self, command: &str) -> Result<String> {
        runtime().block_on(self.device.shell_raw(command))
    }

    /// Run `program` with quoted `args`.
    pub fn shell<I, S>(&self, program: &str, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let cmd = self.device.shell(program).args(args);
        runtime().block_on(async move { cmd.await })
    }

    pub fn has_command(&self, cmd: &str) -> bool {
        runtime().block_on(self.device.has_command(cmd))
    }

    pub fn press(&self, key: Key) -> Result<()> {
        runtime().block_on(self.device.press(key))
    }

    pub fn push_bytes(&self, bytes: &[u8], remote_path: &str) -> Result<u64> {
        runtime().block_on(self.device.push_bytes(bytes, remote_path))
    }

    pub fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        runtime().block_on(self.device.pull_bytes(remote_path))
    }

    pub fn install(&self, apk: impl Into<PathBuf>) -> Result<()> {
        let req = self.device.install(apk);
        runtime().block_on(async move { req.await })
    }

    pub fn uninstall(&self, package: &PackageName) -> Result<()> {
        runtime().block_on(self.device.uninstall(package))
    }

    pub fn screencap(&self) -> Result<Vec<u8>> {
        runtime().block_on(self.device.screencap())
    }

    pub fn hardware_info(&self) -> Result<DeviceHardwareInfo> {
        runtime().block_on(self.device.hardware_info())
    }

    pub fn close(&self) {
        runtime().block_on(self.device.close())
    }
}
