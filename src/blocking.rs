use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

use crate::crypto::load_or_create_from_path;
use crate::device::ShellOutput;
use crate::error::Result;
use crate::pool::DevicePool;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("airadb-runtime")
            .build()
            .expect("Failed to initialize airadb background tokio runtime")
    })
}

/// Synchronous (blocking) connection pool for environments that cannot use `async`/`await` directly.
///
/// Internally uses a dedicated background Tokio runtime to drive async I/O.
#[derive(Clone, Default)]
pub struct BlockingDevicePool {
    pool: DevicePool,
}

impl BlockingDevicePool {
    /// Creates a new `BlockingDevicePool`.
    pub fn new() -> Self {
        Self {
            pool: DevicePool::new(),
        }
    }

    /// Executes a shell command synchronously on `addr`, caching and reusing the TCP connection.
    pub fn shell(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        command: &str,
    ) -> Result<ShellOutput> {
        let key = load_or_create_from_path(key_path)?;
        get_runtime().block_on(async {
            self.pool.shell_output(addr, Some(&key), command).await
        })
    }

    /// Executes a shell command synchronously and validates its exit code.
    pub fn shell_checked(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        command: &str,
    ) -> Result<String> {
        let key = load_or_create_from_path(key_path)?;
        get_runtime().block_on(self.pool.shell_checked(addr, Some(&key), command))
    }

    /// Checks if an executable command exists in PATH on `addr`.
    pub fn has_command(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        cmd: &str,
    ) -> bool {
        if let Ok(key) = load_or_create_from_path(key_path) {
            get_runtime().block_on(self.pool.has_command(addr, Some(&key), cmd))
        } else {
            false
        }
    }

    /// Pushes in-memory bytes to `remote_path` on `addr` synchronously.
    pub fn push(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        bytes: &[u8],
        remote_path: &str,
    ) -> Result<()> {
        let key = load_or_create_from_path(key_path)?;
        get_runtime().block_on(async {
            let _ = self.pool.push_bytes(addr, Some(&key), bytes, remote_path).await?;
            Ok(())
        })
    }

    /// Pumps synchronous `stdin` into a remote `exec:` daemon and streams output to `stdout`.
    ///
    /// Ideal for driving on-device agent binaries (like `mukeinstall-device-util`).
    pub fn exec(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        command: &str,
        stdin: &mut dyn Read,
        mut stdout: Box<dyn Write + Send>,
    ) -> Result<()> {
        let key = load_or_create_from_path(key_path)?;
        let rt = get_runtime();

        let device = rt.block_on(async {
            self.pool.get_or_connect(addr, Some(&key)).await
        })?;

        let stream = rt.block_on(async {
            device.exec_stream(command).await
        })?;

        let (mut stream_r, mut stream_w) = tokio::io::split(stream);

        // Spawn stdout drainer task in runtime
        let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let read_handle = rt.spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 4096];
            loop {
                match stream_r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdout_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Drain stdout in background thread
        let stdout_thread = std::thread::spawn(move || -> std::io::Result<()> {
            while let Some(chunk) = stdout_rx.blocking_recv() {
                stdout.write_all(&chunk)?;
                stdout.flush()?;
            }
            Ok(())
        });

        // Pump stdin synchronously
        let mut stdin_buf = [0u8; 4096];
        loop {
            match stdin.read(&mut stdin_buf) {
                Ok(0) => break,
                Ok(n) => {
                    use tokio::io::AsyncWriteExt;
                    let chunk = stdin_buf[..n].to_vec();
                    let res = rt.block_on(async {
                        stream_w.write_all(&chunk).await
                    });
                    if res.is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }

        // Close write half so remote process receives EOF
        let _ = rt.block_on(async {
            use tokio::io::AsyncWriteExt;
            stream_w.shutdown().await
        });

        let _ = rt.block_on(read_handle);
        let _ = stdout_thread.join();

        Ok(())
    }

    /// Captures a screenshot from `addr` synchronously, returning PNG bytes.
    pub fn screencap(&self, addr: SocketAddr, key_path: &Path) -> Result<Vec<u8>> {
        let key = load_or_create_from_path(key_path)?;
        get_runtime().block_on(self.pool.screencap(addr, Some(&key)))
    }

    /// Pulls a remote file from `addr` directly into memory.
    pub fn pull_bytes(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        remote_path: &str,
    ) -> Result<Vec<u8>> {
        let key = load_or_create_from_path(key_path)?;
        get_runtime().block_on(self.pool.pull_bytes(addr, Some(&key), remote_path))
    }

    /// Installs an APK on `addr` synchronously from a local file path.
    pub fn install_apk<P: AsRef<Path>>(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        local_apk_path: P,
    ) -> Result<()> {
        let key = load_or_create_from_path(key_path)?;
        get_runtime().block_on(self.pool.install_apk(addr, Some(&key), local_apk_path))
    }

    /// Installs an APK on `addr` synchronously directly from in-memory bytes.
    pub fn install_apk_bytes(
        &self,
        addr: SocketAddr,
        key_path: &Path,
        apk_bytes: &[u8],
    ) -> Result<()> {
        let key = load_or_create_from_path(key_path)?;
        get_runtime().block_on(self.pool.install_apk_bytes(addr, Some(&key), apk_bytes))
    }

    /// Scans the local network for ADB devices synchronously.
    pub fn scan(
        &self,
        subnet: Option<&str>,
        ports: Option<&[u16]>,
        timeout: Option<std::time::Duration>,
    ) -> Result<Vec<crate::scan::DiscoveredDevice>> {
        let options = crate::scan::ScanOptions {
            subnet: subnet.map(|s| s.to_string()),
            candidates: None,
            ports: ports
                .map(|p| p.to_vec())
                .unwrap_or_else(|| vec![crate::scan::DEFAULT_ADB_PORT]),
            timeout: timeout.unwrap_or(std::time::Duration::from_millis(800)),
            concurrency: 96,
        };
        get_runtime().block_on(crate::scan::scan_devices(options))
    }
}
