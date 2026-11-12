use std::path::Path;
use std::time::SystemTime;
use byteorder::{ByteOrder, LittleEndian};
use tokio::fs as tokio_fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AdbError, Result};
use crate::stream::AdbStream;

// Sync Protocol IDs (little endian)
pub const ID_STAT: u32 = 0x54415453; // 'STAT'
pub const ID_LIST: u32 = 0x5453494c; // 'LIST'
pub const ID_DENT: u32 = 0x544e4544; // 'DENT'
pub const ID_SEND: u32 = 0x444e4553; // 'SEND'
pub const ID_RECV: u32 = 0x56434552; // 'RECV'
pub const ID_DONE: u32 = 0x454e4f44; // 'DONE'
pub const ID_DATA: u32 = 0x41544144; // 'DATA'
pub const ID_OKAY: u32 = 0x59414b4f; // 'OKAY'
pub const ID_FAIL: u32 = 0x4c494146; // 'FAIL'
pub const ID_QUIT: u32 = 0x54495551; // 'QUIT'

pub const SYNC_DATA_MAX: usize = 64 * 1024;
pub const DEFAULT_FILE_MODE: u32 = 0o100644; // Regular file, rw-r--r-- (33188)

/// File metadata returned by ADB sync `STAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStat {
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

impl SyncStat {
    pub fn exists(&self) -> bool {
        self.mode != 0
    }

    pub fn is_file(&self) -> bool {
        (self.mode & 0o170000) == 0o100000
    }

    pub fn is_dir(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }
}

/// Directory entry returned by ADB sync `LIST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDent {
    pub name: String,
    pub mode: u32,
    pub size: u32,
    pub mtime: u32,
}

impl SyncDent {
    pub fn is_file(&self) -> bool {
        (self.mode & 0o170000) == 0o100000
    }

    pub fn is_dir(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }
}

/// ADB file synchronization client operating over a `sync:` stream.
pub struct AdbSync {
    stream: AdbStream,
}

impl AdbSync {
    /// Creates a new `AdbSync` from an established `sync:` `AdbStream`.
    pub fn new(stream: AdbStream) -> Self {
        Self { stream }
    }

    /// Retrieves file metadata via sync `STAT`.
    pub async fn stat(&mut self, remote_path: &str) -> Result<SyncStat> {
        let path_bytes = remote_path.as_bytes();
        let mut req = Vec::with_capacity(8 + path_bytes.len());
        req.extend_from_slice(&[0u8; 8]);
        LittleEndian::write_u32(&mut req[0..4], ID_STAT);
        LittleEndian::write_u32(&mut req[4..8], path_bytes.len() as u32);
        req.extend_from_slice(path_bytes);

        self.stream.write_all(&req).await?;

        let mut resp = [0u8; 16];
        self.read_exact(&mut resp).await?;

        let id = LittleEndian::read_u32(&resp[0..4]);
        if id != ID_STAT {
            return Err(AdbError::SyncError(format!(
                "Expected ID_STAT, got {:#x}",
                id
            )));
        }

        let mode = LittleEndian::read_u32(&resp[4..8]);
        let size = LittleEndian::read_u32(&resp[8..12]);
        let mtime = LittleEndian::read_u32(&resp[12..16]);

        Ok(SyncStat { mode, size, mtime })
    }

    /// Lists directory entries via sync `LIST`.
    pub async fn list(&mut self, remote_path: &str) -> Result<Vec<SyncDent>> {
        let path_bytes = remote_path.as_bytes();
        let mut req = Vec::with_capacity(8 + path_bytes.len());
        req.extend_from_slice(&[0u8; 8]);
        LittleEndian::write_u32(&mut req[0..4], ID_LIST);
        LittleEndian::write_u32(&mut req[4..8], path_bytes.len() as u32);
        req.extend_from_slice(path_bytes);

        self.stream.write_all(&req).await?;

        let mut results = Vec::new();
        let mut header = [0u8; 20];

        loop {
            self.read_exact(&mut header[0..4]).await?;
            let id = LittleEndian::read_u32(&header[0..4]);

            if id == ID_DONE {
                // Read remaining 16 bytes of DONE message
                let mut dummy = [0u8; 16];
                self.read_exact(&mut dummy).await?;
                break;
            }

            if id != ID_DENT {
                return Err(AdbError::SyncError(format!(
                    "Expected ID_DENT or ID_DONE, got {:#x}",
                    id
                )));
            }

            self.read_exact(&mut header[4..20]).await?;
            let mode = LittleEndian::read_u32(&header[4..8]);
            let size = LittleEndian::read_u32(&header[8..12]);
            let mtime = LittleEndian::read_u32(&header[12..16]);
            let namelen = LittleEndian::read_u32(&header[16..20]) as usize;

            let mut name_buf = vec![0u8; namelen];
            self.read_exact(&mut name_buf).await?;
            let name = String::from_utf8_lossy(&name_buf).to_string();

            // Skip current and parent dir markers
            if name != "." && name != ".." {
                results.push(SyncDent {
                    name,
                    mode,
                    size,
                    mtime,
                });
            }
        }

        Ok(results)
    }

    /// Pulls a remote file and writes it into `writer`.
    pub async fn pull<W: AsyncWrite + Unpin>(
        &mut self,
        remote_path: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let path_bytes = remote_path.as_bytes();
        let mut req = Vec::with_capacity(8 + path_bytes.len());
        req.extend_from_slice(&[0u8; 8]);
        LittleEndian::write_u32(&mut req[0..4], ID_RECV);
        LittleEndian::write_u32(&mut req[4..8], path_bytes.len() as u32);
        req.extend_from_slice(path_bytes);

        self.stream.write_all(&req).await?;

        let mut total_bytes = 0u64;
        let mut header = [0u8; 8];

        loop {
            self.read_exact(&mut header).await?;
            let id = LittleEndian::read_u32(&header[0..4]);
            let len = LittleEndian::read_u32(&header[4..8]) as usize;

            if id == ID_DONE {
                break;
            } else if id == ID_DATA {
                let mut chunk = vec![0u8; len];
                self.read_exact(&mut chunk).await?;
                writer.write_all(&chunk).await?;
                total_bytes += len as u64;
            } else if id == ID_FAIL {
                let mut err_buf = vec![0u8; len];
                self.read_exact(&mut err_buf).await?;
                let err_msg = String::from_utf8_lossy(&err_buf);
                return Err(AdbError::SyncError(format!(
                    "Pull failed on device: {}",
                    err_msg
                )));
            } else {
                return Err(AdbError::SyncError(format!(
                    "Unexpected sync response: {:#x}",
                    id
                )));
            }
        }

        writer.flush().await?;
        Ok(total_bytes)
    }

    /// Pulls a remote file and saves it to a local file path.
    pub async fn pull_file<P: AsRef<Path>>(
        &mut self,
        remote_path: &str,
        local_path: P,
    ) -> Result<u64> {
        let local_path = local_path.as_ref();
        if let Some(parent) = local_path.parent() {
            tokio_fs::create_dir_all(parent).await?;
        }
        let mut file = tokio_fs::File::create(local_path).await?;
        self.pull(remote_path, &mut file).await
    }

    /// Pushes data from `reader` to a remote file path.
    pub async fn push<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        remote_path: &str,
        mode: u32,
        mtime: u32,
    ) -> Result<u64> {
        // ID_SEND_V1 path format: "<remote_path>,<mode>"
        let path_and_mode = format!("{},{}", remote_path, mode);
        let path_bytes = path_and_mode.as_bytes();

        let mut req = Vec::with_capacity(8 + path_bytes.len());
        req.extend_from_slice(&[0u8; 8]);
        LittleEndian::write_u32(&mut req[0..4], ID_SEND);
        LittleEndian::write_u32(&mut req[4..8], path_bytes.len() as u32);
        req.extend_from_slice(path_bytes);

        self.stream.write_all(&req).await?;

        let max_chunk = std::cmp::min(
            self.stream.max_payload.saturating_sub(8).max(512),
            SYNC_DATA_MAX,
        );
        let mut buf = vec![0u8; max_chunk];
        let mut total_bytes = 0u64;

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            let mut chunk_packet = Vec::with_capacity(8 + n);
            chunk_packet.extend_from_slice(&[0u8; 8]);
            LittleEndian::write_u32(&mut chunk_packet[0..4], ID_DATA);
            LittleEndian::write_u32(&mut chunk_packet[4..8], n as u32);
            chunk_packet.extend_from_slice(&buf[..n]);

            self.stream.write_all(&chunk_packet).await?;
            total_bytes += n as u64;
        }

        // Send ID_DONE with mtime
        let mut done_header = [0u8; 8];
        LittleEndian::write_u32(&mut done_header[0..4], ID_DONE);
        LittleEndian::write_u32(&mut done_header[4..8], mtime);
        self.stream.write_all(&done_header).await?;

        // Read response: ID_OKAY or ID_FAIL
        let mut resp_header = [0u8; 8];
        self.read_exact(&mut resp_header).await?;
        let resp_id = LittleEndian::read_u32(&resp_header[0..4]);
        let msg_len = LittleEndian::read_u32(&resp_header[4..8]) as usize;

        if resp_id == ID_OKAY {
            Ok(total_bytes)
        } else if resp_id == ID_FAIL {
            let mut err_buf = vec![0u8; msg_len];
            self.read_exact(&mut err_buf).await?;
            let err_msg = String::from_utf8_lossy(&err_buf);
            Err(AdbError::SyncError(format!(
                "Push failed on device: {}",
                err_msg
            )))
        } else {
            Err(AdbError::SyncError(format!(
                "Unexpected response to ID_DONE: {:#x}",
                resp_id
            )))
        }
    }

    /// Pushes in-memory bytes to a remote file path.
    pub async fn push_bytes(
        &mut self,
        bytes: &[u8],
        remote_path: &str,
        mode: u32,
        mtime: u32,
    ) -> Result<u64> {
        let mut cursor = std::io::Cursor::new(bytes);
        self.push(&mut cursor, remote_path, mode, mtime).await
    }

    /// Pushes a local file to a remote file path.
    pub async fn push_file<P: AsRef<Path>>(
        &mut self,
        local_path: P,
        remote_path: &str,
    ) -> Result<u64> {
        let local_path = local_path.as_ref();
        let metadata = tokio_fs::metadata(local_path).await?;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let mode = DEFAULT_FILE_MODE;

        let mut file = tokio_fs::File::open(local_path).await?;
        self.push(&mut file, remote_path, mode, mtime).await
    }

    /// Closes the sync service by sending `QUIT`.
    pub async fn quit(&mut self) -> Result<()> {
        let mut req = [0u8; 8];
        LittleEndian::write_u32(&mut req[0..4], ID_QUIT);
        LittleEndian::write_u32(&mut req[4..8], 0);
        let _ = self.stream.write_all(&req).await;
        self.stream.close().await
    }

    /// Helper to read exact number of bytes from the sync stream.
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            let n = self.stream.read(&mut buf[offset..]).await?;
            if n == 0 {
                return Err(AdbError::ConnectionClosed);
            }
            offset += n;
        }
        Ok(())
    }
}
