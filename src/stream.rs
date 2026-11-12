use std::cmp;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::error::{AdbError, Result};
use crate::packet::{AdbPacket, A_CLSE, A_WRTE};

/// A bidirectional multiplexed stream over an ADB connection.
pub struct AdbStream {
    pub(crate) local_id: u32,
    pub(crate) remote_id: u32,
    pub(crate) max_payload: usize,
    pub(crate) writer_tx: mpsc::Sender<AdbPacket>,
    pub(crate) data_rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) write_ack_rx: mpsc::Receiver<()>,
    pub(crate) read_buf: Vec<u8>,
    pub(crate) read_pos: usize,
    pub(crate) closed: Arc<AtomicBool>,
    pub(crate) waiting_ack: bool,
}

impl AdbStream {
    pub(crate) fn new(
        local_id: u32,
        remote_id: u32,
        max_payload: usize,
        writer_tx: mpsc::Sender<AdbPacket>,
        data_rx: mpsc::Receiver<Vec<u8>>,
        write_ack_rx: mpsc::Receiver<()>,
        closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            local_id,
            remote_id,
            max_payload,
            writer_tx,
            data_rx,
            write_ack_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            closed,
            waiting_ack: false,
        }
    }

    /// Returns the local stream identifier.
    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    /// Returns the remote stream identifier.
    pub fn remote_id(&self) -> u32 {
        self.remote_id
    }

    /// Checks if the stream has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Reads incoming data into the buffer. Returns 0 on EOF.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Consume any remaining data in internal buffer
        if self.read_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_pos;
            let to_read = cmp::min(available, buf.len());
            buf[..to_read].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;
            return Ok(to_read);
        }

        // Wait for next chunk
        match self.data_rx.recv().await {
            Some(chunk) => {
                let to_read = cmp::min(chunk.len(), buf.len());
                buf[..to_read].copy_from_slice(&chunk[..to_read]);
                if to_read < chunk.len() {
                    self.read_buf = chunk;
                    self.read_pos = to_read;
                } else {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                Ok(to_read)
            }
            None => Ok(0), // EOF
        }
    }

    /// Reads all remaining data from the stream until it is closed.
    pub async fn read_all(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = self.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buf[..n]);
        }
        Ok(result)
    }

    /// Reads all remaining data as a UTF-8 string (lossy).
    pub async fn read_string_lossy(&mut self) -> Result<String> {
        let bytes = self.read_all().await?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    /// Writes data to the remote stream.
    ///
    /// Respects the device max payload limit and waits for an `A_OKAY`
    /// acknowledgment from the device after each chunk according to the ADB protocol.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Err(AdbError::StreamClosed {
                local_id: self.local_id,
                remote_id: self.remote_id,
            });
        }

        let chunk_size = cmp::min(self.max_payload, 64 * 1024);
        for chunk in data.chunks(chunk_size) {
            let packet = AdbPacket::new(
                A_WRTE,
                self.local_id,
                self.remote_id,
                chunk.to_vec(),
            );

            self.writer_tx
                .send(packet)
                .await
                .map_err(|_| AdbError::ConnectionClosed)?;

            // Wait for A_OKAY acknowledgment before sending next chunk
            match self.write_ack_rx.recv().await {
                Some(()) => {}
                None => {
                    return Err(AdbError::StreamClosed {
                        local_id: self.local_id,
                        remote_id: self.remote_id,
                    });
                }
            }
        }

        Ok(())
    }

    /// Closes the stream by sending an `A_CLSE` packet.
    pub async fn close(&mut self) -> Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let packet = AdbPacket::new(A_CLSE, self.local_id, self.remote_id, Vec::new());
            let _ = self.writer_tx.send(packet).await;
        }
        Ok(())
    }
}

impl Drop for AdbStream {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let packet = AdbPacket::new(A_CLSE, self.local_id, self.remote_id, Vec::new());
            let _ = self.writer_tx.try_send(packet);
        }
    }
}

impl AsyncRead for AdbStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if self.read_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_pos;
            let to_read = cmp::min(available, buf.remaining());
            buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;
            return Poll::Ready(Ok(()));
        }

        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let to_read = cmp::min(chunk.len(), buf.remaining());
                buf.put_slice(&chunk[..to_read]);
                if to_read < chunk.len() {
                    self.read_buf = chunk;
                    self.read_pos = to_read;
                } else {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AdbStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream closed",
            )));
        }

        if self.waiting_ack {
            match self.write_ack_rx.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    self.waiting_ack = false;
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Stream closed while awaiting ACK",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let chunk_size = cmp::min(self.max_payload, buf.len());
        let chunk = buf[..chunk_size].to_vec();
        let packet = AdbPacket::new(A_WRTE, self.local_id, self.remote_id, chunk);

        match self.writer_tx.try_send(packet) {
            Ok(()) => {
                self.waiting_ack = true;
                Poll::Ready(Ok(chunk_size))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Connection writer channel closed",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.waiting_ack {
            match self.write_ack_rx.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    self.waiting_ack = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Stream closed while awaiting ACK",
                ))),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let packet = AdbPacket::new(A_CLSE, self.local_id, self.remote_id, Vec::new());
            let _ = self.writer_tx.try_send(packet);
        }
        Poll::Ready(Ok(()))
    }
}
