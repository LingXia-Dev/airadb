use std::fmt;
use byteorder::{ByteOrder, LittleEndian};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AdbError, Result};

pub const HEADER_SIZE: usize = 24;

// ADB Message Commands
pub const A_SYNC: u32 = 0x434e5953;
pub const A_CNXN: u32 = 0x4e584e43;
pub const A_OPEN: u32 = 0x4e45504f;
pub const A_OKAY: u32 = 0x59414b4f;
pub const A_CLSE: u32 = 0x45534c43;
pub const A_WRTE: u32 = 0x45545257;
pub const A_AUTH: u32 = 0x48545541;
pub const A_STLS: u32 = 0x534c5453;

// Protocol versions
pub const A_VERSION_MIN: u32 = 0x01000000;
pub const A_VERSION_SKIP_CHECKSUM: u32 = 0x01000001;

// Auth sub-types
pub const ADB_AUTH_TOKEN: u32 = 1;
pub const ADB_AUTH_SIGNATURE: u32 = 2;
pub const ADB_AUTH_RSAPUBLICKEY: u32 = 3;

// Max payloads
pub const MAX_PAYLOAD_V1: usize = 4096;
pub const MAX_PAYLOAD: usize = 1024 * 1024;

/// Calculate ADB payload checksum.
/// In ADB protocol v1 (e.g. Android 5), this is the sum of each byte as a uint32.
pub fn calculate_checksum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for &b in data {
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

/// 24-byte message header transmitted across the wire in little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdbMessageHeader {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_check: u32,
    pub magic: u32,
}

impl AdbMessageHeader {
    pub fn new(command: u32, arg0: u32, arg1: u32, data_length: u32, data_check: u32) -> Self {
        Self {
            command,
            arg0,
            arg1,
            data_length,
            data_check,
            magic: command ^ 0xffffffff,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        LittleEndian::write_u32(&mut buf[0..4], self.command);
        LittleEndian::write_u32(&mut buf[4..8], self.arg0);
        LittleEndian::write_u32(&mut buf[8..12], self.arg1);
        LittleEndian::write_u32(&mut buf[12..16], self.data_length);
        LittleEndian::write_u32(&mut buf[16..20], self.data_check);
        LittleEndian::write_u32(&mut buf[20..24], self.magic);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(AdbError::InvalidHeader("Header buffer too small".into()));
        }
        let command = LittleEndian::read_u32(&bytes[0..4]);
        let arg0 = LittleEndian::read_u32(&bytes[4..8]);
        let arg1 = LittleEndian::read_u32(&bytes[8..12]);
        let data_length = LittleEndian::read_u32(&bytes[12..16]);
        let data_check = LittleEndian::read_u32(&bytes[16..20]);
        let magic = LittleEndian::read_u32(&bytes[20..24]);

        if magic != (command ^ 0xffffffff) {
            return Err(AdbError::MagicMismatch { command, magic });
        }

        Ok(Self {
            command,
            arg0,
            arg1,
            data_length,
            data_check,
            magic,
        })
    }
}

/// Represents an ADB packet containing a command, arguments, and optional payload.
#[derive(Clone, PartialEq, Eq)]
pub struct AdbPacket {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub payload: Vec<u8>,
}

impl AdbPacket {
    pub fn new(command: u32, arg0: u32, arg1: u32, payload: Vec<u8>) -> Self {
        Self {
            command,
            arg0,
            arg1,
            payload,
        }
    }

    pub fn command_name(&self) -> &'static str {
        command_name(self.command)
    }

    pub fn header(&self) -> AdbMessageHeader {
        let checksum = calculate_checksum(&self.payload);
        AdbMessageHeader::new(
            self.command,
            self.arg0,
            self.arg1,
            self.payload.len() as u32,
            checksum,
        )
    }
}

pub fn command_name(cmd: u32) -> &'static str {
    match cmd {
        A_SYNC => "A_SYNC",
        A_CNXN => "A_CNXN",
        A_OPEN => "A_OPEN",
        A_OKAY => "A_OKAY",
        A_CLSE => "A_CLSE",
        A_WRTE => "A_WRTE",
        A_AUTH => "A_AUTH",
        A_STLS => "A_STLS",
        _ => "UNKNOWN",
    }
}

impl fmt::Debug for AdbPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdbPacket")
            .field("command", &self.command_name())
            .field("arg0", &format_args!("{:#x} ({})", self.arg0, self.arg0))
            .field("arg1", &format_args!("{:#x} ({})", self.arg1, self.arg1))
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Reads an ADB packet from an async reader.
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    skip_checksum: bool,
) -> Result<AdbPacket> {
    let mut header_buf = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            AdbError::ConnectionClosed
        } else {
            AdbError::Io(e)
        }
    })?;

    let header = AdbMessageHeader::from_bytes(&header_buf)?;

    let mut payload = vec![0u8; header.data_length as usize];
    if header.data_length > 0 {
        reader.read_exact(&mut payload).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                AdbError::ConnectionClosed
            } else {
                AdbError::Io(e)
            }
        })?;

        if !skip_checksum {
            let calculated = calculate_checksum(&payload);
            if calculated != header.data_check {
                return Err(AdbError::ChecksumMismatch {
                    expected: header.data_check,
                    calculated,
                });
            }
        }
    }

    Ok(AdbPacket::new(
        header.command,
        header.arg0,
        header.arg1,
        payload,
    ))
}

/// Writes an ADB packet to an async writer.
pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &AdbPacket,
) -> Result<()> {
    let header = packet.header();
    let header_bytes = header.to_bytes();
    writer.write_all(&header_bytes).await?;
    if !packet.payload.is_empty() {
        writer.write_all(&packet.payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_header_serialization() {
        let header = AdbMessageHeader::new(A_CNXN, 0x01000000, 4096, 12, 1234);
        let bytes = header.to_bytes();
        let parsed = AdbMessageHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
        assert_eq!(parsed.magic, A_CNXN ^ 0xffffffff);
    }

    #[test]
    fn test_magic_mismatch() {
        let mut header = AdbMessageHeader::new(A_CNXN, 0x01000000, 4096, 12, 1234);
        header.magic = 0;
        let bytes = header.to_bytes();
        assert!(matches!(
            AdbMessageHeader::from_bytes(&bytes),
            Err(AdbError::MagicMismatch { .. })
        ));
    }

    #[test]
    fn test_checksum_calculation() {
        let data = b"hello world!";
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        assert_eq!(calculate_checksum(data), sum);
    }

    #[tokio::test]
    async fn test_read_write_packet() {
        let payload = b"host::features=cmd".to_vec();
        let packet = AdbPacket::new(A_CNXN, A_VERSION_MIN, 4096, payload.clone());

        let mut buf = Vec::new();
        write_packet(&mut buf, &packet).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let read = read_packet(&mut cursor, false).await.unwrap();
        assert_eq!(read.command, A_CNXN);
        assert_eq!(read.arg0, A_VERSION_MIN);
        assert_eq!(read.arg1, 4096);
        assert_eq!(read.payload, payload);
    }

    #[tokio::test]
    async fn test_checksum_error_detection() {
        let payload = b"some data".to_vec();
        let packet = AdbPacket::new(A_WRTE, 1, 2, payload);
        let mut buf = Vec::new();
        write_packet(&mut buf, &packet).await.unwrap();

        // Corrupt payload
        buf[HEADER_SIZE + 1] ^= 0xff;

        let mut cursor = Cursor::new(buf);
        let res = read_packet(&mut cursor, false).await;
        assert!(matches!(res, Err(AdbError::ChecksumMismatch { .. })));
    }
}
