use std::io;
use thiserror::Error;

/// Result type alias for ADB operations.
pub type Result<T> = std::result::Result<T, AdbError>;

/// Errors that can occur during ADB operations.
#[derive(Debug, Error)]
pub enum AdbError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid packet header: {0}")]
    InvalidHeader(String),

    #[error("Checksum mismatch: expected {expected:#x}, got {calculated:#x}")]
    ChecksumMismatch { expected: u32, calculated: u32 },

    #[error("Magic mismatch: command {command:#x} does not match magic {magic:#x}")]
    MagicMismatch { command: u32, magic: u32 },

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Stream closed: local_id={local_id}, remote_id={remote_id}")]
    StreamClosed { local_id: u32, remote_id: u32 },

    #[error("Sync service error: {0}")]
    SyncError(String),

    #[error("Command execution failed with message: {0}")]
    CommandFailed(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Device offline or unauthorized")]
    DeviceUnauthorized,

    #[error("Timeout waiting for response: {0}")]
    Timeout(String),
}
