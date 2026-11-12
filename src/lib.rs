//! radb - Pure Rust ADB (Android Debug Bridge) client library.
//!
//! Provides a TCP-only client supporting Android 5+ with persistent
//! multiplexed connections.

pub mod connection;
pub mod crypto;
pub mod error;
pub mod packet;
pub mod stream;

pub use connection::AdbConnection;
pub use crypto::AdbKeyPair;
pub use error::{AdbError, Result};
pub use packet::{AdbMessageHeader, AdbPacket};
pub use stream::AdbStream;
