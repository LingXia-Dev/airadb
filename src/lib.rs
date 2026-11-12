//! radb - Pure Rust ADB (Android Debug Bridge) client library.
//!
//! Provides a TCP-only client supporting Android 5+ with persistent
//! multiplexed connections.

pub mod error;
pub mod packet;

pub use error::{AdbError, Result};
pub use packet::{AdbMessageHeader, AdbPacket};
