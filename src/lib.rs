//! airadb — a pure-Rust ADB client over TCP for Android 5+.
//!
//! ```no_run
//! # async fn demo() -> airadb::Result<()> {
//! use airadb::{Authorization, Client, Key, KeyPair};
//!
//! let client = Client::new(KeyPair::load_or_create("adbkey")?);
//! let tv = client.device("192.168.1.20:5555".parse().unwrap());
//!
//! // Shows "Allow USB debugging?" only if the key is not trusted yet.
//! if let Authorization::Waiting(prompt) = tv.authorize().await? {
//!     prompt.wait().await?;
//! }
//! tv.press(Key::Home).await?;
//! let model = tv.shell("getprop").arg("ro.product.model").await?;
//! # Ok(()) }
//! ```

#[cfg(feature = "blocking")]
pub mod blocking;
mod client;
mod connection;
mod crypto;
mod device;
mod error;
mod info;
pub mod packet;
mod scan;
mod stream;
mod sync;
mod types;

pub use client::{Client, ClientBuilder};
pub use connection::AdbConnection;
pub use crypto::KeyPair;
pub use device::{
    shell_quote, AuthPrompt, Authorization, Device, Foreground, InstallRequest, Package, RebootMode, ShellCommand,
};
pub use error::{Error, ErrorKind, Result};
pub use info::DeviceHardwareInfo;
pub use scan::{Discover, DiscoveredDevice, Discovery, DEFAULT_ADB_PORT, DEFAULT_ADB_PORTS};
pub use stream::AdbStream;
pub use sync::{AdbSync, SyncDent, SyncStat};
pub use types::{local_ipv4, ActivityName, Key, PackageName, Subnet};

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
