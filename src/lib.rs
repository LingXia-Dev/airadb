//! airadb - Pure Rust ADB (Android Debug Bridge) client library.
//!
//! Provides a TCP-only client supporting Android 5+ with persistent
//! multiplexed connections, device discovery, and mobile cross-platform embedding.

pub mod blocking;
pub mod connection;
pub mod crypto;
pub mod device;
pub mod error;
pub mod packet;
pub mod pool;
pub mod scan;
pub mod stream;
pub mod sync;

pub use blocking::BlockingDevicePool;
pub use connection::AdbConnection;
pub use crypto::{load_or_create_from_path, load_or_generate_default_key, AdbKeyPair};
pub use device::{AdbDevice, RebootMode, ShellOutput};
pub use error::{AdbError, Result};
pub use packet::{AdbMessageHeader, AdbPacket};
pub use pool::DevicePool;
pub use scan::{
    detect_local_ipv4, parse_subnet_candidates, probe_adb_device, scan_devices,
    DiscoveredDevice, ScanOptions, DEFAULT_ADB_PORT,
};
pub use stream::AdbStream;
pub use sync::{AdbSync, SyncDent, SyncStat};
