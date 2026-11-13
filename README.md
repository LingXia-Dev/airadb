# airadb

[![crates.io](https://img.shields.io/crates/v/airadb.svg)](https://crates.io/crates/airadb)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platform-iOS%20|%20Android%20|%20HarmonyOS%20|%20macOS%20|%20Linux%20|%20Windows-lightgrey.svg)](Cargo.toml)

A pure Rust ADB (Android Debug Bridge) client library and CLI tool designed for direct TCP connections to `adbd`.

Targeting mobile/embedded embedding (**iOS, Android, HarmonyOS, macOS, Linux, Windows**) and legacy-to-modern Android devices (**Android 5.0 Lollipop through Android 15**).

---

## Features

- **Pure Rust & Zero C Dependencies**: No OpenSSL C-bindings, no CMake. Cross-compiles out-of-the-box (`aarch64-apple-ios`, `aarch64-linux-android`, `aarch64-unknown-linux-ohos`).
- **Direct TCP Only**: Directly connects to `adbd` (`<ip>:<port>`), eliminating the need for a local Google ADB server daemon.
- **Android 5.0+ to Modern Android 15**:
  - Full ADB Protocol v1 framing with legacy byte-sum checksum handling (and modern checksum bypass).
  - Respects negotiated `max_payload` (4 KB up to 1 MB).
  - Pure Rust RSA-2048 keygen, token challenge signing, and Android `RSAPublicKey` structure format.
- **Persistent Stream Multiplexing**: Multiple commands, interactive shells, and file sync streams run over a single persistent TCP connection (`A_CNXN`) with automatic TCP keepalive.
- **Fast Network Discovery**: Combines mDNS multicast discovery (`_adb._tcp.local`) with concurrent TCP sweeping on common ports (`5555`, `9527`, `5566`).
- **Sync & Async Interfaces**: Async Tokio API for high performance, plus `BlockingDevicePool` for synchronous FFI integration.

---

## Installation & Library Usage

Add `airadb` to your `Cargo.toml`:

```toml
[dependencies]
airadb = "0.1.0"
tokio = { version = "1.43", features = ["full"] }
```

### Quick Example

```rust
use airadb::AdbDevice;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connects to device over TCP and handles RSA authentication
    let device = AdbDevice::connect("192.168.1.100:5555").await?;

    // Query hardware & system information (~180ms compound query)
    let info = device.get_hardware_info().await?;
    println!("Device: {} (Android {}, CPU: {} cores)", info.model, info.android_version, info.cpu_cores);

    // Run shell commands over the persistent connection
    let output = device.shell("uptime").await?;
    println!("Uptime: {}", output.trim());

    // File Sync: Push and Pull
    device.push_file("local.apk", "/data/local/tmp/app.apk").await?;
    device.pull_file("/sdcard/shot.png", "pulled.png").await?;

    // Screencap (streaming exec: with automatic Android 5.0 fallback)
    let png_bytes = device.screencap().await?;
    std::fs::write("screenshot.png", png_bytes)?;

    Ok(())
}
```

### Device Pool & Synchronous FFI

For multi-device management or synchronous C/FFI environments (e.g. `mukeinstall`):

```rust
use airadb::BlockingDevicePool;
use std::net::SocketAddr;

let pool = BlockingDevicePool::new();
let addr: SocketAddr = "192.168.1.100:5555".parse().unwrap();

// Synchronously run commands from any thread without async runtime
let output = pool.shell(addr, None, "uname -a").unwrap();
pool.push(addr, None, b"binary_payload", "/data/local/tmp/agent").unwrap();
```

---

## CLI Usage

```bash
# Scan network for ADB devices (ports 5555, 9527, 5566 + mDNS)
airadb scan

# Connect & query detailed hardware information
airadb -s 192.168.1.100:5555 info

# Capture screenshot directly to local PNG
airadb -s 192.168.1.100:5555 screencap screen.png

# Shell execution
airadb -s 192.168.1.100:5555 shell "getprop ro.product.model"
airadb -s 192.168.1.100:5555 shell   # Interactive shell

# File operations & App installation
airadb -s 192.168.1.100:5555 push app.apk /data/local/tmp/
airadb -s 192.168.1.100:5555 pull /sdcard/log.txt
airadb -s 192.168.1.100:5555 install app-release.apk

# Management
airadb -s 192.168.1.100:5555 reboot [system|bootloader|recovery]
airadb -s 192.168.1.100:5555 tcpip 5555
airadb keygen ~/.android/adbkey
```

---

## License

Dual-licensed under MIT or Apache-2.0.
