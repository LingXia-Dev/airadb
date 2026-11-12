# radb

A pure Rust ADB (Android Debug Bridge) client library and CLI tool designed for direct TCP connections to `adbd`.

`radb` is specifically tailored for cross-platform environments (including **iOS**, **Android**, macOS, Linux, and Windows) and legacy Android devices (**Android 5.0 Lollipop and above**).

---

## Key Highlights

- **Pure Rust & Portable**: Zero C/C++ dependencies (no OpenSSL C-bindings, no cmake). Compiles smoothly for `aarch64-apple-ios`, `aarch64-linux-android`, desktop OSes, and embedded targets.
- **Direct TCP Only**: Connects directly to `adbd` over TCP (`<device_ip>:5555`) without requiring a local Google ADB server daemon.
- **Android 5+ Compatibility**:
  - Full support for ADB Protocol v1 (`0x01000000` / `0x01000001`).
  - Correct legacy byte-sum checksum calculation required by Android 5.
  - Respects negotiated `max_payload` (e.g. 4096 bytes on older devices).
  - Proper null-terminated service destination strings and RSA public key strings.
  - Standard RSA-2048 authentication challenge signing (PKCS#1 v1.5 + SHA-1 DigestInfo) and Android binary `RSAPublicKey` structure generation.
- **Persistent Multiplexed Connection**:
  - A single TCP connection (`A_CNXN`) is established and kept alive.
  - Multiple commands, shells, and file sync transfers are multiplexed sequentially or concurrently without reconnecting or re-authenticating.
- **Lean & Focused**: Does not require wireless TLS pairing or mDNS discovery. Built specifically for connecting to existing and legacy Android devices reliably.

---

## Library Usage

Add `radb` to your `Cargo.toml`:

```toml
[dependencies]
radb = "0.1.0"
tokio = { version = "1.38", features = ["full"] }
```

### 1. Basic Connection & Running Multiple Commands

Notice that all commands reuse the **same TCP connection**:

```rust
use radb::AdbDevice;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connects to device over TCP and handles RSA authentication
    let device = AdbDevice::connect("192.168.1.100:5555").await?;

    // Query device properties over the persistent connection
    let model = device.get_model().await?;
    let android_ver = device.get_android_version().await?;
    println!("Device: {} (Android {})", model, android_ver);

    // Run multiple shell commands without reconnecting
    let output1 = device.shell("uptime").await?;
    println!("Uptime: {}", output1.trim());

    let output2 = device.shell("pm list packages -3").await?;
    println!("Third-party packages:\n{}", output2);

    Ok(())
}
```

### 2. File Synchronization (Push & Pull)

File transfers use the binary ADB `sync:` protocol over the persistent connection:

```rust
use radb::AdbDevice;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = AdbDevice::connect("192.168.1.100:5555").await?;

    // Stat remote file
    let stat = device.stat("/sdcard/Download").await?;
    if stat.exists() {
        println!("Download dir mode: {:#o}, size: {}", stat.mode, stat.size);
    }

    // List remote directory
    let entries = device.list("/sdcard/Download").await?;
    for entry in entries {
        println!("{:<10} {:>8} bytes {}", entry.mode, entry.size, entry.name);
    }

    // Push local file to device
    let bytes_pushed = device.push_file("local_app.apk", "/data/local/tmp/app.apk").await?;
    println!("Pushed {} bytes", bytes_pushed);

    // Pull remote file to local
    let bytes_pulled = device.pull_file("/sdcard/screenshot.png", "pulled.png").await?;
    println!("Pulled {} bytes", bytes_pulled);

    Ok(())
}
```

### 3. Raw Execution (No PTY Mangling)

Ideal for binary outputs such as taking screenshots:

```rust
use radb::AdbDevice;
use tokio::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = AdbDevice::connect("192.168.1.100:5555").await?;

    // Capture screenshot as raw PNG bytes
    let png_bytes = device.exec("screencap -p").await?;
    fs::write("screenshot.png", png_bytes).await?;
    println!("Saved screenshot.png");

    Ok(())
}
```

### 4. Custom Key Management

```rust
use radb::crypto::AdbKeyPair;
use radb::AdbDevice;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate an in-memory key or load from custom file
    let key = AdbKeyPair::from_file("/path/to/custom_key")?;

    let device = AdbDevice::connect_with_key("192.168.1.100:5555", &key).await?;
    println!("Connected using custom key!");

    Ok(())
}
```

---

## CLI Tool

`radb` comes with a command-line binary.

### Installation

```bash
cargo install --path .
```

### Global Options

- `-s, --server <IP:PORT>`: Target device TCP address (default: `127.0.0.1:5555`).
- `-k, --key <PATH>`: Custom private key path (defaults to `~/.android/adbkey` or auto-generated).
- `-v, --verbose`: Enable debug/trace logging.

### Examples

```bash
# Test connection and show device info
radb -s 192.168.1.100:5555 connect

# Run a shell command
radb -s 192.168.1.100:5555 shell getprop ro.product.model

# Start an interactive shell session
radb -s 192.168.1.100:5555 shell

# Run exec command (raw binary stdout)
radb -s 192.168.1.100:5555 exec screencap -p > screenshot.png

# Push and Pull files
radb -s 192.168.1.100:5555 push local_video.mp4 /sdcard/Movies/
radb -s 192.168.1.100:5555 pull /sdcard/Movies/local_video.mp4

# Check file stat and list directory
radb -s 192.168.1.100:5555 stat /sdcard/Movies
radb -s 192.168.1.100:5555 ls /sdcard/Movies

# Install an APK
radb -s 192.168.1.100:5555 install app-debug.apk

# Reboot device
radb -s 192.168.1.100:5555 reboot recovery

# Remount filesystem as RW
radb -s 192.168.1.100:5555 remount

# Switch adbd TCP port
radb -s 192.168.1.100:5555 tcpip 5555

# Generate an ADB RSA keypair
radb keygen ~/.android/adbkey
```

---

## License

Dual-licensed under MIT or Apache-2.0.
