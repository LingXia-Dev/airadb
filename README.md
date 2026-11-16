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
- **Explicit authorization**: connecting only *signs* with your key, so an untrusted device fails fast with `ErrorKind::Unauthorized` and shows nothing. Only `authorize()` makes it ask "Allow USB debugging?".
- **Safe shell arguments**: `shell("pm").arg(x)` quotes every argument; `shell_raw` is the explicit escape hatch.
- **Embeddable**: `default-features = false` drops the CLI deps (clap, dirs, tracing-subscriber). Optional `blocking` and `serde` features.

---

## Library

```toml
[dependencies]
airadb = { version = "0.3", default-features = false }
```

### Design

- `Client` holds the key and all timeouts. It never reads `~/.android/adbkey` on its own; load a key with `KeyPair::load_or_create(path)`, which creates it if missing and **errors** (never silently regenerates) if it is unreadable.
- `client.device(addr)` returns a cheap, cloneable `Device` and sends nothing. Handles for the same address share one multiplexed connection, opened on first use and closed after `idle_timeout` (default 60s) with no open streams.
- Every error is an `airadb::Error` with a `kind()` to branch on (`Unreachable`, `Timeout`, `Unauthorized`, `Disconnected`, `Rejected`, `InstallFailed`, `InvalidArg`, `Protocol`, `Key`, …) and `is_retryable()`.
- Every network step has a timeout: TCP connect 3s, each handshake reply / service open 5s, the user's authorization 30s (all configurable on `Client::builder`).

### Connect and control

```rust
use airadb::{Authorization, Client, Key, KeyPair, PackageName};

# async fn demo() -> airadb::Result<()> {
let client = Client::new(KeyPair::load_or_create("adbkey")?);
let tv = client.device("192.168.1.100:5555".parse().unwrap());

// First time only: the device shows "Allow USB debugging?".
if let Authorization::Waiting(prompt) = tv.authorize().await? {
    prompt.wait().await?; // ErrorKind::Unauthorized if declined or ignored
}

tv.press(Key::Home).await?;
let pkg: PackageName = "com.android.settings".parse()?;
tv.launch(&pkg).await?;
if let Some(fg) = tv.foreground().await? {
    println!("focused: {}", fg.package);
}
let model = tv.shell("getprop").arg("ro.product.model").await?;
let png = tv.screencap().await?;
# Ok(()) }
```

### Install

```rust
# async fn demo(tv: airadb::Device) -> airadb::Result<()> {
tv.install("app-release.apk")
    .on_progress(|sent, total| eprint!("\r{sent}/{total}"))
    .await?; // ErrorKind::InstallFailed carries pm's message
# Ok(()) }
```

The APK is pushed to `/data/local/tmp/`, installed with `pm install -r` and removed, also when the future is dropped half-way.

### Apps, names and icons

```rust
# async fn demo(tv: airadb::Device) -> airadb::Result<()> {
for app in tv.apps().await? {               // launcher apps (phone and TV); all_apps() for every package
    println!("{} {:?}", app.package, app.name); // name: the label the launcher shows
}
let png = tv.app_icon(&airadb::PackageName::new("com.android.settings")?).await?;
# Ok(()) }
```

`pm` prints neither labels nor icons, so a 4 KB dex (`helper/`, embedded in the crate) is pushed to `/data/local/tmp/` on first use and run with `app_process` as the shell user; it asks `PackageManager`. No APK is installed and no root is needed. Where it cannot run, listing falls back to `pm` without names. Rebuild it with `helper/build.sh` after editing `Helper.java`.

### Discovery

```rust
# async fn demo(client: airadb::Client) -> airadb::Result<()> {
// Everything at once (default: local /24, ports 5555/9527/5566 + mDNS, 3s).
for d in client.discover().await? {
    println!("{} {:?} auth_required={}", d.addr, d.model, d.auth_required);
}

// Or as they answer; dropping the stream stops all probes.
let mut found = client.discover().subnet("192.168.1".parse()?).start()?;
while let Some(d) = found.next().await {
    println!("{}", d.addr);
}
# Ok(()) }
```

Probing sends `CNXN` and reads the reply; it never offers a key, so no device shows a dialog.

### Blocking

With the `blocking` feature, `blocking::BlockingClient` wraps a `Client` for callers without an async runtime.

---

## CLI Usage

```bash
# Scan network for ADB devices (ports 5555, 9527, 5566 + mDNS)
airadb scan

# Connect (accept the prompt on the device the first time) & query hardware info
airadb -s 192.168.1.100:5555 connect
airadb -s 192.168.1.100:5555 info
airadb -s 192.168.1.100 press home down enter

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

The CLI uses `~/.android/adbkey` (override with `-k`), creating it if missing. When the device does not trust the key yet, the CLI asks it to and waits up to 30s.

---

## License

Dual-licensed under MIT or Apache-2.0.
