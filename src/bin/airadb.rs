use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use tokio::io::{self, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

use airadb::{
    ActivityName, Authorization, Client, Device, Error, ErrorKind, Key, KeyPair, PackageName,
    RebootMode, Result, Subnet,
};

#[derive(Parser)]
#[command(name = "airadb", author, version, about = "Pure Rust ADB client for TCP connections (Android 5+)", long_about = None)]
struct Cli {
    /// Target device TCP address (ip:port)
    #[arg(short = 's', long = "server", default_value = "127.0.0.1:5555")]
    server: String,

    /// ADB private key (default ~/.android/adbkey, created if missing)
    #[arg(short = 'k', long = "key")]
    key: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect, asking the device to authorize this key if needed
    Connect,

    /// Press remote keys in order (home, back, up, down, left, right, enter, menu, power, volumeup, volumedown)
    Press {
        #[arg(required = true)]
        keys: Vec<String>,
    },

    /// Query comprehensive device hardware info (CPU, RAM, storage, Android version, Android ID)
    Info,

    /// Get the 64-bit unique Android ID
    GetId,

    /// Query a system property via getprop
    Getprop {
        /// Property key name (e.g. ro.product.model). If omitted, prints all properties.
        key: Option<String>,
    },

    /// Run a shell command or start an interactive shell
    Shell {
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Run a command via exec service (raw binary, no PTY mangling)
    Exec {
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Push a local file to the device
    Push {
        /// Local source file path
        local: PathBuf,
        /// Remote destination file path
        remote: String,
    },

    /// Pull a remote file from the device
    Pull {
        /// Remote file path
        remote: String,
        /// Local destination file path (defaults to filename in current dir)
        local: Option<PathBuf>,
    },

    /// Capture a screenshot: full-size PNG, or with --width a small JPEG
    /// scaled on the device
    Screencap {
        /// Destination local file path (defaults to "screenshot.png")
        #[arg(default_value = "screenshot.png")]
        out: PathBuf,
        /// Scale to at most this many pixels wide and send a JPEG
        #[arg(long)]
        width: Option<u32>,
        /// JPEG quality (1-100) with --width
        #[arg(long, default_value_t = 70)]
        quality: u8,
    },

    /// Get file metadata (stat)
    Stat {
        /// Remote file path
        remote: String,
    },

    /// List directory contents on the device
    Ls {
        /// Remote directory path (defaults to "/")
        #[arg(default_value = "/")]
        remote: String,
    },

    /// Install an APK package on the device
    Install {
        /// Local path to APK file
        apk: PathBuf,
    },

    /// Uninstall a package from the device
    Uninstall {
        /// Package name (e.g. com.example.app)
        package: String,

        /// Keep app data and cache directories
        #[arg(short = 'k', long = "keep-data")]
        keep_data: bool,
    },

    /// Android package manager: list, current/top, start, stop, uninstall, clear
    #[command(alias = "app")]
    Pm {
        #[command(subcommand)]
        subcommand: PmCommands,
    },

    /// List installed packages on the device (shortcut for `pm list`)
    Apps {
        /// Show only third-party (user installed) applications
        #[arg(short = '3', long = "third-party")]
        third_party: bool,

        /// Filter packages by keyword
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
    },

    /// Start / launch an application on the device (shortcut for `pm start`)
    #[command(alias = "launch", alias = "run")]
    Start {
        /// Application package name (e.g. com.android.settings)
        package: String,

        /// Optional activity class name to launch directly
        #[arg(short = 'a', long = "activity")]
        activity: Option<String>,
    },

    /// Force stop / close an application on the device (shortcut for `pm stop`)
    #[command(alias = "close", alias = "kill")]
    Stop {
        /// Application package name to force stop
        package: String,
    },

    /// Reboot the device
    Reboot {
        /// Reboot mode
        #[arg(value_enum, default_value = "system")]
        mode: CliRebootMode,
    },

    /// Remount partitions as read-write
    Remount,

    /// Restart adbd listening on a TCP port
    Tcpip {
        /// Port to listen on
        #[arg(default_value = "5555")]
        port: u16,
    },

    /// Restart adbd with root permissions
    Root,

    /// Restart adbd without root permissions
    Unroot,

    /// Generate an ADB RSA-2048 keypair
    Keygen {
        /// Output path for private key (default: ~/.android/adbkey)
        out: Option<PathBuf>,
    },

    /// Scan local network for ADB devices
    Scan {
        /// Subnet or prefix to scan (e.g. 192.168.1 or 192.168.1.0/24). Auto-detected if omitted.
        #[arg(short = 'n', long = "subnet")]
        subnet: Option<String>,

        /// Comma-separated ports to probe (default: 5555,9527,5566)
        #[arg(
            short = 'p',
            long = "ports",
            value_delimiter = ',',
            default_value = "5555,9527,5566"
        )]
        ports: Vec<u16>,

        /// Disable mDNS multicast discovery
        #[arg(long = "no-mdns")]
        no_mdns: bool,

        /// Per-probe timeout in milliseconds
        #[arg(short = 't', long = "timeout", default_value = "1200")]
        timeout_ms: u64,

        /// Overall time limit in milliseconds
        #[arg(long = "wait", default_value = "5000")]
        wait_ms: u64,
    },
}

#[derive(Subcommand)]
enum PmCommands {
    /// List installed application packages on the device
    #[command(alias = "ls")]
    List {
        /// Show only third-party (user installed) applications
        #[arg(short = '3', long = "third-party")]
        third_party: bool,

        /// Show only system applications
        #[arg(short = 's', long = "system")]
        system: bool,

        /// Filter packages by keyword
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
    },

    /// Show currently focused foreground application
    #[command(alias = "top")]
    Current,

    /// Start/launch an application on the device
    #[command(alias = "launch", alias = "run")]
    Start {
        /// Application package name (e.g. com.android.settings)
        package: String,

        /// Optional activity class name to launch directly
        #[arg(short = 'a', long = "activity")]
        activity: Option<String>,
    },

    /// Force stop / close an application
    #[command(alias = "close", alias = "kill")]
    Stop {
        /// Application package name to force stop
        package: String,
    },

    /// Uninstall an application from the device
    Uninstall {
        /// Application package name to uninstall
        package: String,

        /// Keep app data and cache directories
        #[arg(short = 'k', long = "keep-data")]
        keep_data: bool,
    },

    /// Clear application cache and user data
    Clear {
        /// Application package name to clear
        package: String,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum CliRebootMode {
    System,
    Bootloader,
    Recovery,
    Sideload,
}

impl From<CliRebootMode> for RebootMode {
    fn from(m: CliRebootMode) -> Self {
        match m {
            CliRebootMode::System => RebootMode::System,
            CliRebootMode::Bootloader => RebootMode::Bootloader,
            CliRebootMode::Recovery => RebootMode::Recovery,
            CliRebootMode::Sideload => RebootMode::Sideload,
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let filter = if cli.verbose {
        EnvFilter::new("debug,airadb=trace")
    } else {
        EnvFilter::new("warn,airadb=info")
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    if let Err(e) = run(cli).await {
        eprintln!("error: {}", e.message());
        if e.kind() == ErrorKind::Unauthorized {
            eprintln!("hint: run `airadb -s <addr> connect` and accept the prompt on the device");
        }
        process::exit(1);
    }
}

fn default_key_path() -> PathBuf {
    if cfg!(target_os = "android") {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() && home != "/" {
                return PathBuf::from(home).join(".android").join("adbkey");
            }
        }
        return PathBuf::from("/data/local/tmp/.android/adbkey");
    }
    dirs::home_dir()
        .map(|h| h.join(".android").join("adbkey"))
        .unwrap_or_else(|| PathBuf::from("adbkey"))
}

fn parse_addr(s: &str) -> Result<SocketAddr> {
    let with_port = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:{}", airadb::DEFAULT_ADB_PORT)
    };
    with_port
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidArg,
                format!("invalid device address '{s}'"),
            )
        })
}

fn package(s: &str) -> Result<PackageName> {
    s.parse()
}

/// Connect; when the device does not know the key, ask on screen and wait
/// (a person is at the terminal, so the dialog is expected).
async fn ensure_authorized(device: &Device) -> Result<()> {
    match device.connect().await {
        Err(e) if e.kind() == ErrorKind::Unauthorized => {}
        other => return other,
    }
    match device.authorize().await? {
        Authorization::Authorized => Ok(()),
        Authorization::Waiting(prompt) => {
            eprintln!("Accept \"Allow USB debugging?\" on the device (waiting up to 30s)...");
            prompt.wait().await
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let key_path = cli.key.clone().unwrap_or_else(default_key_path);

    if let Commands::Keygen { out } = &cli.command {
        let path = out.clone().unwrap_or_else(default_key_path);
        if path.exists() {
            return Err(Error::new(
                ErrorKind::InvalidArg,
                format!("{} already exists", path.display()),
            ));
        }
        KeyPair::load_or_create(&path)?;
        println!(
            "Created {} and {}",
            path.display(),
            path.with_extension("pub").display()
        );
        return Ok(());
    }

    if let Commands::Scan {
        subnet,
        ports,
        no_mdns,
        timeout_ms,
        wait_ms,
    } = &cli.command
    {
        let mut discover = airadb::Discover::new()
            .ports(ports.iter().copied())
            .mdns(!no_mdns)
            .probe_timeout(Duration::from_millis(*timeout_ms))
            .timeout(Duration::from_millis(*wait_ms));
        if let Some(s) = subnet {
            discover = discover.subnet(s.parse::<Subnet>()?);
        }
        let ports_str = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "Scanning for ADB devices (ports {ports_str}{})...",
            if *no_mdns { "" } else { " + mDNS" }
        );
        let found = discover.await?;
        if found.is_empty() {
            println!("No ADB devices discovered.");
        } else {
            println!("\nDiscovered {} ADB device(s):", found.len());
            for d in found {
                let auth = if d.auth_required {
                    "auth required"
                } else {
                    "open"
                };
                println!(
                    "  - {:21} [{:16}] ({auth})",
                    d.addr,
                    d.model.as_deref().unwrap_or("unknown")
                );
            }
        }
        return Ok(());
    }

    let client = Client::new(KeyPair::load_or_create(&key_path)?);

    let device = client.device(parse_addr(&cli.server)?);
    ensure_authorized(&device).await?;

    match cli.command {
        Commands::Keygen { .. } | Commands::Scan { .. } => unreachable!(),
        Commands::Connect => {
            println!("Connected to {}", device.addr());
            println!("Device banner: {}", device.banner().await?.trim());
            if let Ok(model) = device.getprop("ro.product.model").await {
                println!("Model:         {model}");
            }
            if let Ok(Some(aid)) = device.android_id().await {
                println!("Android ID:    {aid}");
            }
            if let Ok(v) = device.getprop("ro.build.version.release").await {
                println!("Android OS:    {v}");
            }
            if let Ok(sdk) = device.getprop("ro.build.version.sdk").await {
                println!("SDK API:       {sdk}");
            }
            println!(
                "Max payload:   {} bytes",
                device.connection().await?.max_payload()
            );
        }
        Commands::Press { keys } => {
            let keys = keys
                .iter()
                .map(|k| k.parse::<Key>())
                .collect::<Result<Vec<_>>>()?;
            device.press_seq(keys).await?;
        }
        Commands::Info => println!("{}", device.hardware_info().await?),
        Commands::GetId => match device.android_id().await? {
            Some(id) => println!("{id}"),
            None => {
                return Err(Error::new(
                    ErrorKind::Rejected,
                    "Android ID not available on device",
                ))
            }
        },
        Commands::Getprop { key } => match key {
            Some(k) => println!("{}", device.getprop(&k).await?),
            None => print!("{}", device.shell("getprop").await?),
        },
        Commands::Shell { command } => {
            if command.is_empty() {
                let stream = device.interactive_shell().await?;
                let (mut stream_r, mut stream_w) = io::split(stream);
                let (mut stdin, mut stdout) = (io::stdin(), io::stdout());
                tokio::select! {
                    _ = io::copy(&mut stdin, &mut stream_w) => {}
                    _ = io::copy(&mut stream_r, &mut stdout) => {}
                }
            } else {
                // Like `adb shell`: the words form one command line.
                print!("{}", device.shell_raw(&command.join(" ")).await?);
            }
        }
        Commands::Exec { command } => {
            let bytes = device.exec_raw(&command.join(" ")).await?;
            io::stdout().write_all(&bytes).await?;
        }
        Commands::Push { local, remote } => {
            println!("Pushing {} -> {remote}...", local.display());
            println!(
                "Transferred {} bytes.",
                device.push_file(&local, &remote).await?
            );
        }
        Commands::Pull { remote, local } => {
            let dest =
                local.unwrap_or_else(|| PathBuf::from(remote.rsplit('/').next().unwrap_or("file")));
            println!("Pulling {remote} -> {}...", dest.display());
            println!(
                "Received {} bytes.",
                device.pull_file(&remote, &dest).await?
            );
        }
        Commands::Screencap { out, width, quality } => {
            let png = match width {
                Some(w) => device.screenshot(w, quality).await?,
                None => device.screencap().await?,
            };
            tokio::fs::write(&out, &png).await?;
            println!(
                "Saved screenshot ({} bytes) to {}",
                png.len(),
                out.display()
            );
        }
        Commands::Stat { remote } => {
            let st = device.stat(&remote).await?;
            if st.exists() {
                println!(
                    "Path:  {remote}\nMode:  {:#o}\nSize:  {} bytes\nMtime: {}",
                    st.mode, st.size, st.mtime
                );
            } else {
                println!("File does not exist: {remote}");
            }
        }
        Commands::Ls { remote } => {
            println!("{:<10} {:>10} {:>10} NAME", "MODE", "SIZE", "MTIME");
            println!("{:-<50}", "");
            for ent in device.list(&remote).await? {
                let t = if ent.is_dir() { 'd' } else { '-' };
                println!(
                    "{t}{:04o}     {:>10} {:>10} {}",
                    ent.mode & 0o777,
                    ent.size,
                    ent.mtime,
                    ent.name
                );
            }
        }
        Commands::Install { apk } => {
            println!("Installing {}...", apk.display());
            let last = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
            device
                .install(&apk)
                .on_progress(move |sent, total| {
                    let pct = (sent * 100).checked_div(total).unwrap_or(100);
                    if last.swap(pct, std::sync::atomic::Ordering::Relaxed) != pct {
                        eprint!("\r  upload {pct:3}%");
                    }
                })
                .await?;
            eprintln!();
            println!("Success");
        }
        Commands::Uninstall {
            package: pkg,
            keep_data,
        }
        | Commands::Pm {
            subcommand:
                PmCommands::Uninstall {
                    package: pkg,
                    keep_data,
                },
        } => {
            let pkg = package(&pkg)?;
            if keep_data {
                device.uninstall_keep_data(&pkg).await?
            } else {
                device.uninstall(&pkg).await?
            }
            println!("Success");
        }
        Commands::Apps {
            third_party,
            filter,
        } => list_apps(&device, third_party, false, filter.as_deref()).await?,
        Commands::Start {
            package: pkg,
            activity,
        }
        | Commands::Pm {
            subcommand:
                PmCommands::Start {
                    package: pkg,
                    activity,
                },
        } => {
            let pkg = package(&pkg)?;
            match activity {
                Some(a) => {
                    device
                        .launch_activity(&pkg, &a.parse::<ActivityName>()?)
                        .await?
                }
                None => device.launch(&pkg).await?,
            }
            println!("Started {pkg}");
        }
        Commands::Stop { package: pkg }
        | Commands::Pm {
            subcommand: PmCommands::Stop { package: pkg },
        } => {
            device.force_stop(&package(&pkg)?).await?;
            println!("Stopped {pkg}");
        }
        Commands::Pm { subcommand } => match subcommand {
            PmCommands::List {
                third_party,
                system,
                filter,
            } => list_apps(&device, third_party, system, filter.as_deref()).await?,
            PmCommands::Current => match device.foreground().await? {
                Some(fg) => println!("Foreground: {}", fg.activity.unwrap_or(fg.package)),
                None => println!("No foreground application detected"),
            },
            PmCommands::Clear { package: pkg } => {
                device.clear_data(&package(&pkg)?).await?;
                println!("Cleared data for {pkg}");
            }
            PmCommands::Start { .. } | PmCommands::Stop { .. } | PmCommands::Uninstall { .. } => {
                unreachable!()
            }
        },
        Commands::Reboot { mode } => {
            device.reboot(mode.into()).await?;
            println!("Reboot command sent.");
        }
        Commands::Remount => print!("{}", device.remount().await?),
        Commands::Tcpip { port } => print!("{}", device.tcpip(port).await?),
        Commands::Root => print!("{}", device.root().await?),
        Commands::Unroot => print!("{}", device.unroot().await?),
    }
    Ok(())
}

async fn list_apps(
    device: &Device,
    third_party: bool,
    system: bool,
    filter: Option<&str>,
) -> Result<()> {
    // No flag: what the launcher shows. -3 / -s: every package, filtered.
    let mut apps = if third_party || system { device.all_apps().await? } else { device.apps().await? };
    if third_party != system {
        apps.retain(|a| a.system == system);
    }
    if let Some(f) = filter {
        apps.retain(|a| a.package.contains(f) || a.name.as_deref().is_some_and(|n| n.contains(f)));
    }
    let label = match (third_party, system) {
        (true, false) => "Third-party",
        (false, true) => "System",
        (true, true) => "Installed",
        _ => "Launcher",
    };
    println!("{label} apps ({} total):\n", apps.len());
    for (i, a) in apps.iter().enumerate() {
        println!(
            "{:>4}  {:<24} {:<56} {}",
            i + 1,
            a.name.as_deref().unwrap_or("-"),
            a.package,
            if a.system { "system" } else { "user" }
        );
    }
    Ok(())
}
