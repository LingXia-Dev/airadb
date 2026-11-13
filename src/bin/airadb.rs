use std::path::PathBuf;
use std::process;
use clap::{Parser, Subcommand, ValueEnum};
use tokio::io::{self, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

use airadb::crypto::{default_key_path, load_or_generate_default_key, AdbKeyPair};
use airadb::device::RebootMode;
use airadb::AdbDevice;

#[derive(Parser)]
#[command(name = "airadb", author, version, about = "Pure Rust ADB client for TCP connections (Android 5+)", long_about = None)]
struct Cli {
    /// Target device TCP address (ip:port)
    #[arg(short = 's', long = "server", default_value = "127.0.0.1:5555")]
    server: String,

    /// Path to custom ADB private key
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
    /// Test connection and authenticate with device
    Connect,

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

    /// Capture a screenshot from the device and save as PNG
    Screencap {
        /// Destination local file path (defaults to "screenshot.png")
        #[arg(default_value = "screenshot.png")]
        out: PathBuf,
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
        #[arg(short = 'p', long = "ports", value_delimiter = ',', default_value = "5555,9527,5566")]
        ports: Vec<u16>,

        /// Disable mDNS multicast discovery
        #[arg(long = "no-mdns")]
        no_mdns: bool,

        /// Per-probe timeout in milliseconds (default: 800)
        #[arg(short = 't', long = "timeout", default_value = "800")]
        timeout_ms: u64,
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

    // Handle keygen standalone without connecting
    if let Commands::Keygen { out } = cli.command {
        let key_path = out
            .or_else(default_key_path)
            .unwrap_or_else(|| PathBuf::from("adbkey"));
        println!("Generating 2048-bit RSA key pair at: {}", key_path.display());
        match AdbKeyPair::generate() {
            Ok(key) => {
                if let Err(e) = key.save_to_file(&key_path) {
                    eprintln!("Error saving private key: {}", e);
                    process::exit(1);
                }
                let pub_path = key_path.with_extension("pub");
                match key.android_pubkey_string("airadb@client") {
                    Ok(pub_str) => {
                        let _ = std::fs::write(
                            &pub_path,
                            pub_str.trim_end_matches('\0'),
                        );
                        println!("Saved public key to: {}", pub_path.display());
                    }
                    Err(e) => {
                        eprintln!("Error creating public key: {}", e);
                    }
                }
                println!("Keypair generated successfully.");
            }
            Err(e) => {
                eprintln!("Key generation failed: {}", e);
                process::exit(1);
            }
        }
        return;
    }

    // Handle scan standalone without connecting to a specific server
    if let Commands::Scan {
        subnet,
        ports,
        no_mdns,
        timeout_ms,
    } = cli.command
    {
        let port_info = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mdns_str = if !no_mdns { " + mDNS" } else { "" };
        println!("Scanning network for ADB devices (ports: {}{})...", port_info, mdns_str);

        let options = airadb::ScanOptions {
            subnet,
            candidates: None,
            ports,
            timeout: std::time::Duration::from_millis(timeout_ms),
            concurrency: 96,
            mdns: !no_mdns,
        };

        match airadb::scan_devices(options).await {
            Ok(devices) => {
                if devices.is_empty() {
                    println!("No ADB devices discovered.");
                } else {
                    println!("\nDiscovered {} ADB device(s):", devices.len());
                    for d in devices {
                        let auth_str = if d.authorized {
                            "authorized"
                        } else {
                            "unauthorized / needs auth"
                        };
                        let model_str = d.model.as_deref().unwrap_or("unknown");
                        println!("  - {:21} [{:16}] ({})", d.addr, model_str, auth_str);
                    }
                }
            }
            Err(e) => {
                eprintln!("Scan error: {}", e);
                process::exit(1);
            }
        }
        return;
    }

    // Load key
    let key = match cli.key {
        Some(p) => match AdbKeyPair::from_file(&p) {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("Failed to load key from {}: {}", p.display(), e);
                process::exit(1);
            }
        },
        None => match load_or_generate_default_key() {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("Warning: failed to load or create default key: {}", e);
                None
            }
        },
    };

    let device = match if let Some(ref k) = key {
        AdbDevice::connect_with_key(&cli.server, k).await
    } else {
        AdbDevice::connect(&cli.server).await
    } {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to connect to device at {}: {}", cli.server, e);
            process::exit(1);
        }
    };

    match cli.command {
        Commands::Keygen { .. } | Commands::Scan { .. } => unreachable!(),
        Commands::Connect => {
            println!("Connected successfully to {}", cli.server);
            println!("Device banner: {}", device.banner().trim());
            if let Ok(model) = device.get_model().await {
                println!("Model:         {}", model);
            }
            if let Ok(Some(aid)) = device.get_android_id().await {
                println!("Android ID:    {}", aid);
            }
            if let Ok(version) = device.get_android_version().await {
                println!("Android OS:    {}", version);
            }
            if let Ok(sdk) = device.get_sdk_version().await {
                println!("SDK API:       {}", sdk);
            }
            println!("Max payload:   {} bytes", device.max_payload());
        }
        Commands::Info => {
            match device.get_hardware_info().await {
                Ok(info) => println!("{}", info),
                Err(e) => {
                    eprintln!("Failed to get device hardware info: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::GetId => {
            match device.get_android_id().await {
                Ok(Some(id)) => println!("{}", id),
                Ok(None) => {
                    eprintln!("Android ID not available on device");
                    process::exit(1);
                }
                Err(e) => {
                    eprintln!("Failed to get Android ID: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Getprop { key } => {
            let cmd = match key {
                Some(k) => format!("getprop {}", k),
                None => "getprop".to_string(),
            };
            match device.shell(&cmd).await {
                Ok(out) => print!("{}", out),
                Err(e) => {
                    eprintln!("Failed to getprop: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Shell { command } => {
            if command.is_empty() {
                // Interactive shell
                match device.interactive_shell().await {
                    Ok(stream) => {
                        let mut stdin = io::stdin();
                        let mut stdout = io::stdout();
                        let (mut stream_r, mut stream_w) = io::split(stream);

                        tokio::select! {
                            _ = io::copy(&mut stdin, &mut stream_w) => {}
                            _ = io::copy(&mut stream_r, &mut stdout) => {}
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to start interactive shell: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                let cmd_str = command.join(" ");
                match device.shell(&cmd_str).await {
                    Ok(out) => print!("{}", out),
                    Err(e) => {
                        eprintln!("Shell command failed: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        Commands::Exec { command } => {
            let cmd_str = command.join(" ");
            match device.exec(&cmd_str).await {
                Ok(bytes) => {
                    let mut stdout = io::stdout();
                    let _ = stdout.write_all(&bytes).await;
                }
                Err(e) => {
                    eprintln!("Exec command failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Push { local, remote } => {
            if !local.exists() {
                eprintln!("Local file does not exist: {}", local.display());
                process::exit(1);
            }
            println!("Pushing {} -> {}...", local.display(), remote);
            match device.push_file(&local, &remote).await {
                Ok(bytes) => println!("Transferred {} bytes successfully.", bytes),
                Err(e) => {
                    eprintln!("Push failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Pull { remote, local } => {
            let dest_path = local.unwrap_or_else(|| {
                let filename = remote.rsplit('/').next().unwrap_or("file");
                PathBuf::from(filename)
            });
            println!("Pulling {} -> {}...", remote, dest_path.display());
            match device.pull_file(&remote, &dest_path).await {
                Ok(bytes) => println!("Received {} bytes successfully.", bytes),
                Err(e) => {
                    eprintln!("Pull failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Screencap { out } => {
            println!("Capturing screenshot from {}...", cli.server);
            match device.screencap().await {
                Ok(png_bytes) => {
                    if let Err(e) = tokio::fs::write(&out, &png_bytes).await {
                        eprintln!("Failed to write screenshot to {}: {}", out.display(), e);
                        process::exit(1);
                    }
                    println!(
                        "Saved screenshot ({} bytes) to {}",
                        png_bytes.len(),
                        out.display()
                    );
                }
                Err(e) => {
                    eprintln!("Screenshot failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Stat { remote } => {
            match device.stat(&remote).await {
                Ok(st) => {
                    if st.exists() {
                        println!("Path:  {}", remote);
                        println!("Mode:  {:#o}", st.mode);
                        println!("Size:  {} bytes", st.size);
                        println!("Mtime: {}", st.mtime);
                    } else {
                        println!("File does not exist: {}", remote);
                    }
                }
                Err(e) => {
                    eprintln!("Stat failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Ls { remote } => {
            match device.list(&remote).await {
                Ok(entries) => {
                    println!("{:<10} {:>10} {:>10} NAME", "MODE", "SIZE", "MTIME");
                    println!("{:-<50}", "");
                    for ent in entries {
                        let type_char = if ent.is_dir() { 'd' } else { '-' };
                        println!(
                            "{}{:04o}     {:>10} {:>10} {}",
                            type_char,
                            ent.mode & 0o777,
                            ent.size,
                            ent.mtime,
                            ent.name
                        );
                    }
                }
                Err(e) => {
                    eprintln!("List failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Install { apk } => {
            if !apk.exists() {
                eprintln!("APK file does not exist: {}", apk.display());
                process::exit(1);
            }
            println!("Installing APK {}...", apk.display());
            match device.install_apk(&apk).await {
                Ok(()) => println!("Success"),
                Err(e) => {
                    eprintln!("Install failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Uninstall { package, keep_data } => {
            println!("Uninstalling {} (keep_data: {})...", package, keep_data);
            match device.uninstall_package(&package, keep_data).await {
                Ok(()) => println!("Success"),
                Err(e) => {
                    eprintln!("Uninstall failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Apps { third_party, filter } => {
            handle_pm_list(&device, third_party, false, filter.as_deref()).await;
        }
        Commands::Start { package, activity } => {
            println!("Starting {}...", package);
            match device.start_app(&package, activity.as_deref()).await {
                Ok(()) => println!("Success: application started"),
                Err(e) => {
                    eprintln!("Start failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Stop { package } => {
            println!("Stopping {}...", package);
            match device.stop_app(&package).await {
                Ok(()) => println!("Success: application stopped"),
                Err(e) => {
                    eprintln!("Stop failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Pm { subcommand } => match subcommand {
            PmCommands::List { third_party, system, filter } => {
                handle_pm_list(&device, third_party, system, filter.as_deref()).await;
            }
            PmCommands::Current => {
                match device.current_app().await {
                    Ok(Some(app)) => println!("Foreground Application: {}", app),
                    Ok(None) => println!("No active foreground application detected"),
                    Err(e) => {
                        eprintln!("Failed to get current app: {}", e);
                        process::exit(1);
                    }
                }
            }
            PmCommands::Start { package, activity } => {
                println!("Starting {}...", package);
                match device.start_app(&package, activity.as_deref()).await {
                    Ok(()) => println!("Success: application started"),
                    Err(e) => {
                        eprintln!("Start failed: {}", e);
                        process::exit(1);
                    }
                }
            }
            PmCommands::Stop { package } => {
                println!("Stopping {}...", package);
                match device.stop_app(&package).await {
                    Ok(()) => println!("Success: application stopped"),
                    Err(e) => {
                        eprintln!("Stop failed: {}", e);
                        process::exit(1);
                    }
                }
            }
            PmCommands::Uninstall { package, keep_data } => {
                println!("Uninstalling {} (keep_data: {})...", package, keep_data);
                match device.uninstall_package(&package, keep_data).await {
                    Ok(()) => println!("Success"),
                    Err(e) => {
                        eprintln!("Uninstall failed: {}", e);
                        process::exit(1);
                    }
                }
            }
            PmCommands::Clear { package } => {
                println!("Clearing data for {}...", package);
                match device.clear_app_data(&package).await {
                    Ok(()) => println!("Success: app data cleared"),
                    Err(e) => {
                        eprintln!("Clear failed: {}", e);
                        process::exit(1);
                    }
                }
            }
        },
        Commands::Reboot { mode } => {
            let m: RebootMode = mode.into();
            println!("Rebooting device ({:?})...", m);
            if let Err(e) = device.reboot(m).await {
                eprintln!("Reboot request failed: {}", e);
                process::exit(1);
            }
            println!("Reboot command sent.");
        }
        Commands::Remount => {
            println!("Remounting...");
            match device.remount().await {
                Ok(out) => print!("{}", out),
                Err(e) => {
                    eprintln!("Remount failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Tcpip { port } => {
            println!("Restarting adbd on port {}...", port);
            match device.tcpip(port).await {
                Ok(out) => print!("{}", out),
                Err(e) => {
                    eprintln!("Tcpip request failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Root => {
            println!("Restarting adbd with root permissions...");
            match device.root().await {
                Ok(out) => print!("{}", out),
                Err(e) => {
                    eprintln!("Root command failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Unroot => {
            println!("Restarting adbd without root permissions...");
            match device.unroot().await {
                Ok(out) => print!("{}", out),
                Err(e) => {
                    eprintln!("Unroot command failed: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}

async fn handle_pm_list(
    device: &AdbDevice,
    third_party: bool,
    system: bool,
    filter: Option<&str>,
) {
    let tp_only = third_party && !system;
    match device.list_packages(filter, tp_only).await {
        Ok(mut pkgs) => {
            if system && !third_party {
                pkgs.retain(|p| p.is_system);
            }
            let label = if third_party && !system {
                "Third-party (User)"
            } else if system && !third_party {
                "System"
            } else {
                "Installed"
            };
            println!("📱 {} Packages ({} total):\n", label, pkgs.len());
            if pkgs.is_empty() {
                println!("  (No packages matching criteria)");
                return;
            }

            println!("┌─────┬────────────────────────────────────────────────────────┬─────────┐");
            println!("│ {:<3} │ {:<54} │ {:<7} │", "#", "Package Name", "Type");
            println!("├─────┼────────────────────────────────────────────────────────┼─────────┤");
            for (i, p) in pkgs.iter().enumerate() {
                let p_type = if p.is_system { "System" } else { "User" };
                let display_name = if p.package_name.len() > 54 {
                    &p.package_name[..54]
                } else {
                    &p.package_name
                };
                println!("│ {:<3} │ {:<54} │ {:<7} │", i + 1, display_name, p_type);
            }
            println!("└─────┴────────────────────────────────────────────────────────┴─────────┘");
        }
        Err(e) => {
            eprintln!("Failed to list packages: {}", e);
            process::exit(1);
        }
    }
}
