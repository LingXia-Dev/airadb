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

        /// Comma-separated ports to probe (default: 5555)
        #[arg(short = 'p', long = "ports", value_delimiter = ',', default_value = "5555")]
        ports: Vec<u16>,

        /// Per-probe timeout in milliseconds (default: 800)
        #[arg(short = 't', long = "timeout", default_value = "800")]
        timeout_ms: u64,
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
        timeout_ms,
    } = cli.command
    {
        let port_info = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!("Scanning network for ADB devices (ports: {})...", port_info);

        let options = airadb::ScanOptions {
            subnet,
            candidates: None,
            ports,
            timeout: std::time::Duration::from_millis(timeout_ms),
            concurrency: 96,
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
            if let Ok(version) = device.get_android_version().await {
                println!("Android OS:    {}", version);
            }
            if let Ok(sdk) = device.get_sdk_version().await {
                println!("SDK API:       {}", sdk);
            }
            println!("Max payload:   {} bytes", device.max_payload());
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
        Commands::Uninstall { package } => {
            println!("Uninstalling {}...", package);
            match device.uninstall(&package).await {
                Ok(()) => println!("Success"),
                Err(e) => {
                    eprintln!("Uninstall failed: {}", e);
                    process::exit(1);
                }
            }
        }
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
