//! End-to-end tests against an in-process adbd that speaks enough of the
//! protocol: CNXN/AUTH, multiplexed streams, `shell:` and `sync:`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use airadb::packet::{
    read_packet, write_packet, AdbPacket, ADB_AUTH_RSAPUBLICKEY, ADB_AUTH_SIGNATURE, ADB_AUTH_TOKEN, A_AUTH,
    A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_VERSION_MIN, A_WRTE,
};
use airadb::{Authorization, Client, ErrorKind, Key, KeyPair, PackageName};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const ID_SEND: &[u8; 4] = b"SEND";
const ID_DATA: &[u8; 4] = b"DATA";
const ID_DONE: &[u8; 4] = b"DONE";
const ID_QUIT: &[u8; 4] = b"QUIT";

#[derive(Clone, Copy, PartialEq)]
enum OnPubkey {
    /// The user taps "Allow".
    Accept,
    /// Nobody answers the dialog.
    Ignore,
}

#[derive(Default)]
struct State {
    commands: Vec<String>,
    files: HashMap<String, Vec<u8>>,
    connections: usize,
    pubkey_offered: bool,
    trusted: Vec<Vec<u8>>, // android-format public keys
}

#[derive(Clone)]
struct Mock {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl Mock {
    async fn start(on_pubkey: OnPubkey) -> Self {
        Self::start_with(on_pubkey, |_| None).await
    }

    /// `script` may override the reply to a shell command.
    async fn start_with(on_pubkey: OnPubkey, script: fn(&str) -> Option<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let st = state.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve(sock, st.clone(), on_pubkey, script));
            }
        });
        Self { addr, state }
    }

    fn trust(&self, key: &KeyPair) {
        let pk = key.android_pubkey_string("airadb@client").unwrap();
        self.state.lock().unwrap().trusted.push(pk.trim_end_matches('\0').as_bytes().to_vec());
    }

    fn commands(&self) -> Vec<String> {
        self.state.lock().unwrap().commands.clone()
    }

    fn connections(&self) -> usize {
        self.state.lock().unwrap().connections
    }
}

fn default_reply(cmd: &str, files: &mut HashMap<String, Vec<u8>>) -> String {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    match words.as_slice() {
        ["getprop", "ro.product.model"] => "MockTV\n".into(),
        ["input", "keyevent", _] => String::new(),
        ["pm", "list", "packages", "-f", "-3"] => "package:/data/app/com.a-1/base.apk=com.a\n".into(),
        ["pm", "list", "packages", "-f"] => {
            "package:/system/app/Settings.apk=com.android.settings\npackage:/data/app/com.a-1/base.apk=com.a\n".into()
        }
        ["pm", "install", "-r", path] => {
            if files.contains_key(*path) { "Success\n".into() } else { "Failure [no such file]\n".into() }
        }
        ["rm", "-f", path] => {
            files.remove(*path);
            String::new()
        }
        ["dumpsys", "window", ..] => {
            "  mCurrentFocus=Window{1 u0 com.mitv.tvhome/com.mitv.tvhome.MainActivity}\n".into()
        }
        ["am", "force-stop", _] => String::new(),
        _ => String::new(),
    }
}

async fn send(tx: &mpsc::Sender<AdbPacket>, cmd: u32, a0: u32, a1: u32, data: Vec<u8>) {
    let _ = tx.send(AdbPacket::new(cmd, a0, a1, data)).await;
}

async fn serve(mut sock: TcpStream, state: Arc<State2>, on_pubkey: OnPubkey, script: fn(&str) -> Option<String>) {
    // ---- handshake
    let Ok(cnxn) = read_packet(&mut sock, false).await else { return };
    assert_eq!(cnxn.command, A_CNXN);
    let token = b"01234567890123456789".to_vec();
    write_packet(&mut sock, &AdbPacket::new(A_AUTH, ADB_AUTH_TOKEN, 0, token.clone())).await.unwrap();
    loop {
        let Ok(p) = read_packet(&mut sock, false).await else { return };
        assert_eq!(p.command, A_AUTH);
        match p.arg0 {
            ADB_AUTH_SIGNATURE => {
                let ok = state.lock().unwrap().trusted.iter().any(|pk| verify(pk, &token, &p.payload));
                if ok {
                    break;
                }
                write_packet(&mut sock, &AdbPacket::new(A_AUTH, ADB_AUTH_TOKEN, 0, token.clone())).await.unwrap();
            }
            ADB_AUTH_RSAPUBLICKEY => {
                state.lock().unwrap().pubkey_offered = true;
                if on_pubkey == OnPubkey::Ignore {
                    // Hold the socket open; never answer.
                    let mut buf = [0u8; 64];
                    use tokio::io::AsyncReadExt;
                    while sock.read(&mut buf).await.is_ok_and(|n| n > 0) {}
                    return;
                }
                let pk = String::from_utf8_lossy(&p.payload).trim_end_matches('\0').as_bytes().to_vec();
                state.lock().unwrap().trusted.push(pk);
                break;
            }
            other => panic!("unexpected auth type {other}"),
        }
    }
    state.lock().unwrap().connections += 1;
    let banner = b"device::ro.product.model=MockTV;ro.build.version.release=9\0".to_vec();
    write_packet(&mut sock, &AdbPacket::new(A_CNXN, A_VERSION_MIN, 4096, banner)).await.unwrap();

    // ---- streams
    let (mut rd, mut wr) = sock.into_split();
    let (tx, mut rx) = mpsc::channel::<AdbPacket>(64);
    tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            if write_packet(&mut wr, &p).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    struct SyncStream {
        buf: Vec<u8>,
        path: Option<String>,
        data: Vec<u8>,
    }
    let mut syncs: HashMap<u32, SyncStream> = HashMap::new();
    let mut next_id = 1000u32;
    while let Ok(p) = read_packet(&mut rd, false).await {
        match p.command {
            A_OPEN => {
                let (local, remote) = (p.arg0, next_id);
                next_id += 1;
                let dest = String::from_utf8_lossy(&p.payload).trim_end_matches('\0').to_string();
                send(&tx, A_OKAY, remote, local, vec![]).await;
                if dest == "sync:" {
                    syncs.insert(remote, SyncStream { buf: vec![], path: None, data: vec![] });
                    continue;
                }
                let cmd = dest.strip_prefix("shell:").or(dest.strip_prefix("exec:")).unwrap_or(&dest).trim().to_string();
                let reply = {
                    let mut st = state.lock().unwrap();
                    st.commands.push(cmd.clone());
                    script(&cmd).unwrap_or_else(|| default_reply(&cmd, &mut st.files))
                };
                if !reply.is_empty() {
                    send(&tx, A_WRTE, remote, local, reply.into_bytes()).await;
                }
                send(&tx, A_CLSE, remote, local, vec![]).await;
            }
            A_WRTE => {
                let (local, remote) = (p.arg0, p.arg1);
                send(&tx, A_OKAY, remote, local, vec![]).await;
                let Some(s) = syncs.get_mut(&remote) else { continue };
                s.buf.extend_from_slice(&p.payload);
                // Parse complete sync requests.
                loop {
                    if s.buf.len() < 8 {
                        break;
                    }
                    let id: [u8; 4] = s.buf[0..4].try_into().unwrap();
                    let len = u32::from_le_bytes(s.buf[4..8].try_into().unwrap()) as usize;
                    match &id {
                        ID_SEND | ID_DATA => {
                            if s.buf.len() < 8 + len {
                                break;
                            }
                            let body: Vec<u8> = s.buf[8..8 + len].to_vec();
                            s.buf.drain(..8 + len);
                            if &id == ID_SEND {
                                let spec = String::from_utf8_lossy(&body).to_string();
                                s.path = Some(spec.rsplit_once(',').map(|(p, _)| p.to_string()).unwrap_or(spec));
                            } else {
                                s.data.extend_from_slice(&body);
                            }
                        }
                        ID_DONE => {
                            s.buf.drain(..8);
                            let path = s.path.take().unwrap();
                            state.lock().unwrap().files.insert(path, std::mem::take(&mut s.data));
                            send(&tx, A_WRTE, remote, local, b"OKAY\0\0\0\0".to_vec()).await;
                        }
                        ID_QUIT => {
                            s.buf.drain(..8);
                        }
                        other => panic!("unexpected sync id {other:?}"),
                    }
                }
            }
            A_CLSE => {
                syncs.remove(&p.arg1);
            }
            _ => {}
        }
    }
}

type State2 = Mutex<State>;

/// The mock only checks that the signature is a well-formed RSA signature
/// by the key whose android-format public key it trusts: re-derive the
/// android encoding of the key that signed by trying the test's keys.
fn verify(trusted_pk: &[u8], token: &[u8], signature: &[u8]) -> bool {
    KEYS.lock().unwrap().iter().any(|k| {
        let pk = k.android_pubkey_string("airadb@client").unwrap();
        pk.trim_end_matches('\0').as_bytes() == trusted_pk && k.verify_signature(token, signature)
    })
}

static KEYS: Mutex<Vec<KeyPair>> = Mutex::new(Vec::new());

fn key() -> KeyPair {
    let k = KeyPair::generate().unwrap();
    KEYS.lock().unwrap().push(k.clone());
    k
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn trusted_key_connects_and_runs_quoted_commands() {
    let mock = Mock::start(OnPubkey::Accept).await;
    let k = key();
    mock.trust(&k);
    let dev = Client::new(k).device(mock.addr);

    dev.connect().await.unwrap();
    assert_eq!(dev.getprop("ro.product.model").await.unwrap(), "MockTV");
    dev.press(Key::Home).await.unwrap();
    dev.shell("echo").arg("a b").arg("$(reboot)").await.unwrap();
    assert!(dev.banner().await.unwrap().contains("MockTV"));

    let cmds = mock.commands();
    assert!(cmds.contains(&"input keyevent 3".to_string()), "{cmds:?}");
    assert!(cmds.contains(&"echo 'a b' '$(reboot)'".to_string()), "{cmds:?}");
    assert!(!mock.state.lock().unwrap().pubkey_offered);
}

#[tokio::test]
async fn unknown_key_fails_fast_and_shows_nothing() {
    let mock = Mock::start(OnPubkey::Accept).await;
    let dev = Client::new(key()).device(mock.addr);
    let err = dev.connect().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unauthorized);
    let err = dev.press(Key::Home).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unauthorized);
    assert!(!mock.state.lock().unwrap().pubkey_offered, "connect() must never offer the key");
}

#[tokio::test]
async fn authorize_waits_for_the_user() {
    let mock = Mock::start(OnPubkey::Accept).await;
    let k = key();
    let client = Client::new(k);
    let dev = client.device(mock.addr);

    match dev.authorize().await.unwrap() {
        Authorization::Waiting(prompt) => prompt.wait().await.unwrap(),
        Authorization::Authorized => panic!("key was not trusted yet"),
    }
    assert!(mock.state.lock().unwrap().pubkey_offered);
    dev.press(Key::Back).await.unwrap();

    // Now trusted: reconnecting with the same key needs no dialog.
    dev.close().await;
    assert!(matches!(dev.authorize().await.unwrap(), Authorization::Authorized));
}

#[tokio::test]
async fn ignored_dialog_ends_unauthorized() {
    let mock = Mock::start(OnPubkey::Ignore).await;
    let dev = Client::new(key()).device(mock.addr);
    let Authorization::Waiting(prompt) = dev.authorize().await.unwrap() else { panic!() };
    let err = prompt.wait_timeout(Duration::from_millis(300)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unauthorized);
}

#[tokio::test]
async fn handles_share_one_connection_and_idle_ones_are_reaped() {
    let mock = Mock::start(OnPubkey::Accept).await;
    let k = key();
    mock.trust(&k);
    let client = Client::builder(k).idle_timeout(Some(Duration::from_millis(200))).build();

    let a = client.device(mock.addr);
    let b = client.device(mock.addr);
    a.press(Key::Up).await.unwrap();
    b.press(Key::Down).await.unwrap();
    a.clone().press(Key::Enter).await.unwrap();
    assert_eq!(mock.connections(), 1);

    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!a.is_connected().await, "idle connection should be closed");
    b.press(Key::Enter).await.unwrap();
    assert_eq!(mock.connections(), 2);
}

#[tokio::test]
async fn install_uploads_reports_progress_and_cleans_up() {
    let mock = Mock::start(OnPubkey::Accept).await;
    let k = key();
    mock.trust(&k);
    let dev = Client::new(k).device(mock.addr);

    let apk = std::env::temp_dir().join(format!("airadb-test-{}.apk", std::process::id()));
    let body: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    std::fs::write(&apk, &body).unwrap();

    let last = Arc::new(AtomicU64::new(0));
    let seen = last.clone();
    dev.install(&apk).on_progress(move |sent, total| {
        assert_eq!(total, 300_000);
        seen.store(sent, Ordering::SeqCst);
    })
    .await
    .unwrap();
    let _ = std::fs::remove_file(&apk);

    assert_eq!(last.load(Ordering::SeqCst), 300_000);
    let cmds = mock.commands();
    let install = cmds.iter().find(|c| c.starts_with("pm install -r /data/local/tmp/airadb_pkg_")).unwrap();
    let remote = install.rsplit(' ').next().unwrap();
    assert!(cmds.contains(&format!("rm -f {remote}")), "temp file must be removed: {cmds:?}");
    assert!(mock.state.lock().unwrap().files.is_empty());
}

#[tokio::test]
async fn failed_install_is_install_failed() {
    let mock = Mock::start_with(OnPubkey::Accept, |cmd| {
        cmd.starts_with("pm install").then(|| "Failure [INSTALL_FAILED_OLDER_SDK]\n".to_string())
    })
    .await;
    let k = key();
    mock.trust(&k);
    let dev = Client::new(k).device(mock.addr);
    let apk = std::env::temp_dir().join(format!("airadb-fail-{}.apk", std::process::id()));
    std::fs::write(&apk, b"not really an apk").unwrap();
    let err = dev.install(&apk).await.unwrap_err();
    let _ = std::fs::remove_file(&apk);
    assert_eq!(err.kind(), ErrorKind::InstallFailed);
    assert!(err.message().contains("OLDER_SDK"));
    assert!(mock.commands().iter().any(|c| c.starts_with("rm -f /data/local/tmp/airadb_pkg_")));
}

#[tokio::test]
async fn apps_foreground_and_stop() {
    let mock = Mock::start(OnPubkey::Accept).await;
    let k = key();
    mock.trust(&k);
    let dev = Client::new(k).device(mock.addr);

    // The mock cannot run the helper dex: listing falls back to `pm`, unnamed.
    let all = dev.all_apps().await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|a| a.package == "com.android.settings" && a.system && a.name.is_none()));
    let launcher = dev.apps().await.unwrap();
    assert_eq!(launcher.len(), 1);
    assert!(!launcher[0].system);

    let fg = dev.foreground().await.unwrap().unwrap();
    assert_eq!(fg.package, "com.mitv.tvhome");

    dev.force_stop(&"com.a".parse::<PackageName>().unwrap()).await.unwrap();
    assert!(mock.commands().contains(&"am force-stop com.a".to_string()));
}

#[tokio::test]
async fn checked_shell_reports_exit_status() {
    let mock = Mock::start_with(OnPubkey::Accept, |cmd| {
        cmd.starts_with("false").then(|| "oops\n__AIRADB_EXIT_STATUS__:1\n".to_string())
    })
    .await;
    let k = key();
    mock.trust(&k);
    let dev = Client::new(k).device(mock.addr);
    let err = dev.shell("false").checked().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Rejected);
}

#[tokio::test]
async fn discovery_finds_mock_without_offering_a_key() {
    let mock = Mock::start(OnPubkey::Accept).await;
    let client = Client::new(key());
    let found = client
        .discover()
        .hosts(["127.0.0.1".parse().unwrap()])
        .ports([mock.addr.port()])
        .mdns(false)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].addr, mock.addr);
    assert!(found[0].auth_required);
    assert!(!mock.state.lock().unwrap().pubkey_offered);
}

#[tokio::test]
async fn silent_peer_times_out_and_closed_port_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s); // accept, never answer
        }
    });
    let client = Client::builder(key()).reply_timeout(Duration::from_millis(300)).build();
    let started = std::time::Instant::now();
    let err = client.device(addr).connect().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));

    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let err = client.device(closed).connect().await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unreachable);
    assert!(err.is_retryable());
}
