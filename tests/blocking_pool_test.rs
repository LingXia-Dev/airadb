use byteorder::{ByteOrder, LittleEndian};
use tokio::net::TcpListener;

use airadb::blocking::BlockingDevicePool;
use airadb::packet::{
    read_packet, write_packet, AdbPacket, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_VERSION_MIN, A_WRTE,
};
use airadb::sync::{ID_DONE, ID_OKAY};

#[test]
fn test_blocking_device_pool_mukeinstall_compat() {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();

    // Spawn mock server in its own thread with its own runtime
    std::thread::spawn(move || {
        let server_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        server_rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            addr_tx.send(addr).unwrap();

            let (mut socket, _) = listener.accept().await.unwrap();

            // Handshake
            let _ = read_packet(&mut socket, false).await.unwrap();
            let cnxn = AdbPacket::new(
                A_CNXN,
                A_VERSION_MIN,
                4096,
                b"device::ro.product.model=MukeTarget\0".to_vec(),
            );
            write_packet(&mut socket, &cnxn).await.unwrap();

            // Serve multiple streams
            loop {
                let p = match read_packet(&mut socket, false).await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                if p.command == A_OPEN {
                    let local_id = p.arg0;
                    let remote_id = local_id + 700;
                    let dest = String::from_utf8_lossy(&p.payload).to_string();
                    let dest_clean = dest.trim_end_matches('\0').trim();

                    // Send A_OKAY
                    let okay = AdbPacket::new(A_OKAY, remote_id, local_id, Vec::new());
                    write_packet(&mut socket, &okay).await.unwrap();

                    if dest_clean.starts_with("shell:") {
                        let resp = b"mock shell output\n";
                        let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, resp.to_vec());
                        write_packet(&mut socket, &wrte).await.unwrap();
                        let _ = read_packet(&mut socket, false).await.unwrap();
                        let clse = AdbPacket::new(A_CLSE, remote_id, local_id, Vec::new());
                        write_packet(&mut socket, &clse).await.unwrap();
                    } else if dest_clean.starts_with("sync:") {
                        // Handle sync push
                        loop {
                            let stream_pkt = match read_packet(&mut socket, false).await {
                                Ok(p) => p,
                                Err(_) => break,
                            };
                            if stream_pkt.command == A_CLSE {
                                break;
                            }
                            if stream_pkt.command == A_WRTE {
                                let ack = AdbPacket::new(A_OKAY, remote_id, local_id, Vec::new());
                                write_packet(&mut socket, &ack).await.unwrap();

                                if stream_pkt.payload.len() >= 4 {
                                    let id = LittleEndian::read_u32(&stream_pkt.payload[0..4]);
                                    if id == ID_DONE {
                                        let mut ok_resp = vec![0u8; 8];
                                        LittleEndian::write_u32(&mut ok_resp[0..4], ID_OKAY);
                                        let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, ok_resp);
                                        write_packet(&mut socket, &wrte).await.unwrap();
                                        let _ = read_packet(&mut socket, false).await.unwrap();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    });

    let addr = addr_rx.recv().unwrap();

    let pool = BlockingDevicePool::new();
    let temp_key_dir = std::env::temp_dir().join("test_airadb_key_home");
    let _ = std::fs::create_dir_all(&temp_key_dir);

    // 1. Sync shell call
    let out = pool.shell(addr, &temp_key_dir, "getprop ro.product.model").unwrap();
    assert_eq!(out.stdout_string_lossy().trim(), "mock shell output");

    // 2. Sync push bytes in-memory (like pushing AGENT_REMOTE_PATH)
    let agent_bytes = b"fake agent binary ELF header";
    pool.push(addr, &temp_key_dir, agent_bytes, "/data/local/tmp/muke-util").unwrap();

    // 3. Second sync shell call (reusing same connection!)
    let out2 = pool.shell(addr, &temp_key_dir, "chmod +x /data/local/tmp/muke-util").unwrap();
    assert_eq!(out2.stdout_string_lossy().trim(), "mock shell output");

    let _ = std::fs::remove_dir_all(&temp_key_dir);
}
