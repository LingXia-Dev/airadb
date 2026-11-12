use std::time::Duration;
use byteorder::{ByteOrder, LittleEndian};
use tokio::net::TcpListener;
use tokio::time::sleep;

use radb::crypto::AdbKeyPair;
use radb::packet::{
    read_packet, write_packet, AdbPacket, A_CLSE, A_CNXN, A_OKAY, A_OPEN, A_VERSION_MIN, A_WRTE,
};
use radb::sync::{ID_DATA, ID_DENT, ID_DONE, ID_LIST, ID_OKAY, ID_RECV, ID_SEND, ID_STAT};
use radb::{AdbDevice, RebootMode};

#[tokio::test]
async fn test_device_high_level_api_and_sync() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = AdbKeyPair::generate().unwrap();

    // Spawn mock adbd
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Handshake: read client CNXN, reply server CNXN (auth bypassed)
        let _ = read_packet(&mut socket, false).await.unwrap();
        let server_cnxn = AdbPacket::new(
            A_CNXN,
            A_VERSION_MIN,
            4096,
            b"device::ro.product.model=Nexus5;ro.build.version.release=5.0.1;ro.build.version.sdk=21\0"
                .to_vec(),
        );
        write_packet(&mut socket, &server_cnxn).await.unwrap();

        // Handle streams
        loop {
            let p = match read_packet(&mut socket, false).await {
                Ok(p) => p,
                Err(_) => break,
            };

            if p.command == A_OPEN {
                let local_id = p.arg0;
                let remote_id = local_id + 500;
                let dest = String::from_utf8_lossy(&p.payload).to_string();
                let dest_clean = dest.trim_end_matches('\0');

                // Send A_OKAY to open stream
                let okay = AdbPacket::new(A_OKAY, remote_id, local_id, Vec::new());
                write_packet(&mut socket, &okay).await.unwrap();

                if dest_clean.starts_with("shell:getprop ro.product.model") {
                    let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, b"Nexus5\n".to_vec());
                    write_packet(&mut socket, &wrte).await.unwrap();
                    let _ = read_packet(&mut socket, false).await.unwrap(); // client A_OKAY
                    let clse = AdbPacket::new(A_CLSE, remote_id, local_id, Vec::new());
                    write_packet(&mut socket, &clse).await.unwrap();
                } else if dest_clean.starts_with("shell:getprop ro.build.version.sdk") {
                    let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, b"21\n".to_vec());
                    write_packet(&mut socket, &wrte).await.unwrap();
                    let _ = read_packet(&mut socket, false).await.unwrap();
                    let clse = AdbPacket::new(A_CLSE, remote_id, local_id, Vec::new());
                    write_packet(&mut socket, &clse).await.unwrap();
                } else if dest_clean.starts_with("exec:screencap") {
                    let raw_bytes = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
                    let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, raw_bytes);
                    write_packet(&mut socket, &wrte).await.unwrap();
                    let _ = read_packet(&mut socket, false).await.unwrap();
                    let clse = AdbPacket::new(A_CLSE, remote_id, local_id, Vec::new());
                    write_packet(&mut socket, &clse).await.unwrap();
                } else if dest_clean == "remount:" {
                    let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, b"remount succeeded\n".to_vec());
                    write_packet(&mut socket, &wrte).await.unwrap();
                    let _ = read_packet(&mut socket, false).await.unwrap();
                    let clse = AdbPacket::new(A_CLSE, remote_id, local_id, Vec::new());
                    write_packet(&mut socket, &clse).await.unwrap();
                } else if dest_clean == "reboot:recovery" {
                    let clse = AdbPacket::new(A_CLSE, remote_id, local_id, Vec::new());
                    write_packet(&mut socket, &clse).await.unwrap();
                } else if dest_clean == "sync:" {
                    // Handle sync requests inside this stream
                    loop {
                        let stream_pkt = match read_packet(&mut socket, false).await {
                            Ok(p) => p,
                            Err(_) => break,
                        };

                        if stream_pkt.command == A_CLSE {
                            break;
                        }

                        if stream_pkt.command == A_WRTE {
                            let payload = stream_pkt.payload;
                            // Flow-control ACK to client: arg0 = remote_id (device), arg1 = local_id (client)
                            let ack = AdbPacket::new(A_OKAY, remote_id, local_id, Vec::new());
                            write_packet(&mut socket, &ack).await.unwrap();

                            if payload.len() >= 4 {
                                let id = LittleEndian::read_u32(&payload[0..4]);
                                match id {
                                    ID_STAT => {
                                        let mut stat_resp = vec![0u8; 16];
                                        LittleEndian::write_u32(&mut stat_resp[0..4], ID_STAT);
                                        LittleEndian::write_u32(&mut stat_resp[4..8], 0o100644);
                                        LittleEndian::write_u32(&mut stat_resp[8..12], 1024);
                                        LittleEndian::write_u32(&mut stat_resp[12..16], 1600000000);

                                        let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, stat_resp);
                                        write_packet(&mut socket, &wrte).await.unwrap();
                                        let _ = read_packet(&mut socket, false).await.unwrap();
                                    }
                                    ID_LIST => {
                                        let name = b"test_file.txt";
                                        let mut dent = vec![0u8; 20 + name.len()];
                                        LittleEndian::write_u32(&mut dent[0..4], ID_DENT);
                                        LittleEndian::write_u32(&mut dent[4..8], 0o100644);
                                        LittleEndian::write_u32(&mut dent[8..12], 500);
                                        LittleEndian::write_u32(&mut dent[12..16], 1600000001);
                                        LittleEndian::write_u32(&mut dent[16..20], name.len() as u32);
                                        dent[20..].copy_from_slice(name);

                                        let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, dent);
                                        write_packet(&mut socket, &wrte).await.unwrap();
                                        let _ = read_packet(&mut socket, false).await.unwrap();

                                        let mut done = vec![0u8; 20];
                                        LittleEndian::write_u32(&mut done[0..4], ID_DONE);
                                        let wrte_done = AdbPacket::new(A_WRTE, remote_id, local_id, done);
                                        write_packet(&mut socket, &wrte_done).await.unwrap();
                                        let _ = read_packet(&mut socket, false).await.unwrap();
                                    }
                                    ID_SEND => {
                                        // Path received; next will be DATA chunks and DONE
                                    }
                                    ID_DATA => {
                                        // Chunk received
                                    }
                                    ID_DONE => {
                                        let mut resp = vec![0u8; 8];
                                        LittleEndian::write_u32(&mut resp[0..4], ID_OKAY);
                                        LittleEndian::write_u32(&mut resp[4..8], 0);

                                        let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, resp);
                                        write_packet(&mut socket, &wrte).await.unwrap();
                                        let _ = read_packet(&mut socket, false).await.unwrap();
                                    }
                                    ID_RECV => {
                                        let content = b"hello from remote file!";
                                        let mut data_chunk = vec![0u8; 8 + content.len()];
                                        LittleEndian::write_u32(&mut data_chunk[0..4], ID_DATA);
                                        LittleEndian::write_u32(&mut data_chunk[4..8], content.len() as u32);
                                        data_chunk[8..].copy_from_slice(content);

                                        let wrte = AdbPacket::new(A_WRTE, remote_id, local_id, data_chunk);
                                        write_packet(&mut socket, &wrte).await.unwrap();
                                        let _ = read_packet(&mut socket, false).await.unwrap();

                                        let mut done = vec![0u8; 8];
                                        LittleEndian::write_u32(&mut done[0..4], ID_DONE);
                                        let wrte_done = AdbPacket::new(A_WRTE, remote_id, local_id, done);
                                        write_packet(&mut socket, &wrte_done).await.unwrap();
                                        let _ = read_packet(&mut socket, false).await.unwrap();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    sleep(Duration::from_millis(10)).await;

    // Connect AdbDevice
    let device = AdbDevice::connect_with_key(addr, &key).await.unwrap();
    assert!(device.is_connected());

    // 1. Get properties
    let model = device.get_model().await.unwrap();
    assert_eq!(model, "Nexus5");

    let sdk = device.get_sdk_version().await.unwrap();
    assert_eq!(sdk, 21); // Android 5.0!

    // 2. Exec command (raw binary)
    let png_header = device.exec("screencap -p").await.unwrap();
    assert_eq!(&png_header[0..4], &[0x89, 0x50, 0x4e, 0x47]);

    // 3. Remount
    let remount_out = device.remount().await.unwrap();
    assert!(remount_out.contains("succeeded"));

    // 4. Reboot
    device.reboot(RebootMode::Recovery).await.unwrap();

    // 5. Sync STAT
    let stat = device.stat("/sdcard/test.txt").await.unwrap();
    assert!(stat.exists());
    assert!(stat.is_file());
    assert_eq!(stat.size, 1024);

    // 6. Sync LIST
    let entries = device.list("/sdcard").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "test_file.txt");
    assert_eq!(entries[0].size, 500);

    // 7. Sync PUSH & PULL
    let temp_dir = tempfile_dir();
    let local_file = temp_dir.join("local_sample.txt");
    tokio::fs::write(&local_file, b"sample push content").await.unwrap();

    let bytes_pushed = device.push_file(&local_file, "/sdcard/uploaded.txt").await.unwrap();
    assert_eq!(bytes_pushed, 19);

    let pulled_file = temp_dir.join("pulled_sample.txt");
    let bytes_pulled = device.pull_file("/sdcard/test_file.txt", &pulled_file).await.unwrap();
    assert_eq!(bytes_pulled, 23);
    let pulled_text = tokio::fs::read_to_string(&pulled_file).await.unwrap();
    assert_eq!(pulled_text, "hello from remote file!");

    // Clean up temp
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

fn tempfile_dir() -> std::path::PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("radb_test_{}", now));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
