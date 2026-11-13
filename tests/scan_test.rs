use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpListener;

use airadb::packet::{read_packet, write_packet, AdbPacket, ADB_AUTH_TOKEN, A_AUTH, A_CNXN};
use airadb::scan::{probe_adb_device, scan_devices, ScanOptions};
use airadb::BlockingDevicePool;

#[tokio::test]
async fn test_scan_and_probe_devices() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    // Spawn mock adbd that responds to probe A_CNXN with A_AUTH
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(packet) = read_packet(&mut socket, false).await {
                    if packet.command == A_CNXN {
                        // Respond with A_AUTH challenge
                        let token = b"12345678901234567890".to_vec();
                        let auth_req = AdbPacket::new(A_AUTH, ADB_AUTH_TOKEN, 0, token);
                        let _ = write_packet(&mut socket, &auth_req).await;
                    }
                }
            });
        }
    });

    // 1. Direct probe
    let device = probe_adb_device(addr, Duration::from_millis(500)).await;
    assert!(device.is_some(), "Expected to discover mock ADB device");
    let dev = device.unwrap();
    assert_eq!(dev.addr, addr);
    assert!(!dev.authorized);

    // 2. Scan with candidate IP
    let options = ScanOptions {
        subnet: None,
        candidates: Some(vec![Ipv4Addr::new(127, 0, 0, 1)]),
        ports: vec![port, 9999], // 9999 is closed
        timeout: Duration::from_millis(500),
        concurrency: 10,
        mdns: false,
    };

    let discovered = scan_devices(options).await.unwrap();
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].addr, addr);

    // 3. Test blocking pool scan
    let pool = BlockingDevicePool::new();
    let discovered_sync = tokio::task::spawn_blocking(move || {
        pool.scan(
            Some("127.0.0.1"),
            Some(&[port]),
            Some(Duration::from_millis(500)),
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(discovered_sync.len(), 1);
    assert_eq!(discovered_sync[0].addr, addr);
}
