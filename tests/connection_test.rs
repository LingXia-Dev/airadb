use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;

use airadb::crypto::AdbKeyPair;
use airadb::packet::{
    read_packet, write_packet, AdbPacket, ADB_AUTH_SIGNATURE, ADB_AUTH_TOKEN, A_AUTH, A_CLSE,
    A_CNXN, A_OKAY, A_OPEN, A_VERSION_MIN, A_WRTE,
};
use airadb::AdbConnection;

#[tokio::test]
async fn test_mock_adbd_single_connection_multiple_commands() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let key = AdbKeyPair::generate().unwrap();
    let key_clone = key.clone();

    // Spawn mock adbd
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // 1. Receive client A_CNXN
        let p_cnxn = read_packet(&mut socket, false).await.unwrap();
        assert_eq!(p_cnxn.command, A_CNXN);

        // 2. Send A_AUTH challenge
        let token = b"12345678901234567890".to_vec();
        let auth_req = AdbPacket::new(A_AUTH, ADB_AUTH_TOKEN, 0, token.clone());
        write_packet(&mut socket, &auth_req).await.unwrap();

        // 3. Receive A_AUTH signature
        let p_sig = read_packet(&mut socket, false).await.unwrap();
        assert_eq!(p_sig.command, A_AUTH);
        assert_eq!(p_sig.arg0, ADB_AUTH_SIGNATURE);
        assert!(key_clone.verify_signature(&token, &p_sig.payload));

        // 4. Send A_CNXN (connection accepted!)
        let banner = b"device::ro.product.model=TestPhone;ro.build.version.release=5.1\0".to_vec();
        let server_cnxn = AdbPacket::new(A_CNXN, A_VERSION_MIN, 4096, banner);
        write_packet(&mut socket, &server_cnxn).await.unwrap();

        // Handle multiple streams on the SAME connection!
        let mut streams_handled = 0;
        while streams_handled < 3 {
            // Read next packet
            let p = match read_packet(&mut socket, false).await {
                Ok(p) => p,
                Err(_) => break,
            };

            if p.command == A_OPEN {
                let local_id = p.arg0;
                let remote_id = local_id + 100;
                let dest = String::from_utf8_lossy(&p.payload);

                // Send A_OKAY
                let okay = AdbPacket::new(A_OKAY, remote_id, local_id, Vec::new());
                write_packet(&mut socket, &okay).await.unwrap();

                // Send response data
                let response_text = format!("response to: {}", dest.trim_end_matches('\0'));
                let wrte = AdbPacket::new(
                    A_WRTE,
                    remote_id,
                    local_id,
                    response_text.into_bytes(),
                );
                write_packet(&mut socket, &wrte).await.unwrap();

                // Wait for client's A_OKAY flow-control ack
                let client_ack = read_packet(&mut socket, false).await.unwrap();
                assert_eq!(client_ack.command, A_OKAY);
                assert_eq!(client_ack.arg0, local_id);
                assert_eq!(client_ack.arg1, remote_id);

                // Send A_CLSE
                let clse = AdbPacket::new(A_CLSE, remote_id, local_id, Vec::new());
                write_packet(&mut socket, &clse).await.unwrap();

                streams_handled += 1;
            }
        }
        // Keep socket open until client disconnects
        let _ = read_packet(&mut socket, false).await;
    });

    sleep(Duration::from_millis(10)).await;

    // Connect client
    let connection = AdbConnection::connect(addr, Some(&key)).await.unwrap();
    assert!(connection.is_connected());
    assert_eq!(connection.max_payload(), 4096);
    assert!(connection.device_banner().contains("TestPhone"));

    // Run Command 1 on connection
    let mut stream1 = connection.open_stream("shell:getprop ro.product.model").await.unwrap();
    let out1 = stream1.read_string_lossy().await.unwrap();
    assert_eq!(out1, "response to: shell:getprop ro.product.model");

    // Run Command 2 on the SAME connection!
    let mut stream2 = connection.open_stream("shell:uname -a").await.unwrap();
    let out2 = stream2.read_string_lossy().await.unwrap();
    assert_eq!(out2, "response to: shell:uname -a");

    // Run Command 3 on the SAME connection!
    let mut stream3 = connection.open_stream("shell:id").await.unwrap();
    let out3 = stream3.read_string_lossy().await.unwrap();
    assert_eq!(out3, "response to: shell:id");

    // Verify connection is still alive
    assert!(connection.is_connected());
}
