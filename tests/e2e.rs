use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn e2e() {
    let exe = env!("CARGO_BIN_EXE_dm");

    // Start client 1
    let client1_name = "Alice";
    let mut client1 = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start client 1");

    let mut client1_stdin = client1.stdin.take().unwrap();
    let client1_stdout = client1.stdout.take().unwrap();

    // Start client 2
    let client2_name = "Bob";
    let mut client2 = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start client 2");

    let mut client2_stdin = client2.stdin.take().unwrap();
    let client2_stdout = client2.stdout.take().unwrap();

    // Channels for output
    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();

    // Thread to read client 1 output
    thread::spawn(move || {
        let reader = BufReader::new(client1_stdout);
        for line in reader.lines() {
            let line = line.unwrap();
            println!("Client 1: {line}");
            let _ = tx1.send(line);
        }
    });

    // Thread to read client 2 output
    thread::spawn(move || {
        let reader = BufReader::new(client2_stdout);
        for line in reader.lines() {
            let line = line.unwrap();
            println!("Client 2: {line}");
            let _ = tx2.send(line);
        }
    });

    // Input name to client 1
    writeln!(client1_stdin, "{client1_name}").unwrap();
    client1_stdin.flush().unwrap();

    // Input listen to client 1
    writeln!(client1_stdin, "l").unwrap();
    client1_stdin.flush().unwrap();

    // Extract address from client 1
    let mut address = None;
    for _ in 0..20 {
        if let Ok(line) = rx1.recv_timeout(Duration::from_secs(1)) {
            if line.contains("Address:") {
                address = Some(line.split("Address: ").nth(1).unwrap().to_string());
                break;
            }
        }
    }

    let mut address = match address {
        Some(addr) => addr.parse::<SocketAddrV6>().unwrap(),
        None => panic!("Failed to open TCP listener"),
    };

    if std::env::var("GITHUB_ACTIONS").is_ok() {
        address.set_ip(Ipv6Addr::LOCALHOST); // Use localhost on GitHub runners
    }

    // Input name to client 2
    writeln!(client2_stdin, "{client2_name}").unwrap();
    client2_stdin.flush().unwrap();

    // Input connect to client 2
    writeln!(client2_stdin, "c").unwrap();
    client2_stdin.flush().unwrap();

    // Input address to client 2
    writeln!(client2_stdin, "{address}").unwrap();
    client2_stdin.flush().unwrap();

    // Wait for connections
    let mut client1_connected = false;
    let mut client2_connected = false;
    for _ in 0..20 {
        if let Ok(line) = rx1.recv_timeout(Duration::from_secs(1)) {
            if line.contains("Connected to") {
                client1_connected = true;
            }
        }
        if let Ok(line) = rx2.recv_timeout(Duration::from_secs(1)) {
            if line.contains("Connected to") {
                client2_connected = true;
            }
        }
        if client1_connected && client2_connected {
            break;
        }
    }

    assert!(client1_connected && client2_connected, "Connections failed");

    // Input recipient to client 1
    writeln!(client1_stdin, "{client2_name}").unwrap();
    client1_stdin.flush().unwrap();

    // Input recipient to client 2
    writeln!(client2_stdin, "{client1_name}").unwrap();
    client2_stdin.flush().unwrap();

    // Send message from client 2 to client 1
    let message = format!("Hello from {client2_name}");
    writeln!(client2_stdin, "{message}").unwrap();
    client2_stdin.flush().unwrap();

    // Wait for message in client 1
    let mut received = false;
    for _ in 0..10 {
        if let Ok(line) = rx1.recv_timeout(Duration::from_secs(1)) {
            if line.contains(&format!("{client2_name}: {message}")) {
                received = true;
                break;
            }
        }
    }

    assert!(received, "Message not received by client 1");

    // Send message from client 1 to client 2
    let message = format!("Hi from {client1_name}");
    writeln!(client1_stdin, "{message}").unwrap();
    client1_stdin.flush().unwrap();

    // Wait for message in client 2
    let mut received = false;
    for _ in 0..10 {
        if let Ok(line) = rx2.recv_timeout(Duration::from_secs(1)) {
            if line.contains(&format!("{client1_name}: {message}")) {
                received = true;
                break;
            }
        }
    }

    assert!(received, "Message not received by client 2");

    // Clean up
    let _ = client1.kill();
    let _ = client2.kill();
}
