use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddrV6, TcpListener, TcpStream};
use std::thread;
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() {
    let name = get_input("Name").expect("Could not get input");

    // Establish TCP connection
    let stream = loop {
        let choice = get_input("Connect/Listen (c/l)").expect("Could not get input");
        match choice.to_lowercase().as_str() {
            "connect" | "c" => break connect(),
            "listen" | "l" => break listen(),
            _ => println!("Invalid choice"),
        };
    };
    println!(
        "Connected to {}",
        stream.peer_addr().expect("Failed to get peer address")
    );

    // Diffie-Hellman key exchange
    let self_sk = EphemeralSecret::random_from_rng(OsRng);
    let self_pk = PublicKey::from(&self_sk);

    send_tcp(&stream, self_pk.as_ref()).expect("Failed to send public key");
    let peer_pk_bytes = receive_tcp(&stream).expect("Failed to receive public key");
    let peer_pk =
        PublicKey::from(<[u8; 32]>::try_from(peer_pk_bytes).expect("Failed to parse public key"));

    let shared_secret = self_sk.diffie_hellman(&peer_pk);

    // Derive symmetric key
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(b"dm/session-key", &mut symmetric_key)
        .expect("Failed to derive symmetric key");

    // Initialize encryption algorithm
    let cipher = ChaCha20Poly1305::new(&symmetric_key.into());

    // Exchange names
    send_encrypted(&stream, &cipher, name.as_bytes()).expect("Failed to send name");
    let peer_name_bytes = receive_encrypted(&stream, &cipher).expect("Failed to receive peer name");
    let peer_name = String::from_utf8(peer_name_bytes).expect("Failed to parse peer name");

    println!();

    // Send messages
    thread::spawn({
        let stream = stream.try_clone().expect("Failed to clone stream");
        let cipher = cipher.clone();
        move || loop {
            let message = prompt_message().expect("Could not prompt message");
            send_encrypted(&stream, &cipher, message.as_bytes()).expect("Failed to send message");
            println!("{name}: {message}");
        }
    });

    // Receive messages
    loop {
        let message_bytes = receive_encrypted(&stream, &cipher).expect("Failed to receive message");
        let message = String::from_utf8(message_bytes).expect("Failed to parse message");
        println!("{peer_name}: {message}");
    }
}

fn connect() -> TcpStream {
    let address = get_input("Address").expect("Could not get input");
    println!("Connecting...");

    loop {
        match TcpStream::connect(&address) {
            Ok(stream) => break stream,
            Err(e) => println!("Failed to send connection: {e}"),
        };
    }
}

fn listen() -> TcpStream {
    let listener = TcpListener::bind("[::]:0").expect("Failed to bind to port");

    let IpAddr::V6(ipv6) =
        local_ip_address::local_ipv6().expect("Failed to get local IPv6 address")
    else {
        panic!("local_ip_address::local_ipv6 returned non-IPv6 address");
    };
    let port = listener
        .local_addr()
        .expect("Failed to get local address")
        .port();
    let address = SocketAddrV6::new(ipv6, port, 0, 0);

    println!("Address: {address}");
    println!("Listening...");

    loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) => println!("Failed to receive connection: {e}"),
        };
    }
}

fn get_input(prompt: &str) -> Result<String, io::Error> {
    print!("{prompt}: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

fn prompt_message() -> Result<String, io::Error> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    // Clear the input
    print!("\x1b[1A\x1b[2K");
    io::stdout().flush()?;

    Ok(input.trim().to_owned())
}

fn send_encrypted(
    stream: &TcpStream,
    cipher: &ChaCha20Poly1305,
    plaintext: &[u8],
) -> Result<(), io::Error> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| io::Error::other(e.to_string()))?;
    send_tcp(stream, nonce.as_ref())?;
    send_tcp(stream, &ciphertext)
}

fn receive_encrypted(stream: &TcpStream, cipher: &ChaCha20Poly1305) -> Result<Vec<u8>, io::Error> {
    let nonce_bytes = receive_tcp(stream)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = receive_tcp(stream)?;
    cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| io::Error::other(e.to_string()))
}

fn send_tcp(mut stream: &TcpStream, bytes: &[u8]) -> Result<(), io::Error> {
    let len = bytes.len() as u64;
    stream.write_all(&len.to_be_bytes())?;

    stream.write_all(bytes)?;
    Ok(())
}

fn receive_tcp(mut stream: &TcpStream) -> Result<Vec<u8>, io::Error> {
    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf)?;
    let len = u64::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}
