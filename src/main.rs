use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
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

    let other_name = get_input("Recipient").expect("Could not get input");
    println!();

    // Diffie-Hellman key exchange
    let self_sk = EphemeralSecret::random_from_rng(OsRng);
    let self_pk = PublicKey::from(&self_sk);

    send_tcp(&stream, self_pk.as_ref()).expect("Failed to send public key");
    let other_pk_bytes = receive_tcp(&stream).expect("Failed to receive public key");
    let other_pk = PublicKey::from(
        *other_pk_bytes
            .as_array()
            .expect("Failed to parse public key"),
    );

    let shared_secret = self_sk.diffie_hellman(&other_pk);

    // Derive symmetric key
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(b"dm/session-key", &mut symmetric_key)
        .expect("Failed to derive symmetric key");

    // Initialize encryption algorithm
    let cipher = ChaCha20Poly1305::new(&symmetric_key.into());

    // Send messages
    let stream_clone = stream.try_clone().expect("Failed to clone stream");
    let cipher_clone = cipher.clone();
    thread::spawn(move || {
        let stream = stream_clone;
        let cipher = cipher_clone;

        loop {
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            send_tcp(&stream, nonce.as_ref()).expect("Failed to send nonce");

            let message = prompt_message().expect("Could not prompt message");

            let encrypted = cipher
                .encrypt(&nonce, message.as_bytes())
                .expect("Failed to encrypt message");

            send_tcp(&stream, &encrypted).expect("Failed to send message");

            println!("{name}: {message}");
        }
    });

    // Receive messages
    {
        loop {
            let nonce_bytes = receive_tcp(&stream).expect("Failed to receive nonce");
            let nonce = Nonce::from_slice(&nonce_bytes);

            let encrypted = receive_tcp(&stream).expect("Failed to receive message");

            let message_bytes = cipher
                .decrypt(nonce, encrypted.as_slice())
                .expect("Failed to decrypt message");
            let message = String::from_utf8(message_bytes).expect("Failed to parse message");

            println!("{other_name}: {message}");
        }
    }
}

fn connect() -> TcpStream {
    let ipv6 = get_input("IPv6 Address").expect("Could not get input");
    let port = get_input("Port").expect("Could not get input");
    println!("Connecting...");

    let address = format!("[{ipv6}]:{port}");
    loop {
        match TcpStream::connect(&address) {
            Ok(stream) => break stream,
            Err(e) => println!("Failed to send connection: {e}"),
        };
    }
}

fn listen() -> TcpStream {
    let listener = TcpListener::bind("[::]:0").expect("Failed to bind to port");

    let local_ipv6 = local_ip_address::local_ipv6().expect("Failed to get local IPv6");
    let port = listener
        .local_addr()
        .expect("Failed to get local address")
        .port();

    println!("IPv6 Address: {local_ipv6}");
    println!("Port: {port}");
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
    Ok(input.trim().to_string())
}

fn prompt_message() -> Result<String, io::Error> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    // Clear the input
    print!("\x1b[1A\x1b[2K");
    io::stdout().flush()?;

    Ok(input.trim().to_string())
}

fn send_tcp(stream: &TcpStream, bytes: &[u8]) -> Result<(), io::Error> {
    let mut writer = BufWriter::new(stream);

    let len = bytes.len() as u64;
    writer.write_all(&len.to_be_bytes())?;

    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

fn receive_tcp(stream: &TcpStream) -> Result<Vec<u8>, io::Error> {
    let mut reader = BufReader::new(stream);

    let mut len_buf = [0u8; 8];
    reader.read_exact(&mut len_buf)?;
    let len = u64::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}
