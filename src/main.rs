use local_ip_address::local_ipv6;
use sodiumoxide::crypto::box_;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn main() {
    let name = get_input("Name");

    // Generate a public/private key
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    let (self_pk, self_sk) = box_::gen_keypair();

    // Establish TCP connection
    let stream = loop {
        let choice = get_input("Connect/Listen (c/l)");
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

    // Exchange keys and confirm names
    let other_name = get_input("Recipient");

    send_ciphered(&stream, self_pk.as_ref(), name.as_bytes());
    let other_pk_bytes = receive_ciphered(&stream, other_name.as_bytes());
    let other_pk = box_::PublicKey::from_slice(&other_pk_bytes).expect("Failed to parse bytes");

    let temp_nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    send_encrypted(
        &stream,
        other_name.as_bytes(),
        &temp_nonce,
        &other_pk,
        &self_sk,
    );
    let conf_bytes = receive_encrypted(&stream, &temp_nonce, &other_pk, &self_sk);
    let conf = String::from_utf8(conf_bytes).expect("Failed to parse bytes");
    if conf == name {
        println!("Confirmed connection with {other_name}");
    } else {
        panic!("Incorrect recipient");
    }

    println!();

    // Send messages
    let stream_clone = stream.try_clone().expect("Failed to clone stream");
    let self_sk_clone = self_sk.clone();
    thread::spawn(move || {
        let stream = stream_clone;
        let self_sk = self_sk_clone;

        let mut nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        loop {
            let message = prompt_message();
            send_encrypted(&stream, message.as_bytes(), &nonce, &other_pk, &self_sk);
            println!("{name}: {message}");
            nonce.increment_le_inplace();
        }
    });

    // Receive messages
    {
        let mut nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        loop {
            let message_bytes = receive_encrypted(&stream, &nonce, &other_pk, &self_sk);
            let message = String::from_utf8(message_bytes).expect("Failed to parse bytes");
            println!("{other_name}: {message}");
            nonce.increment_le_inplace();
        }
    }
}

fn get_input(prompt: &str) -> String {
    print!("{prompt}: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    input.trim().to_string()
}

fn prompt_message() -> String {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    // Clear the input
    print!("\x1b[1A\x1b[2K");
    io::stdout().flush().expect("Failed to flush stdout");

    input.trim().to_string()
}

fn connect() -> TcpStream {
    let ipv6 = get_input("IPv6 Address");
    let port = get_input("Port");
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

    let local_ipv6 = local_ipv6().expect("Failed to get local IPv6");
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

fn send_insecure(stream: &TcpStream, bytes: &[u8]) {
    let mut writer = BufWriter::new(stream);
    let len = bytes.len();
    writer
        .write_all(&len.to_be_bytes())
        .expect("Failed to write length");
    writer.write_all(bytes).expect("Failed to write");
    writer.flush().expect("Failed to flush");
}

fn receive_insecure(stream: &TcpStream) -> Vec<u8> {
    let mut reader = BufReader::new(stream);

    let mut len_buf = [0u8; 8];
    reader
        .read_exact(&mut len_buf)
        .expect("Failed to read length");
    let len = u64::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).expect("Failed to read");
    buf
}

fn send_ciphered(stream: &TcpStream, bytes: &[u8], cipher: &[u8]) {
    let mut bytes = bytes.to_vec();
    for (i, byte) in bytes.iter_mut().enumerate() {
        let diff = cipher[i % cipher.len()];
        *byte = byte.wrapping_add(diff);
    }
    send_insecure(stream, &bytes);
}

fn receive_ciphered(stream: &TcpStream, cipher: &[u8]) -> Vec<u8> {
    let mut bytes = receive_insecure(stream);
    for (i, byte) in bytes.iter_mut().enumerate() {
        let diff = cipher[i % cipher.len()];
        *byte = byte.wrapping_sub(diff);
    }
    bytes
}

fn send_encrypted(
    stream: &TcpStream,
    bytes: &[u8],
    nonce: &box_::Nonce,
    other_pk: &box_::PublicKey,
    self_sk: &box_::SecretKey,
) {
    let encrypted = box_::seal(bytes, nonce, other_pk, self_sk);
    send_insecure(stream, &encrypted);
}

fn receive_encrypted(
    stream: &TcpStream,
    nonce: &box_::Nonce,
    other_pk: &box_::PublicKey,
    self_sk: &box_::SecretKey,
) -> Vec<u8> {
    let encrypted = receive_insecure(stream);
    box_::open(&encrypted, nonce, other_pk, self_sk).expect("Failed to decrypt message")
}
