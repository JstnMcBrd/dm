use sodiumoxide::crypto::box_::{self, Nonce, PublicKey, SecretKey};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn main() {
    let name = get_input("Name").expect("Could not get input");

    // Generate a public/private key
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    let (self_pk, self_sk) = box_::gen_keypair();

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

    // Exchange keys and confirm names
    let other_name = get_input("Recipient").expect("Could not get input");

    send_ciphered(&stream, self_pk.as_ref(), name.as_bytes()).expect("Failed to send public key");
    let other_pk_bytes =
        receive_ciphered(&stream, other_name.as_bytes()).expect("Failed to receive public key");
    let other_pk = PublicKey::from_slice(&other_pk_bytes).expect("Failed to parse public key");

    let temp_nonce = Nonce([0u8; box_::NONCEBYTES]);
    send_encrypted(
        &stream,
        other_name.as_bytes(),
        &temp_nonce,
        &other_pk,
        &self_sk,
    )
    .expect("Failed to send confirmation");
    let conf_bytes = receive_encrypted(&stream, &temp_nonce, &other_pk, &self_sk)
        .expect("Failed to receive confirmation");
    let conf = String::from_utf8(conf_bytes).expect("Failed to parse confirmation");
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

        let mut nonce = Nonce([0u8; box_::NONCEBYTES]);
        loop {
            let message = prompt_message().expect("Could not prompt message");
            send_encrypted(&stream, message.as_bytes(), &nonce, &other_pk, &self_sk)
                .expect("Failed to send message");
            println!("{name}: {message}");
            nonce.increment_le_inplace();
        }
    });

    // Receive messages
    {
        let mut nonce = Nonce([0u8; box_::NONCEBYTES]);
        loop {
            let message_bytes = receive_encrypted(&stream, &nonce, &other_pk, &self_sk)
                .expect("Failed to receive message");
            let message = String::from_utf8(message_bytes).expect("Failed to parse message");
            println!("{other_name}: {message}");
            nonce.increment_le_inplace();
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

fn send_insecure(stream: &TcpStream, bytes: &[u8]) -> Result<(), io::Error> {
    let mut writer = BufWriter::new(stream);

    let len = bytes.len();
    writer.write_all(&len.to_be_bytes())?;

    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

fn receive_insecure(stream: &TcpStream) -> Result<Vec<u8>, io::Error> {
    let mut reader = BufReader::new(stream);

    let mut len_buf = [0u8; 8];
    reader.read_exact(&mut len_buf)?;
    let len = u64::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn send_ciphered(stream: &TcpStream, bytes: &[u8], cipher: &[u8]) -> Result<(), io::Error> {
    let mut bytes = bytes.to_vec();
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte ^= cipher[i % cipher.len()]; // XOR
    }
    send_insecure(stream, &bytes)
}

fn receive_ciphered(stream: &TcpStream, cipher: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut bytes = receive_insecure(stream)?;
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte ^= cipher[i % cipher.len()]; // XOR
    }
    Ok(bytes)
}

fn send_encrypted(
    stream: &TcpStream,
    bytes: &[u8],
    nonce: &Nonce,
    other_pk: &PublicKey,
    self_sk: &SecretKey,
) -> Result<(), io::Error> {
    let encrypted = box_::seal(bytes, nonce, other_pk, self_sk);
    send_insecure(stream, &encrypted)
}

fn receive_encrypted(
    stream: &TcpStream,
    nonce: &Nonce,
    other_pk: &PublicKey,
    self_sk: &SecretKey,
) -> Result<Vec<u8>, io::Error> {
    let encrypted = receive_insecure(stream)?;
    match box_::open(&encrypted, nonce, other_pk, self_sk) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Decryption failed",
        )),
    }
}
