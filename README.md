# dm

## About

Command-line application for encrypted chat over TCP.

I wrote this project to teach myself Rust.

## Disclaimer

This project uses simple end-to-end encryption, but it is far from comprehensive and could be vulnerable to man-in-the-middle attacks.

I designed it as a fun experiment, not a reliable secure communication method. Do not use this project for anything important.

## Versioning

This project abides by [Semantic Versioning](https://semver.org/) and [Keep A Changelog](https://keepachangelog.com/).

## Development

You must have Cargo installed. See the [documentation](https://doc.rust-lang.org/cargo/).

Format and lint the project:

```sh
cargo fmt
cargo clippy
```

Run the project:

```sh
cargo run
```

Build the project:

```sh
cargo build --release
```

The executable will be in `./target/release`.
