# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Breaking:** add Diffie-Hellman key exchange with [`x25519-dalek`](https://crates.io/crates/x25519-dalek) ([#18](https://github.com/JstnMcBrd/dm/pull/18))
- **Breaking:** add HKDF key derivation with [`hkdf`](https://crates.io/crates/hkdf) and [`sha2`](https://crates.io/crates/sha2) ([#18](https://github.com/JstnMcBrd/dm/pull/18))
- **Breaking:** add symmetric encryption with [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) ([#18](https://github.com/JstnMcBrd/dm/pull/18))

### Changed

- Refactor error handling to be more robust and idiomatic ([#17](https://github.com/JstnMcBrd/dm/pull/17))
- **Breaking:** generate random nonces instead of incrementing ([#18](https://github.com/JstnMcBrd/dm/pull/18))
- **Breaking:** send the nonce before each message ([#18](https://github.com/JstnMcBrd/dm/pull/18))
- Display and read IPv6 address and port together ([#20](https://github.com/JstnMcBrd/dm/pull/20))

### Removed

- **Breaking:** remove asymmetric encryption with deprecated [`sodiumoxide`](https://crates.io/crates/sodiumoxide) ([#18](https://github.com/JstnMcBrd/dm/pull/18))
- **Breaking:** remove username-ciphered key exchange and confirmation ([#18](https://github.com/JstnMcBrd/dm/pull/18))

### Fixed

- Move executable to root of zip file ([#16](https://github.com/JstnMcBrd/dm/pull/16))

## [0.2.0] - 2026-02-09

### Added

- Add a CHANGELOG file ([#11](https://github.com/JstnMcBrd/dm/pull/11))
- Add versioning section to README ([#11](https://github.com/JstnMcBrd/dm/pull/11))

### Changed

- **Breaking:** use bitwise XOR for ciphertext ([#7](https://github.com/JstnMcBrd/dm/pull/7))
- Use idiomatic `use` paths ([#8](https://github.com/JstnMcBrd/dm/pull/8))

### Fixed

- Bump local-ip-address from 0.6.9 to 0.6.10 to fix memory leak ([#10](https://github.com/JstnMcBrd/dm/pull/10))

## [0.1.0] - 2026-01-20

### Added

- Add code and README ([#1](https://github.com/JstnMcBrd/dm/pull/1))

[Unreleased]: https://github.com/JstnMcBrd/dm/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/JstnMcBrd/dm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/JstnMcBrd/dm/releases/tag/v0.1.0
