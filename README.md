# Rust-OTP

[![Build Status](https://travis-ci.org/pantsman0/rust-rust-otp.png?branch=master)](https://github.com/pantsman0/rust-otp)
![creates.io version](https://img.shields.io/crates/v/rust-otp.svg)

A pure rust implementation for HOTP (RFC 4226) and TOTP(RFC 6238).

## Usage

To import rust-rust-otp add the following to your Cargo.toml:
```toml
[dependencies]
otp = "^0.1"
```

To use rust-rust-otp add the following to your crate root:
```rust
extern crate otp
```
## Contributions

Any contributions are welcome. This was implemented as a learning experience and any advice is appreciated.

## License

This crate is licensed under the BSD 3-Clause license, as is its dependancy [hmac-sha1](https://github.com/pantsman0/rust-hmac-sha1