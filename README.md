# Cipher

Educational TLS 1.3 implementation in Rust.

## Warning

This is an educational implementation, NOT for production use. Use rustls or native-tls for real applications.

## Features

- Full TLS 1.3 handshake (1-RTT)
- AEAD encryption (AES-GCM, ChaCha20-Poly1305)
- X25519 key exchange
- Basic certificate validation
- Client and server modes

## Quick Start

```rust
use cipher::{TlsClient, TlsClientConfig};

#[tokio::main]
async fn main() {
    let config = TlsClientConfig::builder()
        .build()
        .unwrap();

    let stream = TlsClient::connect("example.com:443", config)
        .await
        .unwrap();

    // Use stream for HTTPS...
}
```

## Building

```bash
cargo build
cargo test
```

## Structure

- `crypto/` - Cryptographic primitives (AEAD, HKDF, hashes)
- `key/` - Key exchange and key schedule
- `record/` - TLS record layer
- `handshake/` - Handshake protocol
- `cert/` - Certificate handling
- `client/` - TLS client implementation
- `server/` - TLS server implementation

## References

- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/)

## License

MIT
