# Cipher

Educational TLS 1.3 implementation in Rust.

## Warning

This is an educational implementation, NOT for production use. Use rustls or native-tls for real applications.

## Features

- Full TLS 1.3 handshake (1-RTT)
- AEAD encryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
- Key exchange (X25519, P-256)
- HKDF key derivation with SHA-256/SHA-384
- Certificate validation with chain verification
- SNI (Server Name Indication)
- ALPN (Application-Layer Protocol Negotiation)
- Client and server modes (sync and async)

## Quick Start

### Client

```rust
use cipher::{TlsClient, TlsClientConfig};

#[tokio::main]
async fn main() {
    let config = TlsClientConfig::builder()
        .danger_skip_verification()
        .build()
        .unwrap();

    let mut stream = cipher::async_connect("example.com:443", config, "example.com")
        .await
        .unwrap();

    // Use stream for HTTPS...
}
```

### Server

```rust
use cipher::{TlsListener, TlsServerConfig, TrustAnchor};

#[tokio::main]
async fn main() {
    let cert = std::fs::read("server.crt").unwrap();
    let key = std::fs::read("server.key").unwrap();

    let config = TlsServerConfig::builder()
        .set_certificate_chain(vec![cert])
        .set_private_key(key)
        .build()
        .unwrap();

    let listener = TlsListener::bind("0.0.0.0:8443", config).await.unwrap();

    while let Ok(stream) = listener.accept().await {
        tokio::spawn(async move {
            // Handle connection...
        });
    }
}
```

## Building

```bash
cargo build
cargo test
cargo clippy
```

## Structure

- `crypto/` - Cryptographic primitives (AEAD, HKDF, hashes)
- `key/` - Key exchange and key schedule
- `record/` - TLS record layer
- `handshake/` - Handshake protocol
- `cert/` - Certificate handling (X.509 parsing, validation)
- `extensions/` - TLS extensions (SNI, ALPN, key_share, etc.)
- `client/` - TLS client implementation
- `server/` - TLS server implementation
- `alert/` - Alert protocol

## Supported Cipher Suites

- TLS_AES_128_GCM_SHA256 (0x1301)
- TLS_AES_256_GCM_SHA384 (0x1302)
- TLS_CHACHA20_POLY1305_SHA256 (0x1303)

## Extensions

- supported_versions
- signature_algorithms
- key_share
- supported_groups
- server_name (SNI)
- application_layer_protocol_negotiation (ALPN)

## References

- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/)

## License

MIT
