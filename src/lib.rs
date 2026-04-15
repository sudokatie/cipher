//! Cipher - Educational TLS 1.3 implementation.
//!
//! This crate provides a TLS 1.3 implementation for learning purposes.
//! It is NOT suitable for production use.
//!
//! # Features
//!
//! - Full TLS 1.3 handshake (1-RTT)
//! - AEAD encryption (AES-GCM, ChaCha20-Poly1305)
//! - X25519 and P-256 key exchange
//! - Certificate validation with signature verification
//!
//! # Example
//!
//! ```rust,ignore
//! use cipher::{TlsClient, TlsClientConfig};
//! use std::net::TcpStream;
//!
//! let stream = TcpStream::connect("example.com:443").unwrap();
//! let config = TlsClientConfig::builder()
//!     .danger_skip_verification()
//!     .build()
//!     .unwrap();
//!
//! let mut tls = TlsClient::new(stream, config, "example.com");
//! tls.handshake().unwrap();
//!
//! tls.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
//! let mut buf = [0u8; 1024];
//! let n = tls.read(&mut buf).unwrap();
//! ```

pub mod alert;
pub mod auth;
pub mod cert;
pub mod client;
pub mod crypto;
pub mod error;
pub mod extensions;
pub mod handshake;
pub mod key;
pub mod record;
pub mod server;
pub mod session;

// Re-export main types
pub use alert::{Alert, AlertLevel};
pub use auth::{AccessPolicy, AuthResult, ClientAuthenticator, ClientIdentity, PolicyAction, PolicyRule};
pub use cert::{Certificate, CertificateValidator, TrustAnchor, ValidationError};
pub use client::{async_connect, AsyncTlsClient, TlsClient, TlsClientConfig};
pub use crypto::{HashAlgorithm, Sha256, Sha384, TranscriptHash};
pub use error::{AlertDescription, TlsError};
pub use extensions::{Extension, SignatureScheme, SupportedVersions};
pub use handshake::{HandshakeRole, HandshakeState};
pub use key::{KeyPair, KeySchedule, KeyShare, NamedGroup, P256KeyPair, X25519KeyPair};
pub use record::{ContentType, RecordLayer, TlsPlaintext};
pub use server::{AsyncTlsServer, TlsListener, TlsServer, TlsServerConfig};
pub use session::{MemorySessionStore, NewSessionTicket, SessionStore, SessionTicket, TicketData};
