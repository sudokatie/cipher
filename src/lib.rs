//! Cipher - Educational TLS 1.3 implementation.
//!
//! This crate provides a TLS 1.3 implementation for learning purposes.
//! It is NOT suitable for production use.
//!
//! # Features
//!
//! - Full TLS 1.3 handshake (1-RTT)
//! - AEAD encryption (AES-GCM, ChaCha20-Poly1305)
//! - X25519 key exchange
//! - Basic certificate validation
//!
//! # Example
//!
//! ```ignore
//! use cipher::{TlsClient, TlsClientConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = TlsClientConfig::builder()
//!         .build()
//!         .unwrap();
//!
//!     let stream = TlsClient::connect("example.com:443", config)
//!         .await
//!         .unwrap();
//!
//!     // Use stream for HTTPS...
//! }
//! ```

pub mod crypto;
pub mod error;
pub mod key;
pub mod record;

// Re-export main types
pub use crypto::{HashAlgorithm, Sha256, Sha384, TranscriptHash};
pub use error::{AlertDescription, TlsError};
pub use key::{KeyShare, NamedGroup, X25519KeyPair};
pub use record::{ContentType, TlsPlaintext};
