//! TLS record layer.

pub mod ciphertext;
pub mod plaintext;
pub mod types;

pub use ciphertext::TlsCiphertext;
pub use plaintext::TlsPlaintext;
pub use types::{version, ContentType, MAX_FRAGMENT_LENGTH, MAX_RECORD_LENGTH};
