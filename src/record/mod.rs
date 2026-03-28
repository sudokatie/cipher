//! TLS record layer.

pub mod plaintext;
pub mod types;

pub use plaintext::TlsPlaintext;
pub use types::{version, ContentType, MAX_FRAGMENT_LENGTH, MAX_RECORD_LENGTH};
