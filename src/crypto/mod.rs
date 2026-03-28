//! Cryptographic primitives for TLS 1.3.

pub mod hash;

pub use hash::{HashAlgorithm, Sha256, Sha384, TranscriptHash};
