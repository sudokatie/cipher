//! Cryptographic primitives for TLS 1.3.

pub mod hash;
pub mod hkdf;

pub use hash::{HashAlgorithm, Sha256, Sha384, TranscriptHash};
pub use hkdf::{
    derive_secret_sha256, derive_secret_sha384, hkdf_expand_label_sha256,
    hkdf_expand_label_sha384, hkdf_expand_sha256, hkdf_expand_sha384, hkdf_extract_sha256,
    hkdf_extract_sha384,
};
