//! HKDF key derivation for TLS 1.3.
//!
//! Implements HKDF-Extract, HKDF-Expand, and TLS 1.3 specific
//! HKDF-Expand-Label and Derive-Secret functions.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

/// HKDF using SHA-256.
pub type HkdfSha256 = Hkdf<Sha256>;

/// HKDF using SHA-384.
pub type HkdfSha384 = Hkdf<Sha384>;

/// HKDF-Extract: Extract a pseudorandom key from input key material.
///
/// PRK = HKDF-Extract(salt, IKM)
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-Extract using SHA-384.
pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-Expand: Expand PRK to desired length.
///
/// OKM = HKDF-Expand(PRK, info, L)
pub fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("valid PRK");
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("valid length");
    okm
}

/// HKDF-Expand using SHA-384.
pub fn hkdf_expand_sha384(prk: &[u8; 48], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha384>::from_prk(prk).expect("valid PRK");
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("valid length");
    okm
}

/// Build the HkdfLabel structure for TLS 1.3.
///
/// struct HkdfLabel {
///    uint16 length = Length;
///    opaque label<7..255> = "tls13 " + Label;
///    opaque context<0..255> = Context;
/// }
fn build_hkdf_label(length: u16, label: &str, context: &[u8]) -> Vec<u8> {
    let tls_label = format!("tls13 {}", label);
    let label_bytes = tls_label.as_bytes();

    let mut result = Vec::with_capacity(2 + 1 + label_bytes.len() + 1 + context.len());

    // Length (2 bytes, big-endian)
    result.extend_from_slice(&length.to_be_bytes());

    // Label length (1 byte) + label
    result.push(label_bytes.len() as u8);
    result.extend_from_slice(label_bytes);

    // Context length (1 byte) + context
    result.push(context.len() as u8);
    result.extend_from_slice(context);

    result
}

/// HKDF-Expand-Label for TLS 1.3.
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
pub fn hkdf_expand_label_sha256(
    secret: &[u8; 32],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let hkdf_label = build_hkdf_label(length as u16, label, context);
    hkdf_expand_sha256(secret, &hkdf_label, length)
}

/// HKDF-Expand-Label using SHA-384.
pub fn hkdf_expand_label_sha384(
    secret: &[u8; 48],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let hkdf_label = build_hkdf_label(length as u16, label, context);
    hkdf_expand_sha384(secret, &hkdf_label, length)
}

/// Derive-Secret for TLS 1.3.
///
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
pub fn derive_secret_sha256(
    secret: &[u8; 32],
    label: &str,
    transcript_hash: &[u8],
) -> [u8; 32] {
    let result = hkdf_expand_label_sha256(secret, label, transcript_hash, 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

/// Derive-Secret using SHA-384.
pub fn derive_secret_sha384(
    secret: &[u8; 48],
    label: &str,
    transcript_hash: &[u8],
) -> [u8; 48] {
    let result = hkdf_expand_label_sha384(secret, label, transcript_hash, 48);
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&result);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract_produces_prk() {
        let salt = [0u8; 32];
        let ikm = b"input key material";

        let prk = hkdf_extract_sha256(&salt, ikm);
        assert_eq!(prk.len(), 32);

        // Same inputs should produce same PRK
        let prk2 = hkdf_extract_sha256(&salt, ikm);
        assert_eq!(prk, prk2);
    }

    #[test]
    fn test_hkdf_expand_produces_okm() {
        let salt = [0u8; 32];
        let ikm = b"input key material";
        let prk = hkdf_extract_sha256(&salt, ikm);

        let okm = hkdf_expand_sha256(&prk, b"info", 64);
        assert_eq!(okm.len(), 64);

        // Different lengths should work
        let okm_short = hkdf_expand_sha256(&prk, b"info", 16);
        assert_eq!(okm_short.len(), 16);
    }

    #[test]
    fn test_hkdf_expand_label_format() {
        // Test the HkdfLabel structure
        let label = build_hkdf_label(32, "derived", b"");

        // Check structure:
        // 2 bytes length (0x00, 0x20 = 32)
        // 1 byte label length (13 = "tls13 derived")
        // 13 bytes label
        // 1 byte context length (0)
        assert_eq!(label[0], 0x00);
        assert_eq!(label[1], 0x20);
        assert_eq!(label[2], 13);
        assert_eq!(&label[3..16], b"tls13 derived");
        assert_eq!(label[16], 0);
    }

    #[test]
    fn test_hkdf_expand_label_sha256() {
        let secret = [0x0bu8; 32]; // Simple test secret

        let result = hkdf_expand_label_sha256(&secret, "derived", b"", 32);
        assert_eq!(result.len(), 32);

        // Different labels should produce different outputs
        let result2 = hkdf_expand_label_sha256(&secret, "other", b"", 32);
        assert_ne!(result, result2);
    }

    #[test]
    fn test_derive_secret() {
        let secret = [0x0bu8; 32];
        let transcript = [0u8; 32]; // Empty transcript hash

        let derived = derive_secret_sha256(&secret, "c hs traffic", &transcript);
        assert_eq!(derived.len(), 32);

        // Different transcripts should produce different secrets
        let different_transcript = [1u8; 32];
        let derived2 = derive_secret_sha256(&secret, "c hs traffic", &different_transcript);
        assert_ne!(derived, derived2);
    }

    #[test]
    fn test_sha384_functions() {
        let salt = [0u8; 48];
        let ikm = b"input key material";

        let prk = hkdf_extract_sha384(&salt, ikm);
        assert_eq!(prk.len(), 48);

        let okm = hkdf_expand_sha384(&prk, b"info", 48);
        assert_eq!(okm.len(), 48);

        let derived = derive_secret_sha384(&prk, "test", b"context");
        assert_eq!(derived.len(), 48);
    }
}
