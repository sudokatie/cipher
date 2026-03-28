//! AEAD cipher abstraction for TLS 1.3.

use crate::error::TlsError;

/// AEAD cipher trait.
pub trait Aead {
    /// Key length in bytes.
    const KEY_LEN: usize;

    /// Nonce/IV length in bytes.
    const NONCE_LEN: usize;

    /// Authentication tag length in bytes.
    const TAG_LEN: usize;

    /// Create a new AEAD instance with the given key.
    fn new(key: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized;

    /// Encrypt and authenticate plaintext.
    ///
    /// Returns ciphertext || tag.
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError>;

    /// Decrypt and verify ciphertext.
    ///
    /// Input is ciphertext || tag.
    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TlsError>;
}

/// Construct nonce from IV and sequence number per RFC 8446.
///
/// The per-record nonce is formed by XORing the sequence number
/// (as a 64-bit big-endian integer) with the IV.
pub fn construct_nonce(iv: &[u8], seq_num: u64) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    let seq_bytes = seq_num.to_be_bytes();

    // XOR sequence number into the last 8 bytes of IV
    let offset = nonce.len() - 8;
    for (i, b) in seq_bytes.iter().enumerate() {
        nonce[offset + i] ^= b;
    }

    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_nonce() {
        let iv = [0u8; 12];
        let nonce = construct_nonce(&iv, 0);
        assert_eq!(nonce, vec![0u8; 12]);

        let nonce = construct_nonce(&iv, 1);
        assert_eq!(nonce[11], 1);
        assert_eq!(nonce[..11], [0u8; 11]);

        let nonce = construct_nonce(&iv, 256);
        assert_eq!(nonce[10], 1);
        assert_eq!(nonce[11], 0);
    }

    #[test]
    fn test_nonce_xor_with_nonzero_iv() {
        let iv = [0xffu8; 12];
        let nonce = construct_nonce(&iv, 0);
        assert_eq!(nonce, vec![0xffu8; 12]);

        let nonce = construct_nonce(&iv, 1);
        assert_eq!(nonce[11], 0xfe);
    }
}
