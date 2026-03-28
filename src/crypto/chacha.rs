//! ChaCha20-Poly1305 AEAD implementation.

use super::aead::Aead;
use crate::error::TlsError;
use chacha20poly1305::{
    aead::{Aead as AeadTrait, KeyInit},
    ChaCha20Poly1305 as ChaCha20Poly1305Impl, Nonce,
};

/// ChaCha20-Poly1305 AEAD cipher.
pub struct ChaCha20Poly1305 {
    cipher: ChaCha20Poly1305Impl,
}

impl Aead for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != Self::KEY_LEN {
            return Err(TlsError::Crypto(format!(
                "invalid key length: expected {}, got {}",
                Self::KEY_LEN,
                key.len()
            )));
        }

        let cipher = ChaCha20Poly1305Impl::new_from_slice(key)
            .map_err(|e| TlsError::Crypto(format!("failed to create cipher: {}", e)))?;

        Ok(ChaCha20Poly1305 { cipher })
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        if nonce.len() != Self::NONCE_LEN {
            return Err(TlsError::Crypto(format!(
                "invalid nonce length: expected {}, got {}",
                Self::NONCE_LEN,
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|e| TlsError::Crypto(format!("encryption failed: {}", e)))
    }

    fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TlsError> {
        if nonce.len() != Self::NONCE_LEN {
            return Err(TlsError::Crypto(format!(
                "invalid nonce length: expected {}, got {}",
                Self::NONCE_LEN,
                nonce.len()
            )));
        }

        if ciphertext.len() < Self::TAG_LEN {
            return Err(TlsError::Crypto("ciphertext too short".into()));
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| TlsError::Crypto("decryption failed: invalid tag".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_encrypt_decrypt() {
        let key = [0u8; 32];
        let cipher = ChaCha20Poly1305::new(&key).unwrap();

        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello world";

        let ciphertext = cipher.seal(&nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + ChaCha20Poly1305::TAG_LEN);

        let decrypted = cipher.open(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_invalid_tag() {
        let key = [0u8; 32];
        let cipher = ChaCha20Poly1305::new(&key).unwrap();

        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello world";

        let mut ciphertext = cipher.seal(&nonce, aad, plaintext).unwrap();

        // Corrupt the tag
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let result = cipher.open(&nonce, aad, &ciphertext);
        assert!(result.is_err());
    }
}
