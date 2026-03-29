//! AES-GCM AEAD implementation.

use super::aead::Aead;
use crate::error::TlsError;
use aes_gcm::{
    aead::{Aead as AeadTrait, KeyInit},
    Aes128Gcm as Aes128GcmImpl, Aes256Gcm as Aes256GcmImpl, Nonce,
};

/// AES-128-GCM AEAD cipher.
pub struct Aes128Gcm {
    cipher: Aes128GcmImpl,
}

impl Aead for Aes128Gcm {
    const KEY_LEN: usize = 16;
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

        let cipher = Aes128GcmImpl::new_from_slice(key)
            .map_err(|e| TlsError::Crypto(format!("failed to create cipher: {}", e)))?;

        Ok(Aes128Gcm { cipher })
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
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };

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
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| TlsError::Crypto("decryption failed: invalid tag".into()))
    }
}

/// AES-256-GCM AEAD cipher.
pub struct Aes256Gcm {
    cipher: Aes256GcmImpl,
}

impl Aead for Aes256Gcm {
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

        let cipher = Aes256GcmImpl::new_from_slice(key)
            .map_err(|e| TlsError::Crypto(format!("failed to create cipher: {}", e)))?;

        Ok(Aes256Gcm { cipher })
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
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };

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
        let payload = aes_gcm::aead::Payload {
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
    fn test_aes128_gcm_encrypt_decrypt() {
        let key = [0u8; 16];
        let cipher = Aes128Gcm::new(&key).unwrap();

        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello world";

        let ciphertext = cipher.seal(&nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + Aes128Gcm::TAG_LEN);

        let decrypted = cipher.open(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_encrypt_decrypt() {
        let key = [0u8; 32];
        let cipher = Aes256Gcm::new(&key).unwrap();

        let nonce = [0u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello world";

        let ciphertext = cipher.seal(&nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + Aes256Gcm::TAG_LEN);

        let decrypted = cipher.open(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_tag_rejected() {
        let key = [0u8; 16];
        let cipher = Aes128Gcm::new(&key).unwrap();

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

    #[test]
    fn test_invalid_key_length() {
        let key = [0u8; 10]; // Wrong length
        let result = Aes128Gcm::new(&key);
        assert!(result.is_err());
    }
}
