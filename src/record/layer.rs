//! TLS record layer state machine.
//!
//! Manages encryption keys, sequence numbers, and record I/O.

use super::ciphertext::TlsCiphertext;
use super::plaintext::TlsPlaintext;
use super::types::ContentType;
use crate::crypto::aead::Aead;
use crate::crypto::aes_gcm::{Aes128Gcm, Aes256Gcm};
use crate::crypto::chacha::ChaCha20Poly1305;
use crate::error::TlsError;

/// Cipher suite for the record layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordCipher {
    /// No encryption (initial state).
    None,
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// Traffic keys for one direction.
#[derive(Clone)]
pub struct TrafficKeys {
    /// The encryption key.
    pub key: Vec<u8>,
    /// The IV/nonce base.
    pub iv: Vec<u8>,
    /// The cipher suite.
    pub cipher: RecordCipher,
}

impl TrafficKeys {
    /// Create new traffic keys.
    pub fn new(key: Vec<u8>, iv: Vec<u8>, cipher: RecordCipher) -> Self {
        TrafficKeys { key, iv, cipher }
    }
}

/// Record layer managing encryption state.
pub struct RecordLayer {
    /// Keys for reading (decryption).
    read_keys: Option<TrafficKeys>,
    /// Keys for writing (encryption).
    write_keys: Option<TrafficKeys>,
    /// Read sequence number.
    read_seq: u64,
    /// Write sequence number.
    write_seq: u64,
}

impl RecordLayer {
    /// Create a new record layer in plaintext mode.
    pub fn new() -> Self {
        RecordLayer {
            read_keys: None,
            write_keys: None,
            read_seq: 0,
            write_seq: 0,
        }
    }

    /// Set the read (decryption) keys.
    ///
    /// Resets the read sequence number to 0.
    pub fn set_read_keys(&mut self, keys: TrafficKeys) {
        self.read_keys = Some(keys);
        self.read_seq = 0;
    }

    /// Set the write (encryption) keys.
    ///
    /// Resets the write sequence number to 0.
    pub fn set_write_keys(&mut self, keys: TrafficKeys) {
        self.write_keys = Some(keys);
        self.write_seq = 0;
    }

    /// Check if the record layer is encrypting writes.
    pub fn is_encrypting(&self) -> bool {
        self.write_keys.is_some()
    }

    /// Check if the record layer is decrypting reads.
    pub fn is_decrypting(&self) -> bool {
        self.read_keys.is_some()
    }

    /// Get the current read sequence number.
    pub fn read_sequence(&self) -> u64 {
        self.read_seq
    }

    /// Get the current write sequence number.
    pub fn write_sequence(&self) -> u64 {
        self.write_seq
    }

    /// Encrypt and format a record for sending.
    ///
    /// Returns the wire-format bytes ready to send.
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        match &self.write_keys {
            None => {
                // No encryption - send as plaintext
                let record = TlsPlaintext::new(content_type, plaintext.to_vec())?;
                Ok(record.serialize())
            }
            Some(keys) => {
                let wire = match keys.cipher {
                    RecordCipher::None => {
                        let record = TlsPlaintext::new(content_type, plaintext.to_vec())?;
                        record.serialize()
                    }
                    RecordCipher::Aes128Gcm => {
                        let cipher = Aes128Gcm::new(&keys.key)?;
                        TlsCiphertext::encrypt(
                            content_type,
                            plaintext,
                            &cipher,
                            &keys.iv,
                            self.write_seq,
                        )?
                    }
                    RecordCipher::Aes256Gcm => {
                        let cipher = Aes256Gcm::new(&keys.key)?;
                        TlsCiphertext::encrypt(
                            content_type,
                            plaintext,
                            &cipher,
                            &keys.iv,
                            self.write_seq,
                        )?
                    }
                    RecordCipher::ChaCha20Poly1305 => {
                        let cipher = ChaCha20Poly1305::new(&keys.key)?;
                        TlsCiphertext::encrypt(
                            content_type,
                            plaintext,
                            &cipher,
                            &keys.iv,
                            self.write_seq,
                        )?
                    }
                };
                self.write_seq += 1;
                Ok(wire)
            }
        }
    }

    /// Decrypt a received record.
    ///
    /// Returns the content type and plaintext.
    pub fn decrypt_record(&mut self, data: &[u8]) -> Result<(ContentType, Vec<u8>, usize), TlsError> {
        match &self.read_keys {
            None => {
                // No decryption - parse as plaintext
                let (record, len) = TlsPlaintext::parse(data)?;
                Ok((record.content_type, record.fragment, len))
            }
            Some(keys) => {
                let (content_type, plaintext, len) = match keys.cipher {
                    RecordCipher::None => {
                        let (record, len) = TlsPlaintext::parse(data)?;
                        (record.content_type, record.fragment, len)
                    }
                    RecordCipher::Aes128Gcm => {
                        let cipher = Aes128Gcm::new(&keys.key)?;
                        let (ct, len) =
                            TlsCiphertext::decrypt(data, &cipher, &keys.iv, self.read_seq)?;
                        (ct.inner_content_type, ct.plaintext, len)
                    }
                    RecordCipher::Aes256Gcm => {
                        let cipher = Aes256Gcm::new(&keys.key)?;
                        let (ct, len) =
                            TlsCiphertext::decrypt(data, &cipher, &keys.iv, self.read_seq)?;
                        (ct.inner_content_type, ct.plaintext, len)
                    }
                    RecordCipher::ChaCha20Poly1305 => {
                        let cipher = ChaCha20Poly1305::new(&keys.key)?;
                        let (ct, len) =
                            TlsCiphertext::decrypt(data, &cipher, &keys.iv, self.read_seq)?;
                        (ct.inner_content_type, ct.plaintext, len)
                    }
                };
                self.read_seq += 1;
                Ok((content_type, plaintext, len))
            }
        }
    }
}

impl Default for RecordLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_keys() -> TrafficKeys {
        TrafficKeys::new(vec![0x01; 16], vec![0x02; 12], RecordCipher::Aes128Gcm)
    }

    #[test]
    fn test_plaintext_mode() {
        let mut layer = RecordLayer::new();

        // Initially in plaintext mode
        assert!(!layer.is_encrypting());
        assert!(!layer.is_decrypting());

        // Send plaintext
        let wire = layer
            .encrypt_record(ContentType::Handshake, b"hello")
            .unwrap();

        // Should be a plaintext record
        let (ct, data, _) = layer.decrypt_record(&wire).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_encrypted_mode() {
        let mut layer = RecordLayer::new();
        let keys = make_test_keys();

        layer.set_write_keys(keys.clone());
        layer.set_read_keys(keys);

        assert!(layer.is_encrypting());
        assert!(layer.is_decrypting());

        // Send encrypted
        let wire = layer
            .encrypt_record(ContentType::ApplicationData, b"secret")
            .unwrap();

        // Outer type should be ApplicationData
        assert_eq!(wire[0], 23);

        // Decrypt
        let (ct, data, _) = layer.decrypt_record(&wire).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(data, b"secret");
    }

    #[test]
    fn test_sequence_numbers_increment() {
        let mut layer = RecordLayer::new();
        let keys = make_test_keys();

        layer.set_write_keys(keys.clone());
        layer.set_read_keys(keys);

        assert_eq!(layer.write_sequence(), 0);
        assert_eq!(layer.read_sequence(), 0);

        // Encrypt increments write seq
        let wire1 = layer.encrypt_record(ContentType::ApplicationData, b"a").unwrap();
        assert_eq!(layer.write_sequence(), 1);

        let wire2 = layer.encrypt_record(ContentType::ApplicationData, b"b").unwrap();
        assert_eq!(layer.write_sequence(), 2);

        // Different sequence produces different ciphertext
        assert_ne!(wire1[5..], wire2[5..]);

        // Decrypt increments read seq
        let _ = layer.decrypt_record(&wire1).unwrap();
        assert_eq!(layer.read_sequence(), 1);

        let _ = layer.decrypt_record(&wire2).unwrap();
        assert_eq!(layer.read_sequence(), 2);
    }

    #[test]
    fn test_key_transition() {
        let mut layer = RecordLayer::new();

        // Start in plaintext
        let wire1 = layer.encrypt_record(ContentType::Handshake, b"clienthello").unwrap();
        assert!(!layer.is_encrypting());

        // Transition to encrypted (simulating handshake completion)
        let keys = make_test_keys();
        layer.set_write_keys(keys.clone());
        layer.set_read_keys(keys);

        // Sequence should reset
        assert_eq!(layer.write_sequence(), 0);
        assert_eq!(layer.read_sequence(), 0);

        // Now encrypting
        assert!(layer.is_encrypting());
        let wire2 = layer.encrypt_record(ContentType::ApplicationData, b"data").unwrap();

        // wire1 is plaintext, wire2 is encrypted (different format)
        assert_eq!(wire1[0], 22); // Handshake
        assert_eq!(wire2[0], 23); // ApplicationData (outer)
    }
}
