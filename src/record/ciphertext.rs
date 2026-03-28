//! TLS ciphertext record handling.
//!
//! TLS 1.3 uses a unified encrypted record format where all
//! encrypted records appear as ApplicationData on the wire.

use super::types::{version, ContentType, MAX_FRAGMENT_LENGTH};
use crate::crypto::aead::{construct_nonce, Aead};
use crate::error::TlsError;

/// Maximum ciphertext expansion (tag + content type byte).
pub const MAX_CIPHERTEXT_EXPANSION: usize = 256;

/// TLS ciphertext record structure.
///
/// In TLS 1.3, encrypted records have this wire format:
/// ```text
/// struct {
///     ContentType opaque_type = application_data(23);
///     ProtocolVersion legacy_record_version = 0x0303;
///     uint16 length;
///     opaque encrypted_record[TLSCiphertext.length];
/// } TLSCiphertext;
/// ```
///
/// The encrypted_record contains:
/// ```text
/// struct {
///     opaque content[TLSPlaintext.length];
///     ContentType type;
///     uint8 zeros[length_of_padding];
/// } TLSInnerPlaintext;
/// ```
#[derive(Debug, Clone)]
pub struct TlsCiphertext {
    /// The actual content type (hidden in encryption).
    pub inner_content_type: ContentType,
    /// Decrypted plaintext.
    pub plaintext: Vec<u8>,
}

impl TlsCiphertext {
    /// Encrypt a plaintext record.
    ///
    /// Returns the wire-format bytes (header + encrypted data + tag).
    pub fn encrypt<A: Aead>(
        content_type: ContentType,
        plaintext: &[u8],
        cipher: &A,
        iv: &[u8],
        seq_num: u64,
    ) -> Result<Vec<u8>, TlsError> {
        if plaintext.len() > MAX_FRAGMENT_LENGTH {
            return Err(TlsError::Protocol("plaintext too large".into()));
        }

        // Build inner plaintext: content || content_type
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(content_type.to_u8());

        // Construct nonce from IV and sequence number
        let nonce = construct_nonce(iv, seq_num);

        // Build AAD: record header with encrypted length
        let encrypted_len = inner.len() + A::TAG_LEN;
        let aad = build_aad(encrypted_len);

        // Encrypt
        let ciphertext = cipher.seal(&nonce, &aad, &inner)?;

        // Build wire format
        let mut wire = Vec::with_capacity(5 + ciphertext.len());
        wire.push(ContentType::ApplicationData.to_u8());
        wire.extend_from_slice(&version::TLS12.to_be_bytes());
        wire.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        wire.extend_from_slice(&ciphertext);

        Ok(wire)
    }

    /// Decrypt a ciphertext record.
    ///
    /// Takes the wire-format bytes and returns the decrypted content.
    pub fn decrypt<A: Aead>(
        data: &[u8],
        cipher: &A,
        iv: &[u8],
        seq_num: u64,
    ) -> Result<(Self, usize), TlsError> {
        if data.len() < 5 {
            return Err(TlsError::Protocol("record too short".into()));
        }

        // Parse header
        let outer_type = data[0];
        if outer_type != ContentType::ApplicationData.to_u8() {
            return Err(TlsError::Protocol(format!(
                "expected ApplicationData outer type, got {}",
                outer_type
            )));
        }

        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if length < A::TAG_LEN + 1 {
            return Err(TlsError::Protocol("ciphertext too short".into()));
        }

        if data.len() < 5 + length {
            return Err(TlsError::Protocol("record truncated".into()));
        }

        let ciphertext = &data[5..5 + length];

        // Construct nonce
        let nonce = construct_nonce(iv, seq_num);

        // Build AAD from record header
        let aad = build_aad(length);

        // Decrypt
        let inner = cipher.open(&nonce, &aad, ciphertext)?;

        // Parse inner plaintext: content || content_type || zeros
        // Find content type by scanning from the end past any zeros
        let content_type_pos = inner
            .iter()
            .rposition(|&b| b != 0)
            .ok_or_else(|| TlsError::Protocol("empty inner plaintext".into()))?;

        let content_type = ContentType::from_u8(inner[content_type_pos])
            .ok_or_else(|| TlsError::Protocol("invalid inner content type".into()))?;

        let plaintext = inner[..content_type_pos].to_vec();

        Ok((
            TlsCiphertext {
                inner_content_type: content_type,
                plaintext,
            },
            5 + length,
        ))
    }
}

/// Build the additional authenticated data (AAD) for AEAD.
fn build_aad(ciphertext_len: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5);
    aad.push(ContentType::ApplicationData.to_u8());
    aad.extend_from_slice(&version::TLS12.to_be_bytes());
    aad.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes_gcm::Aes128Gcm;

    fn test_key() -> [u8; 16] {
        [0x01; 16]
    }

    fn test_iv() -> [u8; 12] {
        [0x02; 12]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = Aes128Gcm::new(&test_key()).unwrap();
        let plaintext = b"Hello, TLS 1.3!";

        let encrypted =
            TlsCiphertext::encrypt(ContentType::ApplicationData, plaintext, &cipher, &test_iv(), 0)
                .unwrap();

        let (decrypted, len) =
            TlsCiphertext::decrypt::<Aes128Gcm>(&encrypted, &cipher, &test_iv(), 0).unwrap();

        assert_eq!(len, encrypted.len());
        assert_eq!(decrypted.inner_content_type, ContentType::ApplicationData);
        assert_eq!(decrypted.plaintext, plaintext);
    }

    #[test]
    fn test_handshake_content_type_preserved() {
        let cipher = Aes128Gcm::new(&test_key()).unwrap();
        let plaintext = b"handshake data";

        let encrypted =
            TlsCiphertext::encrypt(ContentType::Handshake, plaintext, &cipher, &test_iv(), 0)
                .unwrap();

        // Outer type is always ApplicationData
        assert_eq!(encrypted[0], ContentType::ApplicationData.to_u8());

        let (decrypted, _) =
            TlsCiphertext::decrypt::<Aes128Gcm>(&encrypted, &cipher, &test_iv(), 0).unwrap();

        // Inner type is preserved
        assert_eq!(decrypted.inner_content_type, ContentType::Handshake);
        assert_eq!(decrypted.plaintext, plaintext);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let cipher1 = Aes128Gcm::new(&test_key()).unwrap();
        let cipher2 = Aes128Gcm::new(&[0x99; 16]).unwrap();
        let plaintext = b"secret";

        let encrypted =
            TlsCiphertext::encrypt(ContentType::ApplicationData, plaintext, &cipher1, &test_iv(), 0)
                .unwrap();

        // Decrypting with wrong key should fail
        let result =
            TlsCiphertext::decrypt::<Aes128Gcm>(&encrypted, &cipher2, &test_iv(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_sequence_number_affects_nonce() {
        let cipher = Aes128Gcm::new(&test_key()).unwrap();
        let plaintext = b"data";

        let enc0 =
            TlsCiphertext::encrypt(ContentType::ApplicationData, plaintext, &cipher, &test_iv(), 0)
                .unwrap();
        let enc1 =
            TlsCiphertext::encrypt(ContentType::ApplicationData, plaintext, &cipher, &test_iv(), 1)
                .unwrap();

        // Same plaintext with different seq nums produces different ciphertext
        assert_ne!(enc0, enc1);

        // Decrypting with wrong sequence number should fail
        let result = TlsCiphertext::decrypt::<Aes128Gcm>(&enc0, &cipher, &test_iv(), 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_format_structure() {
        let cipher = Aes128Gcm::new(&test_key()).unwrap();
        let plaintext = b"test";

        let wire =
            TlsCiphertext::encrypt(ContentType::ApplicationData, plaintext, &cipher, &test_iv(), 0)
                .unwrap();

        // Check header
        assert_eq!(wire[0], 23); // ApplicationData
        assert_eq!(wire[1], 0x03); // Version high byte
        assert_eq!(wire[2], 0x03); // Version low byte

        // Length field
        let length = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert_eq!(wire.len(), 5 + length);

        // Length should be plaintext + content_type + tag
        assert_eq!(length, plaintext.len() + 1 + Aes128Gcm::TAG_LEN);
    }

    #[test]
    fn test_empty_plaintext() {
        let cipher = Aes128Gcm::new(&test_key()).unwrap();
        let plaintext = b"";

        let encrypted =
            TlsCiphertext::encrypt(ContentType::Alert, plaintext, &cipher, &test_iv(), 0).unwrap();

        let (decrypted, _) =
            TlsCiphertext::decrypt::<Aes128Gcm>(&encrypted, &cipher, &test_iv(), 0).unwrap();

        assert_eq!(decrypted.inner_content_type, ContentType::Alert);
        assert!(decrypted.plaintext.is_empty());
    }
}
