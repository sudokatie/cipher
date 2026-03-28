//! TLS plaintext record handling.

use super::types::{version, ContentType, MAX_FRAGMENT_LENGTH};
use crate::error::TlsError;

/// TLS plaintext record structure.
///
/// ```text
/// struct {
///     ContentType type;
///     ProtocolVersion legacy_record_version;
///     uint16 length;
///     opaque fragment[TLSPlaintext.length];
/// } TLSPlaintext;
/// ```
#[derive(Debug, Clone)]
pub struct TlsPlaintext {
    /// Content type.
    pub content_type: ContentType,
    /// Record version (always 0x0303 for TLS 1.3).
    pub legacy_version: u16,
    /// Fragment data.
    pub fragment: Vec<u8>,
}

impl TlsPlaintext {
    /// Create a new plaintext record.
    pub fn new(content_type: ContentType, fragment: Vec<u8>) -> Result<Self, TlsError> {
        if fragment.len() > MAX_FRAGMENT_LENGTH {
            return Err(TlsError::Protocol(format!(
                "fragment too large: {} > {}",
                fragment.len(),
                MAX_FRAGMENT_LENGTH
            )));
        }

        Ok(TlsPlaintext {
            content_type,
            legacy_version: version::TLS12,
            fragment,
        })
    }

    /// Parse a plaintext record from bytes.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), TlsError> {
        if data.len() < 5 {
            return Err(TlsError::Protocol("record header too short".into()));
        }

        let content_type = ContentType::from_u8(data[0])
            .ok_or_else(|| TlsError::Protocol(format!("unknown content type: {}", data[0])))?;

        let legacy_version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if length > MAX_FRAGMENT_LENGTH {
            return Err(TlsError::Protocol(format!(
                "record too large: {} > {}",
                length, MAX_FRAGMENT_LENGTH
            )));
        }

        if data.len() < 5 + length {
            return Err(TlsError::Protocol("record data truncated".into()));
        }

        let fragment = data[5..5 + length].to_vec();

        Ok((
            TlsPlaintext {
                content_type,
                legacy_version,
                fragment,
            },
            5 + length,
        ))
    }

    /// Serialize the record to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(5 + self.fragment.len());
        data.push(self.content_type.to_u8());
        data.extend_from_slice(&self.legacy_version.to_be_bytes());
        data.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.fragment);
        data
    }

    /// Get the total length of the serialized record.
    pub fn wire_length(&self) -> usize {
        5 + self.fragment.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_record_creation() {
        let record = TlsPlaintext::new(ContentType::Handshake, vec![1, 2, 3]).unwrap();
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.legacy_version, 0x0303);
        assert_eq!(record.fragment, vec![1, 2, 3]);
    }

    #[test]
    fn test_plaintext_record_serialization() {
        let record = TlsPlaintext::new(ContentType::Handshake, vec![0x01, 0x02, 0x03]).unwrap();
        let serialized = record.serialize();

        assert_eq!(serialized[0], 22); // Handshake
        assert_eq!(serialized[1], 0x03); // Version high
        assert_eq!(serialized[2], 0x03); // Version low
        assert_eq!(serialized[3], 0x00); // Length high
        assert_eq!(serialized[4], 0x03); // Length low
        assert_eq!(&serialized[5..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_plaintext_record_parsing() {
        let data = [22, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let (record, len) = TlsPlaintext::parse(&data).unwrap();

        assert_eq!(len, 8);
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.fragment, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_max_fragment_enforced() {
        let large_fragment = vec![0u8; MAX_FRAGMENT_LENGTH + 1];
        let result = TlsPlaintext::new(ContentType::ApplicationData, large_fragment);
        assert!(result.is_err());
    }
}
