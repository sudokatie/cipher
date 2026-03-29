//! EncryptedExtensions message (RFC 8446 Section 4.3.1)

use crate::error::TlsError;
use crate::extensions::{encode_extensions, parse_extensions, Extension};

/// EncryptedExtensions message
#[derive(Debug, Clone)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,
}

impl EncryptedExtensions {
    /// Create a new EncryptedExtensions message
    pub fn new(extensions: Vec<Extension>) -> Self {
        Self { extensions }
    }

    /// Create an empty EncryptedExtensions
    pub fn empty() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("EncryptedExtensions too short".into()));
        }

        let ext_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + ext_len {
            return Err(TlsError::Protocol("EncryptedExtensions truncated".into()));
        }

        let extensions = parse_extensions(&data[2..2 + ext_len])?;
        Ok(Self { extensions })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let ext_data = encode_extensions(&self.extensions);
        let mut data = Vec::new();
        data.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext_data);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_extensions_empty() {
        let ee = EncryptedExtensions::empty();
        let encoded = ee.encode();
        assert_eq!(encoded, vec![0, 0]);

        let parsed = EncryptedExtensions::parse(&encoded).unwrap();
        assert!(parsed.extensions.is_empty());
    }
}
