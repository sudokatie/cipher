//! Finished message (RFC 8446 Section 4.4.4)

use crate::error::TlsError;
use hmac::{Hmac, Mac};
use sha2::Sha256 as Sha256Impl;

type HmacSha256 = Hmac<Sha256Impl>;

/// Finished message
#[derive(Debug, Clone)]
pub struct Finished {
    /// The verify data
    pub verify_data: Vec<u8>,
}

impl Finished {
    /// Create a new Finished message
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self { verify_data }
    }

    /// Compute the verify_data for a Finished message
    pub fn compute_verify_data(finished_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(finished_key).expect("HMAC can take key of any size");
        mac.update(transcript_hash);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify the finished message
    pub fn verify(&self, finished_key: &[u8], transcript_hash: &[u8]) -> bool {
        let expected = Self::compute_verify_data(finished_key, transcript_hash);
        self.verify_data == expected
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        // Verify data length depends on hash algorithm
        // For SHA-256: 32 bytes, SHA-384: 48 bytes
        if data.is_empty() {
            return Err(TlsError::Protocol("Finished message empty".into()));
        }

        Ok(Self {
            verify_data: data.to_vec(),
        })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        self.verify_data.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finished_compute_verify() {
        let key = [0u8; 32];
        let hash = [1u8; 32];

        let verify_data = Finished::compute_verify_data(&key, &hash);
        assert_eq!(verify_data.len(), 32);

        let finished = Finished::new(verify_data);
        assert!(finished.verify(&key, &hash));
    }

    #[test]
    fn test_finished_encode_parse() {
        let finished = Finished::new(vec![1, 2, 3, 4, 5]);
        let encoded = finished.encode();
        let parsed = Finished::parse(&encoded).unwrap();
        assert_eq!(parsed.verify_data, vec![1, 2, 3, 4, 5]);
    }
}
