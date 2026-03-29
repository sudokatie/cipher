//! CertificateVerify message (RFC 8446 Section 4.4.3)

use crate::error::TlsError;
use crate::extensions::SignatureScheme;

/// CertificateVerify message
#[derive(Debug, Clone)]
pub struct CertificateVerify {
    /// Signature algorithm used
    pub algorithm: SignatureScheme,
    /// The signature
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// Create a new CertificateVerify message
    pub fn new(algorithm: SignatureScheme, signature: Vec<u8>) -> Self {
        Self {
            algorithm,
            signature,
        }
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 4 {
            return Err(TlsError::Protocol("CertificateVerify too short".into()));
        }

        let algorithm = SignatureScheme::from_u16(u16::from_be_bytes([data[0], data[1]]));

        let sig_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + sig_len {
            return Err(TlsError::Protocol("CertificateVerify truncated".into()));
        }

        let signature = data[4..4 + sig_len].to_vec();

        Ok(Self {
            algorithm,
            signature,
        })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.algorithm.to_u16().to_be_bytes());
        data.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.signature);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_verify() {
        let cv = CertificateVerify::new(SignatureScheme::EcdsaSecp256r1Sha256, vec![1, 2, 3, 4]);
        let encoded = cv.encode();
        let parsed = CertificateVerify::parse(&encoded).unwrap();
        assert_eq!(parsed.algorithm, SignatureScheme::EcdsaSecp256r1Sha256);
        assert_eq!(parsed.signature, vec![1, 2, 3, 4]);
    }
}
