//! Signature Algorithms Extension (RFC 8446 Section 4.2.3)

use crate::error::TlsError;

/// Signature schemes (RFC 8446 Section 4.2.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SignatureScheme {
    // RSASSA-PKCS1-v1_5
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,

    // ECDSA
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,

    // RSASSA-PSS with public key OID rsaEncryption
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,

    // EdDSA
    Ed25519 = 0x0807,
    Ed448 = 0x0808,

    // RSASSA-PSS with public key OID RSASSA-PSS
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,

    // Legacy (SHA-1)
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,

    Unknown(u16),
}

impl SignatureScheme {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0401 => SignatureScheme::RsaPkcs1Sha256,
            0x0501 => SignatureScheme::RsaPkcs1Sha384,
            0x0601 => SignatureScheme::RsaPkcs1Sha512,
            0x0403 => SignatureScheme::EcdsaSecp256r1Sha256,
            0x0503 => SignatureScheme::EcdsaSecp384r1Sha384,
            0x0603 => SignatureScheme::EcdsaSecp521r1Sha512,
            0x0804 => SignatureScheme::RsaPssRsaeSha256,
            0x0805 => SignatureScheme::RsaPssRsaeSha384,
            0x0806 => SignatureScheme::RsaPssRsaeSha512,
            0x0807 => SignatureScheme::Ed25519,
            0x0808 => SignatureScheme::Ed448,
            0x0809 => SignatureScheme::RsaPssPssSha256,
            0x080a => SignatureScheme::RsaPssPssSha384,
            0x080b => SignatureScheme::RsaPssPssSha512,
            0x0201 => SignatureScheme::RsaPkcs1Sha1,
            0x0203 => SignatureScheme::EcdsaSha1,
            v => SignatureScheme::Unknown(v),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => 0x0401,
            SignatureScheme::RsaPkcs1Sha384 => 0x0501,
            SignatureScheme::RsaPkcs1Sha512 => 0x0601,
            SignatureScheme::EcdsaSecp256r1Sha256 => 0x0403,
            SignatureScheme::EcdsaSecp384r1Sha384 => 0x0503,
            SignatureScheme::EcdsaSecp521r1Sha512 => 0x0603,
            SignatureScheme::RsaPssRsaeSha256 => 0x0804,
            SignatureScheme::RsaPssRsaeSha384 => 0x0805,
            SignatureScheme::RsaPssRsaeSha512 => 0x0806,
            SignatureScheme::Ed25519 => 0x0807,
            SignatureScheme::Ed448 => 0x0808,
            SignatureScheme::RsaPssPssSha256 => 0x0809,
            SignatureScheme::RsaPssPssSha384 => 0x080a,
            SignatureScheme::RsaPssPssSha512 => 0x080b,
            SignatureScheme::RsaPkcs1Sha1 => 0x0201,
            SignatureScheme::EcdsaSha1 => 0x0203,
            SignatureScheme::Unknown(v) => v,
        }
    }
}

/// Signature Algorithms extension
#[derive(Debug, Clone)]
pub struct SignatureAlgorithms {
    pub algorithms: Vec<SignatureScheme>,
}

impl SignatureAlgorithms {
    /// Create with default TLS 1.3 algorithms
    pub fn default_algorithms() -> Self {
        Self {
            algorithms: vec![
                SignatureScheme::EcdsaSecp256r1Sha256,
                SignatureScheme::EcdsaSecp384r1Sha384,
                SignatureScheme::RsaPssRsaeSha256,
                SignatureScheme::RsaPssRsaeSha384,
                SignatureScheme::RsaPssRsaeSha512,
                SignatureScheme::Ed25519,
                SignatureScheme::RsaPkcs1Sha256,
                SignatureScheme::RsaPkcs1Sha384,
                SignatureScheme::RsaPkcs1Sha512,
            ],
        }
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("signature_algorithms too short".into()));
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if len + 2 != data.len() || !len.is_multiple_of(2) {
            return Err(TlsError::Protocol(
                "invalid signature_algorithms length".into(),
            ));
        }

        let mut algorithms = Vec::new();
        for i in (2..2 + len).step_by(2) {
            let scheme = u16::from_be_bytes([data[i], data[i + 1]]);
            algorithms.push(SignatureScheme::from_u16(scheme));
        }

        Ok(Self { algorithms })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let len = (self.algorithms.len() * 2) as u16;
        let mut data = len.to_be_bytes().to_vec();
        for alg in &self.algorithms {
            data.extend_from_slice(&alg.to_u16().to_be_bytes());
        }
        data
    }

    /// Check if a scheme is supported
    pub fn supports(&self, scheme: SignatureScheme) -> bool {
        self.algorithms.contains(&scheme)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_algorithms() {
        let sa = SignatureAlgorithms::default_algorithms();
        assert!(sa.supports(SignatureScheme::EcdsaSecp256r1Sha256));
        assert!(sa.supports(SignatureScheme::Ed25519));
    }

    #[test]
    fn test_encode_parse() {
        let sa = SignatureAlgorithms::default_algorithms();
        let encoded = sa.encode();
        let parsed = SignatureAlgorithms::parse(&encoded).unwrap();
        assert_eq!(sa.algorithms.len(), parsed.algorithms.len());
    }
}
