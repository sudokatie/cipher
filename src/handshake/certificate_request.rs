//! CertificateRequest message (RFC 8446 Section 4.3.2)
//!
//! Sent by the server to request client certificate authentication.

use crate::error::TlsError;
use crate::extensions::{encode_extensions, parse_extensions, Extension, SignatureAlgorithms};

/// CertificateRequest message
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// Certificate request context (opaque, 0-255 bytes)
    pub certificate_request_context: Vec<u8>,
    /// Extensions (must include signature_algorithms)
    pub extensions: Vec<Extension>,
}

impl CertificateRequest {
    /// Create a new CertificateRequest
    pub fn new(context: Vec<u8>, extensions: Vec<Extension>) -> Self {
        Self {
            certificate_request_context: context,
            extensions,
        }
    }

    /// Create a basic CertificateRequest with default signature algorithms
    pub fn basic() -> Self {
        Self {
            certificate_request_context: Vec::new(),
            extensions: vec![Extension::SignatureAlgorithms(
                SignatureAlgorithms::default_algorithms(),
            )],
        }
    }

    /// Get the signature algorithms from extensions
    pub fn signature_algorithms(&self) -> Option<&SignatureAlgorithms> {
        for ext in &self.extensions {
            if let Extension::SignatureAlgorithms(sa) = ext {
                return Some(sa);
            }
        }
        None
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.is_empty() {
            return Err(TlsError::Protocol("CertificateRequest too short".into()));
        }

        let context_len = data[0] as usize;
        if data.len() < 1 + context_len + 2 {
            return Err(TlsError::Protocol("CertificateRequest truncated".into()));
        }

        let certificate_request_context = data[1..1 + context_len].to_vec();
        let offset = 1 + context_len;

        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        if data.len() < offset + 2 + ext_len {
            return Err(TlsError::Protocol(
                "CertificateRequest extensions truncated".into(),
            ));
        }

        let extensions = parse_extensions(&data[offset + 2..offset + 2 + ext_len])?;

        Ok(Self {
            certificate_request_context,
            extensions,
        })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let ext_data = encode_extensions(&self.extensions);

        let mut data = Vec::new();
        data.push(self.certificate_request_context.len() as u8);
        data.extend_from_slice(&self.certificate_request_context);
        data.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext_data);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_request_basic() {
        let cr = CertificateRequest::basic();
        assert!(cr.certificate_request_context.is_empty());
        assert!(cr.signature_algorithms().is_some());
    }

    #[test]
    fn test_certificate_request_encode_parse() {
        let cr = CertificateRequest::basic();
        let encoded = cr.encode();
        let parsed = CertificateRequest::parse(&encoded).unwrap();

        assert_eq!(
            parsed.certificate_request_context,
            cr.certificate_request_context
        );
        assert!(parsed.signature_algorithms().is_some());
    }

    #[test]
    fn test_certificate_request_with_context() {
        let cr = CertificateRequest::new(
            vec![1, 2, 3, 4],
            vec![Extension::SignatureAlgorithms(
                SignatureAlgorithms::default_algorithms(),
            )],
        );

        let encoded = cr.encode();
        let parsed = CertificateRequest::parse(&encoded).unwrap();

        assert_eq!(parsed.certificate_request_context, vec![1, 2, 3, 4]);
    }
}
