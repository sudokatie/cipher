//! X.509 Certificate handling for TLS 1.3

mod parser;
mod validator;

pub use parser::{Certificate, PublicKeyInfo, Validity};
pub use validator::{CertificateValidator, TrustAnchor, ValidationError};

use crate::error::TlsError;

/// Parse a DER-encoded X.509 certificate
pub fn parse_certificate(der: &[u8]) -> Result<Certificate, TlsError> {
    Certificate::from_der(der)
}

/// Validate a certificate chain
pub fn validate_chain(
    chain: &[Vec<u8>],
    server_name: Option<&str>,
    trust_anchors: &[TrustAnchor],
) -> Result<(), TlsError> {
    let validator = CertificateValidator::new(trust_anchors);
    validator.validate_chain(chain, server_name)
}
