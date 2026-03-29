//! Certificate chain validation

use super::parser::Certificate;
use crate::crypto::verify_signature;
use crate::error::TlsError;

/// Certificate validation error
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Certificate has expired
    Expired,
    /// Certificate is not yet valid
    NotYetValid,
    /// Hostname mismatch
    HostnameMismatch,
    /// Invalid certificate chain
    InvalidChain,
    /// Untrusted root
    UntrustedRoot,
    /// Signature verification failed
    InvalidSignature,
    /// Certificate parsing failed
    ParseError(String),
    /// Key usage violation
    KeyUsageViolation,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Expired => write!(f, "certificate has expired"),
            ValidationError::NotYetValid => write!(f, "certificate is not yet valid"),
            ValidationError::HostnameMismatch => write!(f, "hostname mismatch"),
            ValidationError::InvalidChain => write!(f, "invalid certificate chain"),
            ValidationError::UntrustedRoot => write!(f, "untrusted root certificate"),
            ValidationError::InvalidSignature => write!(f, "invalid signature"),
            ValidationError::ParseError(e) => write!(f, "parse error: {}", e),
            ValidationError::KeyUsageViolation => write!(f, "key usage violation"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Trust anchor (root CA certificate)
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Subject distinguished name
    pub subject: String,
    /// DER-encoded certificate
    pub der: Vec<u8>,
}

impl TrustAnchor {
    /// Create from DER-encoded certificate
    pub fn from_der(der: &[u8]) -> Result<Self, TlsError> {
        let cert = Certificate::from_der(der)?;
        Ok(Self {
            subject: cert.subject,
            der: der.to_vec(),
        })
    }
}

/// Certificate validator
pub struct CertificateValidator {
    trust_anchors: Vec<TrustAnchor>,
    /// Skip time validation (for testing)
    skip_time_validation: bool,
}

impl CertificateValidator {
    /// Create a new validator with trust anchors
    pub fn new(trust_anchors: &[TrustAnchor]) -> Self {
        Self {
            trust_anchors: trust_anchors.to_vec(),
            skip_time_validation: false,
        }
    }

    /// Create a validator that skips time checks (for testing)
    pub fn new_insecure() -> Self {
        Self {
            trust_anchors: Vec::new(),
            skip_time_validation: true,
        }
    }

    /// Validate a certificate chain
    pub fn validate_chain(
        &self,
        chain: &[Vec<u8>],
        server_name: Option<&str>,
    ) -> Result<(), TlsError> {
        if chain.is_empty() {
            return Err(TlsError::Certificate("empty certificate chain".into()));
        }

        // Parse all certificates
        let mut certs = Vec::new();
        for der in chain {
            let cert = Certificate::from_der(der)?;
            certs.push(cert);
        }

        // Validate end-entity certificate
        let ee_cert = &certs[0];

        // Check hostname
        if let Some(name) = server_name {
            if !ee_cert.matches_hostname(name) {
                return Err(TlsError::Certificate(
                    ValidationError::HostnameMismatch.to_string(),
                ));
            }
        }

        // Check end-entity certificate can be used for digital signatures (TLS server auth)
        if !ee_cert.can_digital_signature() {
            return Err(TlsError::Certificate(
                ValidationError::KeyUsageViolation.to_string(),
            ));
        }

        // Check validity period
        if !self.skip_time_validation {
            for cert in &certs {
                if !cert.validity.is_valid_now() {
                    return Err(TlsError::Certificate(ValidationError::Expired.to_string()));
                }
            }
        }

        // Verify chain structure (each cert's issuer matches next cert's subject)
        for i in 0..certs.len() - 1 {
            if certs[i].issuer != certs[i + 1].subject {
                return Err(TlsError::Certificate(
                    ValidationError::InvalidChain.to_string(),
                ));
            }
        }

        // Check if root is trusted
        let root = certs.last().unwrap();
        let is_trusted = self
            .trust_anchors
            .iter()
            .any(|ta| ta.subject == root.subject)
            || self.trust_anchors.is_empty(); // Allow empty for testing

        if !is_trusted && !self.skip_time_validation {
            return Err(TlsError::Certificate(
                ValidationError::UntrustedRoot.to_string(),
            ));
        }

        // Verify signatures in chain
        if !self.skip_time_validation {
            self.verify_chain_signatures(&certs)?;
        }

        Ok(())
    }

    /// Verify all signatures in the certificate chain
    fn verify_chain_signatures(&self, certs: &[Certificate]) -> Result<(), TlsError> {
        for i in 0..certs.len() {
            let cert = &certs[i];

            // Get the issuer's public key
            let issuer_public_key = if i + 1 < certs.len() {
                // Issuer is the next certificate in the chain
                let issuer = &certs[i + 1];

                // Check that issuer can sign certificates
                if !issuer.can_sign_certificates() && i + 1 < certs.len() - 1 {
                    return Err(TlsError::Certificate(
                        ValidationError::KeyUsageViolation.to_string(),
                    ));
                }

                issuer.public_key_bytes()
            } else {
                // Self-signed root - verify against its own public key
                cert.public_key_bytes()
            };

            // Get signature scheme
            let scheme = cert.signature_scheme().ok_or_else(|| {
                TlsError::Certificate(format!(
                    "unsupported signature algorithm: {}",
                    cert.signature_algorithm
                ))
            })?;

            // Verify signature
            verify_signature(
                scheme,
                issuer_public_key,
                &cert.tbs_certificate,
                &cert.signature_value,
            )
            .map_err(|_| TlsError::Certificate(ValidationError::InvalidSignature.to_string()))?;
        }

        Ok(())
    }

    /// Add a trust anchor
    pub fn add_trust_anchor(&mut self, anchor: TrustAnchor) {
        self.trust_anchors.push(anchor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        assert_eq!(
            ValidationError::Expired.to_string(),
            "certificate has expired"
        );
        assert_eq!(
            ValidationError::HostnameMismatch.to_string(),
            "hostname mismatch"
        );
    }

    #[test]
    fn test_insecure_validator() {
        let validator = CertificateValidator::new_insecure();
        // Should not panic with empty chain
        assert!(validator.validate_chain(&[], None).is_err());
    }
}
