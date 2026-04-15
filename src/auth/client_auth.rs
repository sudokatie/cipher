//! Client certificate authentication.

use x509_parser::prelude::*;
use std::collections::HashSet;

use crate::cert::{CertificateValidator, TrustAnchor};

/// Result of client authentication.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Client authenticated successfully.
    Authenticated(ClientIdentity),
    /// Client provided no certificate (anonymous).
    Anonymous,
    /// Client certificate validation failed.
    Failed(String),
}

impl AuthResult {
    /// Check if authentication succeeded.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }

    /// Check if client is anonymous (no cert provided).
    pub fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous)
    }

    /// Get the client identity if authenticated.
    pub fn identity(&self) -> Option<&ClientIdentity> {
        match self {
            Self::Authenticated(id) => Some(id),
            _ => None,
        }
    }
}

/// Client identity extracted from certificate.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// Common Name (CN) from subject.
    pub common_name: Option<String>,
    /// Organization (O) from subject.
    pub organization: Option<String>,
    /// Organizational Unit (OU) from subject.
    pub organizational_unit: Option<String>,
    /// Subject Alternative Names (DNS names).
    pub dns_names: Vec<String>,
    /// Subject Alternative Names (email addresses).
    pub email_addresses: Vec<String>,
    /// Certificate serial number (hex).
    pub serial_number: String,
    /// Certificate fingerprint (SHA-256, hex).
    pub fingerprint: String,
    /// Issuer Common Name.
    pub issuer_cn: Option<String>,
}

impl ClientIdentity {
    /// Extract identity from a parsed certificate.
    pub fn from_certificate(cert: &X509Certificate<'_>) -> Self {
        let subject = cert.subject();
        let issuer = cert.issuer();

        // Extract subject attributes
        let common_name = subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());

        let organization = subject
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok())
            .map(|s| s.to_string());

        let organizational_unit = subject
            .iter_organizational_unit()
            .next()
            .and_then(|ou| ou.as_str().ok())
            .map(|s| s.to_string());

        let issuer_cn = issuer
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());

        // Extract SANs
        let mut dns_names = Vec::new();
        let mut email_addresses = Vec::new();

        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        dns_names.push(dns.to_string());
                    }
                    GeneralName::RFC822Name(email) => {
                        email_addresses.push(email.to_string());
                    }
                    _ => {}
                }
            }
        }

        // Serial number as hex
        let serial_number = cert
            .serial
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        // Fingerprint (SHA-256 of DER)
        use sha2::{Sha256, Digest};
        let raw_der = cert.as_ref();
        let mut hasher = Sha256::new();
        hasher.update(raw_der);
        let fingerprint = hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        Self {
            common_name,
            organization,
            organizational_unit,
            dns_names,
            email_addresses,
            serial_number,
            fingerprint,
            issuer_cn,
        }
    }

    /// Check if identity matches a pattern (supports wildcards).
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        // Check CN
        if let Some(ref cn) = self.common_name {
            if pattern_matches(pattern, cn) {
                return true;
            }
        }

        // Check DNS names
        for dns in &self.dns_names {
            if pattern_matches(pattern, dns) {
                return true;
            }
        }

        // Check email addresses
        for email in &self.email_addresses {
            if pattern_matches(pattern, email) {
                return true;
            }
        }

        false
    }
}

/// Simple pattern matching with wildcard support.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: *.example.com matches foo.example.com but not example.com
        // The value must have at least one dot, and the part after the first dot must match the suffix
        if let Some(dot_pos) = value.find('.') {
            let value_suffix = &value[dot_pos + 1..];
            return value_suffix == suffix;
        }
        return false;
    }

    pattern == value
}

/// Client certificate authenticator.
pub struct ClientAuthenticator {
    /// Trusted CA certificates.
    trust_anchors: Vec<TrustAnchor>,
    /// Whether to allow anonymous clients.
    allow_anonymous: bool,
    /// Allowed certificate fingerprints (if set, only these are allowed).
    allowed_fingerprints: Option<HashSet<String>>,
    /// Revoked certificate serial numbers.
    revoked_serials: HashSet<String>,
}

impl ClientAuthenticator {
    /// Create a new authenticator with trusted CAs.
    pub fn new(trust_anchors: Vec<TrustAnchor>) -> Self {
        Self {
            trust_anchors,
            allow_anonymous: false,
            allowed_fingerprints: None,
            revoked_serials: HashSet::new(),
        }
    }

    /// Allow anonymous clients (no certificate).
    pub fn with_anonymous_allowed(mut self) -> Self {
        self.allow_anonymous = true;
        self
    }

    /// Only allow specific certificate fingerprints.
    pub fn with_allowed_fingerprints(mut self, fingerprints: Vec<String>) -> Self {
        self.allowed_fingerprints = Some(fingerprints.into_iter().collect());
        self
    }

    /// Add a revoked certificate serial number.
    pub fn revoke_serial(&mut self, serial: impl Into<String>) {
        self.revoked_serials.insert(serial.into());
    }

    /// Authenticate a client certificate chain.
    pub fn authenticate(&self, cert_chain: &[Vec<u8>]) -> AuthResult {
        // Handle no certificate case
        if cert_chain.is_empty() {
            return if self.allow_anonymous {
                AuthResult::Anonymous
            } else {
                AuthResult::Failed("client certificate required".to_string())
            };
        }

        // Parse the leaf certificate
        let leaf_der = &cert_chain[0];
        let (_, leaf_cert) = match X509Certificate::from_der(leaf_der) {
            Ok(cert) => cert,
            Err(e) => {
                return AuthResult::Failed(format!("failed to parse certificate: {:?}", e));
            }
        };

        // Extract identity
        let identity = ClientIdentity::from_certificate(&leaf_cert);

        // Check if certificate is revoked
        if self.revoked_serials.contains(&identity.serial_number) {
            return AuthResult::Failed("certificate has been revoked".to_string());
        }

        // Check fingerprint allowlist
        if let Some(ref allowed) = self.allowed_fingerprints {
            if !allowed.contains(&identity.fingerprint) {
                return AuthResult::Failed("certificate not in allowlist".to_string());
            }
        }

        // Validate certificate chain
        let validator = CertificateValidator::new(&self.trust_anchors);

        if let Err(e) = validator.validate_chain(cert_chain, None) {
            return AuthResult::Failed(format!("certificate validation failed: {:?}", e));
        }

        AuthResult::Authenticated(identity)
    }

    /// Get the trust anchors.
    pub fn trust_anchors(&self) -> &[TrustAnchor] {
        &self.trust_anchors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_result_methods() {
        let identity = ClientIdentity {
            common_name: Some("test".to_string()),
            organization: None,
            organizational_unit: None,
            dns_names: vec![],
            email_addresses: vec![],
            serial_number: "1234".to_string(),
            fingerprint: "abcd".to_string(),
            issuer_cn: None,
        };

        let auth = AuthResult::Authenticated(identity.clone());
        assert!(auth.is_authenticated());
        assert!(!auth.is_anonymous());
        assert!(auth.identity().is_some());

        let anon = AuthResult::Anonymous;
        assert!(!anon.is_authenticated());
        assert!(anon.is_anonymous());
        assert!(anon.identity().is_none());

        let failed = AuthResult::Failed("test".to_string());
        assert!(!failed.is_authenticated());
        assert!(!failed.is_anonymous());
    }

    #[test]
    fn test_pattern_matching() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("test.com", "test.com"));
        assert!(!pattern_matches("test.com", "other.com"));
        assert!(pattern_matches("*.example.com", "foo.example.com"));
        assert!(!pattern_matches("*.example.com", "example.com"));
    }

    #[test]
    fn test_identity_matches_pattern() {
        let identity = ClientIdentity {
            common_name: Some("client.example.com".to_string()),
            organization: None,
            organizational_unit: None,
            dns_names: vec!["alt.example.com".to_string()],
            email_addresses: vec!["user@example.com".to_string()],
            serial_number: "1234".to_string(),
            fingerprint: "abcd".to_string(),
            issuer_cn: None,
        };

        assert!(identity.matches_pattern("client.example.com"));
        assert!(identity.matches_pattern("alt.example.com"));
        assert!(identity.matches_pattern("user@example.com"));
        assert!(identity.matches_pattern("*"));
        assert!(!identity.matches_pattern("other.com"));
    }

    #[test]
    fn test_authenticator_no_cert_required() {
        let auth = ClientAuthenticator::new(vec![]).with_anonymous_allowed();
        let result = auth.authenticate(&[]);
        assert!(result.is_anonymous());
    }

    #[test]
    fn test_authenticator_no_cert_denied() {
        let auth = ClientAuthenticator::new(vec![]);
        let result = auth.authenticate(&[]);
        assert!(!result.is_authenticated());
        assert!(!result.is_anonymous());
    }

    #[test]
    fn test_revoked_serial() {
        let mut auth = ClientAuthenticator::new(vec![]);
        auth.revoke_serial("1234abcd");
        assert!(auth.revoked_serials.contains("1234abcd"));
    }
}
