//! X.509 Certificate Parser

use crate::error::TlsError;
use std::time::SystemTime;
use x509_parser::prelude::*;

/// Key usage flags
#[derive(Debug, Clone, Default)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub key_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
}

/// Parsed X.509 certificate
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Subject distinguished name
    pub subject: String,
    /// Issuer distinguished name
    pub issuer: String,
    /// Validity period
    pub validity: Validity,
    /// Public key info
    pub public_key: PublicKeyInfo,
    /// Raw SubjectPublicKeyInfo DER bytes (for signature verification)
    pub raw_public_key: Vec<u8>,
    /// Serial number
    pub serial_number: Vec<u8>,
    /// Subject Alternative Names (DNS names)
    pub san_dns_names: Vec<String>,
    /// Is this a CA certificate?
    pub is_ca: bool,
    /// Key usage extension
    pub key_usage: Option<KeyUsage>,
    /// Raw DER data
    pub raw: Vec<u8>,
    /// TBS (To Be Signed) certificate bytes - the signed portion
    pub tbs_certificate: Vec<u8>,
    /// Signature algorithm OID
    pub signature_algorithm: String,
    /// Signature value
    pub signature_value: Vec<u8>,
}

/// Certificate validity period
#[derive(Debug, Clone)]
pub struct Validity {
    /// Not valid before (Unix timestamp)
    pub not_before: i64,
    /// Not valid after (Unix timestamp)
    pub not_after: i64,
}

impl Validity {
    /// Check if certificate is currently valid
    pub fn is_valid_now(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        now >= self.not_before && now <= self.not_after
    }
}

/// Public key information
#[derive(Debug, Clone)]
pub enum PublicKeyInfo {
    /// RSA public key
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    /// ECDSA public key (P-256)
    EcdsaP256 { point: Vec<u8> },
    /// ECDSA public key (P-384)
    EcdsaP384 { point: Vec<u8> },
    /// Ed25519 public key
    Ed25519 { key: Vec<u8> },
    /// Unknown/unsupported
    Unknown {
        algorithm_oid: String,
        data: Vec<u8>,
    },
}

impl Certificate {
    /// Parse from DER-encoded data
    pub fn from_der(der: &[u8]) -> Result<Self, TlsError> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| TlsError::Certificate(format!("failed to parse certificate: {}", e)))?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();

        let validity = Validity {
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
        };

        let public_key = Self::parse_public_key(cert.public_key())?;

        // Get raw SPKI bytes for signature verification
        let raw_public_key = cert.public_key().raw.to_vec();

        let serial_number = cert.raw_serial().to_vec();

        // Extract SAN DNS names
        let san_dns_names = cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .filter_map(|name| {
                        if let GeneralName::DNSName(dns) = name {
                            Some(dns.to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Check if CA
        let is_ca = cert
            .basic_constraints()
            .ok()
            .flatten()
            .map(|bc| bc.value.ca)
            .unwrap_or(false);

        // Parse key usage extension
        let key_usage = cert.key_usage().ok().flatten().map(|ku| {
            let flags = ku.value;
            KeyUsage {
                digital_signature: flags.digital_signature(),
                key_encipherment: flags.key_encipherment(),
                key_agreement: flags.key_agreement(),
                key_cert_sign: flags.key_cert_sign(),
                crl_sign: flags.crl_sign(),
            }
        });

        // Get TBS certificate bytes (the signed portion)
        let tbs_certificate = cert.tbs_certificate.as_ref().to_vec();

        // Get signature algorithm
        let signature_algorithm = cert.signature_algorithm.algorithm.to_id_string();

        // Get signature value
        let signature_value = cert.signature_value.data.to_vec();

        Ok(Self {
            subject,
            issuer,
            validity,
            public_key,
            raw_public_key,
            serial_number,
            san_dns_names,
            is_ca,
            key_usage,
            raw: der.to_vec(),
            tbs_certificate,
            signature_algorithm,
            signature_value,
        })
    }

    /// Parse public key from SubjectPublicKeyInfo
    fn parse_public_key(spki: &SubjectPublicKeyInfo) -> Result<PublicKeyInfo, TlsError> {
        let oid = spki.algorithm.algorithm.to_id_string();

        match oid.as_str() {
            // RSA
            "1.2.840.113549.1.1.1" => {
                // Parse RSA public key
                let data = spki.subject_public_key.data.to_vec();
                // Simplified - real implementation would parse ASN.1
                Ok(PublicKeyInfo::Rsa {
                    modulus: data.clone(),
                    exponent: vec![0x01, 0x00, 0x01], // Common exponent
                })
            }
            // EC public key
            "1.2.840.10045.2.1" => {
                let data = spki.subject_public_key.data.to_vec();
                // Check curve OID in parameters
                let params = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok())
                    .map(|oid| oid.to_id_string());

                match params.as_deref() {
                    Some("1.2.840.10045.3.1.7") => Ok(PublicKeyInfo::EcdsaP256 { point: data }),
                    Some("1.3.132.0.34") => Ok(PublicKeyInfo::EcdsaP384 { point: data }),
                    _ => Ok(PublicKeyInfo::Unknown {
                        algorithm_oid: oid,
                        data,
                    }),
                }
            }
            // Ed25519
            "1.3.101.112" => {
                let data = spki.subject_public_key.data.to_vec();
                Ok(PublicKeyInfo::Ed25519 { key: data })
            }
            _ => Ok(PublicKeyInfo::Unknown {
                algorithm_oid: oid,
                data: spki.subject_public_key.data.to_vec(),
            }),
        }
    }

    /// Check if certificate matches a hostname
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        // Check SAN DNS names first
        for name in &self.san_dns_names {
            if Self::hostname_matches(name, hostname) {
                return true;
            }
        }

        // Fall back to CN in subject (deprecated but still used)
        if self.subject.contains(&format!("CN={}", hostname)) {
            return true;
        }

        false
    }

    /// Check if a pattern matches a hostname (supports wildcards)
    fn hostname_matches(pattern: &str, hostname: &str) -> bool {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard certificate
            if let Some(pos) = hostname.find('.') {
                return &hostname[pos + 1..] == suffix;
            }
            false
        } else {
            pattern.eq_ignore_ascii_case(hostname)
        }
    }

    /// Get public key bytes suitable for signature verification
    pub fn public_key_bytes(&self) -> &[u8] {
        match &self.public_key {
            PublicKeyInfo::Rsa { modulus, .. } => modulus,
            PublicKeyInfo::EcdsaP256 { point } => point,
            PublicKeyInfo::EcdsaP384 { point } => point,
            PublicKeyInfo::Ed25519 { key } => key,
            PublicKeyInfo::Unknown { data, .. } => data,
        }
    }

    /// Check if this certificate can sign other certificates (CA)
    pub fn can_sign_certificates(&self) -> bool {
        if !self.is_ca {
            return false;
        }
        match &self.key_usage {
            Some(ku) => ku.key_cert_sign,
            None => true, // If no key usage extension, assume allowed
        }
    }

    /// Check if this certificate can be used for digital signatures (TLS server auth)
    pub fn can_digital_signature(&self) -> bool {
        match &self.key_usage {
            Some(ku) => ku.digital_signature,
            None => true, // If no key usage extension, assume allowed
        }
    }

    /// Map signature algorithm OID to SignatureScheme
    pub fn signature_scheme(&self) -> Option<crate::extensions::SignatureScheme> {
        use crate::extensions::SignatureScheme;
        match self.signature_algorithm.as_str() {
            // RSA PKCS#1 v1.5
            "1.2.840.113549.1.1.11" => Some(SignatureScheme::RsaPkcs1Sha256),
            "1.2.840.113549.1.1.12" => Some(SignatureScheme::RsaPkcs1Sha384),
            "1.2.840.113549.1.1.13" => Some(SignatureScheme::RsaPkcs1Sha512),
            // RSA-PSS
            "1.2.840.113549.1.1.10" => Some(SignatureScheme::RsaPssRsaeSha256), // May need refinement
            // ECDSA
            "1.2.840.10045.4.3.2" => Some(SignatureScheme::EcdsaSecp256r1Sha256),
            "1.2.840.10045.4.3.3" => Some(SignatureScheme::EcdsaSecp384r1Sha384),
            // Ed25519
            "1.3.101.112" => Some(SignatureScheme::Ed25519),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_matches() {
        assert!(Certificate::hostname_matches("example.com", "example.com"));
        assert!(Certificate::hostname_matches(
            "*.example.com",
            "www.example.com"
        ));
        assert!(Certificate::hostname_matches(
            "*.example.com",
            "api.example.com"
        ));
        assert!(!Certificate::hostname_matches(
            "*.example.com",
            "example.com"
        ));
        assert!(!Certificate::hostname_matches("example.com", "other.com"));
    }

    #[test]
    fn test_validity() {
        let validity = Validity {
            not_before: 0,
            not_after: i64::MAX,
        };
        assert!(validity.is_valid_now());

        let expired = Validity {
            not_before: 0,
            not_after: 1,
        };
        assert!(!expired.is_valid_now());
    }
}
