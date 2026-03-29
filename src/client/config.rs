//! TLS Client Configuration

use crate::cert::TrustAnchor;
use crate::error::TlsError;

/// TLS client configuration
#[derive(Clone, Default)]
pub struct TlsClientConfig {
    /// Root certificates for validation
    pub root_certificates: Vec<TrustAnchor>,
    /// Skip certificate validation (INSECURE - for testing only)
    pub danger_skip_verification: bool,
    /// Application-layer protocol negotiation
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl TlsClientConfig {
    /// Create a new config builder
    pub fn builder() -> TlsClientConfigBuilder {
        TlsClientConfigBuilder::new()
    }
}

/// Builder for TlsClientConfig
pub struct TlsClientConfigBuilder {
    config: TlsClientConfig,
}

impl TlsClientConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: TlsClientConfig::default(),
        }
    }

    /// Add root certificates
    pub fn set_root_certificates(mut self, certs: Vec<TrustAnchor>) -> Self {
        self.config.root_certificates = certs;
        self
    }

    /// Add a single root certificate
    pub fn add_root_certificate(mut self, cert: TrustAnchor) -> Self {
        self.config.root_certificates.push(cert);
        self
    }

    /// Skip certificate verification (DANGEROUS - testing only)
    pub fn danger_skip_verification(mut self) -> Self {
        self.config.danger_skip_verification = true;
        self
    }

    /// Set ALPN protocols
    pub fn set_alpn_protocols(mut self, protocols: Vec<&str>) -> Self {
        self.config.alpn_protocols = protocols
            .into_iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<TlsClientConfig, TlsError> {
        Ok(self.config)
    }
}

impl Default for TlsClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = TlsClientConfig::builder()
            .danger_skip_verification()
            .set_alpn_protocols(vec!["h2", "http/1.1"])
            .build()
            .unwrap();

        assert!(config.danger_skip_verification);
        assert_eq!(config.alpn_protocols.len(), 2);
    }
}
