//! TLS Server Configuration

use crate::error::TlsError;
use crate::extensions::SignatureScheme;

/// TLS server configuration
#[derive(Clone)]
pub struct TlsServerConfig {
    /// Certificate chain (DER-encoded, leaf first)
    pub certificate_chain: Vec<Vec<u8>>,
    /// Private key (DER-encoded PKCS#8)
    pub private_key: Vec<u8>,
    /// Signature scheme to use
    pub signature_scheme: SignatureScheme,
    /// Application-layer protocol negotiation
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Require client certificate
    pub require_client_auth: bool,
}

impl TlsServerConfig {
    /// Create a new config builder
    pub fn builder() -> TlsServerConfigBuilder {
        TlsServerConfigBuilder::new()
    }
}

/// Builder for TlsServerConfig
pub struct TlsServerConfigBuilder {
    certificate_chain: Option<Vec<Vec<u8>>>,
    private_key: Option<Vec<u8>>,
    signature_scheme: SignatureScheme,
    alpn_protocols: Vec<Vec<u8>>,
    require_client_auth: bool,
}

impl TlsServerConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            certificate_chain: None,
            private_key: None,
            signature_scheme: SignatureScheme::EcdsaSecp256r1Sha256,
            alpn_protocols: Vec::new(),
            require_client_auth: false,
        }
    }

    /// Set certificate chain (PEM or DER)
    pub fn set_certificate_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.certificate_chain = Some(chain);
        self
    }

    /// Set private key
    pub fn set_private_key(mut self, key: Vec<u8>) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Set signature scheme
    pub fn set_signature_scheme(mut self, scheme: SignatureScheme) -> Self {
        self.signature_scheme = scheme;
        self
    }

    /// Set ALPN protocols
    pub fn set_alpn_protocols(mut self, protocols: Vec<&str>) -> Self {
        self.alpn_protocols = protocols
            .into_iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();
        self
    }

    /// Require client authentication
    pub fn require_client_auth(mut self) -> Self {
        self.require_client_auth = true;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<TlsServerConfig, TlsError> {
        let certificate_chain = self
            .certificate_chain
            .ok_or_else(|| TlsError::Config("certificate chain required".into()))?;
        let private_key = self
            .private_key
            .ok_or_else(|| TlsError::Config("private key required".into()))?;

        Ok(TlsServerConfig {
            certificate_chain,
            private_key,
            signature_scheme: self.signature_scheme,
            alpn_protocols: self.alpn_protocols,
            require_client_auth: self.require_client_auth,
        })
    }
}

impl Default for TlsServerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
