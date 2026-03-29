//! Supported Versions Extension (RFC 8446 Section 4.2.1)

use crate::error::TlsError;

/// TLS 1.3 version constant
pub const TLS_1_3: u16 = 0x0304;
/// TLS 1.2 version constant (kept for future compatibility)
#[allow(dead_code)]
pub const TLS_1_2: u16 = 0x0303;

/// Supported Versions extension
#[derive(Debug, Clone)]
pub enum SupportedVersions {
    /// Client hello format (list of versions)
    ClientHello(Vec<u16>),
    /// Server hello format (single selected version)
    ServerHello(u16),
}

impl SupportedVersions {
    /// Create for client hello with TLS 1.3
    pub fn client_hello() -> Self {
        SupportedVersions::ClientHello(vec![TLS_1_3])
    }

    /// Create for server hello with TLS 1.3
    pub fn server_hello() -> Self {
        SupportedVersions::ServerHello(TLS_1_3)
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.is_empty() {
            return Err(TlsError::Protocol("empty supported_versions".into()));
        }

        // Server hello: just 2 bytes (selected version)
        if data.len() == 2 {
            let version = u16::from_be_bytes([data[0], data[1]]);
            return Ok(SupportedVersions::ServerHello(version));
        }

        // Client hello: length byte + version list
        let len = data[0] as usize;
        if len + 1 != data.len() || !len.is_multiple_of(2) {
            return Err(TlsError::Protocol(
                "invalid supported_versions length".into(),
            ));
        }

        let mut versions = Vec::new();
        for i in (1..=len).step_by(2) {
            let version = u16::from_be_bytes([data[i], data[i + 1]]);
            versions.push(version);
        }

        Ok(SupportedVersions::ClientHello(versions))
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SupportedVersions::ClientHello(versions) => {
                let mut data = vec![(versions.len() * 2) as u8];
                for v in versions {
                    data.extend_from_slice(&v.to_be_bytes());
                }
                data
            }
            SupportedVersions::ServerHello(version) => version.to_be_bytes().to_vec(),
        }
    }

    /// Check if TLS 1.3 is supported
    pub fn supports_tls_1_3(&self) -> bool {
        match self {
            SupportedVersions::ClientHello(versions) => versions.contains(&TLS_1_3),
            SupportedVersions::ServerHello(version) => *version == TLS_1_3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello() {
        let sv = SupportedVersions::client_hello();
        assert!(sv.supports_tls_1_3());

        let encoded = sv.encode();
        let parsed = SupportedVersions::parse(&encoded).unwrap();
        assert!(parsed.supports_tls_1_3());
    }

    #[test]
    fn test_server_hello() {
        let sv = SupportedVersions::server_hello();
        let encoded = sv.encode();
        assert_eq!(encoded, vec![0x03, 0x04]);

        let parsed = SupportedVersions::parse(&encoded).unwrap();
        assert!(parsed.supports_tls_1_3());
    }
}
