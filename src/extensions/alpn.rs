//! Application-Layer Protocol Negotiation (ALPN) extension (RFC 7301)

use crate::error::TlsError;

/// ALPN extension for ClientHello
#[derive(Debug, Clone)]
pub struct AlpnClientHello {
    /// List of protocol names
    pub protocols: Vec<Vec<u8>>,
}

impl AlpnClientHello {
    /// Create a new ALPN extension with the given protocols
    pub fn new(protocols: Vec<Vec<u8>>) -> Self {
        Self { protocols }
    }

    /// Create from string protocol names
    pub fn from_strings(protocols: &[&str]) -> Self {
        Self {
            protocols: protocols.iter().map(|s| s.as_bytes().to_vec()).collect(),
        }
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("ALPN extension too short".into()));
        }

        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + list_len {
            return Err(TlsError::Protocol("ALPN list truncated".into()));
        }

        let mut protocols = Vec::new();
        let mut offset = 2;

        while offset < 2 + list_len {
            if offset >= data.len() {
                return Err(TlsError::Protocol("ALPN protocol truncated".into()));
            }
            let proto_len = data[offset] as usize;
            offset += 1;

            if offset + proto_len > data.len() {
                return Err(TlsError::Protocol("ALPN protocol data truncated".into()));
            }
            protocols.push(data[offset..offset + proto_len].to_vec());
            offset += proto_len;
        }

        Ok(Self { protocols })
    }

    /// Encode to extension data
    pub fn encode(&self) -> Vec<u8> {
        let mut list_data = Vec::new();
        for proto in &self.protocols {
            list_data.push(proto.len() as u8);
            list_data.extend_from_slice(proto);
        }

        let mut data = Vec::with_capacity(2 + list_data.len());
        data.extend_from_slice(&(list_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&list_data);
        data
    }

    /// Check if a protocol is in the list
    pub fn contains(&self, protocol: &[u8]) -> bool {
        self.protocols.iter().any(|p| p == protocol)
    }
}

/// ALPN extension for ServerHello/EncryptedExtensions
#[derive(Debug, Clone)]
pub struct AlpnServerHello {
    /// Selected protocol
    pub protocol: Vec<u8>,
}

impl AlpnServerHello {
    /// Create a new ALPN response
    pub fn new(protocol: Vec<u8>) -> Self {
        Self { protocol }
    }

    /// Create from protocol string
    pub fn from_protocol(protocol: &str) -> Self {
        Self {
            protocol: protocol.as_bytes().to_vec(),
        }
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("ALPN response too short".into()));
        }

        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if list_len < 1 || data.len() < 2 + list_len {
            return Err(TlsError::Protocol("ALPN response invalid".into()));
        }

        let proto_len = data[2] as usize;
        if data.len() < 3 + proto_len {
            return Err(TlsError::Protocol("ALPN protocol truncated".into()));
        }

        Ok(Self {
            protocol: data[3..3 + proto_len].to_vec(),
        })
    }

    /// Encode to extension data
    pub fn encode(&self) -> Vec<u8> {
        let list_len = 1 + self.protocol.len();
        let mut data = Vec::with_capacity(2 + list_len);
        data.extend_from_slice(&(list_len as u16).to_be_bytes());
        data.push(self.protocol.len() as u8);
        data.extend_from_slice(&self.protocol);
        data
    }

    /// Get protocol as string (if valid UTF-8)
    pub fn protocol_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.protocol).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_client_hello() {
        let alpn = AlpnClientHello::from_strings(&["h2", "http/1.1"]);
        assert_eq!(alpn.protocols.len(), 2);

        let encoded = alpn.encode();
        let parsed = AlpnClientHello::parse(&encoded).unwrap();
        assert_eq!(parsed.protocols, alpn.protocols);
    }

    #[test]
    fn test_alpn_server_hello() {
        let alpn = AlpnServerHello::from_protocol("h2");
        assert_eq!(alpn.protocol, b"h2");

        let encoded = alpn.encode();
        let parsed = AlpnServerHello::parse(&encoded).unwrap();
        assert_eq!(parsed.protocol, alpn.protocol);
    }

    #[test]
    fn test_alpn_contains() {
        let alpn = AlpnClientHello::from_strings(&["h2", "http/1.1"]);
        assert!(alpn.contains(b"h2"));
        assert!(alpn.contains(b"http/1.1"));
        assert!(!alpn.contains(b"h3"));
    }
}
