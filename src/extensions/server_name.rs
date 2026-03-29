//! Server Name Indication Extension (RFC 6066 Section 3)

use crate::error::TlsError;

/// Server name type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServerNameType {
    HostName = 0,
    Unknown(u8),
}

impl ServerNameType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ServerNameType::HostName,
            v => ServerNameType::Unknown(v),
        }
    }
}

/// A single server name entry
#[derive(Debug, Clone)]
pub struct ServerName {
    pub name_type: ServerNameType,
    pub name: String,
}

impl ServerName {
    /// Create a hostname entry
    pub fn hostname(name: &str) -> Self {
        Self {
            name_type: ServerNameType::HostName,
            name: name.to_string(),
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let mut data = vec![0]; // HostName type
        data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(name_bytes);
        data
    }
}

/// Server Name List extension
#[derive(Debug, Clone)]
pub struct ServerNameList {
    pub names: Vec<ServerName>,
}

impl ServerNameList {
    /// Create with a single hostname
    pub fn new(hostname: &str) -> Self {
        Self {
            names: vec![ServerName::hostname(hostname)],
        }
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("server_name too short".into()));
        }

        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if list_len + 2 != data.len() {
            return Err(TlsError::Protocol("invalid server_name length".into()));
        }

        let mut names = Vec::new();
        let mut offset = 2;

        while offset < data.len() {
            if offset + 3 > data.len() {
                return Err(TlsError::Protocol("server_name entry truncated".into()));
            }

            let name_type = ServerNameType::from_u8(data[offset]);
            let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
            offset += 3;

            if offset + name_len > data.len() {
                return Err(TlsError::Protocol("server_name entry truncated".into()));
            }

            let name = String::from_utf8(data[offset..offset + name_len].to_vec())
                .map_err(|_| TlsError::Protocol("invalid server_name encoding".into()))?;
            offset += name_len;

            names.push(ServerName { name_type, name });
        }

        Ok(Self { names })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut list_data = Vec::new();
        for name in &self.names {
            list_data.extend_from_slice(&name.encode());
        }

        let mut data = Vec::new();
        data.extend_from_slice(&(list_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&list_data);
        data
    }

    /// Get the first hostname
    pub fn hostname(&self) -> Option<&str> {
        self.names
            .iter()
            .find(|n| matches!(n.name_type, ServerNameType::HostName))
            .map(|n| n.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_name() {
        let sni = ServerNameList::new("example.com");
        assert_eq!(sni.hostname(), Some("example.com"));
    }

    #[test]
    fn test_encode_parse() {
        let sni = ServerNameList::new("test.example.org");
        let encoded = sni.encode();
        let parsed = ServerNameList::parse(&encoded).unwrap();
        assert_eq!(parsed.hostname(), Some("test.example.org"));
    }
}
