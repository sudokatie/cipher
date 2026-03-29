//! Key Share Extension (RFC 8446 Section 4.2.8)

use crate::error::TlsError;
use crate::key::NamedGroup;

/// A single key share entry
#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    /// Create a new key share entry
    pub fn new(group: NamedGroup, key_exchange: Vec<u8>) -> Self {
        Self {
            group,
            key_exchange,
        }
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<(Self, usize), TlsError> {
        if data.len() < 4 {
            return Err(TlsError::Protocol("key share entry too short".into()));
        }

        let group_id = u16::from_be_bytes([data[0], data[1]]);
        let group = NamedGroup::from_u16(group_id)
            .ok_or_else(|| TlsError::Protocol(format!("unknown group: {}", group_id)))?;

        let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + key_len {
            return Err(TlsError::Protocol("key share entry truncated".into()));
        }

        let key_exchange = data[4..4 + key_len].to_vec();
        Ok((
            Self {
                group,
                key_exchange,
            },
            4 + key_len,
        ))
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.group.to_u16().to_be_bytes());
        data.extend_from_slice(&(self.key_exchange.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.key_exchange);
        data
    }
}

/// Key Share extension for ClientHello
#[derive(Debug, Clone)]
pub struct KeyShareClientHello {
    pub entries: Vec<KeyShareEntry>,
}

impl KeyShareClientHello {
    /// Create with a single entry
    pub fn new(entries: Vec<KeyShareEntry>) -> Self {
        Self { entries }
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("key_share too short".into()));
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if len + 2 != data.len() {
            return Err(TlsError::Protocol("invalid key_share length".into()));
        }

        let mut entries = Vec::new();
        let mut offset = 2;
        while offset < data.len() {
            let (entry, consumed) = KeyShareEntry::parse(&data[offset..])?;
            entries.push(entry);
            offset += consumed;
        }

        Ok(Self { entries })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut entries_data = Vec::new();
        for entry in &self.entries {
            entries_data.extend_from_slice(&entry.encode());
        }

        let mut data = Vec::new();
        data.extend_from_slice(&(entries_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&entries_data);
        data
    }

    /// Find an entry for a specific group
    pub fn find(&self, group: NamedGroup) -> Option<&KeyShareEntry> {
        self.entries.iter().find(|e| e.group == group)
    }
}

/// Key Share extension for ServerHello
#[derive(Debug, Clone)]
pub struct KeyShareServerHello {
    pub entry: KeyShareEntry,
}

impl KeyShareServerHello {
    /// Create with an entry
    pub fn new(entry: KeyShareEntry) -> Self {
        Self { entry }
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        let (entry, _) = KeyShareEntry::parse(data)?;
        Ok(Self { entry })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        self.entry.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_share_entry() {
        let entry = KeyShareEntry::new(NamedGroup::X25519, vec![0; 32]);
        let encoded = entry.encode();
        let (parsed, len) = KeyShareEntry::parse(&encoded).unwrap();
        assert_eq!(len, encoded.len());
        assert_eq!(parsed.group, NamedGroup::X25519);
        assert_eq!(parsed.key_exchange.len(), 32);
    }

    #[test]
    fn test_key_share_client_hello() {
        let entry = KeyShareEntry::new(NamedGroup::X25519, vec![0; 32]);
        let ks = KeyShareClientHello::new(vec![entry]);
        let encoded = ks.encode();
        let parsed = KeyShareClientHello::parse(&encoded).unwrap();
        assert_eq!(parsed.entries.len(), 1);
    }
}
