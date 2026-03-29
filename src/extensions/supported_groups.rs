//! Supported Groups Extension (RFC 8446 Section 4.2.7)

use crate::error::TlsError;
use crate::key::NamedGroup;

/// Supported Groups extension
#[derive(Debug, Clone)]
pub struct SupportedGroups {
    pub groups: Vec<NamedGroup>,
}

impl SupportedGroups {
    /// Create with default groups for TLS 1.3
    pub fn default_groups() -> Self {
        Self {
            groups: vec![
                NamedGroup::X25519,
                NamedGroup::Secp256r1,
                NamedGroup::Secp384r1,
            ],
        }
    }

    /// Parse from extension data
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::Protocol("supported_groups too short".into()));
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if len + 2 != data.len() || !len.is_multiple_of(2) {
            return Err(TlsError::Protocol("invalid supported_groups length".into()));
        }

        let mut groups = Vec::new();
        for i in (2..2 + len).step_by(2) {
            let group_id = u16::from_be_bytes([data[i], data[i + 1]]);
            if let Some(group) = NamedGroup::from_u16(group_id) {
                groups.push(group);
            }
        }

        Ok(Self { groups })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let len = (self.groups.len() * 2) as u16;
        let mut data = len.to_be_bytes().to_vec();
        for group in &self.groups {
            data.extend_from_slice(&group.to_u16().to_be_bytes());
        }
        data
    }

    /// Check if a group is supported
    pub fn supports(&self, group: NamedGroup) -> bool {
        self.groups.contains(&group)
    }

    /// Find the first mutually supported group
    pub fn find_common(&self, other: &SupportedGroups) -> Option<NamedGroup> {
        for group in &self.groups {
            if other.groups.contains(group) {
                return Some(*group);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_groups() {
        let sg = SupportedGroups::default_groups();
        assert!(sg.supports(NamedGroup::X25519));
        assert!(sg.supports(NamedGroup::Secp256r1));
    }

    #[test]
    fn test_encode_parse() {
        let sg = SupportedGroups::default_groups();
        let encoded = sg.encode();
        let parsed = SupportedGroups::parse(&encoded).unwrap();
        assert_eq!(sg.groups.len(), parsed.groups.len());
    }

    #[test]
    fn test_find_common() {
        let sg1 = SupportedGroups {
            groups: vec![NamedGroup::X25519, NamedGroup::Secp256r1],
        };
        let sg2 = SupportedGroups {
            groups: vec![NamedGroup::Secp256r1, NamedGroup::Secp384r1],
        };
        assert_eq!(sg1.find_common(&sg2), Some(NamedGroup::Secp256r1));
    }
}
