//! TLS record layer types.

/// TLS record content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// Invalid content type (0).
    Invalid = 0,
    /// Change cipher spec (20) - for compatibility only.
    ChangeCipherSpec = 20,
    /// Alert message (21).
    Alert = 21,
    /// Handshake message (22).
    Handshake = 22,
    /// Application data (23).
    ApplicationData = 23,
}

impl ContentType {
    /// Parse from a byte.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ContentType::Invalid),
            20 => Some(ContentType::ChangeCipherSpec),
            21 => Some(ContentType::Alert),
            22 => Some(ContentType::Handshake),
            23 => Some(ContentType::ApplicationData),
            _ => None,
        }
    }

    /// Convert to byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// TLS protocol version constants.
pub mod version {
    /// TLS 1.2 version (0x0303) - used in record layer for compatibility.
    pub const TLS12: u16 = 0x0303;

    /// TLS 1.3 version (0x0304) - used in supported_versions extension.
    pub const TLS13: u16 = 0x0304;

    /// Legacy version for ClientHello (0x0301).
    pub const TLS10: u16 = 0x0301;
}

/// Maximum TLS record fragment length.
pub const MAX_FRAGMENT_LENGTH: usize = 16384; // 2^14

/// Maximum TLS record length (fragment + overhead).
pub const MAX_RECORD_LENGTH: usize = MAX_FRAGMENT_LENGTH + 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_roundtrip() {
        let types = [
            ContentType::Invalid,
            ContentType::ChangeCipherSpec,
            ContentType::Alert,
            ContentType::Handshake,
            ContentType::ApplicationData,
        ];

        for ct in types {
            let byte = ct.to_u8();
            let parsed = ContentType::from_u8(byte).unwrap();
            assert_eq!(ct, parsed);
        }
    }

    #[test]
    fn test_content_type_values() {
        assert_eq!(ContentType::Invalid.to_u8(), 0);
        assert_eq!(ContentType::ChangeCipherSpec.to_u8(), 20);
        assert_eq!(ContentType::Alert.to_u8(), 21);
        assert_eq!(ContentType::Handshake.to_u8(), 22);
        assert_eq!(ContentType::ApplicationData.to_u8(), 23);
    }

    #[test]
    fn test_unknown_content_type() {
        assert_eq!(ContentType::from_u8(99), None);
    }

    #[test]
    fn test_version_constants() {
        assert_eq!(version::TLS12, 0x0303);
        assert_eq!(version::TLS13, 0x0304);
    }
}
