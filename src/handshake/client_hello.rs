//! ClientHello message (RFC 8446 Section 4.1.2)

use crate::error::TlsError;
use crate::extensions::{encode_extensions, parse_extensions, Extension};
use rand::RngCore;

/// TLS 1.3 cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    Tls13Aes128GcmSha256 = 0x1301,
    Tls13Aes256GcmSha384 = 0x1302,
    Tls13Chacha20Poly1305Sha256 = 0x1303,
    Unknown(u16),
}

impl CipherSuite {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x1301 => CipherSuite::Tls13Aes128GcmSha256,
            0x1302 => CipherSuite::Tls13Aes256GcmSha384,
            0x1303 => CipherSuite::Tls13Chacha20Poly1305Sha256,
            v => CipherSuite::Unknown(v),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            CipherSuite::Tls13Aes128GcmSha256 => 0x1301,
            CipherSuite::Tls13Aes256GcmSha384 => 0x1302,
            CipherSuite::Tls13Chacha20Poly1305Sha256 => 0x1303,
            CipherSuite::Unknown(v) => v,
        }
    }
}

/// ClientHello message
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Legacy version (always 0x0303 for TLS 1.3)
    pub legacy_version: u16,
    /// 32-byte random value
    pub random: [u8; 32],
    /// Legacy session ID
    pub legacy_session_id: Vec<u8>,
    /// Supported cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Legacy compression methods (always [0])
    pub legacy_compression_methods: Vec<u8>,
    /// Extensions
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Create a new ClientHello with default values
    pub fn new(extensions: Vec<Extension>) -> Self {
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);

        let mut session_id = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_id);

        Self {
            legacy_version: 0x0303,
            random,
            legacy_session_id: session_id,
            cipher_suites: vec![
                CipherSuite::Tls13Aes128GcmSha256,
                CipherSuite::Tls13Aes256GcmSha384,
                CipherSuite::Tls13Chacha20Poly1305Sha256,
            ],
            legacy_compression_methods: vec![0],
            extensions,
        }
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 38 {
            return Err(TlsError::Protocol("ClientHello too short".into()));
        }

        let legacy_version = u16::from_be_bytes([data[0], data[1]]);

        let mut random = [0u8; 32];
        random.copy_from_slice(&data[2..34]);

        let session_id_len = data[34] as usize;
        if data.len() < 35 + session_id_len {
            return Err(TlsError::Protocol(
                "ClientHello truncated at session_id".into(),
            ));
        }
        let legacy_session_id = data[35..35 + session_id_len].to_vec();
        let mut offset = 35 + session_id_len;

        // Cipher suites
        if data.len() < offset + 2 {
            return Err(TlsError::Protocol(
                "ClientHello truncated at cipher_suites".into(),
            ));
        }
        let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + cipher_suites_len {
            return Err(TlsError::Protocol("ClientHello truncated".into()));
        }

        let mut cipher_suites = Vec::new();
        for i in (0..cipher_suites_len).step_by(2) {
            let cs = u16::from_be_bytes([data[offset + i], data[offset + i + 1]]);
            cipher_suites.push(CipherSuite::from_u16(cs));
        }
        offset += cipher_suites_len;

        // Compression methods
        if data.len() < offset + 1 {
            return Err(TlsError::Protocol(
                "ClientHello truncated at compression".into(),
            ));
        }
        let comp_len = data[offset] as usize;
        offset += 1;
        let legacy_compression_methods = data[offset..offset + comp_len].to_vec();
        offset += comp_len;

        // Extensions
        let extensions = if data.len() > offset + 2 {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            parse_extensions(&data[offset..offset + ext_len])?
        } else {
            Vec::new()
        };

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Legacy version
        data.extend_from_slice(&self.legacy_version.to_be_bytes());

        // Random
        data.extend_from_slice(&self.random);

        // Session ID
        data.push(self.legacy_session_id.len() as u8);
        data.extend_from_slice(&self.legacy_session_id);

        // Cipher suites
        let cs_len = (self.cipher_suites.len() * 2) as u16;
        data.extend_from_slice(&cs_len.to_be_bytes());
        for cs in &self.cipher_suites {
            data.extend_from_slice(&cs.to_u16().to_be_bytes());
        }

        // Compression methods
        data.push(self.legacy_compression_methods.len() as u8);
        data.extend_from_slice(&self.legacy_compression_methods);

        // Extensions
        let ext_data = encode_extensions(&self.extensions);
        data.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext_data);

        data
    }

    /// Find an extension by type
    pub fn find_extension<F, T>(&self, f: F) -> Option<T>
    where
        F: Fn(&Extension) -> Option<T>,
    {
        self.extensions.iter().find_map(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_encode_parse() {
        let ch = ClientHello::new(vec![]);
        let encoded = ch.encode();
        let parsed = ClientHello::parse(&encoded).unwrap();

        assert_eq!(parsed.legacy_version, 0x0303);
        assert_eq!(parsed.cipher_suites.len(), 3);
    }

    #[test]
    fn test_cipher_suite() {
        let cs = CipherSuite::Tls13Aes128GcmSha256;
        assert_eq!(cs.to_u16(), 0x1301);
        assert_eq!(CipherSuite::from_u16(0x1301), cs);
    }
}
