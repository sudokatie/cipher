//! ServerHello message (RFC 8446 Section 4.1.3)

use super::client_hello::CipherSuite;
use crate::error::TlsError;
use crate::extensions::{encode_extensions, parse_extensions, Extension};
use rand::RngCore;

/// ServerHello message
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Legacy version (always 0x0303 for TLS 1.3)
    pub legacy_version: u16,
    /// 32-byte random value
    pub random: [u8; 32],
    /// Legacy session ID (echoed from ClientHello)
    pub legacy_session_id_echo: Vec<u8>,
    /// Selected cipher suite
    pub cipher_suite: CipherSuite,
    /// Legacy compression method (always 0)
    pub legacy_compression_method: u8,
    /// Extensions
    pub extensions: Vec<Extension>,
}

/// Special random value indicating HelloRetryRequest
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

impl ServerHello {
    /// Create a new ServerHello
    pub fn new(
        session_id_echo: Vec<u8>,
        cipher_suite: CipherSuite,
        extensions: Vec<Extension>,
    ) -> Self {
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);

        Self {
            legacy_version: 0x0303,
            random,
            legacy_session_id_echo: session_id_echo,
            cipher_suite,
            legacy_compression_method: 0,
            extensions,
        }
    }

    /// Check if this is a HelloRetryRequest
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 38 {
            return Err(TlsError::Protocol("ServerHello too short".into()));
        }

        let legacy_version = u16::from_be_bytes([data[0], data[1]]);

        let mut random = [0u8; 32];
        random.copy_from_slice(&data[2..34]);

        let session_id_len = data[34] as usize;
        if data.len() < 35 + session_id_len + 3 {
            return Err(TlsError::Protocol("ServerHello truncated".into()));
        }
        let legacy_session_id_echo = data[35..35 + session_id_len].to_vec();
        let mut offset = 35 + session_id_len;

        // Cipher suite
        let cipher_suite =
            CipherSuite::from_u16(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;

        // Compression method
        let legacy_compression_method = data[offset];
        offset += 1;

        // Extensions
        let extensions = if data.len() > offset + 2 {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if offset + ext_len <= data.len() {
                parse_extensions(&data[offset..offset + ext_len])?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
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
        data.push(self.legacy_session_id_echo.len() as u8);
        data.extend_from_slice(&self.legacy_session_id_echo);

        // Cipher suite
        data.extend_from_slice(&self.cipher_suite.to_u16().to_be_bytes());

        // Compression method
        data.push(self.legacy_compression_method);

        // Extensions
        let ext_data = encode_extensions(&self.extensions);
        data.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext_data);

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_hello_encode_parse() {
        let sh = ServerHello::new(vec![0; 32], CipherSuite::Tls13Aes128GcmSha256, vec![]);
        let encoded = sh.encode();
        let parsed = ServerHello::parse(&encoded).unwrap();

        assert_eq!(parsed.legacy_version, 0x0303);
        assert_eq!(parsed.cipher_suite, CipherSuite::Tls13Aes128GcmSha256);
        assert!(!parsed.is_hello_retry_request());
    }
}
