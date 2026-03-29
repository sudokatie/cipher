//! TLS 1.3 Extensions (RFC 8446 Section 4.2)

mod alpn;
mod key_share;
mod server_name;
mod signature_algorithms;
mod supported_groups;
mod supported_versions;
mod types;

pub use alpn::{AlpnClientHello, AlpnServerHello};
pub use key_share::{KeyShareClientHello, KeyShareEntry, KeyShareServerHello};
pub use server_name::{ServerName, ServerNameList};
pub use signature_algorithms::{SignatureAlgorithms, SignatureScheme};
pub use supported_groups::SupportedGroups;
pub use supported_versions::SupportedVersions;
pub use types::{Extension, ExtensionType};

use crate::error::TlsError;

/// Parse extensions from a byte slice
pub fn parse_extensions(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
    let mut extensions = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > data.len() {
            return Err(TlsError::Protocol("extension length exceeds data".into()));
        }

        let ext_data = &data[offset..offset + ext_len];
        offset += ext_len;

        let extension = Extension::parse(ext_type, ext_data)?;
        extensions.push(extension);
    }

    Ok(extensions)
}

/// Encode extensions to bytes
pub fn encode_extensions(extensions: &[Extension]) -> Vec<u8> {
    let mut data = Vec::new();

    for ext in extensions {
        let encoded = ext.encode();
        let ext_type = match ext.extension_type() {
            ExtensionType::ServerName => 0,
            ExtensionType::SupportedGroups => 10,
            ExtensionType::SignatureAlgorithms => 13,
            ExtensionType::ApplicationLayerProtocolNegotiation => 16,
            ExtensionType::SupportedVersions => 43,
            ExtensionType::KeyShare => 51,
            ExtensionType::Unknown(v) => v,
            _ => continue, // Skip unsupported for encoding
        };
        data.extend_from_slice(&ext_type.to_be_bytes());
        data.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
        data.extend_from_slice(&encoded);
    }

    data
}
