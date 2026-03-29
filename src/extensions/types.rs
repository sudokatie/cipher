//! Extension type definitions

use super::{
    AlpnClientHello, AlpnServerHello, KeyShareClientHello, KeyShareServerHello, ServerNameList,
    SignatureAlgorithms, SupportedGroups, SupportedVersions,
};
use crate::error::TlsError;

/// TLS extension types (RFC 8446 Section 4.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    Unknown(u16),
}

impl ExtensionType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => ExtensionType::ServerName,
            1 => ExtensionType::MaxFragmentLength,
            5 => ExtensionType::StatusRequest,
            10 => ExtensionType::SupportedGroups,
            13 => ExtensionType::SignatureAlgorithms,
            14 => ExtensionType::UseSrtp,
            15 => ExtensionType::Heartbeat,
            16 => ExtensionType::ApplicationLayerProtocolNegotiation,
            18 => ExtensionType::SignedCertificateTimestamp,
            19 => ExtensionType::ClientCertificateType,
            20 => ExtensionType::ServerCertificateType,
            21 => ExtensionType::Padding,
            41 => ExtensionType::PreSharedKey,
            42 => ExtensionType::EarlyData,
            43 => ExtensionType::SupportedVersions,
            44 => ExtensionType::Cookie,
            45 => ExtensionType::PskKeyExchangeModes,
            47 => ExtensionType::CertificateAuthorities,
            48 => ExtensionType::OidFilters,
            49 => ExtensionType::PostHandshakeAuth,
            50 => ExtensionType::SignatureAlgorithmsCert,
            51 => ExtensionType::KeyShare,
            v => ExtensionType::Unknown(v),
        }
    }
}

/// Parsed TLS extension
#[derive(Debug, Clone)]
pub enum Extension {
    /// Server Name Indication
    ServerName(ServerNameList),
    /// Supported Groups (named curves)
    SupportedGroups(SupportedGroups),
    /// Signature Algorithms
    SignatureAlgorithms(SignatureAlgorithms),
    /// Supported Versions
    SupportedVersions(SupportedVersions),
    /// Key Share (client)
    KeyShareClientHello(KeyShareClientHello),
    /// Key Share (server)
    KeyShareServerHello(KeyShareServerHello),
    /// ALPN (client)
    AlpnClientHello(AlpnClientHello),
    /// ALPN (server response)
    AlpnServerHello(AlpnServerHello),
    /// Unknown extension
    Unknown { ext_type: u16, data: Vec<u8> },
}

impl Extension {
    /// Parse an extension from its type and data
    pub fn parse(ext_type: u16, data: &[u8]) -> Result<Self, TlsError> {
        match ExtensionType::from_u16(ext_type) {
            ExtensionType::ServerName => Ok(Extension::ServerName(ServerNameList::parse(data)?)),
            ExtensionType::SupportedGroups => {
                Ok(Extension::SupportedGroups(SupportedGroups::parse(data)?))
            }
            ExtensionType::SignatureAlgorithms => Ok(Extension::SignatureAlgorithms(
                SignatureAlgorithms::parse(data)?,
            )),
            ExtensionType::SupportedVersions => Ok(Extension::SupportedVersions(
                SupportedVersions::parse(data)?,
            )),
            ExtensionType::KeyShare => {
                // Try parsing as client hello first, then server hello
                if let Ok(ks) = KeyShareClientHello::parse(data) {
                    Ok(Extension::KeyShareClientHello(ks))
                } else {
                    Ok(Extension::KeyShareServerHello(KeyShareServerHello::parse(
                        data,
                    )?))
                }
            }
            ExtensionType::ApplicationLayerProtocolNegotiation => {
                // Try parsing as client hello first, then server hello
                if let Ok(alpn) = AlpnClientHello::parse(data) {
                    if alpn.protocols.len() > 1 {
                        Ok(Extension::AlpnClientHello(alpn))
                    } else {
                        // Single protocol could be either, try server format
                        Ok(Extension::AlpnServerHello(AlpnServerHello::parse(data)?))
                    }
                } else {
                    Ok(Extension::AlpnServerHello(AlpnServerHello::parse(data)?))
                }
            }
            _ => Ok(Extension::Unknown {
                ext_type,
                data: data.to_vec(),
            }),
        }
    }

    /// Encode the extension to bytes (without type/length header)
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Extension::ServerName(sn) => sn.encode(),
            Extension::SupportedGroups(sg) => sg.encode(),
            Extension::SignatureAlgorithms(sa) => sa.encode(),
            Extension::SupportedVersions(sv) => sv.encode(),
            Extension::KeyShareClientHello(ks) => ks.encode(),
            Extension::KeyShareServerHello(ks) => ks.encode(),
            Extension::AlpnClientHello(alpn) => alpn.encode(),
            Extension::AlpnServerHello(alpn) => alpn.encode(),
            Extension::Unknown { data, .. } => data.clone(),
        }
    }

    /// Get the extension type
    pub fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::ServerName(_) => ExtensionType::ServerName,
            Extension::SupportedGroups(_) => ExtensionType::SupportedGroups,
            Extension::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Extension::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Extension::KeyShareClientHello(_) => ExtensionType::KeyShare,
            Extension::KeyShareServerHello(_) => ExtensionType::KeyShare,
            Extension::AlpnClientHello(_) => ExtensionType::ApplicationLayerProtocolNegotiation,
            Extension::AlpnServerHello(_) => ExtensionType::ApplicationLayerProtocolNegotiation,
            Extension::Unknown { ext_type, .. } => ExtensionType::Unknown(*ext_type),
        }
    }
}
