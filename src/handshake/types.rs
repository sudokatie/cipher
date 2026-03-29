//! Handshake message types

use super::{
    Certificate, CertificateRequest, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
    ServerHello,
};

/// Handshake message types (RFC 8446 Section 4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
    Unknown(u8),
}

impl HandshakeType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            13 => HandshakeType::CertificateRequest,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            24 => HandshakeType::KeyUpdate,
            254 => HandshakeType::MessageHash,
            v => HandshakeType::Unknown(v),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            HandshakeType::ClientHello => 1,
            HandshakeType::ServerHello => 2,
            HandshakeType::NewSessionTicket => 4,
            HandshakeType::EndOfEarlyData => 5,
            HandshakeType::EncryptedExtensions => 8,
            HandshakeType::Certificate => 11,
            HandshakeType::CertificateRequest => 13,
            HandshakeType::CertificateVerify => 15,
            HandshakeType::Finished => 20,
            HandshakeType::KeyUpdate => 24,
            HandshakeType::MessageHash => 254,
            HandshakeType::Unknown(v) => *v,
        }
    }
}

/// Parsed handshake message
#[derive(Debug, Clone)]
pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EncryptedExtensions(EncryptedExtensions),
    CertificateRequest(CertificateRequest),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
}

impl HandshakeMessage {
    /// Get the handshake type
    pub fn msg_type(&self) -> HandshakeType {
        match self {
            HandshakeMessage::ClientHello(_) => HandshakeType::ClientHello,
            HandshakeMessage::ServerHello(_) => HandshakeType::ServerHello,
            HandshakeMessage::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            HandshakeMessage::CertificateRequest(_) => HandshakeType::CertificateRequest,
            HandshakeMessage::Certificate(_) => HandshakeType::Certificate,
            HandshakeMessage::CertificateVerify(_) => HandshakeType::CertificateVerify,
            HandshakeMessage::Finished(_) => HandshakeType::Finished,
        }
    }
}
