//! TLS 1.3 Handshake Protocol (RFC 8446 Section 4)

mod certificate;
mod certificate_request;
mod certificate_verify;
pub mod client_hello;
mod encrypted_extensions;
mod finished;
mod server_hello;
mod state;
mod types;

pub use certificate::{Certificate, CertificateEntry};
pub use certificate_request::CertificateRequest;
pub use certificate_verify::CertificateVerify;
pub use client_hello::{CipherSuite, ClientHello};
pub use encrypted_extensions::EncryptedExtensions;
pub use finished::Finished;
pub use server_hello::ServerHello;
pub use state::{HandshakeRole, HandshakeState};
pub use types::{HandshakeMessage, HandshakeType};

use crate::error::TlsError;

/// Parse a handshake message from bytes
pub fn parse_handshake(data: &[u8]) -> Result<HandshakeMessage, TlsError> {
    if data.len() < 4 {
        return Err(TlsError::Protocol("handshake message too short".into()));
    }

    let msg_type = HandshakeType::from_u8(data[0]);
    let length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + length {
        return Err(TlsError::Protocol("handshake message truncated".into()));
    }

    let payload = &data[4..4 + length];

    match msg_type {
        HandshakeType::ClientHello => {
            Ok(HandshakeMessage::ClientHello(ClientHello::parse(payload)?))
        }
        HandshakeType::ServerHello => {
            Ok(HandshakeMessage::ServerHello(ServerHello::parse(payload)?))
        }
        HandshakeType::EncryptedExtensions => Ok(HandshakeMessage::EncryptedExtensions(
            EncryptedExtensions::parse(payload)?,
        )),
        HandshakeType::CertificateRequest => Ok(HandshakeMessage::CertificateRequest(
            CertificateRequest::parse(payload)?,
        )),
        HandshakeType::Certificate => {
            Ok(HandshakeMessage::Certificate(Certificate::parse(payload)?))
        }
        HandshakeType::CertificateVerify => Ok(HandshakeMessage::CertificateVerify(
            CertificateVerify::parse(payload)?,
        )),
        HandshakeType::Finished => Ok(HandshakeMessage::Finished(Finished::parse(payload)?)),
        _ => Err(TlsError::Protocol(format!(
            "unsupported handshake type: {:?}",
            msg_type
        ))),
    }
}

/// Encode a handshake message to bytes
pub fn encode_handshake(msg: &HandshakeMessage) -> Vec<u8> {
    let (msg_type, payload) = match msg {
        HandshakeMessage::ClientHello(ch) => (HandshakeType::ClientHello, ch.encode()),
        HandshakeMessage::ServerHello(sh) => (HandshakeType::ServerHello, sh.encode()),
        HandshakeMessage::EncryptedExtensions(ee) => {
            (HandshakeType::EncryptedExtensions, ee.encode())
        }
        HandshakeMessage::CertificateRequest(cr) => {
            (HandshakeType::CertificateRequest, cr.encode())
        }
        HandshakeMessage::Certificate(c) => (HandshakeType::Certificate, c.encode()),
        HandshakeMessage::CertificateVerify(cv) => (HandshakeType::CertificateVerify, cv.encode()),
        HandshakeMessage::Finished(f) => (HandshakeType::Finished, f.encode()),
    };

    let length = payload.len() as u32;
    let mut data = vec![msg_type.to_u8()];
    data.extend_from_slice(&length.to_be_bytes()[1..4]); // 3 bytes
    data.extend_from_slice(&payload);
    data
}
