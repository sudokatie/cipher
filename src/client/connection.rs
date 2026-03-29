//! TLS Client Connection

use super::TlsClientConfig;
use crate::alert::Alert;
use crate::cert::{Certificate as ParsedCert, CertificateValidator};
use crate::crypto::{construct_certificate_verify_message, verify_signature};
use crate::error::TlsError;
use crate::handshake::{
    encode_handshake, parse_handshake, Finished, HandshakeMessage, HandshakeState, ServerHello,
};
use crate::record::{ContentType, RecordLayer};
use std::io::{Read, Write};

/// TLS client connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state
    Initial,
    /// Handshake in progress
    Handshaking,
    /// Connected (handshake complete)
    Connected,
    /// Connection closed
    Closed,
    /// Error state
    Error,
}

/// TLS client connection
pub struct TlsClient<S: Read + Write> {
    /// Underlying stream
    stream: S,
    /// Configuration
    config: TlsClientConfig,
    /// Connection state
    state: ConnectionState,
    /// Handshake state machine
    handshake: HandshakeState,
    /// Record layer
    record: RecordLayer,
    /// Server name for SNI
    server_name: Option<String>,
}

impl<S: Read + Write> TlsClient<S> {
    /// Create a new TLS client wrapping a stream
    pub fn new(stream: S, config: TlsClientConfig, server_name: &str) -> Self {
        Self {
            stream,
            config,
            state: ConnectionState::Initial,
            handshake: HandshakeState::new_client(Some(server_name)),
            record: RecordLayer::new(),
            server_name: Some(server_name.to_string()),
        }
    }

    /// Perform the TLS handshake
    pub fn handshake(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;

        // Send ClientHello
        let client_hello = self.handshake.build_client_hello()?;
        let ch_bytes = encode_handshake(&HandshakeMessage::ClientHello(client_hello));
        self.handshake.update_transcript(&ch_bytes);
        self.send_record(ContentType::Handshake, &ch_bytes)?;

        // Receive ServerHello
        let server_hello = self.receive_server_hello()?;
        let sh_bytes = encode_handshake(&HandshakeMessage::ServerHello(server_hello.clone()));
        self.handshake.update_transcript(&sh_bytes);
        self.handshake.process_server_hello(&server_hello)?;

        // Now we have keys - switch to encrypted mode
        self.record.enable_encryption(
            self.handshake.key_schedule.as_ref().unwrap(),
            false, // client
        )?;

        // Receive encrypted handshake messages
        self.receive_encrypted_handshake()?;

        // Send client Finished
        self.send_client_finished()?;

        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Send an application data record
    fn send_record(&mut self, content_type: ContentType, data: &[u8]) -> Result<(), TlsError> {
        let record = self.record.encode_record(content_type, data)?;
        self.stream
            .write_all(&record)
            .map_err(|e| TlsError::Io(e.to_string()))?;
        Ok(())
    }

    /// Receive a record
    fn receive_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        // Read record header
        let mut header = [0u8; 5];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| TlsError::Io(e.to_string()))?;

        let length = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Read record body
        let mut body = vec![0u8; length];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| TlsError::Io(e.to_string()))?;

        let mut full_record = header.to_vec();
        full_record.extend_from_slice(&body);

        self.record.decode_record(&full_record)
    }

    /// Receive ServerHello
    fn receive_server_hello(&mut self) -> Result<ServerHello, TlsError> {
        let (content_type, data) = self.receive_record()?;

        if content_type != ContentType::Handshake {
            return Err(TlsError::Protocol("expected handshake record".into()));
        }

        match parse_handshake(&data)? {
            HandshakeMessage::ServerHello(sh) => Ok(sh),
            _ => Err(TlsError::Protocol("expected ServerHello".into())),
        }
    }

    /// Receive encrypted handshake messages
    fn receive_encrypted_handshake(&mut self) -> Result<(), TlsError> {
        // EncryptedExtensions
        let (_, data) = self.receive_record()?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::EncryptedExtensions(ee) = msg {
            self.handshake.update_transcript(&data);
            self.handshake.process_encrypted_extensions(&ee)?;
        } else {
            return Err(TlsError::Protocol("expected EncryptedExtensions".into()));
        }

        // Certificate
        let (_, data) = self.receive_record()?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::Certificate(cert) = msg {
            self.handshake.update_transcript(&data);

            // Validate certificate
            if !self.config.danger_skip_verification {
                let validator = CertificateValidator::new(&self.config.root_certificates);
                let chain: Vec<Vec<u8>> = cert
                    .certificate_list
                    .iter()
                    .map(|e| e.cert_data.clone())
                    .collect();
                validator.validate_chain(&chain, self.server_name.as_deref())?;
            }

            self.handshake.process_certificate(&cert)?;
        } else {
            return Err(TlsError::Protocol("expected Certificate".into()));
        }

        // CertificateVerify
        let (_, data) = self.receive_record()?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::CertificateVerify(cv) = msg {
            // Get transcript hash BEFORE updating with CertificateVerify
            let transcript_hash = self.handshake.transcript_hash();

            // Verify the signature if not skipping verification
            if !self.config.danger_skip_verification {
                // Get the server's public key from the certificate
                if let Some(cert_der) = self.handshake.peer_certificates.first() {
                    let cert = ParsedCert::from_der(cert_der)?;
                    let message = construct_certificate_verify_message(&transcript_hash, true);
                    verify_signature(
                        cv.algorithm,
                        cert.public_key_bytes(),
                        &message,
                        &cv.signature,
                    )?;
                } else {
                    return Err(TlsError::Handshake(
                        "no server certificate for verification".into(),
                    ));
                }
            }

            self.handshake.update_transcript(&data);
            self.handshake.process_certificate_verify(&cv)?;
        } else {
            return Err(TlsError::Protocol("expected CertificateVerify".into()));
        }

        // Finished
        let (_, data) = self.receive_record()?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::Finished(fin) = msg {
            self.handshake.update_transcript(&data);
            self.handshake.process_finished(&fin)?;
        } else {
            return Err(TlsError::Protocol("expected Finished".into()));
        }

        Ok(())
    }

    /// Send client Finished
    fn send_client_finished(&mut self) -> Result<(), TlsError> {
        let key_schedule = self
            .handshake
            .key_schedule
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("no key schedule".into()))?;

        let transcript_hash = self.handshake.transcript_hash();
        let verify_data =
            Finished::compute_verify_data(&key_schedule.client_finished_key, &transcript_hash);

        let finished = Finished::new(verify_data);
        let data = encode_handshake(&HandshakeMessage::Finished(finished));
        self.handshake.update_transcript(&data);
        self.send_record(ContentType::Handshake, &data)?;

        // Derive application traffic keys
        let transcript_hash = self.handshake.transcript_hash();
        if let Some(ref mut ks) = self.handshake.key_schedule {
            ks.derive_application_secret(&transcript_hash);
        }

        Ok(())
    }

    /// Read application data
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::Handshake("not connected".into()));
        }

        let (content_type, data) = self.receive_record()?;

        match content_type {
            ContentType::ApplicationData => {
                let len = std::cmp::min(buf.len(), data.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            ContentType::Alert => {
                let alert = Alert::parse(&data)?;
                if alert.is_close_notify() {
                    self.state = ConnectionState::Closed;
                    Ok(0) // EOF
                } else if alert.is_fatal() {
                    self.state = ConnectionState::Error;
                    Err(alert.to_error())
                } else {
                    // Warning alert - log and continue
                    Ok(0)
                }
            }
            _ => Err(TlsError::Protocol("unexpected record type".into())),
        }
    }

    /// Write application data
    pub fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::Handshake("not connected".into()));
        }

        self.send_record(ContentType::ApplicationData, data)?;
        Ok(data.len())
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Close the connection
    pub fn close(&mut self) -> Result<(), TlsError> {
        // Send close_notify alert
        let alert = Alert::close_notify();
        self.send_record(ContentType::Alert, &alert.encode())?;
        self.state = ConnectionState::Closed;
        Ok(())
    }

    /// Send an alert
    pub fn send_alert(&mut self, alert: Alert) -> Result<(), TlsError> {
        self.send_record(ContentType::Alert, &alert.encode())?;
        if alert.is_fatal() {
            self.state = ConnectionState::Error;
        }
        Ok(())
    }

    /// Get the negotiated ALPN protocol
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.handshake.alpn_protocol.as_deref()
    }

    /// Get peer certificates
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.handshake.peer_certificates
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_client_creation() {
        let stream = Cursor::new(Vec::new());
        let config = TlsClientConfig::default();
        let client = TlsClient::new(stream, config, "example.com");

        assert_eq!(client.state(), ConnectionState::Initial);
        assert!(!client.is_connected());
    }
}
