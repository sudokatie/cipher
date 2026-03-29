//! TLS Server Connection

use super::TlsServerConfig;
use crate::alert::Alert;
use crate::crypto::{construct_certificate_verify_message, sign_message};
use crate::error::TlsError;
use crate::extensions::{Extension, KeyShareEntry, KeyShareServerHello, SupportedVersions};
use crate::handshake::client_hello::CipherSuite;
use crate::handshake::{
    encode_handshake, parse_handshake, Certificate, CertificateVerify, ClientHello,
    EncryptedExtensions, Finished, HandshakeMessage, HandshakeState, ServerHello,
};
use crate::key::NamedGroup;
use crate::record::{ContentType, RecordLayer};
use std::io::{Read, Write};

/// TLS server connection state
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

/// TLS server connection
pub struct TlsServer<S: Read + Write> {
    /// Underlying stream
    stream: S,
    /// Configuration
    config: TlsServerConfig,
    /// Connection state
    state: ConnectionState,
    /// Handshake state machine
    handshake: HandshakeState,
    /// Record layer
    record: RecordLayer,
    /// Client's SNI hostname
    client_sni: Option<String>,
}

impl<S: Read + Write> TlsServer<S> {
    /// Create a new TLS server wrapping a stream
    pub fn new(stream: S, config: TlsServerConfig) -> Self {
        Self {
            stream,
            config,
            state: ConnectionState::Initial,
            handshake: HandshakeState::new_server(),
            record: RecordLayer::new(),
            client_sni: None,
        }
    }

    /// Accept a TLS connection (perform handshake)
    pub fn accept(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;

        // Receive ClientHello
        let client_hello = self.receive_client_hello()?;
        let ch_bytes = encode_handshake(&HandshakeMessage::ClientHello(client_hello.clone()));
        self.handshake.update_transcript(&ch_bytes);

        // Extract SNI
        self.client_sni = client_hello.extensions.iter().find_map(|ext| match ext {
            Extension::ServerName(sni) => sni.hostname().map(String::from),
            _ => None,
        });

        // Get client's key share
        let client_key_share = client_hello
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::KeyShareClientHello(ks) => ks.find(NamedGroup::X25519),
                _ => None,
            })
            .ok_or_else(|| TlsError::Handshake("no supported key share".into()))?;

        // Generate our key share and compute shared secret
        let our_key_pair = self
            .handshake
            .key_pair
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("no key pair".into()))?;
        let shared_secret = our_key_pair.compute_shared_secret(&client_key_share.key_exchange)?;

        // Build and send ServerHello
        let server_hello = self.build_server_hello(&client_hello)?;
        let sh_bytes = encode_handshake(&HandshakeMessage::ServerHello(server_hello));
        self.handshake.update_transcript(&sh_bytes);
        self.send_record(ContentType::Handshake, &sh_bytes)?;

        // Initialize key schedule with shared secret
        let transcript_hash = self.handshake.transcript_hash();
        if let Some(ref mut ks) = self.handshake.key_schedule {
            ks.derive_early_secret(None);
            ks.derive_handshake_secret(&shared_secret, &transcript_hash);
        }

        // Enable encryption
        self.record.enable_encryption(
            self.handshake.key_schedule.as_ref().unwrap(),
            true, // server
        )?;

        // Send encrypted handshake messages
        self.send_encrypted_handshake()?;

        // Receive client Finished
        self.receive_client_finished()?;

        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Send a record
    fn send_record(&mut self, content_type: ContentType, data: &[u8]) -> Result<(), TlsError> {
        let record = self.record.encode_record(content_type, data)?;
        self.stream
            .write_all(&record)
            .map_err(|e| TlsError::Io(e.to_string()))?;
        Ok(())
    }

    /// Receive a record
    fn receive_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        let mut header = [0u8; 5];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| TlsError::Io(e.to_string()))?;

        let length = u16::from_be_bytes([header[3], header[4]]) as usize;

        let mut body = vec![0u8; length];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| TlsError::Io(e.to_string()))?;

        let mut full_record = header.to_vec();
        full_record.extend_from_slice(&body);

        self.record.decode_record(&full_record)
    }

    /// Receive ClientHello
    fn receive_client_hello(&mut self) -> Result<ClientHello, TlsError> {
        let (content_type, data) = self.receive_record()?;

        if content_type != ContentType::Handshake {
            return Err(TlsError::Protocol("expected handshake record".into()));
        }

        match parse_handshake(&data)? {
            HandshakeMessage::ClientHello(ch) => Ok(ch),
            _ => Err(TlsError::Protocol("expected ClientHello".into())),
        }
    }

    /// Build ServerHello
    fn build_server_hello(&self, _client_hello: &ClientHello) -> Result<ServerHello, TlsError> {
        let key_pair = self
            .handshake
            .key_pair
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("no key pair".into()))?;

        let extensions = vec![
            Extension::SupportedVersions(SupportedVersions::server_hello()),
            Extension::KeyShareServerHello(KeyShareServerHello::new(KeyShareEntry::new(
                NamedGroup::X25519,
                key_pair.public_key().to_vec(),
            ))),
        ];

        Ok(ServerHello::new(
            vec![0; 32], // Session ID echo
            CipherSuite::Tls13Aes128GcmSha256,
            extensions,
        ))
    }

    /// Send encrypted handshake messages
    fn send_encrypted_handshake(&mut self) -> Result<(), TlsError> {
        // EncryptedExtensions
        let ee = EncryptedExtensions::empty();
        let ee_bytes = encode_handshake(&HandshakeMessage::EncryptedExtensions(ee));
        self.handshake.update_transcript(&ee_bytes);
        self.send_record(ContentType::Handshake, &ee_bytes)?;

        // Certificate
        let cert = Certificate::new(self.config.certificate_chain.clone());
        let cert_bytes = encode_handshake(&HandshakeMessage::Certificate(cert));
        self.handshake.update_transcript(&cert_bytes);
        self.send_record(ContentType::Handshake, &cert_bytes)?;

        // CertificateVerify
        let transcript_hash = self.handshake.transcript_hash();
        let cv = self.build_certificate_verify(&transcript_hash)?;
        let cv_bytes = encode_handshake(&HandshakeMessage::CertificateVerify(cv));
        self.handshake.update_transcript(&cv_bytes);
        self.send_record(ContentType::Handshake, &cv_bytes)?;

        // Finished
        let transcript_hash = self.handshake.transcript_hash();
        let key_schedule = self
            .handshake
            .key_schedule
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("no key schedule".into()))?;
        let verify_data =
            Finished::compute_verify_data(&key_schedule.server_finished_key, &transcript_hash);
        let finished = Finished::new(verify_data);
        let fin_bytes = encode_handshake(&HandshakeMessage::Finished(finished));
        self.handshake.update_transcript(&fin_bytes);
        self.send_record(ContentType::Handshake, &fin_bytes)?;

        Ok(())
    }

    /// Build CertificateVerify
    fn build_certificate_verify(
        &self,
        transcript_hash: &[u8],
    ) -> Result<CertificateVerify, TlsError> {
        // Construct the message to be signed
        let message = construct_certificate_verify_message(transcript_hash, true);

        // Sign with the server's private key
        let signature = sign_message(
            self.config.signature_scheme,
            &self.config.private_key,
            &message,
        )?;

        Ok(CertificateVerify::new(
            self.config.signature_scheme,
            signature,
        ))
    }

    /// Receive client Finished
    fn receive_client_finished(&mut self) -> Result<(), TlsError> {
        let (_, data) = self.receive_record()?;
        let msg = parse_handshake(&data)?;

        if let HandshakeMessage::Finished(fin) = msg {
            // Verify client's finished message
            let key_schedule = self
                .handshake
                .key_schedule
                .as_ref()
                .ok_or_else(|| TlsError::Handshake("no key schedule".into()))?;
            let transcript_hash = self.handshake.transcript_hash();

            if !fin.verify(&key_schedule.client_finished_key, &transcript_hash) {
                return Err(TlsError::Handshake("invalid client Finished".into()));
            }

            self.handshake.update_transcript(&data);

            // Derive application traffic keys
            let transcript_hash = self.handshake.transcript_hash();
            if let Some(ref mut ks) = self.handshake.key_schedule {
                ks.derive_application_secret(&transcript_hash);
            }

            Ok(())
        } else {
            Err(TlsError::Protocol("expected Finished".into()))
        }
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

    /// Get client's SNI hostname
    pub fn client_sni(&self) -> Option<&str> {
        self.client_sni.as_deref()
    }

    /// Close the connection
    pub fn close(&mut self) -> Result<(), TlsError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_server_creation() {
        let stream = Cursor::new(Vec::new());
        let config = TlsServerConfig {
            certificate_chain: vec![vec![1, 2, 3]],
            private_key: vec![4, 5, 6],
            signature_scheme: crate::extensions::SignatureScheme::EcdsaSecp256r1Sha256,
            alpn_protocols: Vec::new(),
            require_client_auth: false,
        };
        let server = TlsServer::new(stream, config);

        assert_eq!(server.state(), ConnectionState::Initial);
        assert!(!server.is_connected());
    }
}
