//! Async TLS Client Connection

use super::TlsClientConfig;
use crate::alert::Alert;
use crate::cert::{Certificate as ParsedCert, CertificateValidator};
use crate::crypto::{construct_certificate_verify_message, verify_signature};
use crate::error::TlsError;
use crate::handshake::{
    encode_handshake, parse_handshake, Finished, HandshakeMessage, HandshakeState, ServerHello,
};
use crate::record::{ContentType, RecordLayer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Async TLS client connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Handshaking,
    Connected,
    Closed,
    Error,
}

/// Async TLS client connection
pub struct AsyncTlsClient<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsClientConfig,
    state: ConnectionState,
    handshake: HandshakeState,
    record: RecordLayer,
    server_name: Option<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsClient<S> {
    /// Create a new async TLS client
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

    /// Perform the TLS handshake asynchronously
    pub async fn handshake(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;

        // Send ClientHello
        let client_hello = self.handshake.build_client_hello()?;
        let ch_bytes = encode_handshake(&HandshakeMessage::ClientHello(client_hello));
        self.handshake.update_transcript(&ch_bytes);
        self.send_record(ContentType::Handshake, &ch_bytes).await?;

        // Receive ServerHello
        let server_hello = self.receive_server_hello().await?;
        let sh_bytes = encode_handshake(&HandshakeMessage::ServerHello(server_hello.clone()));
        self.handshake.update_transcript(&sh_bytes);
        self.handshake.process_server_hello(&server_hello)?;

        // Switch to encrypted mode
        self.record
            .enable_encryption(self.handshake.key_schedule.as_ref().unwrap(), false)?;

        // Receive encrypted handshake messages
        self.receive_encrypted_handshake().await?;

        // Send client Finished
        self.send_client_finished().await?;

        self.state = ConnectionState::Connected;
        Ok(())
    }

    async fn send_record(
        &mut self,
        content_type: ContentType,
        data: &[u8],
    ) -> Result<(), TlsError> {
        let record = self.record.encode_record(content_type, data)?;
        self.stream
            .write_all(&record)
            .await
            .map_err(|e| TlsError::Io(e.to_string()))?;
        Ok(())
    }

    async fn receive_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        let mut header = [0u8; 5];
        self.stream
            .read_exact(&mut header)
            .await
            .map_err(|e| TlsError::Io(e.to_string()))?;

        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; length];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(|e| TlsError::Io(e.to_string()))?;

        let mut full_record = header.to_vec();
        full_record.extend_from_slice(&body);

        self.record.decode_record(&full_record)
    }

    async fn receive_server_hello(&mut self) -> Result<ServerHello, TlsError> {
        let (content_type, data) = self.receive_record().await?;
        if content_type != ContentType::Handshake {
            return Err(TlsError::Protocol("expected handshake record".into()));
        }
        match parse_handshake(&data)? {
            HandshakeMessage::ServerHello(sh) => Ok(sh),
            _ => Err(TlsError::Protocol("expected ServerHello".into())),
        }
    }

    async fn receive_encrypted_handshake(&mut self) -> Result<(), TlsError> {
        // EncryptedExtensions
        let (_, data) = self.receive_record().await?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::EncryptedExtensions(ee) = msg {
            self.handshake.update_transcript(&data);
            self.handshake.process_encrypted_extensions(&ee)?;
        } else {
            return Err(TlsError::Protocol("expected EncryptedExtensions".into()));
        }

        // Certificate
        let (_, data) = self.receive_record().await?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::Certificate(cert) = msg {
            self.handshake.update_transcript(&data);

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
        let (_, data) = self.receive_record().await?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::CertificateVerify(cv) = msg {
            let transcript_hash = self.handshake.transcript_hash();

            if !self.config.danger_skip_verification {
                if let Some(cert_der) = self.handshake.peer_certificates.first() {
                    let cert = ParsedCert::from_der(cert_der)?;
                    let message = construct_certificate_verify_message(&transcript_hash, true);
                    verify_signature(
                        cv.algorithm,
                        cert.public_key_bytes(),
                        &message,
                        &cv.signature,
                    )?;
                }
            }

            self.handshake.update_transcript(&data);
            self.handshake.process_certificate_verify(&cv)?;
        } else {
            return Err(TlsError::Protocol("expected CertificateVerify".into()));
        }

        // Finished
        let (_, data) = self.receive_record().await?;
        let msg = parse_handshake(&data)?;
        if let HandshakeMessage::Finished(fin) = msg {
            self.handshake.update_transcript(&data);
            self.handshake.process_finished(&fin)?;
        } else {
            return Err(TlsError::Protocol("expected Finished".into()));
        }

        Ok(())
    }

    async fn send_client_finished(&mut self) -> Result<(), TlsError> {
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
        self.send_record(ContentType::Handshake, &data).await?;

        let transcript_hash = self.handshake.transcript_hash();
        if let Some(ref mut ks) = self.handshake.key_schedule {
            ks.derive_application_secret(&transcript_hash);
        }

        Ok(())
    }

    /// Read application data asynchronously
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::Handshake("not connected".into()));
        }

        let (content_type, data) = self.receive_record().await?;

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
                    Ok(0)
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

    /// Write application data asynchronously
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::Handshake("not connected".into()));
        }

        self.send_record(ContentType::ApplicationData, data).await?;
        Ok(data.len())
    }

    /// Write all data
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.write(data).await?;
        Ok(())
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
    pub async fn close(&mut self) -> Result<(), TlsError> {
        let alert = Alert::close_notify();
        self.send_record(ContentType::Alert, &alert.encode())
            .await?;
        self.state = ConnectionState::Closed;
        Ok(())
    }

    /// Get peer certificates
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.handshake.peer_certificates
    }
}

/// Connect to a TLS server
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    config: TlsClientConfig,
    server_name: &str,
) -> Result<AsyncTlsClient<S>, TlsError> {
    let mut client = AsyncTlsClient::new(stream, config, server_name);
    client.handshake().await?;
    Ok(client)
}
