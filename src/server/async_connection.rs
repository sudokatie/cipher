//! Async TLS Server Connection

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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Async TLS server connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Handshaking,
    Connected,
    Closed,
    Error,
}

/// Async TLS server connection
pub struct AsyncTlsServer<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsServerConfig,
    state: ConnectionState,
    handshake: HandshakeState,
    record: RecordLayer,
    client_sni: Option<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsServer<S> {
    /// Create a new async TLS server
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

    /// Accept a TLS connection asynchronously
    pub async fn accept(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Handshaking;

        // Receive ClientHello
        let client_hello = self.receive_client_hello().await?;
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

        // Compute shared secret
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
        self.send_record(ContentType::Handshake, &sh_bytes).await?;

        // Initialize key schedule
        let transcript_hash = self.handshake.transcript_hash();
        if let Some(ref mut ks) = self.handshake.key_schedule {
            ks.derive_early_secret(None);
            ks.derive_handshake_secret(&shared_secret, &transcript_hash);
        }

        // Enable encryption
        self.record
            .enable_encryption(self.handshake.key_schedule.as_ref().unwrap(), true)?;

        // Send encrypted handshake messages
        self.send_encrypted_handshake().await?;

        // Receive client Finished
        self.receive_client_finished().await?;

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

    async fn receive_client_hello(&mut self) -> Result<ClientHello, TlsError> {
        let (content_type, data) = self.receive_record().await?;
        if content_type != ContentType::Handshake {
            return Err(TlsError::Protocol("expected handshake record".into()));
        }
        match parse_handshake(&data)? {
            HandshakeMessage::ClientHello(ch) => Ok(ch),
            _ => Err(TlsError::Protocol("expected ClientHello".into())),
        }
    }

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
            vec![0; 32],
            CipherSuite::Tls13Aes128GcmSha256,
            extensions,
        ))
    }

    async fn send_encrypted_handshake(&mut self) -> Result<(), TlsError> {
        // EncryptedExtensions
        let ee = EncryptedExtensions::empty();
        let ee_bytes = encode_handshake(&HandshakeMessage::EncryptedExtensions(ee));
        self.handshake.update_transcript(&ee_bytes);
        self.send_record(ContentType::Handshake, &ee_bytes).await?;

        // Certificate
        let cert = Certificate::new(self.config.certificate_chain.clone());
        let cert_bytes = encode_handshake(&HandshakeMessage::Certificate(cert));
        self.handshake.update_transcript(&cert_bytes);
        self.send_record(ContentType::Handshake, &cert_bytes)
            .await?;

        // CertificateVerify
        let transcript_hash = self.handshake.transcript_hash();
        let cv = self.build_certificate_verify(&transcript_hash)?;
        let cv_bytes = encode_handshake(&HandshakeMessage::CertificateVerify(cv));
        self.handshake.update_transcript(&cv_bytes);
        self.send_record(ContentType::Handshake, &cv_bytes).await?;

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
        self.send_record(ContentType::Handshake, &fin_bytes).await?;

        Ok(())
    }

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

    async fn receive_client_finished(&mut self) -> Result<(), TlsError> {
        let (_, data) = self.receive_record().await?;
        let msg = parse_handshake(&data)?;

        if let HandshakeMessage::Finished(fin) = msg {
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

            let transcript_hash = self.handshake.transcript_hash();
            if let Some(ref mut ks) = self.handshake.key_schedule {
                ks.derive_application_secret(&transcript_hash);
            }

            Ok(())
        } else {
            Err(TlsError::Protocol("expected Finished".into()))
        }
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

    /// Get client's SNI hostname
    pub fn client_sni(&self) -> Option<&str> {
        self.client_sni.as_deref()
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<(), TlsError> {
        let alert = Alert::close_notify();
        self.send_record(ContentType::Alert, &alert.encode())
            .await?;
        self.state = ConnectionState::Closed;
        Ok(())
    }
}

/// TLS Listener wrapper
pub struct TlsListener<L> {
    listener: L,
    config: TlsServerConfig,
}

impl<L> TlsListener<L> {
    /// Create a new TLS listener
    pub fn new(listener: L, config: TlsServerConfig) -> Self {
        Self { listener, config }
    }

    /// Get the underlying listener
    pub fn inner(&self) -> &L {
        &self.listener
    }
}

use tokio::net::{TcpListener, TcpStream};

impl TlsListener<TcpListener> {
    /// Bind to an address
    pub async fn bind(addr: &str, config: TlsServerConfig) -> Result<Self, TlsError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| TlsError::Io(e.to_string()))?;
        Ok(Self::new(listener, config))
    }

    /// Accept a new TLS connection
    pub async fn accept(&self) -> Result<AsyncTlsServer<TcpStream>, TlsError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| TlsError::Io(e.to_string()))?;
        let mut server = AsyncTlsServer::new(stream, self.config.clone());
        server.accept().await?;
        Ok(server)
    }
}
