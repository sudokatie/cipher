//! Handshake state machine

use super::client_hello::CipherSuite;
use super::{
    Certificate, CertificateRequest, CertificateVerify, ClientHello, EncryptedExtensions, Finished,
    ServerHello,
};
use crate::crypto::{Sha256, TranscriptHash};
use crate::error::TlsError;
use crate::extensions::{
    Extension, KeyShareClientHello, KeyShareEntry, ServerNameList, SignatureAlgorithms,
    SignatureScheme, SupportedGroups, SupportedVersions,
};
use crate::key::{KeySchedule, NamedGroup, X25519KeyPair};

/// Role in the handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Client,
    Server,
}

/// Handshake state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    /// Initial state
    Start,
    /// Waiting for ServerHello
    WaitServerHello,
    /// Waiting for EncryptedExtensions
    WaitEncryptedExtensions,
    /// Waiting for CertificateRequest or Certificate
    WaitCertificateOrRequest,
    /// Waiting for CertificateVerify
    WaitCertificateVerify,
    /// Waiting for Finished
    WaitFinished,
    /// Handshake complete
    Connected,
    /// Error state
    Error,
}

/// Handshake state machine
pub struct HandshakeState {
    /// Role (client or server)
    pub role: HandshakeRole,
    /// Current stage
    pub stage: HandshakeStage,
    /// Transcript hash
    pub transcript: TranscriptHash<Sha256>,
    /// Key schedule
    pub key_schedule: Option<KeySchedule>,
    /// Our key pair
    pub key_pair: Option<X25519KeyPair>,
    /// Selected cipher suite
    pub cipher_suite: Option<CipherSuite>,
    /// Server name (SNI)
    pub server_name: Option<String>,
    /// Peer's certificate chain
    pub peer_certificates: Vec<Vec<u8>>,
    /// Signature algorithm used in CertificateVerify
    pub certificate_verify_algorithm: Option<SignatureScheme>,
    /// Negotiated ALPN protocol
    pub alpn_protocol: Option<Vec<u8>>,
    /// Whether client certificate was requested
    pub client_auth_requested: bool,
    /// Certificate request context (if client auth was requested)
    pub certificate_request_context: Option<Vec<u8>>,
}

impl HandshakeState {
    /// Create a new client handshake state
    pub fn new_client(server_name: Option<&str>) -> Self {
        Self {
            role: HandshakeRole::Client,
            stage: HandshakeStage::Start,
            transcript: TranscriptHash::new(),
            key_schedule: None,
            key_pair: Some(X25519KeyPair::generate()),
            cipher_suite: None,
            server_name: server_name.map(String::from),
            peer_certificates: Vec::new(),
            certificate_verify_algorithm: None,
            alpn_protocol: None,
            client_auth_requested: false,
            certificate_request_context: None,
        }
    }

    /// Create a new server handshake state
    pub fn new_server() -> Self {
        Self {
            role: HandshakeRole::Server,
            stage: HandshakeStage::Start,
            transcript: TranscriptHash::new(),
            key_schedule: None,
            key_pair: Some(X25519KeyPair::generate()),
            cipher_suite: None,
            server_name: None,
            peer_certificates: Vec::new(),
            certificate_verify_algorithm: None,
            alpn_protocol: None,
            client_auth_requested: false,
            certificate_request_context: None,
        }
    }

    /// Build ClientHello message
    pub fn build_client_hello(&mut self) -> Result<ClientHello, TlsError> {
        let key_pair = self
            .key_pair
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("no key pair".into()))?;

        let mut extensions = vec![
            Extension::SupportedVersions(SupportedVersions::client_hello()),
            Extension::SignatureAlgorithms(SignatureAlgorithms::default_algorithms()),
            Extension::SupportedGroups(SupportedGroups::default_groups()),
            Extension::KeyShareClientHello(KeyShareClientHello::new(vec![KeyShareEntry::new(
                NamedGroup::X25519,
                key_pair.public_key().to_vec(),
            )])),
        ];

        if let Some(ref name) = self.server_name {
            extensions.insert(0, Extension::ServerName(ServerNameList::new(name)));
        }

        let client_hello = ClientHello::new(extensions);
        self.stage = HandshakeStage::WaitServerHello;

        Ok(client_hello)
    }

    /// Process ServerHello message (client side)
    pub fn process_server_hello(&mut self, server_hello: &ServerHello) -> Result<(), TlsError> {
        if self.role != HandshakeRole::Client {
            return Err(TlsError::Handshake("unexpected ServerHello".into()));
        }

        if self.stage != HandshakeStage::WaitServerHello {
            return Err(TlsError::Handshake("unexpected ServerHello".into()));
        }

        // Check for TLS 1.3
        let has_tls_1_3 = server_hello
            .extensions
            .iter()
            .any(|ext| matches!(ext, Extension::SupportedVersions(sv) if sv.supports_tls_1_3()));

        if !has_tls_1_3 {
            return Err(TlsError::Handshake(
                "server does not support TLS 1.3".into(),
            ));
        }

        // Get server's key share
        let server_key_share = server_hello
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::KeyShareServerHello(ks) => Some(ks),
                _ => None,
            })
            .ok_or_else(|| TlsError::Handshake("no key_share in ServerHello".into()))?;

        // Compute shared secret
        let key_pair = self
            .key_pair
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("no key pair".into()))?;

        let shared_secret = key_pair.compute_shared_secret(&server_key_share.entry.key_exchange)?;

        // Initialize key schedule
        let mut key_schedule = KeySchedule::new();
        key_schedule.derive_early_secret(None);

        let transcript_hash = self.transcript.current_hash();
        key_schedule.derive_handshake_secret(&shared_secret, &transcript_hash);

        self.key_schedule = Some(key_schedule);
        self.cipher_suite = Some(server_hello.cipher_suite);
        self.stage = HandshakeStage::WaitEncryptedExtensions;

        Ok(())
    }

    /// Process EncryptedExtensions (client side)
    pub fn process_encrypted_extensions(
        &mut self,
        ee: &EncryptedExtensions,
    ) -> Result<(), TlsError> {
        if self.stage != HandshakeStage::WaitEncryptedExtensions {
            return Err(TlsError::Handshake("unexpected EncryptedExtensions".into()));
        }

        // Extract ALPN if present
        for ext in &ee.extensions {
            if let Extension::AlpnServerHello(alpn) = ext {
                self.alpn_protocol = Some(alpn.protocol.clone());
            }
        }

        self.stage = HandshakeStage::WaitCertificateOrRequest;
        Ok(())
    }

    /// Process CertificateRequest (client side)
    pub fn process_certificate_request(&mut self, cr: &CertificateRequest) -> Result<(), TlsError> {
        if self.stage != HandshakeStage::WaitCertificateOrRequest {
            return Err(TlsError::Handshake("unexpected CertificateRequest".into()));
        }

        self.client_auth_requested = true;
        self.certificate_request_context = Some(cr.certificate_request_context.clone());

        // Still waiting for server's Certificate next
        Ok(())
    }

    /// Process Certificate (client side)
    pub fn process_certificate(&mut self, cert: &Certificate) -> Result<(), TlsError> {
        if self.stage != HandshakeStage::WaitCertificateOrRequest {
            return Err(TlsError::Handshake("unexpected Certificate".into()));
        }

        self.peer_certificates = cert
            .certificate_list
            .iter()
            .map(|e| e.cert_data.clone())
            .collect();

        self.stage = HandshakeStage::WaitCertificateVerify;
        Ok(())
    }

    /// Process CertificateVerify (client side)
    ///
    /// Note: Signature verification should be done by the caller before
    /// calling this method, as it requires access to the parsed certificate
    /// which is not stored in the state machine.
    pub fn process_certificate_verify(&mut self, cv: &CertificateVerify) -> Result<(), TlsError> {
        if self.stage != HandshakeStage::WaitCertificateVerify {
            return Err(TlsError::Handshake("unexpected CertificateVerify".into()));
        }

        // Store the signature algorithm for reference
        self.certificate_verify_algorithm = Some(cv.algorithm);
        self.stage = HandshakeStage::WaitFinished;
        Ok(())
    }

    /// Process Finished (client side)
    pub fn process_finished(&mut self, finished: &Finished) -> Result<(), TlsError> {
        if self.stage != HandshakeStage::WaitFinished {
            return Err(TlsError::Handshake("unexpected Finished".into()));
        }

        let key_schedule = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| TlsError::Handshake("no key schedule".into()))?;

        // Verify server's finished message
        let transcript_hash = self.transcript.current_hash();
        if !finished.verify(&key_schedule.server_finished_key, &transcript_hash) {
            return Err(TlsError::Handshake("invalid server Finished".into()));
        }

        self.stage = HandshakeStage::Connected;
        Ok(())
    }

    /// Update transcript with a handshake message
    pub fn update_transcript(&mut self, data: &[u8]) {
        self.transcript.update(data);
    }

    /// Get current transcript hash
    pub fn transcript_hash(&self) -> Vec<u8> {
        self.transcript.current_hash()
    }

    /// Check if handshake is complete
    pub fn is_connected(&self) -> bool {
        self.stage == HandshakeStage::Connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_handshake_state() {
        let mut state = HandshakeState::new_client(Some("example.com"));
        assert_eq!(state.role, HandshakeRole::Client);
        assert_eq!(state.stage, HandshakeStage::Start);

        let ch = state.build_client_hello().unwrap();
        assert_eq!(state.stage, HandshakeStage::WaitServerHello);
        assert!(!ch.extensions.is_empty());
    }

    #[test]
    fn test_server_handshake_state() {
        let state = HandshakeState::new_server();
        assert_eq!(state.role, HandshakeRole::Server);
        assert_eq!(state.stage, HandshakeStage::Start);
    }
}
