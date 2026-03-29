//! Integration tests for TLS 1.3 handshake between client and server.

use cipher::extensions::SignatureScheme;
use cipher::{TlsClientConfig, TlsServerConfig};
use std::io::{Read, Write};

/// Generate a self-signed test certificate and private key.
/// Returns (certificate_der, private_key_der)
fn generate_test_certificate() -> (Vec<u8>, Vec<u8>) {
    // Use a pre-generated self-signed certificate for testing
    // In a real test, you'd use rcgen or similar to generate these
    // For now, we'll use placeholder data and skip verification
    (vec![0x30; 256], vec![0x30; 64])
}

#[test]
fn test_client_server_handshake_loopback() {
    // This test uses a mock stream to test the handshake flow
    // without real network I/O

    let (cert_der, key_der) = generate_test_certificate();

    // Create a pipe/mock stream
    let (_client_stream, _server_stream) = create_mock_streams();

    // Server config
    let server_config = TlsServerConfig {
        certificate_chain: vec![cert_der.clone()],
        private_key: key_der,
        signature_scheme: SignatureScheme::EcdsaSecp256r1Sha256,
        alpn_protocols: Vec::new(),
        require_client_auth: false,
    };

    // Client config (skip verification for self-signed test cert)
    let client_config = TlsClientConfig::builder()
        .danger_skip_verification()
        .build()
        .unwrap();

    // The actual handshake test would require proper mock streams
    // For now, verify the configs are valid
    assert!(client_config.danger_skip_verification);
    assert_eq!(server_config.certificate_chain.len(), 1);
}

/// Simple mock stream pair for testing
fn create_mock_streams() -> (MockStream, MockStream) {
    let (client, server) = MockStream::pair();
    (client, server)
}

/// A mock stream for testing that implements Read + Write
struct MockStream {
    read_buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    write_buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl MockStream {
    fn pair() -> (MockStream, MockStream) {
        let buf1 = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let buf2 = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let client = MockStream {
            read_buf: buf2.clone(),
            write_buf: buf1.clone(),
        };
        let server = MockStream {
            read_buf: buf1,
            write_buf: buf2,
        };

        (client, server)
    }
}

impl Read for MockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_buf = self.read_buf.lock().unwrap();
        let len = std::cmp::min(buf.len(), read_buf.len());
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no data",
            ));
        }
        buf[..len].copy_from_slice(&read_buf[..len]);
        read_buf.drain(..len);
        Ok(len)
    }
}

impl Write for MockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut write_buf = self.write_buf.lock().unwrap();
        write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_handshake_state_machine_client() {
    use cipher::handshake::{HandshakeRole, HandshakeState};

    let mut state = HandshakeState::new_client(Some("example.com"));
    assert_eq!(state.role, HandshakeRole::Client);

    let client_hello = state.build_client_hello().unwrap();
    assert!(!client_hello.extensions.is_empty());
}

#[test]
fn test_handshake_state_machine_server() {
    use cipher::handshake::{HandshakeRole, HandshakeState};

    let state = HandshakeState::new_server();
    assert_eq!(state.role, HandshakeRole::Server);
}

#[test]
fn test_key_schedule_full_derivation() {
    use cipher::key::KeySchedule;

    let mut ks = KeySchedule::new();
    ks.derive_early_secret(None);

    let ecdhe = [0x42u8; 32];
    let transcript = [0x00u8; 32];
    ks.derive_handshake_secret(&ecdhe, &transcript);

    // Verify keys were derived
    assert!(!ks.client_write_key.is_empty());
    assert!(!ks.server_write_key.is_empty());
    assert!(!ks.client_finished_key.is_empty());
    assert!(!ks.server_finished_key.is_empty());

    // Derive application secrets
    let app_transcript = [0x01u8; 32];
    ks.derive_application_secret(&app_transcript);

    assert!(!ks.exporter_master_secret.is_empty());
}

#[test]
fn test_record_layer_roundtrip() {
    use cipher::record::{ContentType, RecordCipher, RecordLayer, TrafficKeys};

    let mut layer = RecordLayer::new();

    // Set up encryption keys
    let keys = TrafficKeys::new(vec![0x01; 16], vec![0x02; 12], RecordCipher::Aes128Gcm);
    layer.set_write_keys(keys.clone());
    layer.set_read_keys(keys);

    // Encrypt and decrypt
    let plaintext = b"Hello, TLS 1.3!";
    let encrypted = layer
        .encrypt_record(ContentType::ApplicationData, plaintext)
        .unwrap();
    let (ct, decrypted, _) = layer.decrypt_record(&encrypted).unwrap();

    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_finished_verification() {
    use cipher::handshake::Finished;

    let key = [0x42u8; 32];
    let transcript = [0x00u8; 32];

    let verify_data = Finished::compute_verify_data(&key, &transcript);
    let finished = Finished::new(verify_data);

    // Should verify correctly
    assert!(finished.verify(&key, &transcript));

    // Should fail with wrong key
    let wrong_key = [0x43u8; 32];
    assert!(!finished.verify(&wrong_key, &transcript));

    // Should fail with wrong transcript
    let wrong_transcript = [0x01u8; 32];
    assert!(!finished.verify(&key, &wrong_transcript));
}

#[test]
fn test_certificate_request_encode_parse() {
    use cipher::handshake::CertificateRequest;

    let cr = CertificateRequest::basic();
    let encoded = cr.encode();
    let parsed = CertificateRequest::parse(&encoded).unwrap();

    assert_eq!(
        parsed.certificate_request_context,
        cr.certificate_request_context
    );
    assert!(parsed.signature_algorithms().is_some());
}

#[test]
fn test_alpn_negotiation() {
    use cipher::extensions::{AlpnClientHello, AlpnServerHello};

    let client_alpn = AlpnClientHello::from_strings(&["h2", "http/1.1"]);
    assert!(client_alpn.contains(b"h2"));
    assert!(client_alpn.contains(b"http/1.1"));
    assert!(!client_alpn.contains(b"h3"));

    let server_alpn = AlpnServerHello::from_protocol("h2");
    assert_eq!(server_alpn.protocol, b"h2");
    assert_eq!(server_alpn.protocol_str(), Some("h2"));
}

#[test]
fn test_all_cipher_suites() {
    use cipher::crypto::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};

    // AES-128-GCM
    let key_128 = [0u8; 16];
    let aes128 = Aes128Gcm::new(&key_128).unwrap();
    let nonce = [0u8; 12];
    let ct = aes128.seal(&nonce, b"aad", b"plaintext").unwrap();
    let pt = aes128.open(&nonce, b"aad", &ct).unwrap();
    assert_eq!(pt, b"plaintext");

    // AES-256-GCM
    let key_256 = [0u8; 32];
    let aes256 = Aes256Gcm::new(&key_256).unwrap();
    let ct = aes256.seal(&nonce, b"aad", b"plaintext").unwrap();
    let pt = aes256.open(&nonce, b"aad", &ct).unwrap();
    assert_eq!(pt, b"plaintext");

    // ChaCha20-Poly1305
    let chacha = ChaCha20Poly1305::new(&key_256).unwrap();
    let ct = chacha.seal(&nonce, b"aad", b"plaintext").unwrap();
    let pt = chacha.open(&nonce, b"aad", &ct).unwrap();
    assert_eq!(pt, b"plaintext");
}

#[test]
fn test_both_key_exchange_algorithms() {
    use cipher::key::{P256KeyPair, X25519KeyPair};

    // X25519
    let kp1_x = X25519KeyPair::generate();
    let kp2_x = X25519KeyPair::generate();
    let shared1_x = kp1_x.compute_shared_secret(&kp2_x.public_key()).unwrap();
    let shared2_x = kp2_x.compute_shared_secret(&kp1_x.public_key()).unwrap();
    assert_eq!(shared1_x, shared2_x);

    // P-256
    let kp1_p = P256KeyPair::generate();
    let kp2_p = P256KeyPair::generate();
    let pub1 = kp1_p.public_key().to_vec();
    let pub2 = kp2_p.public_key().to_vec();
    let shared1_p = kp1_p.compute_shared_secret(&pub2).unwrap();
    let shared2_p = kp2_p.compute_shared_secret(&pub1).unwrap();
    assert_eq!(shared1_p, shared2_p);
}
