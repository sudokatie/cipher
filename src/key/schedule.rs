//! TLS 1.3 Key Schedule.
//!
//! Implements the key derivation schedule from RFC 8446 Section 7.1.

use crate::crypto::{
    derive_secret_sha256, hkdf_expand_label_sha256, hkdf_extract_sha256, HashAlgorithm,
    Sha256 as Sha256Hash,
};

/// TLS 1.3 Key Schedule state.
///
/// Tracks the progression through the key schedule:
/// Early Secret -> Handshake Secret -> Master Secret
pub struct KeySchedule {
    /// Current secret (Early, Handshake, or Master)
    current_secret: [u8; 32],

    /// Current stage
    stage: KeyScheduleStage,

    // Derived keys (populated during handshake)
    /// Client write key (handshake or application)
    pub client_write_key: Vec<u8>,
    /// Client write IV
    pub client_write_iv: Vec<u8>,
    /// Server write key
    pub server_write_key: Vec<u8>,
    /// Server write IV  
    pub server_write_iv: Vec<u8>,
    /// Client finished key
    pub client_finished_key: Vec<u8>,
    /// Server finished key
    pub server_finished_key: Vec<u8>,
    /// Exporter master secret (for key exporters)
    pub exporter_master_secret: Vec<u8>,
}

/// Stage of the key schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScheduleStage {
    /// Initial state
    Initial,
    /// Early secret derived (from PSK or zeros)
    EarlySecret,
    /// Handshake secret derived (from ECDHE)
    HandshakeSecret,
    /// Master secret derived
    MasterSecret,
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

impl KeySchedule {
    /// Create a new key schedule.
    pub fn new() -> Self {
        KeySchedule {
            current_secret: [0u8; 32],
            stage: KeyScheduleStage::Initial,
            client_write_key: Vec::new(),
            client_write_iv: Vec::new(),
            server_write_key: Vec::new(),
            server_write_iv: Vec::new(),
            client_finished_key: Vec::new(),
            server_finished_key: Vec::new(),
            exporter_master_secret: Vec::new(),
        }
    }

    /// Derive early secret from optional PSK.
    pub fn derive_early_secret(&mut self, psk: Option<&[u8]>) {
        let zero_salt = [0u8; 32];
        let ikm = psk.unwrap_or(&[0u8; 32]);
        self.current_secret = hkdf_extract_sha256(&zero_salt, ikm);
        self.stage = KeyScheduleStage::EarlySecret;
    }

    /// Create a new key schedule with PSK.
    ///
    /// Starts at the Initial stage with the early secret derived from
    /// an optional PSK (or zeros if no PSK).
    pub fn with_psk(psk: Option<&[u8]>) -> Self {
        let zero_salt = [0u8; 32];
        let ikm = psk.unwrap_or(&[0u8; 32]);

        let early_secret = hkdf_extract_sha256(&zero_salt, ikm);

        KeySchedule {
            current_secret: early_secret,
            stage: KeyScheduleStage::EarlySecret,
            client_write_key: Vec::new(),
            client_write_iv: Vec::new(),
            server_write_key: Vec::new(),
            server_write_iv: Vec::new(),
            client_finished_key: Vec::new(),
            server_finished_key: Vec::new(),
            exporter_master_secret: Vec::new(),
        }
    }

    /// Get the current stage.
    pub fn stage(&self) -> KeyScheduleStage {
        self.stage
    }

    /// Derive the handshake secret from ECDHE shared secret.
    ///
    /// Also derives handshake traffic keys.
    pub fn derive_handshake_secret(&mut self, ecdhe_secret: &[u8], transcript_hash: &[u8]) {
        // Derive-Secret(Early Secret, "derived", "")
        let empty_hash = Sha256Hash::hash(&[]);
        let derived = derive_secret_sha256(&self.current_secret, "derived", &empty_hash);

        // HKDF-Extract(Derived, ECDHE)
        let handshake_secret = hkdf_extract_sha256(&derived, ecdhe_secret);
        self.current_secret = handshake_secret;
        self.stage = KeyScheduleStage::HandshakeSecret;

        // Derive handshake traffic secrets
        let client_hs_secret =
            derive_secret_sha256(&self.current_secret, "c hs traffic", transcript_hash);
        let server_hs_secret =
            derive_secret_sha256(&self.current_secret, "s hs traffic", transcript_hash);

        // Derive keys and IVs (16-byte key for AES-128-GCM)
        self.client_write_key = derive_traffic_key(&client_hs_secret, 16);
        self.client_write_iv = derive_traffic_iv(&client_hs_secret).to_vec();
        self.server_write_key = derive_traffic_key(&server_hs_secret, 16);
        self.server_write_iv = derive_traffic_iv(&server_hs_secret).to_vec();

        // Derive finished keys
        self.client_finished_key = derive_finished_key(&client_hs_secret).to_vec();
        self.server_finished_key = derive_finished_key(&server_hs_secret).to_vec();
    }

    /// Derive application traffic secrets and keys.
    pub fn derive_application_secret(&mut self, transcript_hash: &[u8]) {
        // First derive master secret
        let empty_hash = Sha256Hash::hash(&[]);
        let derived = derive_secret_sha256(&self.current_secret, "derived", &empty_hash);
        let master_secret = hkdf_extract_sha256(&derived, &[0u8; 32]);
        self.current_secret = master_secret;
        self.stage = KeyScheduleStage::MasterSecret;

        // Derive application traffic secrets
        let client_app_secret =
            derive_secret_sha256(&self.current_secret, "c ap traffic", transcript_hash);
        let server_app_secret =
            derive_secret_sha256(&self.current_secret, "s ap traffic", transcript_hash);

        // Derive exporter master secret
        let exp_master = derive_secret_sha256(&self.current_secret, "exp master", transcript_hash);
        self.exporter_master_secret = exp_master.to_vec();

        // Derive keys and IVs
        self.client_write_key = derive_traffic_key(&client_app_secret, 16);
        self.client_write_iv = derive_traffic_iv(&client_app_secret).to_vec();
        self.server_write_key = derive_traffic_key(&server_app_secret, 16);
        self.server_write_iv = derive_traffic_iv(&server_app_secret).to_vec();
    }

    /// Derive the handshake secret from ECDHE shared secret (legacy API).
    ///
    /// Must be called after new() and before derive_master_secret().
    pub fn derive_handshake_secret_legacy(
        &mut self,
        ecdhe_secret: &[u8],
    ) -> Result<(), &'static str> {
        if self.stage != KeyScheduleStage::EarlySecret {
            return Err("must be at EarlySecret stage");
        }

        // Derive-Secret(Early Secret, "derived", "")
        let empty_hash = Sha256Hash::hash(&[]);
        let derived = derive_secret_sha256(&self.current_secret, "derived", &empty_hash);

        // HKDF-Extract(Derived, ECDHE)
        let handshake_secret = hkdf_extract_sha256(&derived, ecdhe_secret);

        self.current_secret = handshake_secret;
        self.stage = KeyScheduleStage::HandshakeSecret;

        Ok(())
    }

    /// Derive the master secret.
    ///
    /// Must be called after derive_handshake_secret().
    pub fn derive_master_secret(&mut self) -> Result<(), &'static str> {
        if self.stage != KeyScheduleStage::HandshakeSecret {
            return Err("must be at HandshakeSecret stage");
        }

        // Derive-Secret(Handshake Secret, "derived", "")
        let empty_hash = Sha256Hash::hash(&[]);
        let derived = derive_secret_sha256(&self.current_secret, "derived", &empty_hash);

        // HKDF-Extract(Derived, 0)
        let master_secret = hkdf_extract_sha256(&derived, &[0u8; 32]);

        self.current_secret = master_secret;
        self.stage = KeyScheduleStage::MasterSecret;

        Ok(())
    }

    /// Derive client handshake traffic secret.
    pub fn client_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<[u8; 32], &'static str> {
        if self.stage != KeyScheduleStage::HandshakeSecret {
            return Err("must be at HandshakeSecret stage");
        }

        Ok(derive_secret_sha256(
            &self.current_secret,
            "c hs traffic",
            transcript_hash,
        ))
    }

    /// Derive server handshake traffic secret.
    pub fn server_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<[u8; 32], &'static str> {
        if self.stage != KeyScheduleStage::HandshakeSecret {
            return Err("must be at HandshakeSecret stage");
        }

        Ok(derive_secret_sha256(
            &self.current_secret,
            "s hs traffic",
            transcript_hash,
        ))
    }

    /// Derive client application traffic secret.
    pub fn client_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<[u8; 32], &'static str> {
        if self.stage != KeyScheduleStage::MasterSecret {
            return Err("must be at MasterSecret stage");
        }

        Ok(derive_secret_sha256(
            &self.current_secret,
            "c ap traffic",
            transcript_hash,
        ))
    }

    /// Derive server application traffic secret.
    pub fn server_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> Result<[u8; 32], &'static str> {
        if self.stage != KeyScheduleStage::MasterSecret {
            return Err("must be at MasterSecret stage");
        }

        Ok(derive_secret_sha256(
            &self.current_secret,
            "s ap traffic",
            transcript_hash,
        ))
    }
}

/// Derive a traffic key from a traffic secret.
pub fn derive_traffic_key(secret: &[u8; 32], key_len: usize) -> Vec<u8> {
    hkdf_expand_label_sha256(secret, "key", &[], key_len)
}

/// Derive a traffic IV from a traffic secret.
pub fn derive_traffic_iv(secret: &[u8; 32]) -> [u8; 12] {
    let iv = hkdf_expand_label_sha256(secret, "iv", &[], 12);
    let mut result = [0u8; 12];
    result.copy_from_slice(&iv);
    result
}

/// Derive a finished key from a traffic secret.
pub fn derive_finished_key(secret: &[u8; 32]) -> [u8; 32] {
    let key = hkdf_expand_label_sha256(secret, "finished", &[], 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&key);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule_progression() {
        let mut ks = KeySchedule::with_psk(None);
        assert_eq!(ks.stage(), KeyScheduleStage::EarlySecret);

        let ecdhe = [0x42u8; 32];
        ks.derive_handshake_secret_legacy(&ecdhe).unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::HandshakeSecret);

        ks.derive_master_secret().unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::MasterSecret);
    }

    #[test]
    fn test_handshake_traffic_secrets() {
        let mut ks = KeySchedule::with_psk(None);
        let ecdhe = [0x42u8; 32];
        ks.derive_handshake_secret_legacy(&ecdhe).unwrap();

        let transcript = [0u8; 32];
        let client_secret = ks.client_handshake_traffic_secret(&transcript).unwrap();
        let server_secret = ks.server_handshake_traffic_secret(&transcript).unwrap();

        // Client and server secrets should be different
        assert_ne!(client_secret, server_secret);
        assert_eq!(client_secret.len(), 32);
    }

    #[test]
    fn test_application_traffic_secrets() {
        let mut ks = KeySchedule::with_psk(None);
        let ecdhe = [0x42u8; 32];
        ks.derive_handshake_secret_legacy(&ecdhe).unwrap();
        ks.derive_master_secret().unwrap();

        let transcript = [0u8; 32];
        let client_secret = ks.client_application_traffic_secret(&transcript).unwrap();
        let server_secret = ks.server_application_traffic_secret(&transcript).unwrap();

        assert_ne!(client_secret, server_secret);
        assert_eq!(client_secret.len(), 32);
    }

    #[test]
    fn test_derive_traffic_key_and_iv() {
        let secret = [0x42u8; 32];

        let key = derive_traffic_key(&secret, 16);
        assert_eq!(key.len(), 16);

        let iv = derive_traffic_iv(&secret);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_derive_finished_key() {
        let secret = [0x42u8; 32];
        let finished_key = derive_finished_key(&secret);
        assert_eq!(finished_key.len(), 32);
    }

    #[test]
    fn test_new_api() {
        let mut ks = KeySchedule::new();
        assert_eq!(ks.stage(), KeyScheduleStage::Initial);

        ks.derive_early_secret(None);
        assert_eq!(ks.stage(), KeyScheduleStage::EarlySecret);

        let ecdhe = [0x42u8; 32];
        let transcript = [0x00u8; 32];
        ks.derive_handshake_secret(&ecdhe, &transcript);
        assert_eq!(ks.stage(), KeyScheduleStage::HandshakeSecret);

        // Keys should be populated
        assert!(!ks.client_write_key.is_empty());
        assert!(!ks.server_write_key.is_empty());
        assert!(!ks.client_finished_key.is_empty());
        assert!(!ks.server_finished_key.is_empty());
    }
}
