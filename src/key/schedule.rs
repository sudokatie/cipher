//! TLS 1.3 Key Schedule.
//!
//! Implements the key derivation schedule from RFC 8446 Section 7.1.

use crate::crypto::{
    derive_secret_sha256, hkdf_expand_label_sha256, hkdf_extract_sha256,
    Sha256 as Sha256Hash, HashAlgorithm,
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

impl KeySchedule {
    /// Create a new key schedule.
    ///
    /// Starts at the Initial stage with the early secret derived from
    /// an optional PSK (or zeros if no PSK).
    pub fn new(psk: Option<&[u8]>) -> Self {
        let zero_salt = [0u8; 32];
        let ikm = psk.unwrap_or(&[0u8; 32]);

        let early_secret = hkdf_extract_sha256(&zero_salt, ikm);

        KeySchedule {
            current_secret: early_secret,
            stage: KeyScheduleStage::EarlySecret,
        }
    }

    /// Get the current stage.
    pub fn stage(&self) -> KeyScheduleStage {
        self.stage
    }

    /// Derive the handshake secret from ECDHE shared secret.
    ///
    /// Must be called after new() and before derive_master_secret().
    pub fn derive_handshake_secret(&mut self, ecdhe_secret: &[u8]) -> Result<(), &'static str> {
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
    pub fn client_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Result<[u8; 32], &'static str> {
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
    pub fn server_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Result<[u8; 32], &'static str> {
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
    pub fn client_application_traffic_secret(&self, transcript_hash: &[u8]) -> Result<[u8; 32], &'static str> {
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
    pub fn server_application_traffic_secret(&self, transcript_hash: &[u8]) -> Result<[u8; 32], &'static str> {
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
        let mut ks = KeySchedule::new(None);
        assert_eq!(ks.stage(), KeyScheduleStage::EarlySecret);

        let ecdhe = [0x42u8; 32];
        ks.derive_handshake_secret(&ecdhe).unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::HandshakeSecret);

        ks.derive_master_secret().unwrap();
        assert_eq!(ks.stage(), KeyScheduleStage::MasterSecret);
    }

    #[test]
    fn test_handshake_traffic_secrets() {
        let mut ks = KeySchedule::new(None);
        let ecdhe = [0x42u8; 32];
        ks.derive_handshake_secret(&ecdhe).unwrap();

        let transcript = [0u8; 32];
        let client_secret = ks.client_handshake_traffic_secret(&transcript).unwrap();
        let server_secret = ks.server_handshake_traffic_secret(&transcript).unwrap();

        // Client and server secrets should be different
        assert_ne!(client_secret, server_secret);
        assert_eq!(client_secret.len(), 32);
    }

    #[test]
    fn test_application_traffic_secrets() {
        let mut ks = KeySchedule::new(None);
        let ecdhe = [0x42u8; 32];
        ks.derive_handshake_secret(&ecdhe).unwrap();
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
    fn test_wrong_stage_errors() {
        let ks = KeySchedule::new(None);

        // Can't derive application secrets at EarlySecret stage
        let result = ks.client_application_traffic_secret(&[0u8; 32]);
        assert!(result.is_err());
    }
}
