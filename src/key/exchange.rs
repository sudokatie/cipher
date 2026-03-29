//! Key exchange for TLS 1.3.

use crate::error::TlsError;
use p256::{
    ecdh::EphemeralSecret as P256EphemeralSecret, elliptic_curve::sec1::FromEncodedPoint,
    EncodedPoint, PublicKey as P256PublicKey,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, ReusableSecret};

/// Named groups for key exchange (RFC 8446 Section 4.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NamedGroup {
    /// X25519 (mandatory-to-implement)
    X25519 = 0x001d,
    /// secp256r1 (P-256)
    Secp256r1 = 0x0017,
    /// secp384r1 (P-384)
    Secp384r1 = 0x0018,
}

impl NamedGroup {
    /// Parse from u16.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x001d => Some(NamedGroup::X25519),
            0x0017 => Some(NamedGroup::Secp256r1),
            0x0018 => Some(NamedGroup::Secp384r1),
            _ => None,
        }
    }

    /// Convert to u16.
    pub fn to_u16(&self) -> u16 {
        match self {
            NamedGroup::X25519 => 0x001d,
            NamedGroup::Secp256r1 => 0x0017,
            NamedGroup::Secp384r1 => 0x0018,
        }
    }

    /// Get the public key length for this group.
    pub fn public_key_len(&self) -> usize {
        match self {
            NamedGroup::X25519 => 32,
            NamedGroup::Secp256r1 => 65, // Uncompressed point
            NamedGroup::Secp384r1 => 97, // Uncompressed point
        }
    }
}

/// Key share for TLS handshake.
#[derive(Debug, Clone)]
pub struct KeyShare {
    /// The named group for this key share.
    pub group: NamedGroup,
    /// The public key data.
    pub public_key: Vec<u8>,
}

impl KeyShare {
    /// Create a new key share.
    pub fn new(group: NamedGroup, public_key: Vec<u8>) -> Self {
        KeyShare { group, public_key }
    }

    /// Serialize for TLS wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + self.public_key.len());
        data.extend_from_slice(&(self.group as u16).to_be_bytes());
        data.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.public_key);
        data
    }

    /// Parse from TLS wire format.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), TlsError> {
        if data.len() < 4 {
            return Err(TlsError::Protocol("key share too short".into()));
        }

        let group_value = u16::from_be_bytes([data[0], data[1]]);
        let group = NamedGroup::from_u16(group_value)
            .ok_or_else(|| TlsError::Protocol(format!("unknown group: 0x{:04x}", group_value)))?;

        let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + key_len {
            return Err(TlsError::Protocol("key share data truncated".into()));
        }

        let public_key = data[4..4 + key_len].to_vec();

        Ok((KeyShare::new(group, public_key), 4 + key_len))
    }
}

/// X25519 key pair for key exchange.
pub struct X25519KeyPair {
    /// Reusable secret (allows non-consuming DH)
    secret: ReusableSecret,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let secret = ReusableSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        X25519KeyPair { secret, public }
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Create a KeyShare for this key pair.
    pub fn key_share(&self) -> KeyShare {
        KeyShare::new(NamedGroup::X25519, self.public_key().to_vec())
    }

    /// Compute shared secret with peer's public key.
    pub fn compute_shared_secret(&self, peer_public: &[u8]) -> Result<[u8; 32], TlsError> {
        if peer_public.len() != 32 {
            return Err(TlsError::Crypto("invalid X25519 public key length".into()));
        }

        let mut peer_key_bytes = [0u8; 32];
        peer_key_bytes.copy_from_slice(peer_public);
        let peer_key = X25519PublicKey::from(peer_key_bytes);

        let shared = self.secret.diffie_hellman(&peer_key);
        Ok(*shared.as_bytes())
    }
}

/// P-256 (secp256r1) key pair for key exchange.
pub struct P256KeyPair {
    /// Ephemeral secret
    secret: P256EphemeralSecret,
    /// Public key bytes (uncompressed point, 65 bytes)
    public_bytes: Vec<u8>,
}

impl P256KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let secret = P256EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key();
        let public_bytes = EncodedPoint::from(public).as_bytes().to_vec();
        P256KeyPair {
            secret,
            public_bytes,
        }
    }

    /// Get the public key bytes (uncompressed point).
    pub fn public_key(&self) -> &[u8] {
        &self.public_bytes
    }

    /// Create a KeyShare for this key pair.
    pub fn key_share(&self) -> KeyShare {
        KeyShare::new(NamedGroup::Secp256r1, self.public_bytes.clone())
    }

    /// Compute shared secret with peer's public key.
    pub fn compute_shared_secret(self, peer_public: &[u8]) -> Result<[u8; 32], TlsError> {
        let peer_point = EncodedPoint::from_bytes(peer_public)
            .map_err(|_| TlsError::Crypto("invalid P-256 public key encoding".into()))?;

        let peer_key = P256PublicKey::from_encoded_point(&peer_point)
            .into_option()
            .ok_or_else(|| TlsError::Crypto("invalid P-256 public key".into()))?;

        let shared = self.secret.diffie_hellman(&peer_key);
        let mut result = [0u8; 32];
        result.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(result)
    }
}

/// Generic key pair that can be either X25519 or P-256.
pub enum KeyPair {
    X25519(X25519KeyPair),
    P256(P256KeyPair),
}

impl KeyPair {
    /// Generate a key pair for the specified group.
    pub fn generate(group: NamedGroup) -> Result<Self, TlsError> {
        match group {
            NamedGroup::X25519 => Ok(KeyPair::X25519(X25519KeyPair::generate())),
            NamedGroup::Secp256r1 => Ok(KeyPair::P256(P256KeyPair::generate())),
            NamedGroup::Secp384r1 => Err(TlsError::Crypto("P-384 not implemented".into())),
        }
    }

    /// Get the named group.
    pub fn group(&self) -> NamedGroup {
        match self {
            KeyPair::X25519(_) => NamedGroup::X25519,
            KeyPair::P256(_) => NamedGroup::Secp256r1,
        }
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        match self {
            KeyPair::X25519(kp) => kp.public_key().to_vec(),
            KeyPair::P256(kp) => kp.public_key().to_vec(),
        }
    }

    /// Create a KeyShare.
    pub fn key_share(&self) -> KeyShare {
        match self {
            KeyPair::X25519(kp) => kp.key_share(),
            KeyPair::P256(kp) => kp.key_share(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_pair_generation() {
        let kp1 = X25519KeyPair::generate();
        let kp2 = X25519KeyPair::generate();

        // Different key pairs should have different public keys
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_x25519_shared_secret_computation() {
        let kp1 = X25519KeyPair::generate();
        let kp2 = X25519KeyPair::generate();

        let pub1 = kp1.public_key();
        let pub2 = kp2.public_key();

        // Both sides should compute the same shared secret
        let secret1 = kp1.compute_shared_secret(&pub2).unwrap();
        let secret2 = kp2.compute_shared_secret(&pub1).unwrap();

        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_p256_key_pair_generation() {
        let kp1 = P256KeyPair::generate();
        let kp2 = P256KeyPair::generate();

        // Different key pairs should have different public keys
        assert_ne!(kp1.public_key(), kp2.public_key());
        // P-256 uncompressed point is 65 bytes (0x04 + 32 + 32)
        assert_eq!(kp1.public_key().len(), 65);
    }

    #[test]
    fn test_p256_shared_secret_computation() {
        let kp1 = P256KeyPair::generate();
        let kp2 = P256KeyPair::generate();

        let pub1 = kp1.public_key().to_vec();
        let pub2 = kp2.public_key().to_vec();

        // Both sides should compute the same shared secret
        let secret1 = kp1.compute_shared_secret(&pub2).unwrap();
        let secret2 = kp2.compute_shared_secret(&pub1).unwrap();

        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_key_share_serialization() {
        let kp = X25519KeyPair::generate();
        let share = kp.key_share();

        let serialized = share.serialize();
        let (parsed, len) = KeyShare::parse(&serialized).unwrap();

        assert_eq!(len, serialized.len());
        assert_eq!(parsed.group, share.group);
        assert_eq!(parsed.public_key, share.public_key);
    }

    #[test]
    fn test_named_group() {
        assert_eq!(NamedGroup::X25519.public_key_len(), 32);
        assert_eq!(NamedGroup::from_u16(0x001d), Some(NamedGroup::X25519));
        assert_eq!(NamedGroup::from_u16(0xffff), None);
    }

    #[test]
    fn test_generic_key_pair() {
        let kp_x25519 = KeyPair::generate(NamedGroup::X25519).unwrap();
        assert_eq!(kp_x25519.group(), NamedGroup::X25519);
        assert_eq!(kp_x25519.public_key().len(), 32);

        let kp_p256 = KeyPair::generate(NamedGroup::Secp256r1).unwrap();
        assert_eq!(kp_p256.group(), NamedGroup::Secp256r1);
        assert_eq!(kp_p256.public_key().len(), 65);
    }
}
