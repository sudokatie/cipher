//! Signature verification for TLS 1.3

use crate::error::TlsError;
use crate::extensions::SignatureScheme;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Verify a signature using the specified scheme
pub fn verify_signature(
    scheme: SignatureScheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    match scheme {
        SignatureScheme::RsaPkcs1Sha256 => verify_rsa_pkcs1_sha256(public_key, message, signature),
        SignatureScheme::RsaPkcs1Sha384 => verify_rsa_pkcs1_sha384(public_key, message, signature),
        SignatureScheme::RsaPkcs1Sha512 => verify_rsa_pkcs1_sha512(public_key, message, signature),
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            verify_ecdsa_p256_sha256(public_key, message, signature)
        }
        SignatureScheme::Ed25519 => verify_ed25519(public_key, message, signature),
        SignatureScheme::RsaPssRsaeSha256 => verify_rsa_pss_sha256(public_key, message, signature),
        SignatureScheme::RsaPssRsaeSha384 => verify_rsa_pss_sha384(public_key, message, signature),
        SignatureScheme::RsaPssRsaeSha512 => verify_rsa_pss_sha512(public_key, message, signature),
        _ => Err(TlsError::Crypto(format!(
            "unsupported signature scheme: {:?}",
            scheme
        ))),
    }
}

/// Parse RSA public key from SPKI or raw format
fn parse_rsa_public_key(data: &[u8]) -> Result<RsaPublicKey, TlsError> {
    // Try PKCS#8/SPKI format first
    if let Ok(key) = RsaPublicKey::from_public_key_der(data) {
        return Ok(key);
    }
    // Try PKCS#1 format
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(data) {
        return Ok(key);
    }
    Err(TlsError::Crypto("invalid RSA public key format".into()))
}

/// Verify RSA PKCS#1 v1.5 with SHA-256
fn verify_rsa_pkcs1_sha256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let key = parse_rsa_public_key(public_key)?;
    let digest = Sha256::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha256>();

    key.verify(scheme, &digest, signature)
        .map_err(|_| TlsError::Crypto("RSA PKCS#1 SHA-256 signature verification failed".into()))
}

/// Verify RSA PKCS#1 v1.5 with SHA-384
fn verify_rsa_pkcs1_sha384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let key = parse_rsa_public_key(public_key)?;
    let digest = Sha384::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha384>();

    key.verify(scheme, &digest, signature)
        .map_err(|_| TlsError::Crypto("RSA PKCS#1 SHA-384 signature verification failed".into()))
}

/// Verify RSA PKCS#1 v1.5 with SHA-512
fn verify_rsa_pkcs1_sha512(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let key = parse_rsa_public_key(public_key)?;
    let digest = Sha512::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha512>();

    key.verify(scheme, &digest, signature)
        .map_err(|_| TlsError::Crypto("RSA PKCS#1 SHA-512 signature verification failed".into()))
}

/// Verify RSA-PSS with SHA-256
fn verify_rsa_pss_sha256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let key = parse_rsa_public_key(public_key)?;
    let verifying_key = VerifyingKey::<Sha256>::new(key);
    let sig = Signature::try_from(signature)
        .map_err(|_| TlsError::Crypto("invalid RSA-PSS signature format".into()))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|_| TlsError::Crypto("RSA-PSS SHA-256 signature verification failed".into()))
}

/// Verify RSA-PSS with SHA-384
fn verify_rsa_pss_sha384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let key = parse_rsa_public_key(public_key)?;
    let verifying_key = VerifyingKey::<Sha384>::new(key);
    let sig = Signature::try_from(signature)
        .map_err(|_| TlsError::Crypto("invalid RSA-PSS signature format".into()))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|_| TlsError::Crypto("RSA-PSS SHA-384 signature verification failed".into()))
}

/// Verify RSA-PSS with SHA-512
fn verify_rsa_pss_sha512(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let key = parse_rsa_public_key(public_key)?;
    let verifying_key = VerifyingKey::<Sha512>::new(key);
    let sig = Signature::try_from(signature)
        .map_err(|_| TlsError::Crypto("invalid RSA-PSS signature format".into()))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|_| TlsError::Crypto("RSA-PSS SHA-512 signature verification failed".into()))
}

/// Verify ECDSA P-256 with SHA-256
fn verify_ecdsa_p256_sha256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use p256::EncodedPoint;

    // Parse public key (uncompressed point format)
    let point = EncodedPoint::from_bytes(public_key)
        .map_err(|_| TlsError::Crypto("invalid P-256 public key encoding".into()))?;

    let verifying_key = P256VerifyingKey::from_encoded_point(&point)
        .map_err(|_| TlsError::Crypto("invalid P-256 public key".into()))?;

    // Parse signature (DER format in TLS)
    let sig = P256Signature::from_der(signature)
        .map_err(|_| TlsError::Crypto("invalid ECDSA signature format".into()))?;

    // Hash the message with SHA-256
    let digest = Sha256::digest(message);

    verifying_key
        .verify(&digest, &sig)
        .map_err(|_| TlsError::Crypto("ECDSA P-256 signature verification failed".into()))
}

/// Verify Ed25519
fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), TlsError> {
    if public_key.len() != 32 {
        return Err(TlsError::Crypto("invalid Ed25519 public key length".into()));
    }
    if signature.len() != 64 {
        return Err(TlsError::Crypto("invalid Ed25519 signature length".into()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(public_key);
    let verifying_key = Ed25519VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| TlsError::Crypto("invalid Ed25519 public key".into()))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Ed25519Signature::from_bytes(&sig_bytes);

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| TlsError::Crypto("Ed25519 signature verification failed".into()))
}

/// Construct the message to be verified for CertificateVerify
///
/// The signed message is:
/// - 64 spaces (0x20)
/// - Context string ("TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify")
/// - A single 0 byte
/// - The transcript hash
pub fn construct_certificate_verify_message(transcript_hash: &[u8], is_server: bool) -> Vec<u8> {
    let context = if is_server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };

    let mut message = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    message.extend_from_slice(&[0x20u8; 64]);
    message.extend_from_slice(context);
    message.push(0x00);
    message.extend_from_slice(transcript_hash);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_verify_message_construction() {
        let hash = [0u8; 32];
        let msg = construct_certificate_verify_message(&hash, true);

        // Should start with 64 spaces
        assert!(msg.starts_with(&[0x20; 64]));
        // Should contain "server"
        assert!(msg.windows(6).any(|w| w == b"server"));
        // Total length: 64 + 33 + 1 + 32 = 130
        assert_eq!(msg.len(), 130);
    }

    #[test]
    fn test_unsupported_scheme() {
        let result = verify_signature(SignatureScheme::EcdsaSecp384r1Sha384, &[], &[], &[]);
        assert!(result.is_err());
    }
}
