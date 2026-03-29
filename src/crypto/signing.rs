//! Signature creation for TLS 1.3 (server-side signing)

use crate::error::TlsError;
use crate::extensions::SignatureScheme;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Sign a message using the specified scheme and private key
pub fn sign_message(
    scheme: SignatureScheme,
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, TlsError> {
    match scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => sign_ecdsa_p256_sha256(private_key, message),
        SignatureScheme::Ed25519 => sign_ed25519(private_key, message),
        SignatureScheme::RsaPkcs1Sha256 => sign_rsa_pkcs1_sha256(private_key, message),
        SignatureScheme::RsaPkcs1Sha384 => sign_rsa_pkcs1_sha384(private_key, message),
        SignatureScheme::RsaPkcs1Sha512 => sign_rsa_pkcs1_sha512(private_key, message),
        SignatureScheme::RsaPssRsaeSha256 => sign_rsa_pss_sha256(private_key, message),
        SignatureScheme::RsaPssRsaeSha384 => sign_rsa_pss_sha384(private_key, message),
        SignatureScheme::RsaPssRsaeSha512 => sign_rsa_pss_sha512(private_key, message),
        _ => Err(TlsError::Crypto(format!(
            "unsupported signature scheme for signing: {:?}",
            scheme
        ))),
    }
}

/// Sign with ECDSA P-256 SHA-256
fn sign_ecdsa_p256_sha256(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|_| TlsError::Crypto("invalid P-256 private key".into()))?;

    let digest = Sha256::digest(message);
    let signature: Signature = signing_key.sign(&digest);

    Ok(signature.to_der().as_bytes().to_vec())
}

/// Sign with Ed25519
fn sign_ed25519(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use ed25519_dalek::{Signer, SigningKey};

    if private_key.len() != 32 {
        return Err(TlsError::Crypto(
            "invalid Ed25519 private key length".into(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(private_key);
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Sign with RSA PKCS#1 v1.5 SHA-256
fn sign_rsa_pkcs1_sha256(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};

    let key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|_| TlsError::Crypto("invalid RSA private key".into()))?;

    let digest = Sha256::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha256>();

    let signature = key
        .sign(scheme, &digest)
        .map_err(|_| TlsError::Crypto("RSA signing failed".into()))?;

    Ok(signature)
}

/// Sign with RSA PKCS#1 v1.5 SHA-384
fn sign_rsa_pkcs1_sha384(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};

    let key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|_| TlsError::Crypto("invalid RSA private key".into()))?;

    let digest = Sha384::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha384>();

    let signature = key
        .sign(scheme, &digest)
        .map_err(|_| TlsError::Crypto("RSA signing failed".into()))?;

    Ok(signature)
}

/// Sign with RSA PKCS#1 v1.5 SHA-512
fn sign_rsa_pkcs1_sha512(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};

    let key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|_| TlsError::Crypto("invalid RSA private key".into()))?;

    let digest = Sha512::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha512>();

    let signature = key
        .sign(scheme, &digest)
        .map_err(|_| TlsError::Crypto("RSA signing failed".into()))?;

    Ok(signature)
}

/// Sign with RSA-PSS SHA-256
fn sign_rsa_pss_sha256(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use rand::rngs::OsRng;
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::RandomizedSigner;
    use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
    use signature::SignatureEncoding;

    let key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|_| TlsError::Crypto("invalid RSA private key".into()))?;

    let signing_key = BlindedSigningKey::<Sha256>::new(key);
    let signature = signing_key.sign_with_rng(&mut OsRng, message);

    Ok(signature.to_vec())
}

/// Sign with RSA-PSS SHA-384
fn sign_rsa_pss_sha384(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use rand::rngs::OsRng;
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::RandomizedSigner;
    use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
    use signature::SignatureEncoding;

    let key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|_| TlsError::Crypto("invalid RSA private key".into()))?;

    let signing_key = BlindedSigningKey::<Sha384>::new(key);
    let signature = signing_key.sign_with_rng(&mut OsRng, message);

    Ok(signature.to_vec())
}

/// Sign with RSA-PSS SHA-512
fn sign_rsa_pss_sha512(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, TlsError> {
    use rand::rngs::OsRng;
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::RandomizedSigner;
    use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
    use signature::SignatureEncoding;

    let key = RsaPrivateKey::from_pkcs8_der(private_key)
        .map_err(|_| TlsError::Crypto("invalid RSA private key".into()))?;

    let signing_key = BlindedSigningKey::<Sha512>::new(key);
    let signature = signing_key.sign_with_rng(&mut OsRng, message);

    Ok(signature.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify_signature;

    #[test]
    fn test_ecdsa_p256_sign_verify() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        // Generate a key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let private_key = signing_key.to_bytes();
        let public_key = signing_key.verifying_key().to_encoded_point(false);

        let message = b"test message for signing";

        // Sign
        let signature =
            sign_message(SignatureScheme::EcdsaSecp256r1Sha256, &private_key, message).unwrap();

        // Verify
        verify_signature(
            SignatureScheme::EcdsaSecp256r1Sha256,
            public_key.as_bytes(),
            message,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn test_ed25519_sign_verify() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key = signing_key.to_bytes();
        let public_key = signing_key.verifying_key().to_bytes();

        let message = b"test message for Ed25519";

        let signature = sign_message(SignatureScheme::Ed25519, &private_key, message).unwrap();

        verify_signature(SignatureScheme::Ed25519, &public_key, message, &signature).unwrap();
    }
}
