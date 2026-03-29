//! Hash function abstractions for TLS 1.3.

use sha2::{Digest, Sha256 as Sha256Impl, Sha384 as Sha384Impl};

/// Hash algorithm trait.
pub trait HashAlgorithm: Clone {
    /// Output size in bytes.
    const OUTPUT_LEN: usize;

    /// Create a new hasher.
    fn new() -> Self;

    /// Update with data.
    fn update(&mut self, data: &[u8]);

    /// Finalize and return hash.
    fn finalize(self) -> Vec<u8>;

    /// Hash data in one shot.
    fn hash(data: &[u8]) -> Vec<u8> {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// SHA-256 hash algorithm.
#[derive(Clone)]
pub struct Sha256(Sha256Impl);

impl HashAlgorithm for Sha256 {
    const OUTPUT_LEN: usize = 32;

    fn new() -> Self {
        Sha256(Sha256Impl::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
}

/// SHA-384 hash algorithm.
#[derive(Clone)]
pub struct Sha384(Sha384Impl);

impl HashAlgorithm for Sha384 {
    const OUTPUT_LEN: usize = 48;

    fn new() -> Self {
        Sha384(Sha384Impl::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
}

/// Transcript hash for accumulating handshake messages.
///
/// Used to compute the transcript hash required for key derivation
/// and Finished message verification.
#[derive(Clone)]
pub struct TranscriptHash<H: HashAlgorithm> {
    hasher: H,
}

impl<H: HashAlgorithm> TranscriptHash<H> {
    /// Create a new empty transcript hash.
    pub fn new() -> Self {
        TranscriptHash { hasher: H::new() }
    }

    /// Add a handshake message to the transcript.
    pub fn update(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    /// Get the current transcript hash without consuming.
    pub fn current_hash(&self) -> Vec<u8> {
        self.hasher.clone().finalize()
    }

    /// Finalize and get the final transcript hash.
    pub fn finalize(self) -> Vec<u8> {
        self.hasher.finalize()
    }

    /// Get the output length of the hash.
    pub fn output_len(&self) -> usize {
        H::OUTPUT_LEN
    }
}

impl<H: HashAlgorithm> Default for TranscriptHash<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_produces_correct_output() {
        let hash = Sha256::hash(b"hello world");
        assert_eq!(hash.len(), 32);

        // Known hash value for "hello world"
        let expected =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha384_produces_correct_output() {
        let hash = Sha384::hash(b"hello world");
        assert_eq!(hash.len(), 48);

        // Known hash value for "hello world"
        let expected = hex::decode(
            "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"
        ).unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_transcript_hash_accumulates() {
        let mut transcript = TranscriptHash::<Sha256>::new();
        transcript.update(b"hello");
        transcript.update(b" ");
        transcript.update(b"world");

        let hash = transcript.finalize();

        // Should be same as hashing "hello world" directly
        let expected = Sha256::hash(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_transcript_current_hash() {
        let mut transcript = TranscriptHash::<Sha256>::new();
        transcript.update(b"hello");

        let hash1 = transcript.current_hash();
        let hash2 = transcript.current_hash();

        // current_hash should be repeatable
        assert_eq!(hash1, hash2);

        // Should match what we'd get from hashing just "hello"
        let expected = Sha256::hash(b"hello");
        assert_eq!(hash1, expected);
    }
}
