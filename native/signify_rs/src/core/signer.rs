use crate::core::{matter_codes, Matter, Verfer};
/// Signer - Ed25519 signing with CESR encoding
use crate::error::{Result, SignifyError};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};

/// Signer wraps an Ed25519 keypair for signing operations
#[derive(Debug)]
pub struct Signer {
    matter: Matter, // Stores the seed
    verfer: Verfer, // Stores the public key
}

impl Signer {
    /// Create a new random Signer
    pub fn new_random(code: &str, transferable: bool) -> Result<Self> {
        if code != matter_codes::ED25519_SEED {
            return Err(SignifyError::UnsupportedAlgorithm(format!(
                "Unsupported signer code: {}. Expected {}",
                code,
                matter_codes::ED25519_SEED
            )));
        }

        // Generate random seed
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        Self::from_seed(&seed, code, transferable)
    }

    /// Create Signer from seed
    pub fn from_seed(seed: &[u8], code: &str, transferable: bool) -> Result<Self> {
        if code != matter_codes::ED25519_SEED {
            return Err(SignifyError::UnsupportedAlgorithm(format!(
                "Unsupported signer code: {}. Expected {}",
                code,
                matter_codes::ED25519_SEED
            )));
        }

        if seed.len() != 32 {
            return Err(SignifyError::InvalidSize {
                expected: 32,
                actual: seed.len(),
            });
        }

        // Generate signing key from seed
        let signing_key = SigningKey::from_bytes(seed.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();

        let matter = Matter::from_raw(seed, code)?;

        // Create verfer with appropriate code
        let verfer_code = if transferable {
            matter_codes::ED25519
        } else {
            matter_codes::ED25519N
        };
        let verfer = Verfer::from_raw(verifying_key.as_bytes(), verfer_code)?;

        Ok(Self { matter, verfer })
    }

    /// Create Signer from qb64 seed
    pub fn from_qb64(qb64: &str, transferable: bool) -> Result<Self> {
        let matter = Matter::from_qb64(qb64)?;

        if matter.code() != matter_codes::ED25519_SEED {
            return Err(SignifyError::InvalidCode(format!(
                "Expected ED25519_SEED code, got {}",
                matter.code()
            )));
        }

        Self::from_seed(matter.raw(), matter.code(), transferable)
    }

    /// Sign serialized data
    /// Returns raw signature bytes (64 bytes for Ed25519)
    pub fn sign(&self, ser: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_bytes(self.matter.raw().try_into().unwrap());
        let signature = signing_key.sign(ser);

        Ok(signature.to_bytes().to_vec())
    }

    /// Sign and return indexed signature (for multi-sig scenarios)
    pub fn sign_indexed(&self, ser: &[u8], index: usize) -> Result<IndexedSignature> {
        let signature = self.sign(ser)?;
        Ok(IndexedSignature { signature, index })
    }

    /// Get the verifier (public key)
    pub fn verfer(&self) -> &Verfer {
        &self.verfer
    }

    /// Get the seed matter
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Get qb64 encoding of seed
    pub fn qb64(&self) -> &str {
        self.matter.qb64()
    }

    /// Check if transferable
    pub fn transferable(&self) -> bool {
        self.verfer.code() == matter_codes::ED25519
    }
}

/// Indexed signature for multi-signature scenarios
#[derive(Debug, Clone)]
pub struct IndexedSignature {
    pub signature: Vec<u8>,
    pub index: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_from_seed() {
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        assert_eq!(signer.matter().code(), matter_codes::ED25519_SEED);
        assert_eq!(signer.verfer().code(), matter_codes::ED25519);
        assert!(signer.transferable());
    }

    #[test]
    fn test_signer_nontransferable() {
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, false).unwrap();

        assert_eq!(signer.verfer().code(), matter_codes::ED25519N);
        assert!(!signer.transferable());
    }

    #[test]
    fn test_signer_invalid_seed_size() {
        let seed = [1u8; 16]; // Wrong size
        let result = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_invalid_code() {
        let seed = [1u8; 32];
        let result = Signer::from_seed(&seed, matter_codes::ED25519, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_sign_and_verify() {
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let message = b"test message to sign";
        let signature = signer.sign(message).unwrap();

        // Verify with the signer's verfer
        let verified = signer.verfer().verify(&signature, message).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_signer_sign_wrong_message() {
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = signer.sign(message).unwrap();

        // Should fail verification
        let verified = signer.verfer().verify(&signature, wrong_message).unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_signer_indexed_signature() {
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let message = b"test message";
        let indexed = signer.sign_indexed(message, 5).unwrap();

        assert_eq!(indexed.index, 5);
        assert_eq!(indexed.signature.len(), 64);

        // Verify the signature
        let verified = signer.verfer().verify(&indexed.signature, message).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_signer_qb64_roundtrip() {
        let seed = [1u8; 32];
        let signer1 = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();
        let qb64 = signer1.qb64();

        let signer2 = Signer::from_qb64(qb64, true).unwrap();
        assert_eq!(signer1.matter().raw(), signer2.matter().raw());
        assert_eq!(signer1.verfer().raw(), signer2.verfer().raw());
    }

    #[test]
    fn test_signer_deterministic() {
        // Same seed should produce same keys
        let seed = [42u8; 32];
        let signer1 = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();
        let signer2 = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        assert_eq!(signer1.verfer().raw(), signer2.verfer().raw());

        // Same message should produce same signature
        let message = b"deterministic test";
        let sig1 = signer1.sign(message).unwrap();
        let sig2 = signer2.sign(message).unwrap();
        assert_eq!(sig1, sig2);
    }
}
