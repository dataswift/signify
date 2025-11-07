/// Siger - Indexed signature with verifier
///
/// Siger extends Indexer to add an optional Verfer for signature verification.
/// This is used for indexed signatures in KERI multi-signature scenarios.
use crate::core::{Indexer, IndexerCodex, Verfer};
use crate::error::{Result, SignifyError};

/// Indexed signature with optional verifier
pub struct Siger {
    indexer: Indexer,
    verfer: Option<Verfer>,
}

impl Siger {
    /// Create new Siger from raw signature and indices
    pub fn new(
        raw: &[u8],
        code: &str,
        index: u32,
        ondex: Option<u32>,
        verfer: Option<Verfer>,
    ) -> Result<Self> {
        // Validate that code is a valid indexed signature code
        if !IndexerCodex::is_valid(code) {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid Siger code: {}",
                code
            )));
        }

        let indexer = Indexer::new(raw, code, index, ondex)?;

        Ok(Self { indexer, verfer })
    }

    /// Create Siger from qb64 string
    pub fn from_qb64(qb64: &str, verfer: Option<Verfer>) -> Result<Self> {
        let indexer = Indexer::from_qb64(qb64)?;

        // Validate code
        if !IndexerCodex::is_valid(indexer.code()) {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid Siger code in qb64: {}",
                indexer.code()
            )));
        }

        Ok(Self { indexer, verfer })
    }

    /// Get qb64 encoding
    pub fn qb64(&self) -> String {
        self.indexer.qb64()
    }

    /// Get signature index
    pub fn index(&self) -> u32 {
        self.indexer.index()
    }

    /// Get other index
    pub fn ondex(&self) -> u32 {
        self.indexer.ondex()
    }

    /// Get code
    pub fn code(&self) -> &str {
        self.indexer.code()
    }

    /// Get raw signature bytes
    pub fn raw(&self) -> &[u8] {
        self.indexer.raw()
    }

    /// Get verifier
    pub fn verfer(&self) -> Option<&Verfer> {
        self.verfer.as_ref()
    }

    /// Set verifier
    pub fn set_verfer(&mut self, verfer: Option<Verfer>) {
        self.verfer = verfer;
    }

    /// Get underlying Indexer
    pub fn indexer(&self) -> &Indexer {
        &self.indexer
    }

    /// Verify signature against message
    pub fn verify(&self, message: &[u8]) -> Result<bool> {
        match &self.verfer {
            Some(verfer) => verfer.verify(self.raw(), message),
            None => Err(SignifyError::Verification(
                "No verfer available for signature verification".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{matter_codes, Signer};

    #[test]
    fn test_siger_creation() {
        let sig = vec![0u8; 64];
        let siger = Siger::new(&sig, IndexerCodex::ED25519_SIG, 5, None, None).unwrap();

        assert_eq!(siger.index(), 5);
        assert_eq!(siger.ondex(), 5);
        assert_eq!(siger.code(), IndexerCodex::ED25519_SIG);
        assert!(siger.verfer().is_none());
    }

    #[test]
    fn test_siger_with_verfer() {
        // Create a signer and get signature
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let message = b"test message";
        let sig = signer.sign(message).unwrap();

        // Create Siger with verfer
        let siger = Siger::new(
            &sig,
            IndexerCodex::ED25519_SIG,
            0,
            None,
            Some(signer.verfer().clone()),
        )
        .unwrap();

        assert!(siger.verfer().is_some());

        // Verify signature
        assert!(siger.verify(message).unwrap());

        // Wrong message should fail
        let wrong_message = b"wrong message";
        assert!(!siger.verify(wrong_message).unwrap());
    }

    #[test]
    fn test_siger_qb64_roundtrip() {
        let sig = vec![1u8; 64];
        let siger = Siger::new(&sig, IndexerCodex::ED25519_BIG_SIG, 100, Some(200), None).unwrap();

        let qb64 = siger.qb64();
        let siger2 = Siger::from_qb64(&qb64, None).unwrap();

        assert_eq!(siger.index(), siger2.index());
        assert_eq!(siger.ondex(), siger2.ondex());
        assert_eq!(siger.code(), siger2.code());
        assert_eq!(siger.raw(), siger2.raw());
    }

    #[test]
    fn test_siger_invalid_code() {
        let sig = vec![0u8; 64];

        // Use a code that's not valid for Indexer (G, H, I, etc.)
        let result = Siger::new(&sig, matter_codes::BLAKE2S_256, 0, None, None); // "G" is not a valid indexer code
        assert!(result.is_err());
    }

    #[test]
    fn test_siger_verify_without_verfer() {
        let sig = vec![0u8; 64];
        let siger = Siger::new(&sig, IndexerCodex::ED25519_SIG, 0, None, None).unwrap();

        let message = b"test";
        let result = siger.verify(message);
        assert!(result.is_err());
    }

    #[test]
    fn test_siger_multi_sig_scenario() {
        // Create multiple signers
        let signer0 = Signer::from_seed(&[1u8; 32], matter_codes::ED25519_SEED, true).unwrap();
        let signer1 = Signer::from_seed(&[2u8; 32], matter_codes::ED25519_SEED, true).unwrap();

        let message = b"multi-sig message";

        // Sign with both
        let sig0 = signer0.sign(message).unwrap();
        let sig1 = signer1.sign(message).unwrap();

        // Create Sigers with different indices
        let siger0 = Siger::new(
            &sig0,
            IndexerCodex::ED25519_SIG,
            0,
            None,
            Some(signer0.verfer().clone()),
        )
        .unwrap();

        let siger1 = Siger::new(
            &sig1,
            IndexerCodex::ED25519_SIG,
            1,
            None,
            Some(signer1.verfer().clone()),
        )
        .unwrap();

        // Verify both signatures
        assert!(siger0.verify(message).unwrap());
        assert!(siger1.verify(message).unwrap());

        // Check indices
        assert_eq!(siger0.index(), 0);
        assert_eq!(siger1.index(), 1);
    }
}
