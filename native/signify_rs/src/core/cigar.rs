/// Cigar - Non-indexed signature with verifier
///
/// Cigar extends Matter to add an optional Verfer for non-indexed signatures.
/// Used for single signatures or when index information is not needed.
use crate::core::{Matter, Verfer};
use crate::error::Result;

/// Non-indexed signature with optional verifier
pub struct Cigar {
    matter: Matter,
    verfer: Option<Verfer>,
}

impl Cigar {
    /// Create new Cigar from raw signature
    pub fn new(raw: &[u8], code: &str, verfer: Option<Verfer>) -> Result<Self> {
        let matter = Matter::from_raw(raw, code)?;
        Ok(Self { matter, verfer })
    }

    /// Create Cigar from qb64 string
    pub fn from_qb64(qb64: &str, verfer: Option<Verfer>) -> Result<Self> {
        let matter = Matter::from_qb64(qb64)?;
        Ok(Self { matter, verfer })
    }

    /// Get qb64 encoding
    pub fn qb64(&self) -> &str {
        self.matter.qb64()
    }

    /// Get code
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// Get raw signature bytes
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Get verifier
    pub fn verfer(&self) -> Option<&Verfer> {
        self.verfer.as_ref()
    }

    /// Set verifier
    pub fn set_verfer(&mut self, verfer: Option<Verfer>) {
        self.verfer = verfer;
    }

    /// Get underlying Matter
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Verify signature against message
    pub fn verify(&self, message: &[u8]) -> Result<bool> {
        match &self.verfer {
            Some(verfer) => verfer.verify(self.raw(), message),
            None => Err(crate::error::SignifyError::Verification(
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
    fn test_cigar_creation() {
        let sig = vec![0u8; 64];
        let cigar = Cigar::new(&sig, matter_codes::ED25519_SIG, None).unwrap();

        assert_eq!(cigar.code(), matter_codes::ED25519_SIG);
        assert!(cigar.verfer().is_none());
        assert_eq!(cigar.raw().len(), 64);
    }

    #[test]
    fn test_cigar_with_verfer() {
        // Create a signer and get signature
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let message = b"test message";
        let sig = signer.sign(message).unwrap();

        // Create Cigar with verfer
        let cigar = Cigar::new(
            &sig,
            matter_codes::ED25519_SIG,
            Some(signer.verfer().clone()),
        )
        .unwrap();

        assert!(cigar.verfer().is_some());

        // Verify signature
        assert!(cigar.verify(message).unwrap());

        // Wrong message should fail
        let wrong_message = b"wrong message";
        assert!(!cigar.verify(wrong_message).unwrap());
    }

    #[test]
    fn test_cigar_qb64_roundtrip() {
        let sig = vec![1u8; 64];
        let cigar = Cigar::new(&sig, matter_codes::ED25519_SIG, None).unwrap();

        let qb64 = cigar.qb64();
        let cigar2 = Cigar::from_qb64(qb64, None).unwrap();

        assert_eq!(cigar.code(), cigar2.code());
        assert_eq!(cigar.raw(), cigar2.raw());
    }

    #[test]
    fn test_cigar_verify_without_verfer() {
        let sig = vec![0u8; 64];
        let cigar = Cigar::new(&sig, matter_codes::ED25519_SIG, None).unwrap();

        let message = b"test";
        let result = cigar.verify(message);
        assert!(result.is_err());
    }

    #[test]
    fn test_cigar_set_verfer() {
        let seed = [1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let message = b"test message";
        let sig = signer.sign(message).unwrap();

        // Create Cigar without verfer
        let mut cigar = Cigar::new(&sig, matter_codes::ED25519_SIG, None).unwrap();
        assert!(cigar.verfer().is_none());

        // Set verfer
        cigar.set_verfer(Some(signer.verfer().clone()));
        assert!(cigar.verfer().is_some());

        // Now verification should work
        assert!(cigar.verify(message).unwrap());
    }

    #[test]
    fn test_cigar_vs_indexed() {
        // Cigar is used for non-indexed signatures
        // This test demonstrates the use case difference

        let signer = Signer::from_seed(&[1u8; 32], matter_codes::ED25519_SEED, true).unwrap();
        let message = b"single signature message";
        let sig = signer.sign(message).unwrap();

        // Use Cigar for single, non-indexed signature
        let cigar = Cigar::new(
            &sig,
            matter_codes::ED25519_SIG,
            Some(signer.verfer().clone()),
        )
        .unwrap();

        assert!(cigar.verify(message).unwrap());
        assert_eq!(cigar.code(), matter_codes::ED25519_SIG);
    }
}
