use crate::core::{matter_codes, Matter};
/// Verfer - Ed25519 signature verification with CESR encoding
use crate::error::{Result, SignifyError};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verfer wraps a Matter containing an Ed25519 public key
#[derive(Debug, Clone)]
pub struct Verfer {
    matter: Matter,
}

impl Verfer {
    /// Create Verfer from raw public key bytes
    pub fn from_raw(raw: &[u8], code: &str) -> Result<Self> {
        // Validate code is a valid verifier code
        if !Self::is_valid_code(code) {
            return Err(SignifyError::InvalidCode(format!(
                "Unsupported verifier code: {}",
                code
            )));
        }

        let matter = Matter::from_raw(raw, code)?;
        Ok(Self { matter })
    }

    /// Create Verfer from qb64
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        let matter = Matter::from_qb64(qb64)?;

        if !Self::is_valid_code(matter.code()) {
            return Err(SignifyError::InvalidCode(format!(
                "Unsupported verifier code: {}",
                matter.code()
            )));
        }

        Ok(Self { matter })
    }

    /// Create Verfer from qb2
    pub fn from_qb2(qb2: &[u8]) -> Result<Self> {
        let matter = Matter::from_qb2(qb2)?;

        if !Self::is_valid_code(matter.code()) {
            return Err(SignifyError::InvalidCode(format!(
                "Unsupported verifier code: {}",
                matter.code()
            )));
        }

        Ok(Self { matter })
    }

    /// Verify signature against serialized data
    pub fn verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool> {
        match self.matter.code() {
            matter_codes::ED25519 | matter_codes::ED25519N => {
                // Ensure signature is 64 bytes
                if sig.len() != 64 {
                    return Err(SignifyError::InvalidSize {
                        expected: 64,
                        actual: sig.len(),
                    });
                }

                // Parse public key
                let verifying_key =
                    VerifyingKey::from_bytes(self.matter.raw().try_into().map_err(|_| {
                        SignifyError::CryptoError("Invalid public key length".to_string())
                    })?)
                    .map_err(|e| SignifyError::CryptoError(e.to_string()))?;

                // Parse signature
                let signature = Signature::from_bytes(sig.try_into().map_err(|_| {
                    SignifyError::InvalidSize {
                        expected: 64,
                        actual: sig.len(),
                    }
                })?);

                // Verify
                match verifying_key.verify(ser, &signature) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            code => Err(SignifyError::UnsupportedAlgorithm(format!(
                "Unsupported verifier code for verification: {}",
                code
            ))),
        }
    }

    /// Check if code is valid for a verifier
    fn is_valid_code(code: &str) -> bool {
        matches!(code, matter_codes::ED25519 | matter_codes::ED25519N)
    }

    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// Check if this is a transferable key
    pub fn transferable(&self) -> bool {
        self.matter.code() == matter_codes::ED25519
    }

    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    pub fn qb64(&self) -> &str {
        self.matter.qb64()
    }

    pub fn qb64b(&self) -> &[u8] {
        self.matter.qb64b()
    }

    pub fn qb2(&self) -> &[u8] {
        self.matter.qb2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_verfer_from_raw() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();

        let verfer = Verfer::from_raw(&public_bytes, matter_codes::ED25519).unwrap();
        assert_eq!(verfer.code(), matter_codes::ED25519);
        assert_eq!(verfer.raw(), &public_bytes);
    }

    #[test]
    fn test_verfer_invalid_code() {
        let public_bytes = [0u8; 32];
        let result = Verfer::from_raw(&public_bytes, matter_codes::BLAKE3_256);
        assert!(result.is_err());
    }

    #[test]
    fn test_verfer_verify_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();

        let message = b"test message";
        let signature = signing_key.sign(message);

        let verfer = Verfer::from_raw(&public_bytes, matter_codes::ED25519).unwrap();
        let result = verfer.verify(&signature.to_bytes(), message).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verfer_verify_invalid_signature() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();

        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = signing_key.sign(message);

        let verfer = Verfer::from_raw(&public_bytes, matter_codes::ED25519).unwrap();
        let result = verfer.verify(&signature.to_bytes(), wrong_message).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verfer_qb64_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();

        let verfer1 = Verfer::from_raw(&public_bytes, matter_codes::ED25519).unwrap();
        let qb64 = verfer1.qb64();

        let verfer2 = Verfer::from_qb64(qb64).unwrap();
        assert_eq!(verfer1.raw(), verfer2.raw());
        assert_eq!(verfer1.code(), verfer2.code());
    }

    #[test]
    fn test_verfer_transferable_vs_nontransferable() {
        let public_bytes = [0u8; 32];

        let verfer_t = Verfer::from_raw(&public_bytes, matter_codes::ED25519).unwrap();
        assert_eq!(verfer_t.code(), matter_codes::ED25519);

        let verfer_nt = Verfer::from_raw(&public_bytes, matter_codes::ED25519N).unwrap();
        assert_eq!(verfer_nt.code(), matter_codes::ED25519N);
    }

    #[test]
    fn test_verfer_invalid_signature_length() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();

        let message = b"test message";
        let bad_sig = [0u8; 32]; // Wrong length

        let verfer = Verfer::from_raw(&public_bytes, matter_codes::ED25519).unwrap();
        let result = verfer.verify(&bad_sig, message);
        assert!(result.is_err());
    }
}
