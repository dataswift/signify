use crate::core::cipher::Cipher;
use crate::core::codes::matter_codes;
use crate::core::matter::{Matter, MatterOpts};
use crate::core::salter::Tier;
use crate::core::signer::Signer;
use crate::core::verfer::Verfer;
use crate::error::{Result, SignifyError};
use crypto_box::PublicKey;
use ed25519_dalek::VerifyingKey;

/// Encrypter handles X25519 public key encryption
/// Converts Ed25519 public keys to X25519 for encryption
pub struct Encrypter {
    matter: Matter,
}

impl Encrypter {
    /// Create a new Encrypter
    ///
    /// # Arguments
    /// * `opts` - Matter options for the encrypter
    /// * `verkey` - Optional Ed25519 verification key bytes to convert to X25519
    pub fn new(opts: MatterOpts, verkey: Option<&[u8]>) -> Result<Self> {
        let (raw, code) = if opts.raw.is_none() && verkey.is_some() {
            // Convert Ed25519 public key to X25519
            let qb64_str = String::from_utf8(verkey.unwrap().to_vec())
                .map_err(|e| SignifyError::InvalidFormat(format!("Invalid qb64 string: {}", e)))?;
            let verfer = Verfer::from_qb64(&qb64_str)?;

            // Verify it's an Ed25519 key
            if verfer.code() != matter_codes::ED25519 && verfer.code() != matter_codes::ED25519N {
                return Err(SignifyError::InvalidCode(format!(
                    "Unsupported verkey derivation code: {}",
                    verfer.code()
                )));
            }

            // Convert Ed25519 public key to Curve25519 (X25519)
            let ed25519_bytes: [u8; 32] = verfer.raw().try_into().map_err(|_| {
                SignifyError::InvalidKey("Invalid Ed25519 public key size".to_string())
            })?;

            let ed25519_pk = VerifyingKey::from_bytes(&ed25519_bytes).map_err(|e| {
                SignifyError::InvalidKey(format!("Invalid Ed25519 public key: {}", e))
            })?;

            let x25519_pk = ed25519_pk.to_montgomery();

            (
                Some(x25519_pk.to_bytes().to_vec()),
                Some(matter_codes::X25519.to_string()),
            )
        } else {
            (opts.raw.clone(), opts.code.clone())
        };

        let matter = Matter::new(MatterOpts {
            raw,
            code: code.or(Some(matter_codes::X25519.to_string())),
            qb64: opts.qb64,
            qb64b: opts.qb64b,
            qb2: opts.qb2,
        })?;

        // Validate code
        if matter.code() != matter_codes::X25519 {
            return Err(SignifyError::InvalidCode(format!(
                "Unsupported encrypter code: {}",
                matter.code()
            )));
        }

        Ok(Self { matter })
    }

    /// Verify that a seed corresponds to this public key
    pub fn verify_seed(&self, seed: &[u8]) -> Result<bool> {
        // seed is qb64b bytes, convert to string
        let qb64_str = String::from_utf8(seed.to_vec())
            .map_err(|e| SignifyError::InvalidFormat(format!("Invalid qb64 string: {}", e)))?;
        let signer = Signer::from_qb64(&qb64_str, true)?;

        // Convert signer's Ed25519 public key to X25519
        let ed25519_bytes: [u8; 32] =
            signer.verfer().raw().try_into().map_err(|_| {
                SignifyError::InvalidKey("Invalid Ed25519 public key size".to_string())
            })?;

        let ed25519_pk = VerifyingKey::from_bytes(&ed25519_bytes)
            .map_err(|e| SignifyError::InvalidKey(format!("Invalid Ed25519 public key: {}", e)))?;

        let x25519_pk = ed25519_pk.to_montgomery();

        Ok(x25519_pk.as_bytes() == self.matter.raw())
    }

    /// Encrypt data using X25519 sealed box
    ///
    /// # Arguments
    /// * `ser` - Optional serialized bytes to encrypt
    /// * `matter` - Optional Matter instance to encrypt
    pub fn encrypt(&self, ser: Option<&[u8]>, matter: Option<&Matter>) -> Result<Cipher> {
        if ser.is_none() && matter.is_none() {
            return Err(SignifyError::InvalidInput(
                "Neither ser nor matter provided".to_string(),
            ));
        }

        let matter_to_encrypt = if let Some(s) = ser {
            Matter::new(MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: Some(s.to_vec()),
                qb2: None,
            })?
        } else {
            matter.unwrap().clone()
        };

        // Determine cipher code based on input matter code
        let cipher_code = if matter_to_encrypt.code() == matter_codes::SALT_128 {
            matter_codes::X25519_CIPHER_SALT
        } else {
            matter_codes::X25519_CIPHER_SEED
        };

        // Perform X25519 sealed box encryption
        let encrypted = self.x25519_encrypt(&matter_to_encrypt.qb64b(), cipher_code)?;

        Ok(encrypted)
    }

    /// Internal X25519 encryption using sealed box
    fn x25519_encrypt(&self, ser: &[u8], code: &str) -> Result<Cipher> {
        // Convert raw bytes to X25519 public key
        let pubkey_bytes: [u8; 32] =
            self.matter.raw().try_into().map_err(|_| {
                SignifyError::InvalidKey("Invalid X25519 public key size".to_string())
            })?;

        let pubkey = PublicKey::from(pubkey_bytes);

        // Encrypt using sealed box (anonymous encryption)
        let ciphertext = pubkey
            .seal(&mut rand::thread_rng(), ser)
            .map_err(|e| SignifyError::CryptoError(format!("Encryption failed: {:?}", e)))?;

        Cipher::new(MatterOpts {
            raw: Some(ciphertext),
            code: Some(code.to_string()),
            qb64: None,
            qb64b: None,
            qb2: None,
        })
    }

    /// Get the underlying Matter instance
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Get the raw X25519 public key bytes
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Get the qb64 representation
    pub fn qb64(&self) -> Result<String> {
        Ok(self.matter.qb64().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::salter::Salter;

    #[test]
    fn test_encrypter_from_verkey() {
        // Create a signer to get an Ed25519 public key
        let seed = vec![0u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let verkey = signer.verfer().matter().qb64b();

        let encrypter = Encrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&verkey),
        )
        .unwrap();

        assert_eq!(encrypter.matter().code(), matter_codes::X25519);
        assert_eq!(encrypter.raw().len(), 32);
    }

    #[test]
    fn test_encrypter_verify_seed() {
        let seed = vec![0u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let verkey = signer.verfer().matter().qb64b();

        let encrypter = Encrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&verkey),
        )
        .unwrap();

        let seed_qb64b = signer.matter().qb64b();
        assert!(encrypter.verify_seed(&seed_qb64b).unwrap());
    }

    #[test]
    fn test_encrypter_encrypt_salt() {
        let seed = vec![0u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let verkey = signer.verfer().matter().qb64b();
        let encrypter = Encrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&verkey),
        )
        .unwrap();

        // Create a salt to encrypt
        let salter = Salter::new(Tier::Low).unwrap();
        let salt_qb64b = salter.matter().qb64b().to_vec();

        let cipher = encrypter.encrypt(Some(&salt_qb64b), None).unwrap();
        assert_eq!(cipher.code(), matter_codes::X25519_CIPHER_SALT);
    }

    #[test]
    fn test_encrypter_invalid_verkey_code() {
        // Try to create encrypter with non-Ed25519 key
        let raw = vec![0u8; 32];
        let result = Encrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&raw),
        );

        // This should fail because raw bytes won't parse as valid qb64
        assert!(result.is_err());
    }
}
