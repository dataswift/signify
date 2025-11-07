use crate::core::cipher::Cipher;
use crate::core::codes::matter_codes;
use crate::core::matter::{Matter, MatterOpts};
use crate::core::salter::{Salter, Tier};
use crate::core::signer::Signer;
use crate::error::{Result, SignifyError};
use crypto_box::SecretKey;
use ed25519_dalek::SigningKey;

/// Decrypter handles X25519 private key decryption
/// Converts Ed25519 private keys to X25519 for decryption
pub struct Decrypter {
    matter: Matter,
}

impl Decrypter {
    /// Create a new Decrypter
    ///
    /// # Arguments
    /// * `opts` - Matter options for the decrypter
    /// * `seed` - Optional Ed25519 seed bytes to convert to X25519 private key
    pub fn new(opts: MatterOpts, seed: Option<&[u8]>) -> Result<Self> {
        // Try to create Matter first
        let matter_result = Matter::new(MatterOpts {
            raw: opts.raw.clone(),
            code: opts
                .code
                .clone()
                .or(Some(matter_codes::X25519_PRIVATE.to_string())),
            qb64: opts.qb64.clone(),
            qb64b: opts.qb64b.clone(),
            qb2: opts.qb2.clone(),
        });

        let matter = match matter_result {
            Ok(m) => m,
            Err(SignifyError::EmptyMaterial(_)) if seed.is_some() => {
                // If empty material but seed provided, derive from seed
                let qb64_str = String::from_utf8(seed.unwrap().to_vec()).map_err(|e| {
                    SignifyError::InvalidFormat(format!("Invalid qb64 string: {}", e))
                })?;
                let signer = Signer::from_qb64(&qb64_str, true)?;

                // Verify it's an Ed25519 seed
                if signer.matter().code() != matter_codes::ED25519_SEED {
                    return Err(SignifyError::InvalidCode(format!(
                        "Unsupported signing seed derivation code: {}",
                        signer.matter().code()
                    )));
                }

                // Convert Ed25519 secret key to Curve25519 (X25519)
                let ed25519_bytes: [u8; 32] = signer.matter().raw().try_into().map_err(|_| {
                    SignifyError::InvalidKey("Invalid Ed25519 seed size".to_string())
                })?;

                let ed25519_sk = SigningKey::from_bytes(&ed25519_bytes);
                let x25519_sk = ed25519_sk.to_scalar_bytes();

                Matter::new(MatterOpts {
                    raw: Some(x25519_sk.to_vec()),
                    code: Some(matter_codes::X25519_PRIVATE.to_string()),
                    qb64: None,
                    qb64b: None,
                    qb2: None,
                })?
            }
            Err(e) => return Err(e),
        };

        // Validate code
        if matter.code() != matter_codes::X25519_PRIVATE {
            return Err(SignifyError::InvalidCode(format!(
                "Unsupported decrypter code: {}",
                matter.code()
            )));
        }

        Ok(Self { matter })
    }

    /// Decrypt cipher text using X25519 sealed box
    ///
    /// # Arguments
    /// * `ser` - Optional serialized cipher bytes to decrypt
    /// * `cipher` - Optional Cipher instance to decrypt
    /// * `transferable` - Whether the decrypted signer should be transferable
    pub fn decrypt(
        &self,
        ser: Option<&[u8]>,
        cipher: Option<&Cipher>,
        transferable: bool,
    ) -> Result<DecryptedMatter> {
        if ser.is_none() && cipher.is_none() {
            return Err(SignifyError::EmptyMaterial(
                "Neither ser nor cipher provided".to_string(),
            ));
        }

        let cipher_to_decrypt = if let Some(s) = ser {
            Cipher::new(MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: Some(s.to_vec()),
                qb2: None,
            })?
        } else {
            // Clone the cipher
            Cipher::new(MatterOpts {
                raw: Some(cipher.unwrap().raw().to_vec()),
                code: Some(cipher.unwrap().code().to_string()),
                qb64: None,
                qb64b: None,
                qb2: None,
            })?
        };

        self.x25519_decrypt(&cipher_to_decrypt, transferable)
    }

    /// Internal X25519 decryption using sealed box
    fn x25519_decrypt(&self, cipher: &Cipher, transferable: bool) -> Result<DecryptedMatter> {
        // Convert raw bytes to X25519 secret key
        let secret_bytes: [u8; 32] =
            self.matter.raw().try_into().map_err(|_| {
                SignifyError::InvalidKey("Invalid X25519 secret key size".to_string())
            })?;

        let secret_key = SecretKey::from(secret_bytes);

        // Decrypt using sealed box
        let plaintext = secret_key.unseal(cipher.raw()).map_err(|e| {
            SignifyError::DecryptionError(format!("Failed to decrypt cipher: {:?}", e))
        })?;

        // Return appropriate type based on cipher code
        match cipher.code() {
            c if c == matter_codes::X25519_CIPHER_SALT => {
                // Plaintext is qb64b bytes, convert to qb64 string
                let qb64_str = String::from_utf8(plaintext).map_err(|e| {
                    SignifyError::InvalidFormat(format!("Invalid qb64 string: {}", e))
                })?;
                let salter = Salter::from_qb64(&qb64_str, Tier::Low)?;
                Ok(DecryptedMatter::Salter(salter))
            }
            c if c == matter_codes::X25519_CIPHER_SEED => {
                // Plaintext is qb64b bytes, convert to qb64 string
                let qb64_str = String::from_utf8(plaintext).map_err(|e| {
                    SignifyError::InvalidFormat(format!("Invalid qb64 string: {}", e))
                })?;
                let signer = Signer::from_qb64(&qb64_str, transferable)?;
                Ok(DecryptedMatter::Signer(signer))
            }
            _ => Err(SignifyError::InvalidCode(format!(
                "Unsupported cipher code: {}",
                cipher.code()
            ))),
        }
    }

    /// Get the underlying Matter instance
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Get the raw X25519 private key bytes
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Get the qb64 representation
    pub fn qb64(&self) -> Result<String> {
        Ok(self.matter.qb64().to_string())
    }
}

/// Result of decryption, either a Salter or Signer
pub enum DecryptedMatter {
    Salter(Salter),
    Signer(Signer),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::encrypter::Encrypter;

    #[test]
    fn test_decrypter_from_seed() {
        let seed = vec![0u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let seed_qb64b = signer.matter().qb64b();

        let decrypter = Decrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&seed_qb64b),
        )
        .unwrap();

        assert_eq!(decrypter.matter().code(), matter_codes::X25519_PRIVATE);
        assert_eq!(decrypter.raw().len(), 32);
    }

    #[test]
    fn test_decrypter_invalid_code() {
        let raw = vec![0u8; 32];
        let result = Decrypter::new(
            MatterOpts {
                raw: Some(raw),
                code: Some(matter_codes::ED25519_SEED.to_string()),
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_salt_roundtrip() {
        // Create a signer and derive encrypter/decrypter
        let seed = vec![1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let verkey = signer.verfer().qb64b();
        let seed_qb64b = signer.matter().qb64b();

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

        let decrypter = Decrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&seed_qb64b),
        )
        .unwrap();

        // Create a salt and encrypt it
        let salter = Salter::new(Tier::Low).unwrap();
        let salt_qb64 = salter.qb64();
        let salt_qb64b = salter.matter().qb64b().to_vec();

        let cipher = encrypter.encrypt(Some(&salt_qb64b), None).unwrap();
        assert_eq!(cipher.code(), matter_codes::X25519_CIPHER_SALT);

        // Decrypt and verify
        let decrypted = decrypter.decrypt(None, Some(&cipher), false).unwrap();

        match decrypted {
            DecryptedMatter::Salter(decrypted_salter) => {
                let decrypted_qb64 = decrypted_salter.qb64();
                assert_eq!(salt_qb64, decrypted_qb64);
            }
            _ => panic!("Expected Salter"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_seed_roundtrip() {
        // Create a signer for encryption key
        let key_seed = vec![1u8; 32];
        let key_signer = Signer::from_seed(&key_seed, matter_codes::ED25519_SEED, true).unwrap();

        let verkey = key_signer.verfer().qb64b();
        let seed_qb64b = key_signer.matter().qb64b();

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

        let decrypter = Decrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&seed_qb64b),
        )
        .unwrap();

        // Create another signer to encrypt
        let data_seed = vec![2u8; 32];
        let data_signer = Signer::from_seed(&data_seed, matter_codes::ED25519_SEED, true).unwrap();

        let data_qb64 = data_signer.qb64().as_bytes();
        let data_qb64b = data_signer.matter().qb64b();

        let cipher = encrypter.encrypt(Some(&data_qb64b), None).unwrap();
        assert_eq!(cipher.code(), matter_codes::X25519_CIPHER_SEED);

        // Decrypt and verify
        let decrypted = decrypter.decrypt(None, Some(&cipher), false).unwrap();

        match decrypted {
            DecryptedMatter::Signer(decrypted_signer) => {
                let decrypted_qb64 = decrypted_signer.qb64().as_bytes();
                assert_eq!(data_qb64, decrypted_qb64);
            }
            _ => panic!("Expected Signer"),
        }
    }

    #[test]
    fn test_decrypt_invalid_cipher() {
        let seed = vec![1u8; 32];
        let signer = Signer::from_seed(&seed, matter_codes::ED25519_SEED, true).unwrap();

        let seed_qb64b = signer.matter().qb64b();

        let decrypter = Decrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&seed_qb64b),
        )
        .unwrap();

        // Try to decrypt with wrong key
        let other_seed = vec![2u8; 32];
        let other_signer =
            Signer::from_seed(&other_seed, matter_codes::ED25519_SEED, true).unwrap();

        let other_verkey = other_signer.verfer().qb64b();
        let other_encrypter = Encrypter::new(
            MatterOpts {
                raw: None,
                code: None,
                qb64: None,
                qb64b: None,
                qb2: None,
            },
            Some(&other_verkey),
        )
        .unwrap();

        let salter = Salter::new(Tier::Low).unwrap();
        let salt_qb64b = salter.matter().qb64b().to_vec();
        let cipher = other_encrypter.encrypt(Some(&salt_qb64b), None).unwrap();

        // This should fail because we're using the wrong decryption key
        let result = decrypter.decrypt(None, Some(&cipher), false);
        assert!(result.is_err());
    }
}
