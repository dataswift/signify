use crate::core::codes::{matter_codes, raw_size};
use crate::core::matter::{Matter, MatterOpts};
use crate::error::{Result, SignifyError};

/// Cipher represents encrypted data in CESR format
/// Supports X25519 encryption of salts and seeds
pub struct Cipher {
    matter: Matter,
}

impl Cipher {
    /// Create a new Cipher from various input formats
    pub fn new(opts: MatterOpts) -> Result<Self> {
        // If raw is provided without code, derive code from raw size
        let code = if opts.raw.is_some() && opts.code.is_none() {
            let raw = opts.raw.as_ref().unwrap();
            let raw_size_val = raw.len();

            // Check which cipher type based on size
            if raw_size_val == raw_size(matter_codes::X25519_CIPHER_SALT)? {
                Some(matter_codes::X25519_CIPHER_SALT.to_string())
            } else if raw_size_val == raw_size(matter_codes::X25519_CIPHER_SEED)? {
                Some(matter_codes::X25519_CIPHER_SEED.to_string())
            } else {
                None
            }
        } else {
            opts.code.clone()
        };

        let matter_opts = MatterOpts { code, ..opts };

        let matter = Matter::new(matter_opts)?;

        // Validate that the code is a supported cipher code
        if matter.code() != matter_codes::X25519_CIPHER_SALT
            && matter.code() != matter_codes::X25519_CIPHER_SEED
        {
            return Err(SignifyError::InvalidCode(format!(
                "Unsupported Cipher code: {}",
                matter.code()
            )));
        }

        Ok(Self { matter })
    }

    /// Get the underlying Matter instance
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Get the code
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// Get the raw bytes
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Get the qb64 representation
    pub fn qb64(&self) -> Result<String> {
        Ok(self.matter.qb64().to_string())
    }

    /// Get the qb64 bytes representation
    pub fn qb64b(&self) -> Result<Vec<u8>> {
        Ok(self.matter.qb64b().to_vec())
    }

    /// Get the qb2 representation
    pub fn qb2(&self) -> Result<Vec<u8>> {
        Ok(self.matter.qb2().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_creation_from_raw() {
        // Create a cipher with raw bytes (72 bytes for X25519_CIPHER_SALT)
        // X25519 sealed box adds 48 bytes overhead to 24-byte salt
        let raw = vec![0u8; 72];
        let cipher = Cipher::new(MatterOpts {
            raw: Some(raw.clone()),
            code: None,
            qb64: None,
            qb64b: None,
            qb2: None,
        })
        .unwrap();

        assert_eq!(cipher.code(), matter_codes::X25519_CIPHER_SALT);
        assert_eq!(cipher.raw().len(), 72);
    }

    #[test]
    fn test_cipher_with_explicit_code() {
        let raw = vec![0u8; 72];
        let cipher = Cipher::new(MatterOpts {
            raw: Some(raw),
            code: Some(matter_codes::X25519_CIPHER_SALT.to_string()),
            qb64: None,
            qb64b: None,
            qb2: None,
        })
        .unwrap();

        assert_eq!(cipher.code(), matter_codes::X25519_CIPHER_SALT);
    }

    #[test]
    fn test_cipher_invalid_code() {
        let raw = vec![0u8; 32];
        let result = Cipher::new(MatterOpts {
            raw: Some(raw),
            code: Some(matter_codes::ED25519.to_string()),
            qb64: None,
            qb64b: None,
            qb2: None,
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_qb64_roundtrip() {
        let raw = vec![1u8; 72];
        let cipher = Cipher::new(MatterOpts {
            raw: Some(raw.clone()),
            code: Some(matter_codes::X25519_CIPHER_SALT.to_string()),
            qb64: None,
            qb64b: None,
            qb2: None,
        })
        .unwrap();

        let qb64 = cipher.qb64().unwrap();

        let cipher2 = Cipher::new(MatterOpts {
            raw: None,
            code: None,
            qb64: Some(qb64),
            qb64b: None,
            qb2: None,
        })
        .unwrap();

        assert_eq!(cipher.raw(), cipher2.raw());
        assert_eq!(cipher.code(), cipher2.code());
    }
}
