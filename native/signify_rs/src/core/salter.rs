use crate::core::{matter_codes, Matter};
/// Salter - Password-based key derivation using Argon2id
use crate::error::{Result, SignifyError};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::Rng;

/// Security tiers for key stretching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Low,
    Med,
    High,
}

impl Tier {
    /// Get Argon2 parameters for this tier
    /// These MUST match signify-ts exactly for compatibility
    pub fn params(&self) -> (u32, u32) {
        match self {
            // (opslimit, memlimit_kb)
            Tier::Low => (2, 65536),    // 64MB
            Tier::Med => (3, 262144),   // 256MB
            Tier::High => (4, 1048576), // 1GB
        }
    }

    /// Convert Tier to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Low => "low",
            Tier::Med => "med",
            Tier::High => "high",
        }
    }

    /// Parse Tier from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "low" => Ok(Tier::Low),
            "med" => Ok(Tier::Med),
            "high" => Ok(Tier::High),
            _ => Err(SignifyError::InvalidArgument(format!(
                "Unknown tier: {}",
                s
            ))),
        }
    }
}

/// Salter maintains a random salt for key derivation
#[derive(Debug, Clone)]
pub struct Salter {
    matter: Matter,
    tier: Tier,
}

impl Salter {
    /// Create new Salter with random salt
    pub fn new(tier: Tier) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let salt: [u8; 16] = rng.gen();
        Self::from_raw(&salt, tier)
    }

    /// Create Salter from raw salt bytes
    pub fn from_raw(raw: &[u8], tier: Tier) -> Result<Self> {
        let matter = Matter::from_raw(raw, matter_codes::SALT_128)?;
        Ok(Self { matter, tier })
    }

    /// Create Salter from qb64
    pub fn from_qb64(qb64: &str, tier: Tier) -> Result<Self> {
        let matter = Matter::from_qb64(qb64)?;
        Ok(Self { matter, tier })
    }

    /// Stretch password to derived key using Argon2id
    ///
    /// # Arguments
    /// * `size` - Output key size in bytes
    /// * `path` - Additional data mixed into derivation (e.g., "signify:controller00")
    /// * `tier` - Override default tier
    /// * `temp` - Use minimal parameters for testing (INSECURE!)
    pub fn stretch(
        &self,
        size: usize,
        path: &str,
        tier: Option<Tier>,
        temp: bool,
    ) -> Result<Vec<u8>> {
        let tier = tier.unwrap_or(self.tier);
        let (opslimit, memlimit_kb) = if temp {
            (1, 8) // Minimal for testing
        } else {
            tier.params()
        };

        // Create Argon2 instance
        let params = Params::new(
            memlimit_kb,
            opslimit,
            1, // parallelism
            Some(size),
        )
        .map_err(|e| SignifyError::Argon2Error(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Use salt from Matter
        let salt_string = SaltString::encode_b64(self.matter.raw())
            .map_err(|e| SignifyError::Argon2Error(e.to_string()))?;

        // Hash password (path) with salt
        let hash = argon2
            .hash_password(path.as_bytes(), &salt_string)
            .map_err(|e| SignifyError::Argon2Error(e.to_string()))?;

        // Extract derived key
        let hash_bytes = hash
            .hash
            .ok_or(SignifyError::Argon2Error("No hash output".to_string()))?;
        Ok(hash_bytes.as_bytes()[..size].to_vec())
    }

    /// Create Signer from stretched key
    ///
    /// # Example Path Patterns (from signify-ts):
    /// - "signify:controller00" - Inception signing key
    /// - "signify:controller01" - Inception rotation key
    /// - "signify:controller02" - Rotation signing key
    /// - Pattern: Different paths = different keys from same salt
    pub fn signer(
        &self,
        code: &str,
        transferable: bool,
        path: &str,
        tier: Option<Tier>,
        temp: bool,
    ) -> Result<crate::core::signer::Signer> {
        let raw_size = crate::core::codes::raw_size(code)?;
        let seed = self.stretch(raw_size, path, tier, temp)?;

        crate::core::signer::Signer::from_seed(&seed, code, transferable)
    }

    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn qb64(&self) -> &str {
        self.matter.qb64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salter_new() {
        let salter = Salter::new(Tier::Low).unwrap();
        assert_eq!(salter.matter().code(), matter_codes::SALT_128);
        assert_eq!(salter.matter().raw().len(), 16);
    }

    #[test]
    fn test_salter_stretch() {
        let salt = [0u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();

        // Stretch with temp params for speed
        let key = salter.stretch(32, "test:path:00", None, true).unwrap();
        assert_eq!(key.len(), 32);

        // Same input = same output (deterministic)
        let key2 = salter.stretch(32, "test:path:00", None, true).unwrap();
        assert_eq!(key, key2);

        // Different path = different output
        let key3 = salter.stretch(32, "test:path:01", None, true).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_salter_qb64_roundtrip() {
        let salter1 = Salter::new(Tier::Med).unwrap();
        let qb64 = salter1.qb64();

        let salter2 = Salter::from_qb64(qb64, Tier::Med).unwrap();
        assert_eq!(salter1.matter().raw(), salter2.matter().raw());
        assert_eq!(salter1.qb64(), salter2.qb64());
    }

    #[test]
    fn test_salter_different_tiers() {
        let salt = [0u8; 16];
        let salter_low = Salter::from_raw(&salt, Tier::Low).unwrap();
        let salter_med = Salter::from_raw(&salt, Tier::Med).unwrap();

        // Same salt, different tiers = different outputs (when not using temp)
        let key_low = salter_low.stretch(32, "test:path", None, true).unwrap();
        let key_med = salter_med.stretch(32, "test:path", None, true).unwrap();

        // With temp=true, tier is overridden so they should be equal
        assert_eq!(key_low, key_med);

        // Override tier in stretch
        let key_high = salter_low
            .stretch(32, "test:path", Some(Tier::High), true)
            .unwrap();
        assert_eq!(key_low, key_high); // Still equal because temp=true
    }

    #[test]
    fn test_tier_params() {
        assert_eq!(Tier::Low.params(), (2, 65536));
        assert_eq!(Tier::Med.params(), (3, 262144));
        assert_eq!(Tier::High.params(), (4, 1048576));
    }
}
