/// Prefixer - Prefix derivation and verification for KERI identifiers
///
/// Prefixer handles identifier prefix derivation from inception events (icp, dip, vcp).
/// Supports three derivation methods:
/// - Ed25519N: Non-transferable single key (prefix = key)
/// - Ed25519: Transferable single key (prefix = key)
/// - Blake3_256: Self-addressing (prefix = BLAKE3 hash of event)
use crate::core::matter::Matter;
use crate::core::matter_codes;
use crate::core::serder::Serder;
use crate::core::verfer::Verfer;
use crate::error::{Result, SignifyError};
use blake3;
use serde_json::Value;

const DUMMY: char = '#';

/// Derivation method for prefix
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DerivationCode {
    Ed25519N,  // Non-transferable
    Ed25519,   // Transferable
    Blake3256, // Self-addressing
}

impl DerivationCode {
    fn from_code(code: &str) -> Result<Self> {
        match code {
            matter_codes::ED25519N => Ok(Self::Ed25519N),
            matter_codes::ED25519 => Ok(Self::Ed25519),
            matter_codes::BLAKE3_256 => Ok(Self::Blake3256),
            _ => Err(SignifyError::InvalidCode(format!(
                "Unsupported derivation code: {}",
                code
            ))),
        }
    }

    fn to_code(&self) -> &'static str {
        match self {
            Self::Ed25519N => matter_codes::ED25519N,
            Self::Ed25519 => matter_codes::ED25519,
            Self::Blake3256 => matter_codes::BLAKE3_256,
        }
    }
}

/// Prefixer for KERI identifier prefix handling
pub struct Prefixer {
    matter: Matter,
    derivation: DerivationCode,
}

impl Prefixer {
    /// Create Prefixer from existing Matter (qb64 or raw)
    pub fn new(matter: Matter) -> Result<Self> {
        let derivation = DerivationCode::from_code(matter.code())?;
        Ok(Self { matter, derivation })
    }

    /// Create Prefixer from qb64
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        let matter = Matter::from_qb64(qb64)?;
        Self::new(matter)
    }

    /// Create Prefixer by deriving from inception event
    pub fn from_event(serder: &Serder, code: Option<&str>) -> Result<Self> {
        let ilk = serder
            .ilk()
            .ok_or_else(|| SignifyError::InvalidFormat("Missing ilk field in event".to_string()))?;

        // Only inception events can derive prefixes
        if ilk != "icp" && ilk != "dip" && ilk != "vcp" {
            return Err(SignifyError::InvalidFormat(format!(
                "Non-incepting ilk {} for prefix derivation",
                ilk
            )));
        }

        let sad = serder.sad();

        // Determine derivation code
        let derivation_code = if let Some(c) = code {
            c
        } else {
            // Try to infer from 'i' field if present
            sad.get("i").and_then(|v| v.as_str()).ok_or_else(|| {
                SignifyError::InvalidFormat("Missing 'i' field and no code provided".to_string())
            })?
        };

        let derivation = DerivationCode::from_code(derivation_code)?;

        // For events that already have a prefix in 'i' field, extract it
        // This is more reliable than re-deriving for self-addressing identifiers
        let prefix_from_event = sad
            .get("i")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());

        let matter = if let Some(prefix_qb64) = prefix_from_event {
            // Event already has prefix, use it
            Matter::from_qb64(prefix_qb64)?
        } else {
            // No prefix yet, derive it
            let (raw, code) = match derivation {
                DerivationCode::Ed25519N => Self::derive_ed25519n(sad)?,
                DerivationCode::Ed25519 => Self::derive_ed25519(sad)?,
                DerivationCode::Blake3256 => Self::derive_blake3_256(serder)?,
            };
            Matter::from_raw(&raw, code)?
        };

        Ok(Self { matter, derivation })
    }

    /// Derive Ed25519N (non-transferable) prefix from event
    fn derive_ed25519n(sad: &Value) -> Result<(Vec<u8>, &'static str)> {
        let keys = sad
            .get("k")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SignifyError::InvalidFormat("Missing 'k' field".to_string()))?;

        if keys.len() != 1 {
            return Err(SignifyError::InvalidFormat(format!(
                "Basic derivation needs exactly 1 key, got {}",
                keys.len()
            )));
        }

        let key_qb64 = keys[0]
            .as_str()
            .ok_or_else(|| SignifyError::InvalidFormat("Key must be string".to_string()))?;

        let verfer = Verfer::from_qb64(key_qb64)?;

        if verfer.code() != matter_codes::ED25519N {
            return Err(SignifyError::InvalidCode(format!(
                "Mismatch derivation code: expected {}, got {}",
                matter_codes::ED25519N,
                verfer.code()
            )));
        }

        // Non-transferable identifiers must have empty next keys
        let next = sad.get("n").and_then(|v| v.as_array());
        if let Some(n) = next {
            if !n.is_empty() {
                return Err(SignifyError::InvalidFormat(
                    "Non-empty next keys for non-transferable identifier".to_string(),
                ));
            }
        }

        // Non-transferable identifiers must have empty backers
        let backers = sad.get("b").and_then(|v| v.as_array());
        if let Some(b) = backers {
            if !b.is_empty() {
                return Err(SignifyError::InvalidFormat(
                    "Non-empty backers for non-transferable identifier".to_string(),
                ));
            }
        }

        // Non-transferable identifiers must have empty anchors
        let anchors = sad.get("a").and_then(|v| v.as_array());
        if let Some(a) = anchors {
            if !a.is_empty() {
                return Err(SignifyError::InvalidFormat(
                    "Non-empty anchors for non-transferable identifier".to_string(),
                ));
            }
        }

        let raw = verfer.raw().to_vec();
        let code = matter_codes::ED25519N;
        Ok((raw, code))
    }

    /// Derive Ed25519 (transferable) prefix from event
    fn derive_ed25519(sad: &Value) -> Result<(Vec<u8>, &'static str)> {
        let keys = sad
            .get("k")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SignifyError::InvalidFormat("Missing 'k' field".to_string()))?;

        if keys.len() != 1 {
            return Err(SignifyError::InvalidFormat(format!(
                "Basic derivation needs exactly 1 key, got {}",
                keys.len()
            )));
        }

        let key_qb64 = keys[0]
            .as_str()
            .ok_or_else(|| SignifyError::InvalidFormat("Key must be string".to_string()))?;

        let verfer = Verfer::from_qb64(key_qb64)?;

        if verfer.code() != matter_codes::ED25519 {
            return Err(SignifyError::InvalidCode(format!(
                "Mismatch derivation code: expected {}, got {}",
                matter_codes::ED25519,
                verfer.code()
            )));
        }

        let raw = verfer.raw().to_vec();
        let code = matter_codes::ED25519;
        Ok((raw, code))
    }

    /// Derive Blake3-256 (self-addressing) prefix from event
    fn derive_blake3_256(serder: &Serder) -> Result<(Vec<u8>, &'static str)> {
        let ilk = serder
            .ilk()
            .ok_or_else(|| SignifyError::InvalidFormat("Missing ilk field".to_string()))?;

        if ilk != "icp" && ilk != "dip" && ilk != "vcp" {
            return Err(SignifyError::InvalidFormat(format!(
                "Invalid ilk {} for BLAKE3 derivation",
                ilk
            )));
        }

        // Create a copy of the event with dummy prefix
        let mut sad = serder.sad().clone();
        let dummy_prefix = DUMMY.to_string().repeat(44); // BLAKE3-256 qb64 length is 44

        sad["i"] = Value::String(dummy_prefix.clone());
        sad["d"] = Value::String(dummy_prefix);

        // Create new Serder with dummy prefix (don't pass code to avoid recalculating SAID)
        let temp_serder = Serder::new(sad, None, None)?;

        // Hash the serialized event
        let raw_bytes = temp_serder.raw().as_bytes();
        let hash = blake3::hash(raw_bytes);

        Ok((hash.as_bytes().to_vec(), matter_codes::BLAKE3_256))
    }

    /// Verify that the prefix matches the event
    pub fn verify(&self, serder: &Serder, prefixed: bool) -> Result<bool> {
        let ilk = serder
            .ilk()
            .ok_or_else(|| SignifyError::InvalidFormat("Missing ilk field".to_string()))?;

        if ilk != "icp" && ilk != "dip" && ilk != "vcp" {
            return Err(SignifyError::InvalidFormat(format!(
                "Non-incepting ilk {} for prefix verification",
                ilk
            )));
        }

        let result = match self.derivation {
            DerivationCode::Ed25519N => self.verify_ed25519n(serder, prefixed),
            DerivationCode::Ed25519 => self.verify_ed25519(serder, prefixed),
            DerivationCode::Blake3256 => self.verify_blake3_256(serder, prefixed),
        };

        Ok(result.unwrap_or(false))
    }

    fn verify_ed25519n(&self, serder: &Serder, prefixed: bool) -> Result<bool> {
        let sad = serder.sad();
        let pre = self.qb64();

        let keys = match sad.get("k").and_then(|v| v.as_array()) {
            Some(k) => k,
            None => return Ok(false),
        };

        if keys.len() != 1 {
            return Ok(false);
        }

        let key = match keys[0].as_str() {
            Some(k) => k,
            None => return Ok(false),
        };

        if key != pre {
            return Ok(false);
        }

        if prefixed {
            let i = match sad.get("i").and_then(|v| v.as_str()) {
                Some(i) => i,
                None => return Ok(false),
            };
            if i != pre {
                return Ok(false);
            }
        }

        // Check empty next keys
        if let Some(n) = sad.get("n").and_then(|v| v.as_array()) {
            if !n.is_empty() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn verify_ed25519(&self, serder: &Serder, prefixed: bool) -> Result<bool> {
        let sad = serder.sad();
        let pre = self.qb64();

        let keys = match sad.get("k").and_then(|v| v.as_array()) {
            Some(k) => k,
            None => return Ok(false),
        };

        if keys.len() != 1 {
            return Ok(false);
        }

        let key = match keys[0].as_str() {
            Some(k) => k,
            None => return Ok(false),
        };

        if key != pre {
            return Ok(false);
        }

        if prefixed {
            let i = match sad.get("i").and_then(|v| v.as_str()) {
                Some(i) => i,
                None => return Ok(false),
            };
            if i != pre {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn verify_blake3_256(&self, serder: &Serder, prefixed: bool) -> Result<bool> {
        // For Blake3-256 (self-addressing), verify by checking the SAID in the serder
        // The serder's SAID should match our prefix
        let said = match serder.said_field() {
            Some(s) => s,
            None => return Ok(false),
        };

        // The 'd' field should match our prefix for self-addressing identifiers
        if said != self.qb64() {
            return Ok(false);
        }

        if prefixed {
            let i = match serder.sad().get("i").and_then(|v| v.as_str()) {
                Some(i) => i,
                None => return Ok(false),
            };
            // For self-addressing, 'i' should also equal the SAID
            if i != self.qb64() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get qb64 encoding
    pub fn qb64(&self) -> &str {
        self.matter.qb64()
    }

    /// Get qb2 encoding
    pub fn qb2(&self) -> &[u8] {
        self.matter.qb2()
    }

    /// Get raw bytes
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Get code
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// Get derivation method
    pub fn derivation(&self) -> DerivationCode {
        self.derivation
    }

    /// Get underlying Matter
    pub fn matter(&self) -> &Matter {
        &self.matter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::diger::Diger;
    use crate::core::eventing::incept;
    use crate::core::salter::{Salter, Tier};
    use crate::core::signer::Signer;

    #[test]
    fn test_prefixer_from_qb64() {
        // Ed25519 key
        let qb64 = "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA";
        let prefixer = Prefixer::from_qb64(qb64).unwrap();
        assert_eq!(prefixer.qb64(), qb64);
        assert_eq!(prefixer.code(), matter_codes::ED25519);
    }

    #[test]
    fn test_prefixer_ed25519_derivation() {
        // Create a signer
        let salt = [1u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();
        let signer = salter
            .signer(matter_codes::ED25519_SEED, true, "test:0", None, true)
            .unwrap();

        let keys = vec![signer.verfer().qb64().to_string()];

        // Create inception event
        let serder = incept(
            keys,
            None,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(matter_codes::ED25519),
            false,
            None,
        )
        .unwrap();

        // Derive prefix
        let prefixer = Prefixer::from_event(&serder, Some(matter_codes::ED25519)).unwrap();
        assert_eq!(prefixer.qb64(), signer.verfer().qb64());
        assert_eq!(prefixer.derivation(), DerivationCode::Ed25519);

        // Verify
        assert!(prefixer.verify(&serder, true).unwrap());
    }

    #[test]
    fn test_prefixer_ed25519n_derivation() {
        // Create non-transferable signer
        let salt = [2u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();
        let signer = salter
            .signer(matter_codes::ED25519_SEED, false, "test:0", None, false)
            .unwrap();

        let keys = vec![signer.verfer().qb64().to_string()];

        // Create inception event with no next keys
        let serder = incept(
            keys,
            None,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(matter_codes::ED25519N),
            false,
            None,
        )
        .unwrap();

        // Derive prefix
        let prefixer = Prefixer::from_event(&serder, Some(matter_codes::ED25519N)).unwrap();
        assert_eq!(prefixer.qb64(), signer.verfer().qb64());
        assert_eq!(prefixer.derivation(), DerivationCode::Ed25519N);

        // Verify
        assert!(prefixer.verify(&serder, true).unwrap());
    }

    #[test]
    fn test_prefixer_blake3_256_derivation() {
        // Create signer
        let salt = [3u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();
        let signer = salter
            .signer(matter_codes::ED25519_SEED, true, "test:0", None, true)
            .unwrap();

        let keys = vec![signer.verfer().qb64().to_string()];

        // Create next key digests
        let next_signer = salter
            .signer(matter_codes::ED25519_SEED, true, "test:1", None, true)
            .unwrap();
        let next_dig = Diger::new(matter_codes::BLAKE3_256, next_signer.verfer().raw()).unwrap();
        let ndigs = vec![next_dig.qb64().to_string()];

        // Create inception event with BLAKE3-256 self-addressing
        let serder = incept(
            keys,
            None,
            ndigs,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(matter_codes::BLAKE3_256),
            false,
            None,
        )
        .unwrap();

        // Derive prefix
        let prefixer = Prefixer::from_event(&serder, Some(matter_codes::BLAKE3_256)).unwrap();
        assert_eq!(prefixer.derivation(), DerivationCode::Blake3256);
        assert!(prefixer.qb64().starts_with('E')); // BLAKE3-256 code

        // Verify
        assert!(prefixer.verify(&serder, true).unwrap());

        // Prefix should match identifier
        let identifier = serder.pre().unwrap();
        assert_eq!(prefixer.qb64(), identifier);
    }

    #[test]
    fn test_prefixer_invalid_ilk() {
        use serde_json::json;

        // Create non-inception event
        let event = json!({
            "v": "KERI10JSON000000_",
            "t": "rot",  // rotation, not inception
            "d": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
            "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
            "s": "1"
        });

        let serder = Serder::new(event, None, None).unwrap();
        let result = Prefixer::from_event(&serder, Some(matter_codes::BLAKE3_256));
        assert!(result.is_err());
    }

    #[test]
    fn test_prefixer_multi_key_error() {
        use serde_json::json;

        // Multi-key inception (not supported for basic derivation)
        let event = json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "2",
            "k": [
                "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA",
                "DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
            ],
            "n": [],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });

        let serder = Serder::new(event, None, None).unwrap();
        let result = Prefixer::from_event(&serder, Some(matter_codes::ED25519));
        assert!(result.is_err()); // Should fail with 2 keys
    }
}
