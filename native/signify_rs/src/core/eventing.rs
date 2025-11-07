//! KERI Event creation and processing
//!
//! Provides functions for creating KERI events like inception (icp), rotation (rot), etc.

use crate::core::codes::matter_codes;
use crate::core::prefixer::Prefixer;
use crate::core::saider::Saider;
use crate::core::serder::Serder;
use crate::core::utils::{Protocols, Serials, VRSN_1_0};
use crate::error::{Result, SignifyError};
use serde_json::{json, Value};

/// Event ilks (types)
pub const ILK_ICP: &str = "icp"; // Inception
pub const ILK_ROT: &str = "rot"; // Rotation
pub const ILK_IXN: &str = "ixn"; // Interaction
pub const ILK_DIP: &str = "dip"; // Delegated inception
pub const ILK_DRT: &str = "drt"; // Delegated rotation

/// Create version string for KERI events
fn versify(protocol: &str, version: &str, kind: &str, size: usize) -> String {
    format!("{}{}{}_{:06x}", protocol, version, kind, size)
}

/// Calculate ample (sufficient majority) threshold
fn ample(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (n / 2) + 1
    }
}

/// Create an inception event
///
/// # Arguments
/// * `keys` - Public keys (verfers) as qb64 strings
/// * `isith` - Initial signing threshold (hex string like "1", "2", etc)
/// * `ndigs` - Next key digests as qb64 strings
/// * `nsith` - Next signing threshold
/// * `toad` - Witness threshold
/// * `wits` - Witness identifiers
/// * `cnfg` - Configuration traits
/// * `data` - Additional data
/// * `version` - Protocol version
/// * `kind` - Serialization kind
/// * `code` - Derivation code for identifier
/// * `intive` - Use integer values for thresholds
/// * `delpre` - Delegator prefix for delegated identifiers
pub fn incept(
    keys: Vec<String>,
    isith: Option<&str>,
    ndigs: Vec<String>,
    nsith: Option<&str>,
    toad: Option<usize>,
    wits: Option<Vec<String>>,
    cnfg: Option<Vec<String>>,
    data: Option<Vec<Value>>,
    version: Option<&str>,
    kind: Option<&str>,
    code: Option<&str>,
    intive: bool,
    delpre: Option<&str>,
) -> Result<Serder> {
    use crate::core::utils::versify;

    let vs = versify(Protocols::KERI, Some(VRSN_1_0), Some(Serials::JSON), 0);

    // Choose event ilk based on delegation
    let ilk = if delpre.is_some() { ILK_DIP } else { ILK_ICP };

    // Parse signing thresholds
    let isith_val = if let Some(s) = isith {
        usize::from_str_radix(s, 16)
            .map_err(|_| SignifyError::InvalidArgument(format!("Invalid isith hex: {}", s)))?
    } else {
        std::cmp::max(1, (keys.len() + 1) / 2)
    };

    if isith_val < 1 {
        return Err(SignifyError::InvalidArgument(format!(
            "Invalid isith = {} less than 1",
            isith_val
        )));
    }

    if isith_val > keys.len() {
        return Err(SignifyError::InvalidArgument(format!(
            "Invalid isith = {} for {} keys",
            isith_val,
            keys.len()
        )));
    }

    let nsith_val = if let Some(s) = nsith {
        usize::from_str_radix(s, 16)
            .map_err(|_| SignifyError::InvalidArgument(format!("Invalid nsith hex: {}", s)))?
    } else {
        std::cmp::max(0, (ndigs.len() + 1) / 2)
    };

    if nsith_val > ndigs.len() {
        return Err(SignifyError::InvalidArgument(format!(
            "Invalid nsith = {} for {} next keys",
            nsith_val,
            ndigs.len()
        )));
    }

    // Process witnesses
    let wits = wits.unwrap_or_default();

    // Check for duplicate witnesses
    let mut wit_set = std::collections::HashSet::new();
    for wit in &wits {
        if !wit_set.insert(wit) {
            return Err(SignifyError::InvalidArgument(format!(
                "Duplicate witness: {}",
                wit
            )));
        }
    }

    // Calculate witness threshold
    let toad_val = toad.unwrap_or_else(|| {
        if wits.is_empty() {
            0
        } else {
            ample(wits.len())
        }
    });

    // Validate witness threshold
    if !wits.is_empty() {
        if toad_val < 1 || toad_val > wits.len() {
            return Err(SignifyError::InvalidArgument(format!(
                "Invalid toad = {} for {} witnesses",
                toad_val,
                wits.len()
            )));
        }
    } else if toad_val != 0 {
        return Err(SignifyError::InvalidArgument(format!(
            "Invalid toad = {} for 0 witnesses",
            toad_val
        )));
    }

    let cnfg = cnfg.unwrap_or_default();
    let data = data.unwrap_or_default();

    // Build the event SAD (Self-Addressing Data)
    let mut sad = json!({
        "v": vs,
        "t": ilk,
        "d": "",
        "i": "",
        "s": "0",
        "kt": if intive { isith_val.to_string() } else { format!("{:x}", isith_val) },
        "k": keys,
        "nt": if intive { nsith_val.to_string() } else { format!("{:x}", nsith_val) },
        "n": ndigs,
        "bt": if intive { toad_val.to_string() } else { format!("{:x}", toad_val) },
        "b": wits,
        "c": cnfg,
        "a": data,
    });

    // Add delegator prefix for delegated identifiers
    if let Some(dp) = delpre {
        sad["di"] = json!(dp);
    }

    // Derive identifier prefix
    let prefixer = if delpre.is_none() && code.is_none() && keys.len() == 1 {
        // Single key, non-delegated: use key as identifier
        let pref = Prefixer::from_qb64(&keys[0])?;

        if pref.code() == matter_codes::BLAKE3_256
            || pref.code() == matter_codes::SHA3_256
            || pref.code() == matter_codes::SHA2_256
            || pref.code() == matter_codes::BLAKE2B_256
        {
            return Err(SignifyError::InvalidArgument(format!(
                "Invalid code, digestive={}, must be derived from ked",
                pref.code()
            )));
        }

        pref
    } else {
        // Multi-key or delegated: derive from event
        let derive_code = code.unwrap_or(matter_codes::BLAKE3_256);

        // Create temporary Serder to use from_event
        let temp_serder = Serder::new(sad.clone(), None, None)?;
        let pref = Prefixer::from_event(&temp_serder, Some(derive_code))?;

        // Delegated identifiers must use digestive code
        if delpre.is_some() {
            let is_digestive = pref.code() == matter_codes::BLAKE3_256
                || pref.code() == matter_codes::SHA3_256
                || pref.code() == matter_codes::SHA2_256
                || pref.code() == matter_codes::BLAKE2B_256;

            if !is_digestive {
                return Err(SignifyError::InvalidArgument(format!(
                    "Invalid derivation code = {} for delegation. Must be digestive",
                    pref.code()
                )));
            }
        }

        pref
    };

    // Set identifier
    sad["i"] = json!(prefixer.qb64());

    // Set digest field
    let is_digestive = prefixer.code() == matter_codes::BLAKE3_256
        || prefixer.code() == matter_codes::SHA3_256
        || prefixer.code() == matter_codes::SHA2_256
        || prefixer.code() == matter_codes::BLAKE2B_256;

    if is_digestive {
        sad["d"] = json!(prefixer.qb64());
    } else {
        // Calculate SAID
        let saider = Saider::saidify(&mut sad)?;
        sad["d"] = json!(saider.qb64());
    }

    Serder::new(sad, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::signer::Signer;

    #[test]
    fn test_versify() {
        let vs = versify("KERI", "1.0", "JSON", 0);
        assert_eq!(vs, "KERI1.0JSON_000000");

        let vs2 = versify("KERI", "1.0", "JSON", 256);
        assert_eq!(vs2, "KERI1.0JSON_000100");
    }

    #[test]
    fn test_ample() {
        assert_eq!(ample(0), 0);
        assert_eq!(ample(1), 1);
        assert_eq!(ample(2), 2);
        assert_eq!(ample(3), 2);
        assert_eq!(ample(4), 3);
        assert_eq!(ample(5), 3);
    }

    #[test]
    fn test_incept_single_key() {
        let signer = Signer::new_random(matter_codes::ED25519_SEED, true).unwrap();
        let keys = vec![signer.verfer().qb64().to_string()];

        let serder = incept(
            keys,
            Some("1"),
            vec![],
            Some("0"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();

        let sad = serder.sad();
        assert_eq!(sad["t"], "icp");
        assert_eq!(sad["s"], "0");
        assert_eq!(sad["kt"], "1");
        assert!(sad["i"].is_string());
    }

    #[test]
    fn test_incept_multi_key() {
        let signer1 = Signer::new_random(matter_codes::ED25519_SEED, true).unwrap();
        let signer2 = Signer::new_random(matter_codes::ED25519_SEED, true).unwrap();
        let signer3 = Signer::new_random(matter_codes::ED25519_SEED, true).unwrap();

        let keys = vec![
            signer1.verfer().qb64().to_string(),
            signer2.verfer().qb64().to_string(),
            signer3.verfer().qb64().to_string(),
        ];

        let serder = incept(
            keys,
            Some("2"),
            vec![],
            Some("0"),
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

        let sad = serder.sad();
        assert_eq!(sad["t"], "icp");
        assert_eq!(sad["kt"], "2");
        assert!(sad["i"].is_string());
        assert!(sad["d"].is_string());
    }

    #[test]
    fn test_incept_with_witnesses() {
        let signer = Signer::new_random(matter_codes::ED25519_SEED, true).unwrap();
        let keys = vec![signer.verfer().qb64().to_string()];

        let wits = vec![
            "BWitness1AAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            "BWitness2AAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ];

        let serder = incept(
            keys,
            Some("1"),
            vec![],
            Some("0"),
            Some(2),
            Some(wits.clone()),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();

        let sad = serder.sad();
        assert_eq!(sad["bt"], "2");
        assert_eq!(sad["b"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_incept_invalid_threshold() {
        let signer = Signer::new_random(matter_codes::ED25519_SEED, true).unwrap();
        let keys = vec![signer.verfer().qb64().to_string()];

        // Threshold greater than key count
        let result = incept(
            keys,
            Some("2"), // Only 1 key but threshold is 2
            vec![],
            Some("0"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        );

        assert!(result.is_err());
    }
}
