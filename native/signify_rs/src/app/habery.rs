//! Habery - High-level identifier (Habitat) management
//!
//! Provides user-friendly API for creating and managing KERI identifiers.
//! Wraps the Manager to handle key generation, inception events, and identifier storage.

use crate::core::codes::matter_codes;
use crate::core::diger::Diger;
use crate::core::manager::{Algos, Keeper, KeyStore, Manager};
use crate::core::salter::{Salter, Tier};
use crate::core::serder::Serder;
use crate::core::signer::Signer;
use crate::core::verfer::Verfer;
use crate::error::{Result, SignifyError};
use std::collections::HashMap;

/// Trait configuration codes for identifier properties
pub struct TraitCodex;

impl TraitCodex {
    /// Only allow establishment events
    pub const EST_ONLY: &'static str = "EO";
    /// Do not allow delegated identifiers
    pub const DO_NOT_DELEGATE: &'static str = "DND";
    /// Do not allow backers
    pub const NO_BACKERS: &'static str = "NB";
}

/// Arguments for creating a new Habery
#[derive(Debug, Clone)]
pub struct HaberyArgs {
    /// Identifier for this habery instance
    pub name: String,
    /// Optional passcode for deterministic key generation
    pub passcode: Option<String>,
    /// Optional seed for encryption/decryption
    pub seed: Option<String>,
    /// Optional AEID (autonomous encryption ID) for encrypted storage
    pub aeid: Option<String>,
    /// Optional prefix index
    pub pidx: Option<usize>,
    /// Optional salt for deterministic key generation
    pub salt: Option<String>,
    /// Optional security tier for key stretching
    pub tier: Option<Tier>,
}

/// Arguments for creating a new Hab (identifier)
#[derive(Debug, Clone)]
pub struct MakeHabArgs {
    /// Digest code for identifier derivation (default: BLAKE3_256)
    pub code: Option<String>,
    /// Whether keys are transferable (default: true)
    pub transferable: Option<bool>,
    /// Initial signing threshold (hex string, e.g. "1", "2")
    pub isith: Option<String>,
    /// Initial key count (default: 1)
    pub icount: Option<usize>,
    /// Next signing threshold (hex string)
    pub nsith: Option<String>,
    /// Next key count (default: same as icount)
    pub ncount: Option<usize>,
    /// Witness threshold (default: ample majority)
    pub toad: Option<usize>,
    /// Witness identifiers
    pub wits: Option<Vec<String>>,
    /// Delegator prefix for delegated identifiers
    pub delpre: Option<String>,
    /// Establishment-only flag (no interaction events)
    pub est_only: Option<bool>,
    /// Do-not-delegate flag
    pub dnd: Option<bool>,
    /// Additional data to include in inception event
    pub data: Option<Vec<serde_json::Value>>,
}

impl Default for MakeHabArgs {
    fn default() -> Self {
        Self {
            code: Some(matter_codes::BLAKE3_256.to_string()),
            transferable: Some(true),
            isith: None,
            icount: Some(1),
            nsith: None,
            ncount: None,
            toad: None,
            wits: None,
            delpre: None,
            est_only: Some(false),
            dnd: Some(false),
            data: None,
        }
    }
}

/// Hab - A KERI identifier (Habitat)
#[derive(Debug, Clone)]
pub struct Hab {
    /// Name of this identifier
    pub name: String,
    /// Inception event serializer/deserializer
    pub serder: Serder,
}

impl Hab {
    /// Create a new Hab from name and inception event
    pub fn new(name: String, serder: Serder) -> Self {
        Self { name, serder }
    }

    /// Get the prefix (identifier) from the inception event
    pub fn pre(&self) -> Result<String> {
        self.serder
            .sad()
            .get("i")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                SignifyError::InvalidEvent("Missing 'i' field in inception event".to_string())
            })
    }
}

/// Habery - Manager for multiple KERI identifiers
pub struct Habery {
    name: String,
    mgr: Manager,
    habs: HashMap<String, Hab>,
}

impl Habery {
    /// Create a new Habery instance
    pub fn new(args: HaberyArgs) -> Result<Self> {
        let mut seed = args.seed;
        let mut aeid = args.aeid;

        // Handle passcode-based key derivation
        if let Some(passcode) = args.passcode {
            if seed.is_none() {
                if passcode.len() < 21 {
                    return Err(SignifyError::InvalidArgument(
                        "Passcode (bran) too short, must be at least 21 characters".to_string(),
                    ));
                }

                // Create salt from passcode
                let bran = format!("{}A{}", matter_codes::SALT_128, &passcode[..21]);
                let salter = Salter::from_qb64(&bran, Tier::Low)?;
                let signer = salter.signer(matter_codes::ED25519_SEED, false, "00", None, false)?;

                seed = Some(signer.qb64().to_string());

                // Use signer's verifier as AEID if not provided
                if aeid.is_none() {
                    aeid = Some(signer.verfer().qb64().to_string());
                }
            }
        }

        // Determine algorithm based on salt
        let algo = if args.salt.is_some() {
            Algos::Salty
        } else {
            Algos::Randy
        };

        // Create salter if salt provided
        let salter = if let Some(ref salt_str) = args.salt {
            Some(Salter::from_qb64(salt_str, args.tier.unwrap_or(Tier::Low))?)
        } else {
            None
        };

        // Create Manager
        let mgr = Manager::new(
            Some(Box::new(Keeper::new())),
            seed.as_deref(),
            aeid.as_deref(),
            args.pidx,
            Some(algo),
            salter.as_ref(),
            args.tier,
        )?;

        Ok(Self {
            name: args.name,
            mgr,
            habs: HashMap::new(),
        })
    }

    /// Get reference to the underlying Manager
    pub fn mgr(&self) -> &Manager {
        &self.mgr
    }

    /// Get mutable reference to the underlying Manager
    pub fn mgr_mut(&mut self) -> &mut Manager {
        &mut self.mgr
    }

    /// Get the Habery name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get all Habs
    pub fn habs(&self) -> Vec<&Hab> {
        self.habs.values().collect()
    }

    /// Get a Hab by name
    pub fn hab_by_name(&self, name: &str) -> Option<&Hab> {
        self.habs.get(name)
    }

    /// Create a new identifier (Hab) with inception event
    pub fn make_hab(&mut self, name: String, args: MakeHabArgs) -> Result<Hab> {
        let code = args
            .code
            .unwrap_or_else(|| matter_codes::BLAKE3_256.to_string());
        let mut transferable = args.transferable.unwrap_or(true);
        let mut isith = args.isith;
        let icount = args.icount.unwrap_or(1);
        let mut nsith = args.nsith.or(isith.clone());
        let mut ncount = args.ncount.unwrap_or(icount);
        let toad = args.toad;
        let wits = args.wits.unwrap_or_default();
        let delpre = args.delpre;
        let est_only = args.est_only.unwrap_or(false);
        let dnd = args.dnd.unwrap_or(false);
        let data = args.data.unwrap_or_default();

        // For non-transferable identifiers, no next keys
        // Note: We use the same ED25519_SEED but set transferable=false
        let final_code = if !transferable {
            ncount = 0;
            nsith = Some("0".to_string());
            transferable = false;
            code.clone()
        } else {
            code.clone()
        };

        // Generate keys using Manager
        // Note: Use ED25519_SEED for key generation codes (icode/ncode)
        // The `code` parameter is for identifier derivation in the inception event
        let (verfers, digers) = self.mgr.incept(
            None,
            icount,
            matter_codes::ED25519_SEED, // Key generation code, not identifier derivation
            None,
            ncount,
            matter_codes::ED25519_SEED, // Next key generation code
            matter_codes::BLAKE3_256,   // Digest code for next key digests
            None,
            None,
            Some(&self.name),
            None,
            true, // rooted
            transferable,
            false, // not temp
        )?;

        // Calculate default thresholds if not provided
        let actual_icount = verfers.len();
        let actual_ncount = digers.len();

        if isith.is_none() {
            isith = Some(format!("{:x}", std::cmp::max(1, (actual_icount + 1) / 2)));
        }

        if nsith.is_none() {
            nsith = Some(format!("{:x}", std::cmp::max(1, (actual_ncount + 1) / 2)));
        }

        // Build configuration traits
        let mut cnfg = Vec::new();
        if est_only {
            cnfg.push(TraitCodex::EST_ONLY.to_string());
        }
        if dnd {
            cnfg.push(TraitCodex::DO_NOT_DELEGATE.to_string());
        }

        // Convert verfers and digers to qb64 strings
        let keys: Vec<String> = verfers.iter().map(|v| v.qb64().to_string()).collect();
        let ndigs: Vec<String> = digers.iter().map(|d| d.qb64().to_string()).collect();

        // Create inception event using incept helper
        let icp = crate::core::eventing::incept(
            keys,
            isith.as_deref(),
            ndigs,
            nsith.as_deref(),
            toad,
            Some(wits),
            Some(cnfg),
            Some(data),
            None, // version
            None, // kind
            Some(&code),
            false, // intive
            delpre.as_deref(),
        )?;

        let hab = Hab::new(name.clone(), icp);
        self.habs.insert(name, hab.clone());

        Ok(hab)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_habery_creation_with_passcode() {
        let habery = Habery::new(HaberyArgs {
            name: "test".to_string(),
            passcode: Some("GCiBGAhduxcggJE4qJeaA".to_string()), // Valid passcode ending with 'A'
            seed: None,
            aeid: None,
            pidx: None,
            salt: None,
            tier: None,
        })
        .unwrap();

        assert_eq!(habery.name(), "test");
        assert_eq!(habery.habs().len(), 0);
    }

    #[test]
    fn test_habery_make_hab() {
        let mut habery = Habery::new(HaberyArgs {
            name: "test-habery".to_string(),
            passcode: Some("GCiBGAhduxcggJE4qJeaA".to_string()), // Valid passcode ending with 'A'
            seed: None,
            aeid: None,
            pidx: None,
            salt: None,
            tier: None,
        })
        .unwrap();

        let hab = habery
            .make_hab(
                "test-hab".to_string(),
                MakeHabArgs {
                    icount: Some(1),
                    ncount: Some(1),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(hab.name, "test-hab");
        assert!(hab.pre().is_ok());

        // Verify hab is stored
        assert!(habery.hab_by_name("test-hab").is_some());
        assert_eq!(habery.habs().len(), 1);
    }

    #[test]
    fn test_habery_passcode_too_short() {
        let result = Habery::new(HaberyArgs {
            name: "test".to_string(),
            passcode: Some("short".to_string()),
            seed: None,
            aeid: None,
            pidx: None,
            salt: None,
            tier: None,
        });

        assert!(result.is_err());
    }
}
