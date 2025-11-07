//! Controller - Local client AID representation
//!
//! Represents the local controller AID for a SignifyClient, managing keys,
//! inception events, and rotation state.

use crate::app::habery::{Habery, HaberyArgs, MakeHabArgs};
use crate::core::cigar::Cigar;
use crate::core::codes::matter_codes;
use crate::core::salter::{Salter, Tier};
use crate::core::serder::Serder;
use crate::core::signer::Signer;
use crate::error::{Result, SignifyError};

/// Controller - Represents a local client AID
pub struct Controller {
    /// Salter for deterministic key generation
    salter: Salter,
    /// Signer for signing requests
    signer: Signer,
    /// Inception event
    serder: Serder,
    /// Prefix (AID)
    pre: String,
    /// Stem for key paths
    stem: String,
    /// Rotation index
    ridx: usize,
    /// Security tier
    tier: Tier,
}

impl Controller {
    /// Create a new Controller from a passcode (bran)
    ///
    /// # Arguments
    /// * `bran` - Base64 21+ char passcode
    /// * `tier` - Optional security tier (defaults to Low)
    pub fn new(bran: String, tier: Option<Tier>) -> Result<Self> {
        if bran.len() < 21 {
            return Err(SignifyError::InvalidArgument(
                "bran must be at least 21 characters".to_string(),
            ));
        }

        let tier = tier.unwrap_or(Tier::Low);
        let stem = "signify:controller";

        // Create salter from bran
        let salt_str = format!("{}A{}", matter_codes::SALT_128, &bran[..21]);
        let salter = Salter::from_qb64(&salt_str, tier)?;

        // Generate signer from salter
        let path = format!("{}:00", stem);
        let signer = salter.signer(
            matter_codes::ED25519_SEED,
            true, // transferable
            &path,
            None,
            true, // generate verifier
        )?;

        // Create Habery for inception
        let mut habery = Habery::new(HaberyArgs {
            name: "controller".to_string(),
            passcode: Some(bran),
            seed: None,
            aeid: None,
            pidx: None,
            salt: None,
            tier: Some(tier),
        })?;

        // Create inception event
        let hab = habery.make_hab("controller".to_string(), MakeHabArgs::default())?;
        let pre = hab.pre()?;

        Ok(Self {
            salter,
            signer,
            serder: hab.serder,
            pre,
            stem: stem.to_string(),
            ridx: 0,
            tier,
        })
    }

    /// Get the controller prefix (AID)
    pub fn pre(&self) -> Result<String> {
        Ok(self.pre.clone())
    }

    /// Get the signer
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// Get the inception event serder
    pub fn serder(&self) -> &Serder {
        &self.serder
    }

    /// Get the stem
    pub fn stem(&self) -> &str {
        &self.stem
    }

    /// Get the rotation index
    pub fn ridx(&self) -> usize {
        self.ridx
    }

    /// Set the rotation index
    pub fn set_ridx(&mut self, ridx: usize) {
        self.ridx = ridx;
    }

    /// Get the tier
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// Get the inception event and signature
    ///
    /// Returns the inception event serder and a signature over it
    pub fn event(&self) -> Result<(Serder, Cigar)> {
        let raw = self.serder.raw();
        let signature = self.signer.sign(raw.as_bytes())?;

        // Create Cigar from signature
        let cigar = Cigar::new(&signature, matter_codes::ED25519_SIG, None)?;

        Ok((self.serder.clone(), cigar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_controller_creation() {
        let controller = Controller::new("GCiBGAhduxcggJE4qJeaA".to_string(), None).unwrap();

        assert!(controller.pre().is_ok());
        assert_eq!(controller.ridx(), 0);
        assert_eq!(controller.stem(), "signify:controller");
    }

    #[test]
    fn test_controller_short_bran() {
        let result = Controller::new("short".to_string(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_controller_event() {
        let controller = Controller::new("GCiBGAhduxcggJE4qJeaA".to_string(), None).unwrap();

        let result = controller.event();
        assert!(result.is_ok());

        let (serder, cigar) = result.unwrap();
        assert_eq!(serder.ilk(), Some("icp"));
        assert!(cigar.qb64().len() > 0);
    }
}
