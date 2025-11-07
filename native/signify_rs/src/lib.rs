pub mod app;
pub mod cesr_parser;
pub mod core;
/// Signify-RS: Complete KERI Signify implementation in Rust
///
/// This library provides a full implementation of the KERI Signify protocol,
/// compatible with signify-ts for cross-platform signature verification.
pub mod error;

// Rustler NIF module for Elixir integration
// Only compile when not testing (NIF requires Erlang runtime)
#[cfg(all(feature = "nif", not(test)))]
pub mod nif;

// Re-export commonly used types
pub use app::{
    create_issuance_event, credential_types, AgentState, Authenticater, Controller,
    CredentialBuilder, CredentialData, CredentialSubject, Hab, Habery, HaberyArgs,
    IssueCredentialResult, MakeHabArgs, SignifyClient, TraitCodex, ACDC_VERSION,
};
pub use core::{
    incept, matter_codes, Cigar, Cipher, Counter, CounterCodex, DecryptedMatter, Decrypter,
    DerivationCode, Diger, Encrypter, IndexedSignature, Indexer, IndexerCodex, Manager, Matter,
    MatterOpts, Prefixer, Saider, Salter, Seqner, Serder, Siger, Signer, Tier, Verfer,
};
pub use error::{Result, SignifyError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_matter() {
        let raw = vec![0u8; 32];
        let matter = Matter::from_raw(&raw, matter_codes::ED25519_SEED).unwrap();
        assert_eq!(matter.code(), matter_codes::ED25519_SEED);
    }

    #[test]
    fn test_basic_diger() {
        let data = b"test data";
        let diger = Diger::new(matter_codes::BLAKE3_256, data).unwrap();
        assert!(diger.verify(data).unwrap());
    }

    /// Integration test: Full flow from Salter -> Signer -> Verfer
    /// This simulates the signify-ts pattern for key generation and signing
    #[test]
    fn test_integration_salter_signer_verfer() {
        // 1. Create a Salter with known salt
        let salt = [42u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();

        // 2. Generate a Signer from the Salter using a path (like signify-ts does)
        let path = "signify:controller00";
        let signer = salter
            .signer(matter_codes::ED25519_SEED, true, path, None, true)
            .unwrap();

        // 3. Verify the signer has correct structure
        assert_eq!(signer.matter().code(), matter_codes::ED25519_SEED);
        assert_eq!(signer.verfer().code(), matter_codes::ED25519);
        assert!(signer.transferable());

        // 4. Sign a message
        let message = b"Hello, KERI!";
        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.len(), 64);

        // 5. Verify the signature with the signer's verfer
        let verified = signer.verfer().verify(&signature, message).unwrap();
        assert!(verified);

        // 6. Verify wrong message fails
        let wrong_message = b"Wrong message";
        let verified_wrong = signer.verfer().verify(&signature, wrong_message).unwrap();
        assert!(!verified_wrong);
    }

    /// Test deterministic key generation (same salt + same path = same keys)
    #[test]
    fn test_integration_deterministic_key_generation() {
        let salt = [1u8; 16];
        let path = "signify:controller00";

        // Generate two signers from the same salt and path
        let salter1 = Salter::from_raw(&salt, Tier::Low).unwrap();
        let signer1 = salter1
            .signer(matter_codes::ED25519_SEED, true, path, None, true)
            .unwrap();

        let salter2 = Salter::from_raw(&salt, Tier::Low).unwrap();
        let signer2 = salter2
            .signer(matter_codes::ED25519_SEED, true, path, None, true)
            .unwrap();

        // Should have identical keys
        assert_eq!(signer1.matter().raw(), signer2.matter().raw());
        assert_eq!(signer1.verfer().raw(), signer2.verfer().raw());

        // Should produce identical signatures
        let message = b"test message";
        let sig1 = signer1.sign(message).unwrap();
        let sig2 = signer2.sign(message).unwrap();
        assert_eq!(sig1, sig2);
    }

    /// Test different paths produce different keys
    #[test]
    fn test_integration_different_paths_different_keys() {
        let salt = [1u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();

        // Generate keys for different paths (inception signing vs rotation)
        let signer_signing = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:controller00",
                None,
                true,
            )
            .unwrap();

        let signer_rotation = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:controller01",
                None,
                true,
            )
            .unwrap();

        // Should have different keys
        assert_ne!(
            signer_signing.verfer().raw(),
            signer_rotation.verfer().raw()
        );
    }

    /// Test qb64 serialization roundtrip for the entire flow
    #[test]
    fn test_integration_qb64_serialization() {
        // Create signer
        let salt = [1u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();
        let signer1 = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:controller00",
                None,
                true,
            )
            .unwrap();

        // Serialize seed and verifier to qb64
        let seed_qb64 = signer1.qb64();
        let verfer_qb64 = signer1.verfer().qb64();

        // Reconstruct from qb64
        let signer2 = Signer::from_qb64(seed_qb64, true).unwrap();
        let verfer2 = Verfer::from_qb64(verfer_qb64).unwrap();

        // Should be identical
        assert_eq!(signer1.matter().raw(), signer2.matter().raw());
        assert_eq!(signer1.verfer().raw(), verfer2.raw());

        // Sign and verify with reconstructed objects
        let message = b"test message";
        let signature = signer2.sign(message).unwrap();
        let verified = verfer2.verify(&signature, message).unwrap();
        assert!(verified);
    }

    /// Test indexed signatures for multi-sig scenarios
    #[test]
    fn test_integration_indexed_signatures() {
        let salt = [1u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();

        // Create multiple signers (simulating multi-sig group)
        let signer0 = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:controller00",
                None,
                true,
            )
            .unwrap();

        let signer1 = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:controller01",
                None,
                true,
            )
            .unwrap();

        let message = b"multi-sig message";

        // Create indexed signatures
        let indexed_sig0 = signer0.sign_indexed(message, 0).unwrap();
        let indexed_sig1 = signer1.sign_indexed(message, 1).unwrap();

        assert_eq!(indexed_sig0.index, 0);
        assert_eq!(indexed_sig1.index, 1);

        // Verify each signature with corresponding verfer
        assert!(signer0
            .verfer()
            .verify(&indexed_sig0.signature, message)
            .unwrap());
        assert!(signer1
            .verfer()
            .verify(&indexed_sig1.signature, message)
            .unwrap());
    }

    /// Integration test: Serder event serialization with SAID
    #[test]
    fn test_integration_serder_event_with_said() {
        use serde_json::json;

        // Create a KERI inception event
        let event = json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
            "s": "0",
            "kt": "1",
            "k": ["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM"],
            "n": ["EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM"],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });

        // Create Serder (automatically calculates size and updates version)
        let serder = Serder::new(event, None, None).unwrap();

        // Verify structure
        assert_eq!(serder.ilk(), Some("icp"));
        assert_eq!(serder.sn(), Some(0));
        assert!(serder.size() > 0);

        // Calculate SAID
        let said = serder.said(None).unwrap();
        assert_eq!(said.len(), 44); // Blake3-256 qb64
        assert!(said.starts_with('E')); // Blake3-256 code

        // Verify version string was updated with correct size
        let version = serder.sad().get("v").and_then(|v| v.as_str()).unwrap();
        assert!(version.starts_with("KERI10JSON"));
        assert!(version.ends_with('_'));

        // Verify serialization roundtrip
        let raw = serder.raw();
        let serder2 = Serder::from_raw(raw).unwrap();
        assert_eq!(serder.ilk(), serder2.ilk());
        assert_eq!(serder.sn(), serder2.sn());
    }

    /// Integration test: SAID determinism
    #[test]
    fn test_integration_said_determinism() {
        use serde_json::json;

        let event = json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "test-identifier",
            "s": "0"
        });

        // Create two Serders from the same event
        let serder1 = Serder::new(event.clone(), None, None).unwrap();
        let serder2 = Serder::new(event, None, None).unwrap();

        // SAIDs should be identical (deterministic)
        let said1 = serder1.said(None).unwrap();
        let said2 = serder2.said(None).unwrap();
        assert_eq!(said1, said2);

        // Raw serialization should be identical
        assert_eq!(serder1.raw(), serder2.raw());
    }

    /// Integration test: Complete inception event workflow
    /// This demonstrates the full flow: Salter -> Signer -> incept() -> Serder
    #[test]
    fn test_integration_full_inception_workflow() {
        // 1. Create a Salter with known salt for reproducibility
        let salt = [42u8; 16];
        let salter = Salter::from_raw(&salt, Tier::Low).unwrap();

        // 2. Generate signing keys
        let signer0 = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:aid:controller:0",
                None,
                true,
            )
            .unwrap();

        let signer1 = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:aid:controller:1",
                None,
                true,
            )
            .unwrap();

        // Get public keys for inception event
        let keys = vec![
            signer0.verfer().qb64().to_string(),
            signer1.verfer().qb64().to_string(),
        ];

        // 3. Generate next rotation keys (pre-rotation commitment)
        let next_signer0 = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:aid:controller:next:0",
                None,
                true,
            )
            .unwrap();

        let next_signer1 = salter
            .signer(
                matter_codes::ED25519_SEED,
                true,
                "signify:aid:controller:next:1",
                None,
                true,
            )
            .unwrap();

        // Create digests of next keys
        let next_key0_bytes = next_signer0.verfer().raw();
        let next_key1_bytes = next_signer1.verfer().raw();

        let next_dig0 = Diger::new(matter_codes::BLAKE3_256, next_key0_bytes).unwrap();
        let next_dig1 = Diger::new(matter_codes::BLAKE3_256, next_key1_bytes).unwrap();

        let ndigs = vec![next_dig0.qb64().to_string(), next_dig1.qb64().to_string()];

        // 4. Create inception event with witnesses
        let witnesses = vec![
            "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU".to_string(),
            "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEV".to_string(),
            "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEW".to_string(),
        ];

        let serder = incept(
            keys.clone(),
            Some("2"), // Both keys required for signing (2-of-2)
            ndigs.clone(),
            Some("2"), // Both next keys required for rotation
            None,      // Auto-calculate ample threshold (3 witnesses -> threshold 1)
            Some(witnesses.clone()),
            Some(vec!["EO".to_string()]), // Establishment only config
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();

        // 5. Verify the inception event structure
        assert_eq!(serder.ilk(), Some("icp"));
        assert_eq!(serder.sn(), Some(0));

        // Verify keys
        let k_field = serder.sad().get("k").and_then(|v| v.as_array()).unwrap();
        assert_eq!(k_field.len(), 2);
        assert_eq!(k_field[0].as_str().unwrap(), keys[0]);
        assert_eq!(k_field[1].as_str().unwrap(), keys[1]);

        // Verify next key digests
        let n_field = serder.sad().get("n").and_then(|v| v.as_array()).unwrap();
        assert_eq!(n_field.len(), 2);

        // Verify witnesses
        let b_field = serder.sad().get("b").and_then(|v| v.as_array()).unwrap();
        assert_eq!(b_field.len(), 3);

        // Verify thresholds
        let kt = serder
            .sad()
            .get("kt")
            .and_then(|v| v.as_str())
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap();
        assert_eq!(kt, 2);

        let bt = serder
            .sad()
            .get("bt")
            .and_then(|v| v.as_str())
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap();
        assert_eq!(bt, 2); // Ample threshold for 3 witnesses: (3/2)+1 = 2

        // 6. Verify SAID field
        let said = serder.said_field().unwrap();
        assert_eq!(said.len(), 44);
        assert!(said.starts_with('E'));

        // For multi-key inception, identifier should equal SAID
        let identifier = serder.pre().unwrap();
        assert_eq!(identifier, said);

        // 7. Verify the event can be serialized and deserialized
        let raw = serder.raw();
        let serder2 = Serder::from_raw(raw).unwrap();
        assert_eq!(serder.said_field(), serder2.said_field());

        // 8. Sign the event with both signers (demonstrating multi-sig)
        let message = raw.as_bytes();
        let sig0 = signer0.sign(message).unwrap();
        let sig1 = signer1.sign(message).unwrap();

        // 9. Verify signatures
        assert!(signer0.verfer().verify(&sig0, message).unwrap());
        assert!(signer1.verfer().verify(&sig1, message).unwrap());

        // Verify cross-signing fails (wrong key for wrong signature)
        assert!(!signer0.verfer().verify(&sig1, message).unwrap());
        assert!(!signer1.verfer().verify(&sig0, message).unwrap());
    }
}
