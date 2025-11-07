//! Rustler NIF bindings for Elixir
//!
//! This module exposes signify-rs functionality to Elixir through Rustler NIFs.
//! It provides safe wrappers around Rust types and functions for use from Elixir.

use rustler::{Binary, Env, Error as RustlerError, ResourceArc, Term};
use std::sync::{Arc, Mutex};

// Re-export core types
use crate::app::credentialing::{CredentialFilter, Credentials};
use crate::app::{Habery, HaberyArgs, MakeHabArgs, SignifyClient};
use crate::core::{Signer, Verfer};
use crate::error::{Result as SignifyResult, SignifyError};

/// Convert SignifyError to Rustler error
fn to_rustler_error(err: SignifyError) -> RustlerError {
    RustlerError::Term(Box::new(format!("{}", err)))
}

//
// Resource types - wrapped in Arc<Mutex<>> for thread safety
//

/// Signer resource for Elixir
pub struct SignerResource {
    inner: Arc<Mutex<Signer>>,
}

impl SignerResource {
    fn new(signer: Signer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(signer)),
        }
    }

    fn with<F, R>(&self, f: F) -> SignifyResult<R>
    where
        F: FnOnce(&Signer) -> SignifyResult<R>,
    {
        let signer = self
            .inner
            .lock()
            .map_err(|_| SignifyError::Other("Lock error".to_string()))?;
        f(&signer)
    }
}

/// Verfer resource for Elixir
pub struct VerferResource {
    inner: Arc<Mutex<Verfer>>,
}

impl VerferResource {
    fn new(verfer: Verfer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(verfer)),
        }
    }

    fn with<F, R>(&self, f: F) -> SignifyResult<R>
    where
        F: FnOnce(&Verfer) -> SignifyResult<R>,
    {
        let verfer = self
            .inner
            .lock()
            .map_err(|_| SignifyError::Other("Lock error".to_string()))?;
        f(&verfer)
    }
}

/// Habery resource for Elixir
pub struct HaberyResource {
    inner: Arc<Mutex<Habery>>,
}

impl HaberyResource {
    fn new(habery: Habery) -> Self {
        Self {
            inner: Arc::new(Mutex::new(habery)),
        }
    }

    fn with_mut<F, R>(&self, f: F) -> SignifyResult<R>
    where
        F: FnOnce(&mut Habery) -> SignifyResult<R>,
    {
        let mut habery = self
            .inner
            .lock()
            .map_err(|_| SignifyError::Other("Lock error".to_string()))?;
        f(&mut habery)
    }
}

/// SignifyClient resource for Elixir
pub struct SignifyClientResource {
    inner: Arc<Mutex<SignifyClient>>,
}

impl SignifyClientResource {
    fn new(client: SignifyClient) -> Self {
        Self {
            inner: Arc::new(Mutex::new(client)),
        }
    }

    fn with_mut<F, R>(&self, f: F) -> SignifyResult<R>
    where
        F: FnOnce(&mut SignifyClient) -> SignifyResult<R>,
    {
        let mut client = self
            .inner
            .lock()
            .map_err(|_| SignifyError::Other("Lock error".to_string()))?;
        f(&mut client)
    }

    fn arc(&self) -> Arc<SignifyClient> {
        // Create a new Arc from the inner client for Credentials
        Arc::new(
            SignifyClient::new(
                self.inner.lock().unwrap().url().to_string(),
                String::new(), // bran not needed for read operations
                None,
            )
            .unwrap(),
        )
    }
}

/// Credentials resource for Elixir
pub struct CredentialsResource {
    inner: Arc<Credentials>,
}

impl CredentialsResource {
    fn new(credentials: Credentials) -> Self {
        Self {
            inner: Arc::new(credentials),
        }
    }

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Credentials) -> R,
    {
        f(&self.inner)
    }
}

//
// Signer NIFs
//

/// Create a new random signer
#[rustler::nif]
fn signer_new_random(transferable: bool) -> Result<ResourceArc<SignerResource>, RustlerError> {
    let signer = Signer::new_random(crate::core::codes::matter_codes::ED25519_SEED, transferable)
        .map_err(to_rustler_error)?;

    Ok(ResourceArc::new(SignerResource::new(signer)))
}

/// Create signer from qb64 seed
#[rustler::nif]
fn signer_from_qb64(
    qb64: String,
    transferable: bool,
) -> Result<ResourceArc<SignerResource>, RustlerError> {
    let signer = Signer::from_qb64(&qb64, transferable).map_err(to_rustler_error)?;

    Ok(ResourceArc::new(SignerResource::new(signer)))
}

/// Get signer's qb64 representation
#[rustler::nif]
fn signer_qb64(resource: ResourceArc<SignerResource>) -> Result<String, RustlerError> {
    resource
        .with(|signer| Ok(signer.qb64().to_string()))
        .map_err(to_rustler_error)
}

/// Sign a message
#[rustler::nif]
fn signer_sign(
    resource: ResourceArc<SignerResource>,
    message: Vec<u8>,
) -> Result<Vec<u8>, RustlerError> {
    resource
        .with(|signer| signer.sign(&message).map(|sig| sig.to_vec()))
        .map_err(to_rustler_error)
}

/// Get signer's verfer
#[rustler::nif]
fn signer_verfer(
    resource: ResourceArc<SignerResource>,
) -> Result<ResourceArc<VerferResource>, RustlerError> {
    let verfer = resource
        .with(|signer| Ok(signer.verfer().clone()))
        .map_err(to_rustler_error)?;

    Ok(ResourceArc::new(VerferResource::new(verfer)))
}

//
// Verfer NIFs
//

/// Create verfer from qb64
#[rustler::nif]
fn verfer_from_qb64(qb64: String) -> Result<ResourceArc<VerferResource>, RustlerError> {
    let verfer = Verfer::from_qb64(&qb64).map_err(to_rustler_error)?;

    Ok(ResourceArc::new(VerferResource::new(verfer)))
}

/// Get verfer's qb64 representation
#[rustler::nif]
fn verfer_qb64(resource: ResourceArc<VerferResource>) -> Result<String, RustlerError> {
    resource
        .with(|verfer| Ok(verfer.qb64().to_string()))
        .map_err(to_rustler_error)
}

/// Verify a signature
#[rustler::nif]
fn verfer_verify(
    resource: ResourceArc<VerferResource>,
    signature: Vec<u8>,
    message: Vec<u8>,
) -> Result<bool, RustlerError> {
    resource
        .with(|verfer| verfer.verify(&signature, &message))
        .map_err(to_rustler_error)
}

//
// Habery NIFs
//

/// Create a new Habery
#[rustler::nif]
fn habery_new(
    name: String,
    passcode: Option<String>,
) -> Result<ResourceArc<HaberyResource>, RustlerError> {
    let habery = Habery::new(HaberyArgs {
        name,
        passcode,
        seed: None,
        aeid: None,
        pidx: None,
        salt: None,
        tier: None,
    })
    .map_err(to_rustler_error)?;

    Ok(ResourceArc::new(HaberyResource::new(habery)))
}

/// Get Habery name
#[rustler::nif]
fn habery_name(resource: ResourceArc<HaberyResource>) -> Result<String, RustlerError> {
    resource
        .with_mut(|habery| Ok(habery.name().to_string()))
        .map_err(to_rustler_error)
}

/// Create a new identifier (Hab)
#[rustler::nif]
fn habery_make_hab(
    resource: ResourceArc<HaberyResource>,
    name: String,
) -> Result<String, RustlerError> {
    resource
        .with_mut(|habery| {
            let hab = habery.make_hab(name, MakeHabArgs::default())?;
            hab.pre()
        })
        .map_err(to_rustler_error)
}

//
// SignifyClient NIFs
//

/// Create a new SignifyClient
#[rustler::nif]
fn client_new(
    url: String,
    bran: String,
) -> Result<ResourceArc<SignifyClientResource>, RustlerError> {
    let client = SignifyClient::new(url, bran, None).map_err(to_rustler_error)?;

    Ok(ResourceArc::new(SignifyClientResource::new(client)))
}

/// Get SignifyClient URL
#[rustler::nif]
fn client_url(resource: ResourceArc<SignifyClientResource>) -> Result<String, RustlerError> {
    resource
        .with_mut(|client| Ok(client.url().to_string()))
        .map_err(to_rustler_error)
}

//
// CESR File Parsing NIFs
//

/// Parse CESR/KERI credential file and extract public key
///
/// Returns a tuple: {verfer_resource, identifier}
/// Note: CESR files only contain public keys, not private keys
#[rustler::nif]
fn parse_cesr_file(
    cesr_data: String,
) -> Result<(ResourceArc<VerferResource>, String), RustlerError> {
    use crate::core::prefixer::Prefixer;
    use serde_json::Value;

    let trimmed = cesr_data.trim();

    if trimmed.is_empty() {
        return Err(RustlerError::Term(Box::new("Empty CESR data")));
    }

    // Check if this is a KERI event stream (starts with JSON)
    if !trimmed.starts_with('{') {
        return Err(RustlerError::Term(Box::new(
            "CESR data must be KERI event stream (JSON format)",
        )));
    }

    // Parse KERI event stream to find inception event
    let mut current_pos = 0;
    let data_bytes = trimmed.as_bytes();
    let mut inception_event: Option<Value> = None;

    // Parse each JSON object in the stream
    while current_pos < data_bytes.len() {
        // Skip whitespace and non-JSON characters
        while current_pos < data_bytes.len() && data_bytes[current_pos] != b'{' {
            current_pos += 1;
        }

        if current_pos >= data_bytes.len() {
            break;
        }

        // Find matching closing brace
        let start = current_pos;
        let mut depth = 0;
        let mut in_string = false;
        let mut escape = false;

        while current_pos < data_bytes.len() {
            let ch = data_bytes[current_pos];

            if escape {
                escape = false;
                current_pos += 1;
                continue;
            }

            if ch == b'\\' {
                escape = true;
            } else if ch == b'"' {
                in_string = !in_string;
            } else if !in_string {
                if ch == b'{' {
                    depth += 1;
                } else if ch == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        current_pos += 1;
                        break;
                    }
                }
            }
            current_pos += 1;
        }

        // Parse this JSON object
        let json_str = &trimmed[start..current_pos];
        if let Ok(event) = serde_json::from_str::<Value>(json_str) {
            // Check if this is an inception event (icp or dip)
            if let Some(event_type) = event.get("t").and_then(|t| t.as_str()) {
                if (event_type == "icp" || event_type == "dip") && inception_event.is_none() {
                    inception_event = Some(event);
                }
            }
        }
    }

    // Extract keys from inception event
    let event = inception_event.ok_or_else(|| {
        RustlerError::Term(Box::new("No inception event (icp/dip) found in CESR file"))
    })?;

    // Get the identifier
    let identifier = event
        .get("i")
        .and_then(|i| i.as_str())
        .ok_or_else(|| RustlerError::Term(Box::new("Missing identifier 'i' in inception event")))?
        .to_string();

    // Get public keys from 'k' field (array of keys)
    let keys = event
        .get("k")
        .and_then(|k| k.as_array())
        .ok_or_else(|| RustlerError::Term(Box::new("Missing keys 'k' in inception event")))?;

    if keys.is_empty() {
        return Err(RustlerError::Term(Box::new(
            "No keys found in inception event",
        )));
    }

    // Get first key (signing key) - in CESR QB64 format
    let public_key_qb64 = keys[0]
        .as_str()
        .ok_or_else(|| RustlerError::Term(Box::new("Invalid key format")))?;

    // Parse the CESR key with cesride's Prefixer for better compatibility
    use cesride::Matter;

    let prefixer = cesride::Prefixer::new_with_qb64(public_key_qb64).map_err(|e| {
        RustlerError::Term(Box::new(format!(
            "Failed to parse CESR key with cesride: {:?}",
            e
        )))
    })?;

    // Get the raw public key bytes using Matter trait method
    let raw_bytes = prefixer.raw();

    // Create a Verfer from the raw bytes
    // Note: Using raw bytes with default Ed25519 code since cesride may have different codes
    let verfer = Verfer::from_raw(&raw_bytes, crate::core::codes::matter_codes::ED25519)
        .map_err(|e| RustlerError::Term(Box::new(format!("Failed to create verfer: {}", e))))?;

    Ok((ResourceArc::new(VerferResource::new(verfer)), identifier))
}

//
// Credentials NIFs
//

/// Create a new Credentials client
#[rustler::nif]
fn credentials_new(
    client: ResourceArc<SignifyClientResource>,
) -> Result<ResourceArc<CredentialsResource>, RustlerError> {
    let client_arc = client.arc();
    let credentials = Credentials::new(client_arc);
    Ok(ResourceArc::new(CredentialsResource::new(credentials)))
}

/// List credentials with optional filter
#[rustler::nif]
fn credentials_list(
    resource: ResourceArc<CredentialsResource>,
    filter_json: Option<String>,
) -> Result<String, RustlerError> {
    use tokio::runtime::Runtime;

    let filter = if let Some(json_str) = filter_json {
        Some(
            serde_json::from_str(&json_str)
                .map_err(|e| RustlerError::Term(Box::new(format!("Invalid filter JSON: {}", e))))?,
        )
    } else {
        None
    };

    resource.with(|creds| {
        let rt = Runtime::new().map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to create runtime: {}", e)))
        })?;

        let results = rt.block_on(creds.list(filter)).map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to list credentials: {}", e)))
        })?;

        serde_json::to_string(&results).map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to serialize results: {}", e)))
        })
    })
}

/// Get a credential in JSON format
#[rustler::nif]
fn credentials_get_json(
    resource: ResourceArc<CredentialsResource>,
    said: String,
) -> Result<String, RustlerError> {
    use tokio::runtime::Runtime;

    resource.with(|creds| {
        let rt = Runtime::new().map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to create runtime: {}", e)))
        })?;

        let result = rt.block_on(creds.get_json(&said)).map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to get credential: {}", e)))
        })?;

        serde_json::to_string(&result)
            .map_err(|e| RustlerError::Term(Box::new(format!("Failed to serialize result: {}", e))))
    })
}

/// Get a credential in CESR format
#[rustler::nif]
fn credentials_get_cesr(
    resource: ResourceArc<CredentialsResource>,
    said: String,
) -> Result<String, RustlerError> {
    use tokio::runtime::Runtime;

    resource.with(|creds| {
        let rt = Runtime::new().map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to create runtime: {}", e)))
        })?;

        rt.block_on(creds.get_cesr(&said))
            .map_err(|e| RustlerError::Term(Box::new(format!("Failed to get credential: {}", e))))
    })
}

/// Delete a credential
#[rustler::nif]
fn credentials_delete(
    resource: ResourceArc<CredentialsResource>,
    said: String,
) -> Result<String, RustlerError> {
    use tokio::runtime::Runtime;

    resource.with(|creds| {
        let rt = Runtime::new().map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to create runtime: {}", e)))
        })?;

        rt.block_on(creds.delete(&said)).map_err(|e| {
            RustlerError::Term(Box::new(format!("Failed to delete credential: {}", e)))
        })?;

        Ok("ok".to_string())
    })
}

//
// Utility NIFs
//

/// Compute BLAKE3-256 digest and return QB64-encoded string
#[rustler::nif]
fn blake3_digest(data: Binary) -> Result<String, RustlerError> {
    use crate::core::codes::matter_codes;
    use crate::core::diger::Diger;

    let diger = Diger::new(matter_codes::BLAKE3_256, data.as_slice()).map_err(to_rustler_error)?;

    Ok(diger.qb64().to_string())
}

/// Get library version
#[rustler::nif]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check if library is ready
#[rustler::nif]
fn ready() -> bool {
    true
}

// Register resources and NIFs with Rustler
fn load(env: Env, _: Term) -> bool {
    rustler::resource!(SignerResource, env);
    rustler::resource!(VerferResource, env);
    rustler::resource!(HaberyResource, env);
    rustler::resource!(SignifyClientResource, env);
    rustler::resource!(CredentialsResource, env);
    true
}

rustler::init!(
    "Elixir.Trustex.Native",
    [
        // Signer NIFs
        signer_new_random,
        signer_from_qb64,
        signer_qb64,
        signer_sign,
        signer_verfer,
        // Verfer NIFs
        verfer_from_qb64,
        verfer_qb64,
        verfer_verify,
        // Habery NIFs
        habery_new,
        habery_name,
        habery_make_hab,
        // Client NIFs
        client_new,
        client_url,
        // Credentials NIFs
        credentials_new,
        credentials_list,
        credentials_get_json,
        credentials_get_cesr,
        credentials_delete,
        // CESR File Parsing NIFs
        parse_cesr_file,
        // Utility NIFs
        blake3_digest,
        version,
        ready,
    ],
    load = load
);
