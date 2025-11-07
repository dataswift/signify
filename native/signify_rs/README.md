# Signify-RS

**Complete KERI Signify implementation in Rust for Elixir NIF integration**

This is a full port of [signify-ts](https://github.com/WebOfTrust/signify-ts) to Rust, providing 100% compatible KERI signing and verification.

## Status: 20% Complete - Foundation Ready

### ✅ Implemented

- **Project Structure** - Complete Rust crate setup
- **Error Handling** - Comprehensive error types
- **CESR Codes** - All code definitions and size tables
- **Matter** - Base class for CESR primitives (with tests)
- **Utils** - Helper functions (versify, concat, canonicalize)
- **Diger** - Cryptographic digests (Blake3, SHA2, SHA3) with tests

### 🚧 Next Priority (Phase 1 - Core Signing)

1. **Salter** - Argon2id key derivation (template provided)
2. **Signer** - Ed25519 signing (template provided)
3. **Verfer** - Ed25519 verification
4. **Serder** - Event serialization with SAID
5. **Eventing** - Event creation (incept, rotate, interact)

## Quick Start

```bash
# Build and test
cargo build
cargo test

# Run specific test
cargo test test_matter_from_raw

# Build for release
cargo build --release
```

## Project Structure

```
src/
├── lib.rs              # Main library entry
├── error.rs            # Error types ✅
├── core/
│   ├── mod.rs          # Core module exports
│   ├── codes.rs        # CESR code tables ✅
│   ├── matter.rs       # Base CESR primitive ✅
│   ├── utils.rs        # Helper functions ✅
│   ├── diger.rs        # Cryptographic digests ✅
│   ├── salter.rs       # Key derivation (TODO)
│   ├── signer.rs       # Ed25519 signing (TODO)
│   ├── verfer.rs       # Ed25519 verification (TODO)
│   ├── cipher.rs       # X25519 encryption (TODO)
│   ├── serder.rs       # Event serialization (TODO)
│   └── eventing.rs     # Event creation (TODO)
├── app/                # Application layer (TODO)
│   ├── habery.rs       # Identifier management
│   ├── client.rs       # SignifyClient
│   └── credentials.rs  # ACDC
└── http/               # HTTP layer (TODO)
    ├── auth.rs         # Authentication
    └── client.rs       # HTTP client
```

## Implementation Guide

See the comprehensive guides in `../../documentation/`:

1. **signify-ts-deep-analysis.md** - Complete analysis of signify-ts
2. **SIGNIFY_IMPLEMENTATION_PLAN.md** - Architecture and phases
3. **IMPLEMENTATION_STATUS.md** - Current progress
4. **IMPLEMENTATION_GUIDE.md** - **START HERE** for continuing development

## Key Features

### CESR Encoding

Complete implementation of Composable Event Streaming Representation:

```rust
use signify_rs::{Matter, matter_codes};

// Create Matter from raw bytes
let raw = vec![0u8; 32];
let matter = Matter::from_raw(&raw, matter_codes::ED25519_SEED)?;
println!("qb64: {}", matter.qb64());  // "AAAAAAA..."

// Parse from qb64
let matter2 = Matter::from_qb64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
assert_eq!(matter.raw(), matter2.raw());
```

### Cryptographic Digests

Support for multiple hash algorithms:

```rust
use signify_rs::{Diger, matter_codes};

// Compute Blake3-256 digest
let data = b"test data";
let diger = Diger::new(matter_codes::BLAKE3_256, data)?;

// Verify
assert!(diger.verify(data)?);

// Get CESR encoding
println!("Digest qb64: {}", diger.qb64());
```

### Version Strings

KERI-compliant version strings:

```rust
use signify_rs::core::{versify, Protocols, Serials};

let vs = versify(Protocols::KERI, None, None, 608);
// "KERI10JSON000260_"
```

## Testing

### Unit Tests

Each module has comprehensive unit tests:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific module tests
cargo test diger::tests

# Run with coverage
cargo tarpaulin
```

### Integration Tests

```bash
# Run integration tests
cargo test --test '*'
```

### Compatibility Tests

Test against signify-ts:

```bash
# Generate test vectors
cargo test --features test-vectors

# Compare with signify-ts
cd ../../reference/signify-ts
npm test
```

## Dependencies

See `Cargo.toml` for full list. Key dependencies:

- **rustler** (0.34) - Elixir NIF integration
- **ed25519-dalek** (2.1) - Ed25519 cryptography
- **blake3** (1.5) - Blake3 hashing
- **argon2** (0.5) - Key derivation
- **serde/serde_json** (1.0) - Serialization
- **tokio/reqwest** - Async HTTP (for KERIA client)

## Benchmarks

```bash
cargo bench
```

Expected performance:
- CESR encoding: ~100ns
- Blake3 hash (1KB): ~1μs
- Ed25519 sign: ~20μs
- Ed25519 verify: ~50μs

## Documentation

Generate API docs:

```bash
cargo doc --open
```

## Contributing

### Implementation Workflow

1. **Choose next module** from priority list
2. **Study signify-ts** reference implementation
3. **Implement in Rust** with tests
4. **Verify compatibility** with signify-ts
5. **Document** with examples
6. **Submit** for review

### Code Style

Follow Rust conventions:
- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Add documentation comments
- Write tests for all public APIs

### Testing Requirements

Every module must have:
- [ ] Unit tests (>80% coverage)
- [ ] Edge case tests (empty, max, invalid)
- [ ] Round-trip tests (encode/decode)
- [ ] Compatibility tests vs signify-ts

## Architecture

### Layered Design

```
┌─────────────────────────────────────┐
│     Elixir Application              │
└────────────┬────────────────────────┘
             │ NIF calls
┌────────────▼────────────────────────┐
│     Rustler NIF Bindings            │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│     Application Layer (app/)        │
│  - SignifyClient                    │
│  - Habery (identifiers)             │
│  - Credentials (ACDC)               │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│     Core Layer (core/)              │
│  - Matter (CESR base)               │
│  - Signer/Verfer (crypto)           │
│  - Serder (events)                  │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│     Cryptography Libraries          │
│  - ed25519-dalek                    │
│  - blake3, sha2, sha3               │
│  - argon2                           │
└─────────────────────────────────────┘
```

### Module Dependencies

```
Matter ──┬──> Diger
         ├──> Salter ──> Signer ──> Verfer
         ├──> Cipher
         └──> Serder ──> Eventing ──> Habery ──> SignifyClient
```

## Compatibility

This implementation aims for 100% compatibility with signify-ts:

- **CESR encoding**: Byte-identical
- **Ed25519 signatures**: Interoperable
- **Event structure**: Exact match
- **SAID calculation**: Identical
- **Argon2 parameters**: Same settings

### Testing Interoperability

```rust
// Sign with Rust
let signer = Signer::new(...)?;
let signature = signer.sign(data)?;

// Verify with signify-ts
// (export signature to Node.js)
```

```typescript
// Sign with signify-ts
const signer = new Signer(...);
const signature = signer.sign(data);

// Verify with Rust
// (import signature from TypeScript)
```

## Roadmap

### Phase 1: Core Signing (Weeks 1-2) ← **WE ARE HERE**
- [x] Matter, Diger, Utils
- [ ] Salter, Signer, Verfer
- [ ] Basic Serder
- [ ] Incept event creation
- [ ] NIF bindings for above

### Phase 2: Full Events (Weeks 3-4)
- [ ] Complete Serder with SAID
- [ ] Rotate, Interact events
- [ ] Indexer, Counter, Seqner
- [ ] Tholder for thresholds

### Phase 3: Key Management (Weeks 5-6)
- [ ] Manager trait
- [ ] SaltyCreator, RandyCreator
- [ ] Habery
- [ ] KeyState tracking

### Phase 4: Encryption (Week 7)
- [ ] Cipher, Encrypter, Decrypter
- [ ] X25519 operations

### Phase 5: KERIA Client (Weeks 8-9)
- [ ] HTTP client
- [ ] Authenticater
- [ ] SignifyClient
- [ ] Operations tracking

### Phase 6: ACDC (Weeks 10-11)
- [ ] Credentials module
- [ ] Registries
- [ ] Schemas

### Phase 7: Advanced (Week 12)
- [ ] Groups, Delegations
- [ ] Contacts, Exchanges
- [ ] Notifications, Escrowing

### Phase 8: Polish (Week 13)
- [ ] Performance optimization
- [ ] Complete documentation
- [ ] Benchmarks
- [ ] Examples

## Resources

- **Reference Implementation**: `../../reference/signify-ts/`
- **Documentation**: `../../documentation/`
- **KERI Spec**: https://github.com/WebOfTrust/keri
- **CESR Spec**: https://github.com/WebOfTrust/cesr
- **Signify-TS**: https://github.com/WebOfTrust/signify-ts

## License

Apache 2.0 (matching signify-ts)

## Contact

See main project README for contact information.

---

**Next Step**: Implement Salter using the template in `IMPLEMENTATION_GUIDE.md`
