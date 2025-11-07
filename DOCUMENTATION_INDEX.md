# Signify Documentation Index

Complete guide to Signify documentation and resources.

## Quick Navigation

- 🚀 **[README.md](README.md)** - Start here! Main project documentation
- 📚 **[GUIDES.md](documentation/GUIDES.md)** - Implementation guides and tutorials
- 🔍 **[GAP_ANALYSIS.md](documentation/GAP_ANALYSIS.md)** - Comparison with signify-ts reference
- 🏗️ **[KERI_ARCHITECTURE.md](documentation/KERI_ARCHITECTURE.md)** - Planned KERI protocol architecture

---

## Documentation Structure

### Main Documentation

**[README.md](README.md)**
- Project overview and features
- Installation and quick start
- Core concepts (KERI, ACDC, CESR)
- Complete API examples
- Performance benchmarks
- Use cases

### Implementation Guides

**[documentation/GUIDES.md](documentation/GUIDES.md)**

Consolidated guide containing:

1. **Quick Start** - 5-minute tutorial
2. **Credentials API Guide** - Managing verifiable credentials
3. **Signing and Verification** - Cryptographic operations
4. **Architecture Reference** - Module structure and design

Covers all practical aspects:
- ✅ Connecting to KERIA
- ✅ Fetching credentials
- ✅ Signing and verifying messages
- ✅ Loading keys from CESR files
- ✅ Working with KERI identifiers

### Technical Analysis

**[documentation/GAP_ANALYSIS.md](documentation/GAP_ANALYSIS.md)**

Detailed comparison with signify-ts reference implementation:
- ✅ Cryptographic algorithm verification
- ✅ Ed25519 signing correctness
- ✅ CESR encoding comparison
- ⚠️ Scope differences (by design)
- ❌ Missing features (planned)

Key findings:
- Algorithmically correct for core primitives
- Production ready for W3C Verifiable Credentials
- Intentionally scoped to cryptographic layer

**[documentation/KERI_ARCHITECTURE.md](documentation/KERI_ARCHITECTURE.md)**

Future architecture for full KERI protocol:
- Event system (inception, rotation, interaction)
- Key Event Log (KEL) management
- Key state caching
- Witness coordination
- CESR communication

Status: **Design document** (not yet implemented)

---

## Getting Started

### For New Users

1. Read **[README.md](README.md)** - Overview and concepts
2. Follow **Quick Start** in [GUIDES.md](documentation/GUIDES.md)
3. Try the examples in `examples/` directory

### For Developers

1. Read **Architecture Reference** in [GUIDES.md](documentation/GUIDES.md)
2. Review **[GAP_ANALYSIS.md](documentation/GAP_ANALYSIS.md)** - Understand scope
3. Check **[KERI_ARCHITECTURE.md](documentation/KERI_ARCHITECTURE.md)** - Future plans
4. Generate API docs: `mix docs`

### For Contributors

1. Review all documentation
2. Check [GAP_ANALYSIS.md](documentation/GAP_ANALYSIS.md) for missing features
3. Review [KERI_ARCHITECTURE.md](documentation/KERI_ARCHITECTURE.md) for roadmap
4. Run tests: `mix test`

---

## API Documentation

Generate complete ExDoc API documentation:

```bash
mix docs
```

Then open `doc/index.html` in your browser.

### Module Documentation

Core modules with inline documentation:

- `Signify` - Main module and utility functions
- `Signify.Signer` - Ed25519 signing operations
- `Signify.Verfer` - Ed25519 verification operations
- `Signify.Habery` - KERI identifier (AID) management
- `Signify.Client` - SignifyClient for KERIA agent communication
- `Signify.Credential` - Verifiable credential operations
- `Signify.CESR` - CESR file parsing utilities
- `Signify.Native` - Low-level Rust NIF interface

---

## Examples

The `examples/` directory contains working code examples:

| Example | Description |
|---------|-------------|
| `load_keri_cesr.exs` | Load keys from CESR credential files |
| `sign_and_verify.exs` | Sign and verify verifiable presentations |

Run examples:

```bash
elixir examples/load_keri_cesr.exs
elixir examples/sign_and_verify.exs
```

---

## External Resources

### KERI Specifications

- **KERI Spec**: https://github.com/WebOfTrust/keri
- **ACDC Spec**: https://github.com/trustoverip/tswg-acdc-specification
- **CESR Spec**: https://github.com/WebOfTrust/cesr

### Reference Implementations

- **signify-ts**: https://github.com/WebOfTrust/signify-ts (TypeScript reference)
- **keripy**: https://github.com/WebOfTrust/keripy (Python reference)

### Tools

- **KERIA**: KERI Agent (requires running instance)
- **Signify Browser Extension**: Browser-based KERI client

---

## Documentation Maintenance

### File Organization

```
.
├── README.md                           # Main documentation
├── DOCUMENTATION_INDEX.md              # This file
└── documentation/
    ├── GUIDES.md                       # Consolidated guides
    ├── GAP_ANALYSIS.md                 # Technical comparison
    └── KERI_ARCHITECTURE.md            # Future architecture
```

### Updates

When updating documentation:

1. **README.md** - For user-facing features and API changes
2. **GUIDES.md** - For tutorials and how-to content
3. **GAP_ANALYSIS.md** - When comparing with signify-ts
4. **KERI_ARCHITECTURE.md** - When planning protocol features

### Deprecated Files (Removed)

The following files were consolidated into GUIDES.md:
- ~~QUICK_START_CREDENTIALS.md~~
- ~~CREDENTIAL_OPERATIONS_GUIDE.md~~
- ~~SIGNING_VERIFICATION_GUIDE.md~~
- ~~CREDENTIALS_API.md~~

---

## Support

- **Issues**: Report bugs on GitHub
- **Questions**: Check GUIDES.md first, then open a discussion
- **Contributing**: See KERI_ARCHITECTURE.md for planned features

---

## License

MIT License - See LICENSE file for details
