defmodule Signify do
  @moduledoc """
  Signify - KERI (Key Event Receipt Infrastructure) implementation in Rust with Elixir bindings.

  Trust-based decentralized identity and verifiable credentials using the KERI protocol.

  ## What is Signify?

  Signify is an Elixir library providing KERI protocol implementation through high-performance
  Rust NIFs. It enables:

  - **Decentralized Identifiers (AIDs)** - Self-certifying identifiers without centralized registry
  - **ACDC Credentials** - Authentic Chained Data Containers for verifiable credentials
  - **Ed25519/X25519 Cryptography** - Fast and secure key operations
  - **CESR Encoding** - Composable Event Streaming Representation
  - **HTTP Signatures** - Secure API authentication with KERIA agents

  ## Architecture

  ```
  Elixir Application
      ↓
  High-level Wrappers (Signify.*)
      ↓
  Signify.Native (NIF Interface)
      ↓
  Rust signify-rs (via Rustler)
      - KERI protocol
      - Ed25519 crypto
      - CESR encoding
      - ACDC credentials
  ```

  ## Modules

  ### Core Cryptographic Primitives

  - `Signify.Signer` - Ed25519 private key signing operations
  - `Signify.Verfer` - Ed25519 public key verification operations

  ### KERI Protocol

  - `Signify.Habery` - High-level identifier (AID) management
  - `Signify.Client` - SignifyClient for KERIA agent communication

  ### Credentials

  - `Signify.Credential` - ACDC verifiable credential operations

  ### Low-level Interface

  - `Signify.Native` - Direct Rust NIF bindings (advanced use only)

  ## Quick Start

      # Create a Habery for managing identifiers
      {:ok, habery} = Signify.Habery.new("my-habery", "GCiBGAhduxcggJE4qJeaA")

      # Create a new KERI identifier (AID)
      {:ok, aid} = Signify.Habery.make_hab(habery, "my-identifier")
      # => {:ok, "EKxy..."}

      # Create a SignifyClient for agent communication
      {:ok, client} = Signify.Client.new("http://localhost:3901", "GCiBGAhduxcggJE4qJeaA")

      # Work with keys directly
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, signature} = Signify.Signer.sign(signer, "Hello, KERI!")
      {:ok, verfer} = Signify.Signer.verfer(signer)
      {:ok, valid} = Signify.Verfer.verify(verfer, signature, "Hello, KERI!")

  ## KERI Protocol Overview

  KERI (Key Event Receipt Infrastructure) is a decentralized identity protocol that:

  1. **Self-Certifying** - Identifiers are cryptographically derived from keys
  2. **Key Rotation** - Built-in key rotation with pre-rotation commitments
  3. **Witnesses** - Decentralized witnesses for event validation
  4. **Portable** - Identifiers can migrate between systems
  5. **Verifiable** - All events are cryptographically signed and chained

  ## ACDC Credentials

  ACDC (Authentic Chained Data Containers) provides:

  - **Self-Addressing** - Credentials contain their own digest (SAID)
  - **Chained** - Credentials can reference other credentials
  - **Schema-bound** - Enforces data structure via schemas
  - **Privacy-preserving** - Selective disclosure support
  - **Revocable** - Registry-based revocation

  ## Use Cases

  - **Decentralized Identity** - Self-sovereign identity management
  - **Verifiable Credentials** - Academic, employment, legal entity credentials
  - **vLEI** - Verifiable Legal Entity Identifier
  - **Supply Chain** - Product provenance and authenticity
  - **IoT Identity** - Device authentication and authorization
  - **Secure APIs** - HTTP Signatures authentication

  ## KERI vs Traditional PKI

  | Feature | Traditional PKI | KERI |
  |---------|----------------|------|
  | Trust Root | Certificate Authority | Self-certifying |
  | Key Rotation | Revoke & reissue | Built-in rotation |
  | Portability | Certificate-bound | Fully portable |
  | Witnesses | Single CA | Decentralized |
  | Recovery | CA dependent | Pre-rotation commitment |

  ## Examples

  ### Creating an Identifier

      # Initialize Habery with a passcode
      {:ok, habery} = Signify.Habery.new("my-app", "GCiBGAhduxcggJE4qJeaA")

      # Create a new AID
      {:ok, aid} = Signify.Habery.make_hab(habery, "user-123")

      # The AID is now a self-certifying identifier
      # aid will be something like "EKxy..."

  ### Signing and Verification

      # Generate a new key pair
      {:ok, signer} = Signify.Signer.new_random(true)

      # Sign a message
      message = "Important document"
      {:ok, signature} = Signify.Signer.sign(signer, message)

      # Get verifier from signer
      {:ok, verfer} = Signify.Signer.verfer(signer)

      # Verify the signature
      {:ok, true} = Signify.Verfer.verify(verfer, signature, message)

  ### Working with KERIA Agent

      # Connect to KERIA agent
      {:ok, client} = Signify.Client.new("http://localhost:3901", "GCiBGAhduxcggJE4qJeaA")

      # Client uses HTTP Signatures for authentication
      {:ok, url} = Signify.Client.url(client)

  ### Key Export/Import

      # Export signer to QB64
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, qb64} = Signify.Signer.to_qb64(signer)

      # Import from QB64
      {:ok, restored_signer} = Signify.Signer.from_qb64(qb64, true)

  ## Documentation

  - Main docs: https://hexdocs.pm/signify
  - KERI Spec: https://github.com/WebOfTrust/keri
  - ACDC Spec: https://github.com/trustoverip/tswg-acdc-specification
  - CESR Spec: https://github.com/WebOfTrust/cesr

  ## Performance

  Signify uses Rust NIFs for cryptographic operations, providing:

  - **Fast signing** - Ed25519 signatures in microseconds
  - **Concurrent** - Thread-safe resource sharing with Arc<Mutex<>>
  - **Memory efficient** - Zero-copy where possible
  - **Production ready** - Battle-tested Rust cryptography libraries

  ## Testing

  Run the test suite:

      mix test

  All tests verify:
  - Cryptographic correctness
  - KERI protocol compliance
  - CESR encoding/decoding
  - NIF memory safety
  """

  @doc """
  Returns the version of Signify.
  """
  @spec version() :: String.t()
  def version do
    Application.spec(:signify, :vsn) |> to_string()
  end

  @doc """
  Checks if the Rust NIF is loaded and ready.

  ## Returns

    * `{:ok, true}` - If the NIF is loaded
    * `{:error, reason}` - If the NIF is not loaded
  """
  @spec ready?() :: {:ok, boolean()} | {:error, String.t()}
  def ready? do
    try do
      result = Signify.Native.ready()
      {:ok, result}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Returns the version of the Rust signify-rs library.

  ## Returns

    * `{:ok, version}` - The version string
    * `{:error, reason}` - If version retrieval fails
  """
  @spec rust_version() :: {:ok, String.t()} | {:error, String.t()}
  def rust_version do
    try do
      version = Signify.Native.version()
      {:ok, version}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end
end
