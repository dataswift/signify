defmodule Signify.KERI do
  @moduledoc """
  KERI (Key Event Receipt Infrastructure) Protocol Implementation.

  This module provides the public API for creating and managing KERI identifiers
  (AIDs - Autonomic IDentifiers) with full support for:

  - Identifier creation (inception)
  - Key rotation
  - Event anchoring (interaction)
  - Key Event Log management
  - Key state tracking

  ## Overview

  KERI provides cryptographically verifiable identifiers that support:
  - Key rotation without changing the identifier
  - Multi-signature schemes
  - Witness-based validation
  - Delegation chains

  ## Basic Usage

      # Create signers
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      # Create identifier
      {:ok, aid} = Signify.KERI.create_identifier(%{
        signer: signer,
        next_signer: next_signer,
        witnesses: [],
        witness_threshold: 0
      })

      # The aid contains the identifier information
      aid.prefix # => "EKN5TkDL1..."

  ## Architecture

  The KERI implementation uses a layered architecture:

  - **Rust NIF Layer**: Fast cryptographic operations (Ed25519, CESR)
  - **Elixir Core**: Event creation, KEL management, state tracking
  - **Public API**: High-level identifier management (this module)

  Events are stored in the Key Event Log (KEL) and processed to compute
  the current Key State for each identifier.
  """

  alias Signify.KERI.Events.Inception
  alias Signify.KERI.Events.Rotation
  alias Signify.KERI.Events.Interaction
  alias Signify.KERI.KEL.Log, as: KEL
  alias Signify.KERI.State.KeyState

  @type aid :: %{
          prefix: String.t(),
          sequence: non_neg_integer(),
          keys: [String.t()],
          threshold: pos_integer(),
          witnesses: [String.t()],
          witness_threshold: non_neg_integer()
        }

  @doc """
  Creates a new KERI identifier (Autonomic IDentifier).

  This performs an inception operation, creating the first event in the
  identifier's Key Event Log.

  ## Parameters

  - `params` - Map with:
    - `:signer` - Current signing key (Signify.Signer reference)
    - `:next_signer` - Pre-rotated next key (Signify.Signer reference)
    - `:witnesses` - List of witness identifiers (default: [])
    - `:witness_threshold` - Required witness receipts (default: 0)
    - `:config` - Configuration traits (default: [])

  ## Returns

  - `{:ok, aid}` - Successfully created identifier
  - `{:error, reason}` - Failed to create identifier

  ## Example

      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = Signify.KERI.create_identifier(%{
        signer: signer,
        next_signer: next_signer,
        witnesses: [],
        witness_threshold: 0
      })

      aid.prefix # => "EKN5TkDL1..."
  """
  @spec create_identifier(map()) :: {:ok, aid()} | {:error, term()}
  def create_identifier(params) do
    with {:ok, inception_event} <-
           Inception.from_signer(
             params.signer,
             params.next_signer,
             witnesses: Map.get(params, :witnesses, []),
             witness_threshold: Map.get(params, :witness_threshold, 0),
             config: Map.get(params, :config, [])
           ),
         {:ok, signature} <- sign_event(inception_event, params.signer),
         :ok <- KEL.append_event(inception_event["i"], inception_event, [signature]),
         {:ok, key_state} <- KEL.build_key_state(inception_event["i"]) do
      aid = %{
        prefix: key_state.prefix,
        sequence: key_state.sequence,
        keys: key_state.keys,
        threshold: key_state.threshold,
        witnesses: key_state.witnesses,
        witness_threshold: key_state.witness_threshold
      }

      {:ok, aid}
    end
  end

  @doc """
  Rotates the signing keys for an identifier.

  This performs a key rotation operation, replacing the current signing keys
  with new keys while committing to the next set of keys.

  ## Parameters

  - `prefix` - The identifier prefix
  - `params` - Map with:
    - `:current_signer` - Current signing key (must match key state)
    - `:new_signer` - New signing key (becomes current after rotation)
    - `:next_signer` - Next key for pre-rotation
    - `:witness_cuts` - Witnesses to remove (default: [])
    - `:witness_adds` - Witnesses to add (default: [])
    - `:anchors` - Event anchors/seals (default: [])

  ## Returns

  - `{:ok, key_state}` - Updated key state after rotation
  - `{:error, reason}` - Failed to rotate keys

  ## Example

      {:ok, current_signer} = Signify.Signer.new_random(true)
      {:ok, new_signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = Signify.KERI.create_identifier(%{
        signer: current_signer,
        next_signer: new_signer
      })

      {:ok, key_state} = Signify.KERI.rotate_keys(aid.prefix, %{
        current_signer: current_signer,
        new_signer: new_signer,
        next_signer: next_signer
      })
  """
  @spec rotate_keys(String.t(), map()) :: {:ok, KeyState.t()} | {:error, term()}
  def rotate_keys(prefix, params) when is_binary(prefix) do
    with {:ok, key_state} <- KEL.build_key_state(prefix),
         {:ok, new_verfer} <- Signify.Signer.verfer(params.new_signer),
         {:ok, new_key_qb64} <- Signify.Verfer.to_qb64(new_verfer),
         {:ok, next_verfer} <- Signify.Signer.verfer(params.next_signer),
         {:ok, next_key_qb64} <- Signify.Verfer.to_qb64(next_verfer),
         {:ok, rotation_event} <-
           Rotation.from_key_state(
             key_state,
             [new_key_qb64],
             [next_key_qb64],
             witness_cuts: Map.get(params, :witness_cuts, []),
             witness_adds: Map.get(params, :witness_adds, []),
             anchors: Map.get(params, :anchors, [])
           ),
         {:ok, signature} <- sign_event(rotation_event, params.current_signer),
         :ok <- KEL.append_event(prefix, rotation_event, [signature]),
         {:ok, new_key_state} <- KEL.build_key_state(prefix) do
      {:ok, new_key_state}
    end
  end

  @doc """
  Creates an interaction event for an identifier.

  Interaction events anchor data without changing the key state.

  ## Parameters

  - `prefix` - The identifier prefix
  - `params` - Map with:
    - `:signer` - Current signing key
    - `:anchors` - Event anchors/seals (default: [])

  ## Returns

  - `{:ok, key_state}` - Updated key state after interaction
  - `{:error, reason}` - Failed to create interaction

  ## Example

      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = Signify.KERI.create_identifier(%{
        signer: signer,
        next_signer: next_signer
      })

      {:ok, key_state} = Signify.KERI.create_interaction(aid.prefix, %{
        signer: signer,
        anchors: [
          %{"i" => "credential_id", "s" => "0", "d" => "E..."}
        ]
      })
  """
  @spec create_interaction(String.t(), map()) :: {:ok, KeyState.t()} | {:error, term()}
  def create_interaction(prefix, params) when is_binary(prefix) do
    with {:ok, key_state} <- KEL.build_key_state(prefix),
         {:ok, interaction_event} <-
           Interaction.from_key_state(key_state, Map.get(params, :anchors, [])),
         {:ok, signature} <- sign_event(interaction_event, params.signer),
         :ok <- KEL.append_event(prefix, interaction_event, [signature]),
         {:ok, new_key_state} <- KEL.build_key_state(prefix) do
      {:ok, new_key_state}
    end
  end

  @doc """
  Gets the current key state for an identifier.

  ## Parameters

  - `prefix` - The identifier prefix

  ## Returns

  - `{:ok, key_state}` - Current key state
  - `{:error, reason}` - Identifier not found or invalid
  """
  @spec get_key_state(String.t()) :: {:ok, KeyState.t()} | {:error, term()}
  def get_key_state(prefix) when is_binary(prefix) do
    KEL.build_key_state(prefix)
  end

  @doc """
  Gets the complete event history for an identifier.

  ## Parameters

  - `prefix` - The identifier prefix
  - `opts` - Options (see Signify.KERI.KEL.Log.get_events/2)

  ## Returns

  - `{:ok, events}` - List of event entries
  - `{:error, reason}` - Failed to retrieve events
  """
  @spec get_events(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_events(prefix, opts \\ []) when is_binary(prefix) do
    KEL.get_events(prefix, opts)
  end

  @doc """
  Verifies the integrity of an identifier's event chain.

  This validates:
  - All event digests are correct
  - All signatures are valid
  - Sequence numbers are incremental
  - Prior event digests match

  ## Parameters

  - `prefix` - The identifier prefix to verify

  ## Returns

  - `{:ok, :valid}` - Chain is valid
  - `{:error, reason}` - Chain is invalid or verification failed
  """
  @spec verify_identifier(String.t()) :: {:ok, :valid} | {:error, term()}
  def verify_identifier(prefix) when is_binary(prefix) do
    KEL.verify_chain(prefix)
  end

  @doc """
  Signs an event with a signer.

  ## Parameters

  - `event` - The KERI event (map)
  - `signer` - Signify.Signer reference

  ## Returns

  - `{:ok, signature}` - Event signature (binary)
  - `{:error, reason}` - Signing failed
  """
  @spec sign_event(map(), reference()) :: {:ok, binary()} | {:error, term()}
  def sign_event(event, signer) do
    with {:ok, serialized} <- Inception.serialize(event) do
      Signify.Signer.sign(signer, serialized)
    end
  end

  @doc """
  Verifies an event signature.

  ## Parameters

  - `event` - The KERI event (map)
  - `signature` - The signature to verify (binary)
  - `verfer` - Public key verifier (Signify.Verfer reference or QB64 string)

  ## Returns

  - `{:ok, true}` - Signature is valid
  - `{:ok, false}` - Signature is invalid
  - `{:error, reason}` - Verification failed
  """
  @spec verify_event_signature(map(), binary(), reference() | String.t()) ::
          {:ok, boolean()} | {:error, term()}
  def verify_event_signature(event, signature, verfer) when is_reference(verfer) do
    with {:ok, serialized} <- Inception.serialize(event) do
      Signify.Verfer.verify(verfer, signature, serialized)
    end
  end

  def verify_event_signature(event, signature, verfer_qb64) when is_binary(verfer_qb64) do
    with {:ok, verfer} <- Signify.Verfer.from_qb64(verfer_qb64),
         {:ok, serialized} <- Inception.serialize(event) do
      Signify.Verfer.verify(verfer, signature, serialized)
    end
  end

  @doc """
  Checks if an identifier exists in the KEL.

  ## Parameters

  - `prefix` - The identifier prefix

  ## Returns

  - `true` - Identifier exists
  - `false` - Identifier does not exist
  """
  @spec identifier_exists?(String.t()) :: boolean()
  def identifier_exists?(prefix) when is_binary(prefix) do
    case KEL.get_current_sequence(prefix) do
      {:ok, _} -> true
      {:error, :not_found} -> false
    end
  end

  @doc """
  Gets statistics about the KERI system.

  Returns information about:
  - Total number of identifiers
  - Total number of events
  - Memory usage

  ## Returns

  - Map with statistics
  """
  @spec stats() :: map()
  def stats do
    KEL.stats()
  end

  @doc """
  Exports an identifier's event log to a portable format.

  This creates a complete, self-contained export that can be imported
  on another system.

  ## Parameters

  - `prefix` - The identifier prefix to export

  ## Returns

  - `{:ok, export}` - Exported data (map)
  - `{:error, reason}` - Export failed
  """
  @spec export_identifier(String.t()) :: {:ok, map()} | {:error, term()}
  def export_identifier(prefix) when is_binary(prefix) do
    with {:ok, events} <- KEL.get_events(prefix),
         {:ok, key_state} <- KEL.build_key_state(prefix) do
      export = %{
        "version" => "1.0",
        "prefix" => prefix,
        "exported_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "key_state" => %{
          "sequence" => key_state.sequence,
          "keys" => key_state.keys,
          "threshold" => key_state.threshold,
          "witnesses" => key_state.witnesses,
          "witness_threshold" => key_state.witness_threshold
        },
        "events" =>
          Enum.map(events, fn entry ->
            %{
              "sequence" => entry.sequence,
              "event" => entry.event,
              "signatures" => Enum.map(entry.signatures, &Base.encode64/1),
              "receipts" => entry.receipts,
              "timestamp" => DateTime.to_iso8601(entry.timestamp)
            }
          end)
      }

      {:ok, export}
    end
  end

  @doc """
  Imports an identifier from an export.

  ## Parameters

  - `export` - Exported data (from export_identifier/1)

  ## Returns

  - `{:ok, prefix}` - Successfully imported
  - `{:error, reason}` - Import failed
  """
  @spec import_identifier(map()) :: {:ok, String.t()} | {:error, term()}
  def import_identifier(%{"prefix" => prefix, "events" => events}) do
    # Clear any existing data for this prefix
    KEL.clear_prefix(prefix)

    # Import events in order
    result =
      Enum.reduce_while(events, :ok, fn event_data, :ok ->
        signatures = Enum.map(event_data["signatures"], &Base.decode64!/1)

        case KEL.append_event(prefix, event_data["event"], signatures) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      :ok -> {:ok, prefix}
      error -> error
    end
  end

  @doc """
  Validates event structure without storing it.

  This is useful for validating events before appending them to the KEL.

  ## Parameters

  - `event` - The KERI event to validate

  ## Returns

  - `:ok` - Event is valid
  - `{:error, reason}` - Event is invalid
  """
  @spec validate_event(map()) :: :ok | {:error, term()}
  def validate_event(%{"t" => "icp"} = event), do: Inception.validate(event)
  def validate_event(%{"t" => "rot"} = event), do: Rotation.validate(event)
  def validate_event(%{"t" => "ixn"} = event), do: Interaction.validate(event)
  def validate_event(%{"t" => type}), do: {:error, {:unsupported_event_type, type}}
  def validate_event(_), do: {:error, :invalid_event_structure}

  @doc """
  Computes a BLAKE3-256 digest of data.

  This is a convenience wrapper around the Rust NIF digest function.

  ## Parameters

  - `data` - Data to hash (binary or string)

  ## Returns

  - `{:ok, digest}` - QB64-encoded digest
  - `{:error, reason}` - Hashing failed
  """
  @spec digest(binary()) :: {:ok, String.t()} | {:error, term()}
  def digest(data) when is_binary(data) do
    Signify.KERI.Events.Event.compute_digest(data)
  end
end
