defmodule Signify.KERI.Events.Inception do
  @moduledoc """
  Inception Event (icp) - Creates a new KERI identifier.

  An inception event establishes a new Autonomic Identifier (AID) with:
  - Initial set of signing keys
  - Commitment to next set of keys (for rotation)
  - Optional witnesses for multi-party validation
  - Configuration traits

  ## Fields

  - `v` - Version string (e.g., "KERI10JSON000160_")
  - `t` - Event type ("icp")
  - `d` - Event digest (SAID - Self-Addressing IDentifier)
  - `i` - Identifier prefix (derived from inception event)
  - `s` - Sequence number (always "0" for inception)
  - `kt` - Keys signing threshold (number of keys required to sign)
  - `k` - List of current signing keys (QB64 encoded)
  - `nt` - Next keys threshold
  - `n` - Next keys commitment (digest of next keys)
  - `bt` - Witness receipt threshold
  - `b` - List of witness identifiers
  - `c` - Configuration traits (list of strings)
  - `a` - Anchors (seals to external data)

  ## Example

      iex> Signify.KERI.Events.Inception.new(%{
      ...>   keys: ["DKvp4T9yNzJxQ3mH5c0v8L2fR9pD1nW6sX4jG7kB3hM8"],
      ...>   next_keys_digest: ["EKvp4T9yNzJxQ3mH5c0v8L2fR9pD1nW6sX4jG7kB3hM8"],
      ...>   threshold: 1,
      ...>   witnesses: [],
      ...>   witness_threshold: 0
      ...> })
      {:ok, %{
        "v" => "KERI10JSON000160_",
        "t" => "icp",
        "d" => "E...",
        "i" => "E...",
        "s" => "0",
        "kt" => "1",
        "k" => ["DKvp4T9yNzJxQ3mH5c0v8L2fR9pD1nW6sX4jG7kB3hM8"],
        "nt" => "1",
        "n" => ["EKvp4T9yNzJxQ3mH5c0v8L2fR9pD1nW6sX4jG7kB3hM8"],
        "bt" => "0",
        "b" => [],
        "c" => [],
        "a" => []
      }}
  """

  @behaviour Signify.KERI.Events.Event

  alias Signify.KERI.Events.Event

  @type t :: %{
          required(:v) => String.t(),
          required(:t) => String.t(),
          required(:d) => String.t(),
          required(:i) => String.t(),
          required(:s) => String.t(),
          required(:kt) => String.t(),
          required(:k) => [String.t()],
          required(:nt) => String.t(),
          required(:n) => [String.t()],
          required(:bt) => String.t(),
          required(:b) => [String.t()],
          required(:c) => [String.t()],
          required(:a) => [map()]
        }

  @doc """
  Creates a new inception event.

  ## Parameters

  - `fields` - Map with:
    - `:keys` - List of current signing keys (QB64 encoded)
    - `:next_keys_digest` - List with digest of next keys (for rotation)
    - `:threshold` - Number of keys required to sign (default: 1)
    - `:next_threshold` - Next keys threshold (default: 1)
    - `:witnesses` - List of witness identifiers (default: [])
    - `:witness_threshold` - Number of witness receipts required (default: 0)
    - `:config` - Configuration traits (default: [])
    - `:anchors` - Anchors/seals (default: [])

  ## Returns

  - `{:ok, event}` - Successfully created inception event with computed SAID
  - `{:error, reason}` - Validation failed
  """
  @impl true
  @spec new(fields :: map()) :: {:ok, t()} | {:error, term()}
  def new(fields) do
    with :ok <- validate_fields(fields),
         {:ok, event} <- build_event(fields),
         {:ok, event_with_said} <- Event.make_said_event(event),
         {:ok, event_with_prefix} <- derive_identifier_prefix(event_with_said) do
      {:ok, event_with_prefix}
    end
  end

  @doc """
  Validates the inception event structure.
  """
  @impl true
  @spec validate(event :: t()) :: :ok | {:error, term()}
  def validate(event) do
    with :ok <- Event.validate_structure(event, required_fields()),
         :ok <- Event.validate_version(event["v"]),
         :ok <- validate_event_type(event["t"]),
         :ok <- validate_sequence_zero(event["s"]),
         :ok <- validate_threshold(event["kt"], event["k"]),
         :ok <- validate_next_threshold(event["nt"], event["n"]),
         :ok <- validate_witness_threshold(event["bt"], event["b"]),
         :ok <- validate_identifier_matches_digest(event) do
      :ok
    end
  end

  @doc """
  Serializes the inception event to JSON.
  """
  @impl true
  @spec serialize(event :: t()) :: {:ok, String.t()} | {:error, term()}
  def serialize(event) do
    Event.serialize_json(event)
  end

  @doc """
  Computes the SAID for the inception event.
  """
  @impl true
  @spec compute_said(event :: t()) :: {:ok, String.t()} | {:error, term()}
  def compute_said(event) do
    with {:ok, serialized} <- serialize(Map.put(event, "d", "")),
         {:ok, digest} <- Event.compute_digest(serialized) do
      {:ok, digest}
    end
  end

  @doc """
  Returns the event type (:icp).
  """
  @impl true
  @spec event_type() :: :icp
  def event_type, do: :icp

  ## Private Functions

  defp required_fields do
    ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"]
  end

  defp validate_fields(fields) do
    cond do
      not is_list(fields[:keys]) or Enum.empty?(fields[:keys]) ->
        {:error, :keys_required}

      not is_list(fields[:next_keys_digest]) or Enum.empty?(fields[:next_keys_digest]) ->
        {:error, :next_keys_digest_required}

      true ->
        :ok
    end
  end

  defp build_event(fields) do
    threshold = Map.get(fields, :threshold, 1)
    next_threshold = Map.get(fields, :next_threshold, 1)
    witnesses = Map.get(fields, :witnesses, [])
    witness_threshold = Map.get(fields, :witness_threshold, 0)
    config = Map.get(fields, :config, [])
    anchors = Map.get(fields, :anchors, [])

    # Estimate size for version string (will be updated after serialization)
    event = %{
      "v" => Event.version_string(:json, 0),
      "t" => "icp",
      # Will be computed
      "d" => "",
      # Will be derived from digest
      "i" => "",
      # Always 0 for inception
      "s" => "0",
      "kt" => Integer.to_string(threshold),
      "k" => fields[:keys],
      "nt" => Integer.to_string(next_threshold),
      "n" => fields[:next_keys_digest],
      "bt" => Integer.to_string(witness_threshold),
      "b" => witnesses,
      "c" => config,
      "a" => anchors
    }

    # Update version string with actual size
    {:ok, serialized} = Event.serialize_json(event)
    size = byte_size(serialized)
    event_with_version = Map.put(event, "v", Event.version_string(:json, size))

    {:ok, event_with_version}
  end

  defp derive_identifier_prefix(event) do
    # For inception events, the identifier prefix is the same as the event digest
    # This makes it self-certifying
    prefix = event["d"]
    {:ok, Map.put(event, "i", prefix)}
  end

  defp validate_event_type("icp"), do: :ok
  defp validate_event_type(t), do: {:error, {:invalid_event_type, t}}

  defp validate_sequence_zero("0"), do: :ok
  defp validate_sequence_zero(s), do: {:error, {:invalid_inception_sequence, s}}

  defp validate_threshold(threshold_str, keys) when is_binary(threshold_str) and is_list(keys) do
    case Integer.parse(threshold_str) do
      {threshold, ""} ->
        cond do
          threshold < 1 ->
            {:error, {:threshold_too_low, threshold}}

          threshold > length(keys) ->
            {:error, {:threshold_exceeds_keys, threshold, length(keys)}}

          true ->
            :ok
        end

      _ ->
        {:error, {:invalid_threshold_format, threshold_str}}
    end
  end

  defp validate_next_threshold(next_threshold_str, next_keys)
       when is_binary(next_threshold_str) and is_list(next_keys) do
    case Integer.parse(next_threshold_str) do
      {next_threshold, ""} ->
        cond do
          next_threshold < 1 ->
            {:error, {:next_threshold_too_low, next_threshold}}

          next_threshold > length(next_keys) ->
            {:error, {:next_threshold_exceeds_keys, next_threshold, length(next_keys)}}

          true ->
            :ok
        end

      _ ->
        {:error, {:invalid_next_threshold_format, next_threshold_str}}
    end
  end

  defp validate_witness_threshold(witness_threshold_str, witnesses)
       when is_binary(witness_threshold_str) and is_list(witnesses) do
    case Integer.parse(witness_threshold_str) do
      {witness_threshold, ""} ->
        cond do
          witness_threshold < 0 ->
            {:error, {:witness_threshold_negative, witness_threshold}}

          witness_threshold > length(witnesses) ->
            {:error, {:witness_threshold_exceeds_witnesses, witness_threshold, length(witnesses)}}

          true ->
            :ok
        end

      _ ->
        {:error, {:invalid_witness_threshold_format, witness_threshold_str}}
    end
  end

  defp validate_identifier_matches_digest(%{"i" => prefix, "d" => digest}) do
    if prefix == digest do
      :ok
    else
      {:error, {:prefix_digest_mismatch, prefix, digest}}
    end
  end

  @doc """
  Computes the next keys commitment digest.

  This is the digest of the next set of signing keys that will be used
  after the first rotation. It's a commitment that prevents key
  compromise from affecting future rotations.

  ## Parameters

  - `next_keys` - List of next signing key public keys (QB64 encoded)
  - `next_threshold` - Threshold for next keys (default: 1)

  ## Returns

  - `{:ok, [digest]}` - List with single digest commitment
  - `{:error, reason}` - Failed to compute commitment

  ## Example

      iex> Signify.KERI.Events.Inception.compute_next_keys_commitment(
      ...>   ["DKvp4T9yNzJxQ3mH5c0v8L2fR9pD1nW6sX4jG7kB3hM8"],
      ...>   1
      ...> )
      {:ok, ["EABCDEFabcdef..."]}
  """
  @spec compute_next_keys_commitment([String.t()], pos_integer()) ::
          {:ok, [String.t()]} | {:error, term()}
  def compute_next_keys_commitment(next_keys, next_threshold \\ 1) when is_list(next_keys) do
    # Format: threshold as hex + sorted keys concatenated
    threshold_hex = Integer.to_string(next_threshold, 16) |> String.downcase()
    sorted_keys = Enum.sort(next_keys)
    commitment_data = threshold_hex <> Enum.join(sorted_keys, "")

    case Event.compute_digest(commitment_data) do
      {:ok, digest} -> {:ok, [digest]}
      error -> error
    end
  end

  @doc """
  Creates an inception event from a signer.

  This is a convenience function that automatically generates the next keys
  commitment and creates a complete inception event.

  ## Parameters

  - `signer` - Signify.Signer resource
  - `next_signer` - Signify.Signer resource for next keys (for rotation)
  - `opts` - Options:
    - `:witnesses` - List of witness identifiers (default: [])
    - `:witness_threshold` - Witness threshold (default: 0)
    - `:config` - Configuration traits (default: [])

  ## Returns

  - `{:ok, event}` - Inception event ready to be signed
  - `{:error, reason}` - Failed to create event
  """
  @spec from_signer(signer :: reference(), next_signer :: reference(), opts :: keyword()) ::
          {:ok, t()} | {:error, term()}
  def from_signer(signer, next_signer, opts \\ []) do
    with {:ok, verfer} <- Signify.Signer.verfer(signer),
         {:ok, verfer_qb64} <- Signify.Verfer.to_qb64(verfer),
         {:ok, next_verfer} <- Signify.Signer.verfer(next_signer),
         {:ok, next_verfer_qb64} <- Signify.Verfer.to_qb64(next_verfer),
         {:ok, next_commitment} <- compute_next_keys_commitment([next_verfer_qb64], 1) do
      new(%{
        keys: [verfer_qb64],
        next_keys_digest: next_commitment,
        threshold: 1,
        next_threshold: 1,
        witnesses: Keyword.get(opts, :witnesses, []),
        witness_threshold: Keyword.get(opts, :witness_threshold, 0),
        config: Keyword.get(opts, :config, []),
        anchors: Keyword.get(opts, :anchors, [])
      })
    end
  end
end
