defmodule Signify.KERI.Events.Rotation do
  @moduledoc """
  KERI Rotation Event (rot).

  A rotation event rotates the current signing keys to new keys while
  committing to the next set of keys. It can also modify the witness pool.

  ## Key Rotation Process

  1. Current keys sign the rotation event
  2. Event includes new signing keys that replace current keys
  3. Event commits to next keys via digest
  4. Optionally adds/removes witnesses
  5. Sequence number increments
  6. Prior event digest links to previous event

  ## Fields

  - `v` - Version string (KERI10JSON...)
  - `t` - Event type ("rot")
  - `d` - SAID (Self-Addressing IDentifier) - digest becomes the event ID
  - `i` - Identifier prefix
  - `s` - Sequence number (must be > 0 for rotation)
  - `p` - Prior event digest
  - `kt` - Current keys signing threshold
  - `k` - Current signing keys (new keys after rotation)
  - `nt` - Next keys threshold
  - `n` - Next keys commitment (digest of next keys)
  - `bt` - Witness threshold
  - `br` - Witness cuts (witnesses being removed)
  - `ba` - Witness adds (witnesses being added)
  - `a` - Anchors (seals to other events/data)

  ## Example

      iex> params = %{
      ...>   identifier: "E5ZFan8CLQWBPuultTZTKERYCxIL9hc9WIckkIfh9rYE",
      ...>   sequence: 1,
      ...>   prior_digest: "E...",
      ...>   keys: ["DKN5TkDL1..."],
      ...>   next_keys: ["EabC..."],
      ...>   threshold: 1,
      ...>   next_threshold: 1,
      ...>   witnesses: ["B...", "B..."],
      ...>   witness_threshold: 2,
      ...>   witness_cuts: [],
      ...>   witness_adds: [],
      ...>   anchors: []
      ...> }
      iex> {:ok, rotation} = Rotation.new(params)
      iex> rotation["t"]
      "rot"
  """

  alias Signify.KERI.Events.Event

  @behaviour Event

  @type t :: %{
          String.t() => term()
        }

  @required_fields ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"]

  @doc """
  Creates a new rotation event from parameters.

  ## Parameters

  - `identifier` - The identifier being rotated
  - `sequence` - Sequence number (must be > 0)
  - `prior_digest` - Digest of prior event
  - `keys` - New signing keys (post-rotation)
  - `next_keys` - List of next public keys for pre-rotation
  - `threshold` - Signing threshold for current keys
  - `next_threshold` - Signing threshold for next keys (default: 1)
  - `witnesses` - Full list of witnesses after rotation
  - `witness_threshold` - Required witness receipts
  - `witness_cuts` - Witnesses being removed (default: [])
  - `witness_adds` - Witnesses being added (default: [])
  - `anchors` - Event seals/anchors (default: [])

  ## Returns

  - `{:ok, rotation_event}` - Successfully created rotation event with SAID
  - `{:error, reason}` - Failed to create rotation event
  """
  @impl Event
  @spec new(map()) :: {:ok, t()} | {:error, term()}
  def new(params) do
    with :ok <- validate_params(params),
         {:ok, next_keys_commitment} <-
           compute_next_keys_commitment(params[:next_keys], params[:next_threshold] || 1),
         {:ok, event} <- build_event(params, next_keys_commitment),
         {:ok, event_with_said} <- Event.make_said_event(event) do
      {:ok, event_with_said}
    end
  end

  @doc """
  Creates a rotation event from current key state.

  This is a convenience function that takes the current key state
  and generates a rotation event with new keys.

  ## Parameters

  - `key_state` - Current KeyState struct
  - `new_keys` - New signing keys
  - `next_keys` - Next keys for pre-rotation
  - `opts` - Optional parameters:
    - `:threshold` - New threshold (default: current)
    - `:next_threshold` - Next threshold (default: current)
    - `:witness_cuts` - Witnesses to remove (default: [])
    - `:witness_adds` - Witnesses to add (default: [])
    - `:anchors` - Event anchors (default: [])
  """
  @spec from_key_state(Signify.KERI.State.KeyState.t(), [String.t()], [String.t()], keyword()) ::
          {:ok, t()} | {:error, term()}
  def from_key_state(key_state, new_keys, next_keys, opts \\ []) do
    # Calculate new witness pool
    cuts = Keyword.get(opts, :witness_cuts, [])
    adds = Keyword.get(opts, :witness_adds, [])
    new_witnesses = (key_state.witnesses -- cuts) ++ adds

    params = %{
      identifier: key_state.prefix,
      sequence: key_state.sequence + 1,
      prior_digest: key_state.digest,
      keys: new_keys,
      next_keys: next_keys,
      threshold: Keyword.get(opts, :threshold, key_state.threshold),
      next_threshold: Keyword.get(opts, :next_threshold, key_state.threshold),
      witnesses: new_witnesses,
      witness_threshold: key_state.witness_threshold,
      witness_cuts: cuts,
      witness_adds: adds,
      anchors: Keyword.get(opts, :anchors, [])
    }

    new(params)
  end

  @impl Event
  def event_type, do: :rot

  @impl Event
  def validate(event) when is_map(event) do
    with :ok <- Event.validate_structure(event, @required_fields),
         :ok <- validate_event_type(event),
         :ok <- validate_sequence(event),
         :ok <- validate_keys(event),
         :ok <- validate_witnesses(event) do
      :ok
    end
  end

  @impl Event
  def serialize(event) when is_map(event) do
    Event.serialize_json(event)
  end

  @impl Event
  def compute_said(event) when is_map(event) do
    Event.make_said_event(event)
  end

  ## Private Functions

  defp validate_params(params) do
    required = [:identifier, :sequence, :prior_digest, :keys, :next_keys]
    missing = Enum.reject(required, &Map.has_key?(params, &1))

    case missing do
      [] -> :ok
      fields -> {:error, {:missing_params, fields}}
    end
  end

  defp build_event(params, next_keys_commitment) do
    event = %{
      "v" => Event.version_string(:json, 0),
      "t" => "rot",
      "d" => "",
      "i" => params[:identifier],
      "s" => Integer.to_string(params[:sequence], 16) |> String.downcase(),
      "p" => params[:prior_digest],
      "kt" => Integer.to_string(params[:threshold] || 1, 16),
      "k" => params[:keys],
      "nt" => Integer.to_string(params[:next_threshold] || 1, 16),
      "n" => next_keys_commitment,
      "bt" => Integer.to_string(params[:witness_threshold] || 0, 16),
      "br" => params[:witness_cuts] || [],
      "ba" => params[:witness_adds] || [],
      "a" => params[:anchors] || []
    }

    {:ok, event}
  end

  defp compute_next_keys_commitment(next_keys, next_threshold) when is_list(next_keys) do
    threshold_hex = Integer.to_string(next_threshold, 16) |> String.downcase()
    sorted_keys = Enum.sort(next_keys)
    commitment_data = threshold_hex <> Enum.join(sorted_keys, "")

    case Event.compute_digest(commitment_data) do
      {:ok, digest} -> {:ok, [digest]}
      error -> error
    end
  end

  defp validate_event_type(%{"t" => "rot"}), do: :ok
  defp validate_event_type(%{"t" => other}), do: {:error, {:invalid_type, other}}
  defp validate_event_type(_), do: {:error, :missing_type}

  defp validate_sequence(%{"s" => s}) when is_binary(s) do
    case Integer.parse(s, 16) do
      {seq, ""} when seq > 0 -> :ok
      {0, ""} -> {:error, :rotation_requires_nonzero_sequence}
      _ -> {:error, {:invalid_sequence, s}}
    end
  end

  defp validate_sequence(_), do: {:error, :missing_sequence}

  defp validate_keys(%{"k" => keys, "kt" => threshold}) when is_list(keys) do
    case Integer.parse(threshold, 16) do
      {t, ""} when t > 0 and t <= length(keys) -> :ok
      {t, ""} -> {:error, {:invalid_threshold, t, length(keys)}}
      _ -> {:error, {:invalid_threshold_format, threshold}}
    end
  end

  defp validate_keys(_), do: {:error, :missing_keys}

  defp validate_witnesses(%{"b" => _witnesses, "bt" => _threshold}), do: :ok

  defp validate_witnesses(%{"br" => cuts, "ba" => adds}) when is_list(cuts) and is_list(adds),
    do: :ok

  defp validate_witnesses(_), do: {:error, :invalid_witness_configuration}
end
