defmodule Signify.KERI.State.KeyState do
  @moduledoc """
  Key State represents the current cryptographic state of a KERI identifier.

  The key state is derived from processing the Key Event Log (KEL) and tracks:
  - Current signing keys and threshold
  - Next keys commitment (for rotation)
  - Witnesses and their threshold
  - Current sequence number
  - Delegator (if delegated identifier)

  Key state is the authoritative representation of an identifier's current
  cryptographic configuration and must be computed from the KEL.
  """

  @type t :: %__MODULE__{
          prefix: String.t(),
          sequence: non_neg_integer(),
          digest: String.t(),
          keys: [String.t()],
          next_keys_digest: [String.t()],
          threshold: pos_integer(),
          next_threshold: pos_integer(),
          witnesses: [String.t()],
          witness_threshold: non_neg_integer(),
          delegator: String.t() | nil,
          last_event_type: atom(),
          establishment_only: boolean(),
          timestamp: DateTime.t()
        }

  @enforce_keys [:prefix, :sequence, :digest, :keys, :threshold]
  defstruct [
    :prefix,
    :sequence,
    :digest,
    :keys,
    :next_keys_digest,
    :threshold,
    :next_threshold,
    :witnesses,
    :witness_threshold,
    :delegator,
    :last_event_type,
    :establishment_only,
    :timestamp
  ]

  @doc """
  Creates initial key state from an inception event.

  ## Parameters

  - `inception_event` - The inception event map

  ## Returns

  - `{:ok, key_state}` - Initial key state
  - `{:error, reason}` - Invalid inception event
  """
  @spec from_inception(map()) :: {:ok, t()} | {:error, term()}
  def from_inception(event) when is_map(event) do
    with :ok <- validate_inception_event(event),
         {:ok, threshold} <- parse_integer(event["kt"]),
         {:ok, next_threshold} <- parse_integer(event["nt"]),
         {:ok, witness_threshold} <- parse_integer(event["bt"]),
         {:ok, sequence} <- parse_sequence(event["s"]) do
      key_state = %__MODULE__{
        prefix: event["i"],
        sequence: sequence,
        digest: event["d"],
        keys: event["k"],
        next_keys_digest: event["n"],
        threshold: threshold,
        next_threshold: next_threshold,
        witnesses: event["b"],
        witness_threshold: witness_threshold,
        # Delegator for delegated inception
        delegator: event["di"],
        last_event_type: get_event_type(event["t"]),
        establishment_only: has_config_trait?(event["c"], "EO"),
        timestamp: DateTime.utc_now()
      }

      {:ok, key_state}
    end
  end

  @doc """
  Applies a rotation event to update the key state.

  ## Parameters

  - `key_state` - Current key state
  - `rotation_event` - The rotation event to apply

  ## Returns

  - `{:ok, new_key_state}` - Updated key state
  - `{:error, reason}` - Invalid rotation or validation failed
  """
  @spec apply_rotation(t(), map()) :: {:ok, t()} | {:error, term()}
  def apply_rotation(%__MODULE__{} = state, event) when is_map(event) do
    with :ok <- validate_rotation_event(event),
         :ok <- validate_sequence_increments(state.sequence, event["s"]),
         :ok <- validate_prior_digest(state.digest, event["p"]),
         :ok <- validate_next_keys_match(state.next_keys_digest, event["k"]),
         {:ok, threshold} <- parse_integer(event["kt"]),
         {:ok, next_threshold} <- parse_integer(event["nt"]),
         {:ok, sequence} <- parse_sequence(event["s"]),
         {:ok, new_witnesses} <-
           apply_witness_rotation(state.witnesses, event["br"], event["ba"]),
         {:ok, witness_threshold} <- parse_integer(event["bt"]) do
      new_state = %__MODULE__{
        state
        | sequence: sequence,
          digest: event["d"],
          keys: event["k"],
          next_keys_digest: event["n"],
          threshold: threshold,
          next_threshold: next_threshold,
          witnesses: new_witnesses,
          witness_threshold: witness_threshold,
          last_event_type: :rot,
          timestamp: DateTime.utc_now()
      }

      {:ok, new_state}
    end
  end

  @doc """
  Applies an interaction event to update the key state.

  Interaction events only update the sequence number and digest.
  They do not change keys or configuration.

  ## Parameters

  - `key_state` - Current key state
  - `interaction_event` - The interaction event to apply

  ## Returns

  - `{:ok, new_key_state}` - Updated key state
  - `{:error, reason}` - Invalid interaction or validation failed
  """
  @spec apply_interaction(t(), map()) :: {:ok, t()} | {:error, term()}
  def apply_interaction(%__MODULE__{} = state, event) when is_map(event) do
    with :ok <- validate_interaction_event(event),
         :ok <- validate_sequence_increments(state.sequence, event["s"]),
         :ok <- validate_prior_digest(state.digest, event["p"]),
         {:ok, sequence} <- parse_sequence(event["s"]) do
      new_state = %__MODULE__{
        state
        | sequence: sequence,
          digest: event["d"],
          last_event_type: :ixn,
          timestamp: DateTime.utc_now()
      }

      {:ok, new_state}
    end
  end

  @doc """
  Checks if the key state allows non-establishment events.

  If establishment_only is true, only rotation events are allowed
  (no interaction events).
  """
  @spec allows_interaction?(t()) :: boolean()
  def allows_interaction?(%__MODULE__{establishment_only: establishment_only}) do
    not establishment_only
  end

  @doc """
  Checks if a set of keys meets the signing threshold.
  """
  @spec meets_threshold?(t(), [String.t()]) :: boolean()
  def meets_threshold?(%__MODULE__{threshold: threshold}, signing_keys)
      when is_list(signing_keys) do
    length(signing_keys) >= threshold
  end

  @doc """
  Checks if witness receipts meet the witness threshold.
  """
  @spec meets_witness_threshold?(t(), [String.t()]) :: boolean()
  def meets_witness_threshold?(%__MODULE__{witness_threshold: threshold}, receipt_witnesses)
      when is_list(receipt_witnesses) do
    length(receipt_witnesses) >= threshold
  end

  @doc """
  Checks if this is a delegated identifier.
  """
  @spec delegated?(t()) :: boolean()
  def delegated?(%__MODULE__{delegator: delegator}), do: not is_nil(delegator)

  ## Private Functions

  defp validate_inception_event(%{"t" => "icp"}), do: :ok
  defp validate_inception_event(%{"t" => "dip"}), do: :ok
  defp validate_inception_event(%{"t" => t}), do: {:error, {:not_inception_event, t}}
  defp validate_inception_event(_), do: {:error, :invalid_event_structure}

  defp validate_rotation_event(%{"t" => "rot"}), do: :ok
  defp validate_rotation_event(%{"t" => "drt"}), do: :ok
  defp validate_rotation_event(%{"t" => t}), do: {:error, {:not_rotation_event, t}}
  defp validate_rotation_event(_), do: {:error, :invalid_event_structure}

  defp validate_interaction_event(%{"t" => "ixn"}), do: :ok
  defp validate_interaction_event(%{"t" => t}), do: {:error, {:not_interaction_event, t}}
  defp validate_interaction_event(_), do: {:error, :invalid_event_structure}

  defp validate_sequence_increments(current_seq, next_seq_str) do
    case parse_sequence(next_seq_str) do
      {:ok, next_seq} ->
        if next_seq == current_seq + 1 do
          :ok
        else
          {:error, {:sequence_not_incremental, current_seq, next_seq}}
        end

      error ->
        error
    end
  end

  defp validate_prior_digest(current_digest, prior_digest) do
    if current_digest == prior_digest do
      :ok
    else
      {:error, {:prior_digest_mismatch, current_digest, prior_digest}}
    end
  end

  defp validate_next_keys_match(next_keys_commitment, new_keys) do
    # Compute the commitment of the new keys and compare with stored commitment
    # This ensures the new keys were previously committed to
    # Simplified - should get from event
    threshold = length(new_keys)

    case Signify.KERI.Events.Inception.compute_next_keys_commitment(new_keys, threshold) do
      {:ok, computed_commitment} ->
        if computed_commitment == next_keys_commitment do
          :ok
        else
          {:error, {:next_keys_mismatch, next_keys_commitment, computed_commitment}}
        end

      error ->
        error
    end
  end

  defp apply_witness_rotation(current_witnesses, cuts, adds) do
    # Remove witnesses in cuts
    remaining = Enum.reject(current_witnesses, fn w -> w in cuts end)

    # Add new witnesses in adds
    new_witnesses = remaining ++ adds

    {:ok, Enum.uniq(new_witnesses)}
  end

  defp parse_integer(str) when is_binary(str) do
    case Integer.parse(str) do
      {num, ""} -> {:ok, num}
      _ -> {:error, {:invalid_integer, str}}
    end
  end

  defp parse_sequence(hex_str) when is_binary(hex_str) do
    case Integer.parse(hex_str, 16) do
      {num, ""} -> {:ok, num}
      _ -> {:error, {:invalid_hex_sequence, hex_str}}
    end
  end

  defp get_event_type("icp"), do: :icp
  defp get_event_type("rot"), do: :rot
  defp get_event_type("ixn"), do: :ixn
  defp get_event_type("dip"), do: :dip
  defp get_event_type("drt"), do: :drt
  defp get_event_type(_), do: :unknown

  defp has_config_trait?(config_list, trait) when is_list(config_list) do
    trait in config_list
  end

  defp has_config_trait?(_, _), do: false
end
