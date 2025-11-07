defmodule Signify.KERI.Events.Event do
  @moduledoc """
  Base event behavior and common functionality for KERI events.

  All KERI events must implement this behavior to ensure consistent
  serialization, validation, and processing.
  """

  @type event_type :: :icp | :rot | :ixn | :dip | :drt | :rct | :vrc

  @type t :: %{
          # Version string
          required(:v) => String.t(),
          # Event type
          required(:t) => String.t(),
          # Event digest (SAID)
          required(:d) => String.t(),
          # Identifier prefix
          required(:i) => String.t(),
          # Sequence number (hex)
          required(:s) => String.t(),
          # Prior event digest
          optional(:p) => String.t(),
          optional(atom()) => any()
        }

  @doc """
  Creates a new event of the specified type with the given fields.
  """
  @callback new(fields :: map()) :: {:ok, t()} | {:error, term()}

  @doc """
  Validates the event structure and content.
  """
  @callback validate(event :: t()) :: :ok | {:error, term()}

  @doc """
  Serializes the event to JSON for signing.
  """
  @callback serialize(event :: t()) :: {:ok, String.t()} | {:error, term()}

  @doc """
  Computes the SAID (Self-Addressing IDentifier) for the event.
  """
  @callback compute_said(event :: t()) :: {:ok, String.t()} | {:error, term()}

  @doc """
  Returns the event type.
  """
  @callback event_type() :: event_type()

  ## Common Functions

  @doc """
  Creates a version string for KERI events.

  Format: KERI{major}{minor}{kind}{size}
  Example: KERI10JSON000160_
  """
  @spec version_string(kind :: :json | :cbor | :mgpk, size :: non_neg_integer()) :: String.t()
  def version_string(kind \\ :json, size \\ 0) do
    kind_str = kind |> Atom.to_string() |> String.upcase()
    size_str = size |> Integer.to_string() |> String.pad_leading(6, "0")
    "KERI10#{kind_str}#{size_str}_"
  end

  @doc """
  Serializes an event to JSON in KERI canonical format.

  KERI uses a specific JSON serialization:
  - No whitespace
  - Specific key ordering
  - UTF-8 encoding
  """
  @spec serialize_json(event :: map()) :: {:ok, String.t()} | {:error, term()}
  def serialize_json(event) do
    # Remove the digest field for serialization (it's computed after)
    event_without_said = Map.delete(event, "d")

    # Serialize with specific key ordering for KERI
    json = Jason.encode!(event_without_said, pretty: false)
    {:ok, json}
  rescue
    e -> {:error, {:serialization_error, Exception.message(e)}}
  end

  @doc """
  Computes BLAKE3-256 digest of serialized event.
  """
  @spec compute_digest(serialized :: String.t()) :: {:ok, String.t()} | {:error, term()}
  def compute_digest(serialized) when is_binary(serialized) do
    # Use Rust NIF to compute BLAKE3-256 digest with CESR encoding
    # Rustler unwraps Result<T, E> - Ok(value) returns value, Err raises exception
    try do
      qb64 = Signify.Native.blake3_digest(serialized)
      {:ok, qb64}
    rescue
      e -> {:error, {:digest_failed, Exception.message(e)}}
    end
  end

  @doc """
  Validates event structure has required fields.
  """
  @spec validate_structure(event :: map(), required_fields :: [String.t()]) ::
          :ok | {:error, term()}
  def validate_structure(event, required_fields) do
    missing_fields = Enum.reject(required_fields, fn field -> Map.has_key?(event, field) end)

    case missing_fields do
      [] -> :ok
      fields -> {:error, {:missing_fields, fields}}
    end
  end

  @doc """
  Validates sequence number format (hex string).
  """
  @spec validate_sequence(sequence :: String.t()) :: :ok | {:error, term()}
  def validate_sequence(sequence) when is_binary(sequence) do
    case Integer.parse(sequence, 16) do
      {_num, ""} -> :ok
      _ -> {:error, {:invalid_sequence, sequence}}
    end
  end

  @doc """
  Converts integer sequence to hex string.
  """
  @spec sequence_to_hex(sequence :: non_neg_integer()) :: String.t()
  def sequence_to_hex(sequence) when is_integer(sequence) and sequence >= 0 do
    Integer.to_string(sequence, 16) |> String.downcase()
  end

  @doc """
  Parses hex sequence string to integer.
  """
  @spec parse_sequence(hex :: String.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def parse_sequence(hex) when is_binary(hex) do
    case Integer.parse(hex, 16) do
      {num, ""} -> {:ok, num}
      _ -> {:error, {:invalid_hex_sequence, hex}}
    end
  end

  @doc """
  Validates version string format.
  """
  @spec validate_version(version :: String.t()) :: :ok | {:error, term()}
  def validate_version(version) when is_binary(version) do
    if String.starts_with?(version, "KERI") and String.ends_with?(version, "_") do
      :ok
    else
      {:error, {:invalid_version, version}}
    end
  end

  @doc """
  Validates event type.
  """
  @spec validate_event_type(type_str :: String.t()) :: :ok | {:error, term()}
  def validate_event_type(type_str)
      when type_str in ["icp", "rot", "ixn", "dip", "drt", "rct", "vrc"] do
    :ok
  end

  def validate_event_type(type_str) do
    {:error, {:invalid_event_type, type_str}}
  end

  @doc """
  Creates event payload with computed SAID.

  This implements the SAID (Self-Addressing IDentifier) protocol:
  1. Serialize event with empty 'd' field
  2. Compute digest
  3. Insert digest as 'd' field
  4. Re-serialize with digest
  """
  @spec make_said_event(event :: map()) :: {:ok, map()} | {:error, term()}
  def make_said_event(event) do
    with {:ok, serialized} <- serialize_json(Map.put(event, "d", "")),
         {:ok, digest} <- compute_digest(serialized) do
      event_with_said = Map.put(event, "d", digest)
      {:ok, event_with_said}
    end
  end
end
