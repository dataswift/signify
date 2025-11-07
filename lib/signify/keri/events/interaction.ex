defmodule Signify.KERI.Events.Interaction do
  @moduledoc """
  KERI Interaction Event (ixn).

  An interaction event is a non-establishment event that anchors data
  without changing the key state. It cannot rotate keys or modify witnesses.

  ## Purpose

  Interaction events are used to:
  - Anchor external data (credentials, receipts, etc.)
  - Prove liveness of an identifier
  - Create a new event in the KEL without changing keys
  - Timestamp operations

  ## Fields

  - `v` - Version string (KERI10JSON...)
  - `t` - Event type ("ixn")
  - `d` - SAID (Self-Addressing IDentifier)
  - `i` - Identifier prefix
  - `s` - Sequence number
  - `p` - Prior event digest
  - `a` - Anchors (seals to other events/data)

  ## Example

      iex> params = %{
      ...>   identifier: "E5ZFan8CLQWBPuultTZTKERYCxIL9hc9WIckkIfh9rYE",
      ...>   sequence: 2,
      ...>   prior_digest: "E...",
      ...>   anchors: [
      ...>     %{"i" => "credential_said", "s" => "0", "d" => "E..."}
      ...>   ]
      ...> }
      iex> {:ok, interaction} = Interaction.new(params)
      iex> interaction["t"]
      "ixn"
  """

  alias Signify.KERI.Events.Event

  @behaviour Event

  @type t :: %{
          String.t() => term()
        }

  @required_fields ["v", "t", "d", "i", "s", "p", "a"]

  @doc """
  Creates a new interaction event from parameters.

  ## Parameters

  - `identifier` - The identifier creating the interaction
  - `sequence` - Sequence number (must be > 0)
  - `prior_digest` - Digest of prior event
  - `anchors` - List of event seals/anchors (default: [])

  ## Returns

  - `{:ok, interaction_event}` - Successfully created interaction event with SAID
  - `{:error, reason}` - Failed to create interaction event
  """
  @impl Event
  @spec new(map()) :: {:ok, t()} | {:error, term()}
  def new(params) do
    with :ok <- validate_params(params),
         {:ok, event} <- build_event(params),
         {:ok, event_with_said} <- Event.make_said_event(event) do
      {:ok, event_with_said}
    end
  end

  @doc """
  Creates an interaction event from current key state.

  This is a convenience function that takes the current key state
  and generates an interaction event.

  ## Parameters

  - `key_state` - Current KeyState struct
  - `anchors` - List of anchors/seals (default: [])
  """
  @spec from_key_state(Signify.KERI.State.KeyState.t(), list()) ::
          {:ok, t()} | {:error, term()}
  def from_key_state(key_state, anchors \\ []) do
    params = %{
      identifier: key_state.prefix,
      sequence: key_state.sequence + 1,
      prior_digest: key_state.digest,
      anchors: anchors
    }

    new(params)
  end

  @impl Event
  def event_type, do: :ixn

  @impl Event
  def validate(event) when is_map(event) do
    with :ok <- Event.validate_structure(event, @required_fields),
         :ok <- validate_event_type(event),
         :ok <- validate_sequence(event),
         :ok <- validate_anchors(event) do
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
    required = [:identifier, :sequence, :prior_digest]
    missing = Enum.reject(required, &Map.has_key?(params, &1))

    case missing do
      [] -> :ok
      fields -> {:error, {:missing_params, fields}}
    end
  end

  defp build_event(params) do
    event = %{
      "v" => Event.version_string(:json, 0),
      "t" => "ixn",
      "d" => "",
      "i" => params[:identifier],
      "s" => Integer.to_string(params[:sequence], 16) |> String.downcase(),
      "p" => params[:prior_digest],
      "a" => params[:anchors] || []
    }

    {:ok, event}
  end

  defp validate_event_type(%{"t" => "ixn"}), do: :ok
  defp validate_event_type(%{"t" => other}), do: {:error, {:invalid_type, other}}
  defp validate_event_type(_), do: {:error, :missing_type}

  defp validate_sequence(%{"s" => s}) when is_binary(s) do
    case Integer.parse(s, 16) do
      {seq, ""} when seq > 0 -> :ok
      {0, ""} -> {:error, :interaction_requires_nonzero_sequence}
      _ -> {:error, {:invalid_sequence, s}}
    end
  end

  defp validate_sequence(_), do: {:error, :missing_sequence}

  defp validate_anchors(%{"a" => anchors}) when is_list(anchors), do: :ok
  defp validate_anchors(_), do: {:error, :invalid_anchors}
end
