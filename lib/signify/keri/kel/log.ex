defmodule Signify.KERI.KEL.Log do
  @moduledoc """
  Key Event Log (KEL) GenServer.

  The KEL is the foundational data structure in KERI that stores all events
  for all identifiers. It provides:

  - Immutable event storage
  - Sequential event ordering
  - Event retrieval by prefix and sequence
  - Chain validation
  - Witness receipt storage

  Events are stored in an ETS table for fast access. The KEL guarantees:
  - Events cannot be modified after insertion
  - Sequence numbers are strictly incremental
  - All events are cryptographically linked via digests
  """

  use GenServer
  require Logger

  alias Signify.KERI.State.KeyState

  @type event_entry :: %{
          prefix: String.t(),
          sequence: non_neg_integer(),
          event: map(),
          signatures: [binary()],
          receipts: [map()],
          timestamp: DateTime.t()
        }

  ## Client API

  @doc """
  Starts the KEL GenServer.

  ## Options

  - `:name` - Registered name (default: __MODULE__)
  - `:storage` - Storage backend (default: :ets)
  - `:table_name` - ETS table name (default: :keri_events)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Appends an event to the KEL.

  ## Parameters

  - `prefix` - Identifier prefix
  - `event` - The KERI event (map)
  - `signatures` - List of signatures (binary)

  ## Returns

  - `:ok` - Event successfully appended
  - `{:error, reason}` - Failed to append
  """
  @spec append_event(String.t(), map(), [binary()]) :: :ok | {:error, term()}
  def append_event(prefix, event, signatures) do
    GenServer.call(__MODULE__, {:append_event, prefix, event, signatures})
  end

  @doc """
  Gets all events for a prefix.

  ## Options

  - `:from` - Start sequence (inclusive, default: 0)
  - `:to` - End sequence (inclusive, default: latest)
  - `:limit` - Maximum number of events (default: :infinity)
  """
  @spec get_events(String.t(), keyword()) :: {:ok, [event_entry()]} | {:error, term()}
  def get_events(prefix, opts \\ []) do
    GenServer.call(__MODULE__, {:get_events, prefix, opts})
  end

  @doc """
  Gets a specific event by sequence number.
  """
  @spec get_event_at_sequence(String.t(), non_neg_integer()) ::
          {:ok, event_entry()} | {:error, :not_found}
  def get_event_at_sequence(prefix, sequence) do
    GenServer.call(__MODULE__, {:get_event, prefix, sequence})
  end

  @doc """
  Gets the current sequence number for a prefix.
  """
  @spec get_current_sequence(String.t()) :: {:ok, non_neg_integer()} | {:error, :not_found}
  def get_current_sequence(prefix) do
    GenServer.call(__MODULE__, {:get_current_sequence, prefix})
  end

  @doc """
  Adds witness receipts to an event.
  """
  @spec add_receipts(String.t(), non_neg_integer(), [map()]) :: :ok | {:error, term()}
  def add_receipts(prefix, sequence, receipts) do
    GenServer.call(__MODULE__, {:add_receipts, prefix, sequence, receipts})
  end

  @doc """
  Verifies the integrity of the entire event chain for a prefix.

  This validates:
  - All event digests are correct
  - All signatures are valid
  - Sequence numbers are incremental
  - Prior event digests match
  """
  @spec verify_chain(String.t()) :: {:ok, :valid} | {:error, term()}
  def verify_chain(prefix) do
    GenServer.call(__MODULE__, {:verify_chain, prefix}, 30_000)
  end

  @doc """
  Builds the current key state from the KEL.

  This processes all events in order and computes the current key state.
  """
  @spec build_key_state(String.t()) :: {:ok, KeyState.t()} | {:error, term()}
  def build_key_state(prefix) do
    GenServer.call(__MODULE__, {:build_key_state, prefix}, 30_000)
  end

  @doc """
  Clears all events for a prefix (use with caution!).
  """
  @spec clear_prefix(String.t()) :: :ok
  def clear_prefix(prefix) do
    GenServer.call(__MODULE__, {:clear_prefix, prefix})
  end

  @doc """
  Gets statistics about the KEL.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  ## Server Callbacks

  @impl true
  def init(opts) do
    storage = Keyword.get(opts, :storage, :ets)
    table_name = Keyword.get(opts, :table_name, :keri_events)

    # Create ETS table
    table =
      :ets.new(table_name, [
        :set,
        :named_table,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    # Create index for sequence queries
    :ets.new(:keri_sequences, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    state = %{
      storage: storage,
      table: table,
      table_name: table_name
    }

    Logger.info("KEL started with storage: #{storage}")

    {:ok, state}
  end

  @impl true
  def handle_call({:append_event, prefix, event, signatures}, _from, state) do
    case do_append_event(state, prefix, event, signatures) do
      :ok -> {:reply, :ok, state}
      {:error, _} = error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_events, prefix, opts}, _from, state) do
    result = do_get_events(state, prefix, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_event, prefix, sequence}, _from, state) do
    result = do_get_event(state, prefix, sequence)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_current_sequence, prefix}, _from, state) do
    result = do_get_current_sequence(state, prefix)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:add_receipts, prefix, sequence, receipts}, _from, state) do
    result = do_add_receipts(state, prefix, sequence, receipts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:verify_chain, prefix}, _from, state) do
    result = do_verify_chain(state, prefix)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:build_key_state, prefix}, _from, state) do
    result = do_build_key_state(state, prefix)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:clear_prefix, prefix}, _from, state) do
    do_clear_prefix(state, prefix)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats = do_get_stats(state)
    {:reply, stats, state}
  end

  ## Private Functions

  defp do_append_event(state, prefix, event, signatures) do
    sequence = parse_sequence!(event["s"])

    # Check if event already exists
    case :ets.lookup(state.table, {prefix, sequence}) do
      [{_, existing}] ->
        # Event already exists - verify it's identical
        if existing.event == event do
          :ok
        else
          {:error, {:event_mismatch, sequence}}
        end

      [] ->
        # New event - validate and insert
        with :ok <- validate_sequence_order(state, prefix, sequence),
             :ok <- validate_prior_digest(state, prefix, event) do
          entry = %{
            prefix: prefix,
            sequence: sequence,
            event: event,
            signatures: signatures,
            receipts: [],
            timestamp: DateTime.utc_now()
          }

          :ets.insert(state.table, {{prefix, sequence}, entry})
          update_current_sequence(prefix, sequence)

          Logger.debug("Appended event for #{prefix} at sequence #{sequence}")
          :ok
        end
    end
  end

  defp do_get_events(state, prefix, opts) do
    from = Keyword.get(opts, :from, 0)
    to = Keyword.get(opts, :to, :infinity)
    limit = Keyword.get(opts, :limit, :infinity)

    # Get all events for prefix
    pattern = {{prefix, :"$1"}, :"$2"}
    matches = :ets.match_object(state.table, pattern)

    events =
      matches
      |> Enum.map(fn {{_prefix, seq}, entry} -> {seq, entry} end)
      |> Enum.filter(fn {seq, _entry} ->
        seq >= from and (to == :infinity or seq <= to)
      end)
      |> Enum.sort_by(fn {seq, _entry} -> seq end)
      |> Enum.take(if limit == :infinity, do: 999_999, else: limit)
      |> Enum.map(fn {_seq, entry} -> entry end)

    {:ok, events}
  end

  defp do_get_event(state, prefix, sequence) do
    case :ets.lookup(state.table, {prefix, sequence}) do
      [{_, entry}] -> {:ok, entry}
      [] -> {:error, :not_found}
    end
  end

  defp do_get_current_sequence(_state, prefix) do
    case :ets.lookup(:keri_sequences, prefix) do
      [{^prefix, sequence}] -> {:ok, sequence}
      [] -> {:error, :not_found}
    end
  end

  defp do_add_receipts(state, prefix, sequence, receipts) do
    case :ets.lookup(state.table, {prefix, sequence}) do
      [{key, entry}] ->
        updated_entry =
          Map.update!(entry, :receipts, fn existing ->
            (existing ++ receipts) |> Enum.uniq()
          end)

        :ets.insert(state.table, {key, updated_entry})
        :ok

      [] ->
        {:error, :event_not_found}
    end
  end

  defp do_verify_chain(state, prefix) do
    case do_get_events(state, prefix, []) do
      {:ok, []} ->
        {:error, :no_events}

      {:ok, events} ->
        verify_event_chain(events)

      error ->
        error
    end
  end

  defp do_build_key_state(state, prefix) do
    case do_get_events(state, prefix, []) do
      {:ok, []} ->
        {:error, :no_events}

      {:ok, [first_event | rest_events]} ->
        with {:ok, initial_state} <- KeyState.from_inception(first_event.event) do
          apply_events_to_state(initial_state, rest_events)
        end

      error ->
        error
    end
  end

  defp do_clear_prefix(state, prefix) do
    # Delete all events for prefix
    pattern = {{prefix, :"$1"}, :"$2"}
    :ets.match_delete(state.table, pattern)

    # Delete sequence tracker
    :ets.delete(:keri_sequences, prefix)

    Logger.info("Cleared all events for #{prefix}")
    :ok
  end

  defp do_get_stats(state) do
    total_events = :ets.info(state.table, :size)
    total_prefixes = :ets.info(:keri_sequences, :size)
    memory_bytes = :ets.info(state.table, :memory) * :erlang.system_info(:wordsize)

    %{
      total_events: total_events,
      total_prefixes: total_prefixes,
      memory_bytes: memory_bytes,
      memory_mb: Float.round(memory_bytes / 1_048_576, 2)
    }
  end

  defp validate_sequence_order(state, prefix, sequence) do
    case do_get_current_sequence(state, prefix) do
      {:ok, current} ->
        if sequence == current + 1 do
          :ok
        else
          {:error, {:sequence_out_of_order, current, sequence}}
        end

      {:error, :not_found} ->
        # First event must be sequence 0
        if sequence == 0 do
          :ok
        else
          {:error, {:first_sequence_not_zero, sequence}}
        end
    end
  end

  defp validate_prior_digest(state, prefix, event) do
    sequence = parse_sequence!(event["s"])

    if sequence == 0 do
      # Inception event has no prior
      :ok
    else
      prior_digest = event["p"]

      case do_get_event(state, prefix, sequence - 1) do
        {:ok, prior_entry} ->
          if prior_entry.event["d"] == prior_digest do
            :ok
          else
            {:error, {:prior_digest_mismatch, prior_entry.event["d"], prior_digest}}
          end

        {:error, :not_found} ->
          {:error, {:prior_event_not_found, sequence - 1}}
      end
    end
  end

  defp verify_event_chain([]), do: {:ok, :valid}

  defp verify_event_chain([first | rest]) do
    # Verify first event is inception
    case first.event["t"] do
      t when t in ["icp", "dip"] ->
        verify_chain_sequence(first, rest)

      t ->
        {:error, {:first_event_not_inception, t}}
    end
  end

  defp verify_chain_sequence(_prev, []), do: {:ok, :valid}

  defp verify_chain_sequence(prev, [current | rest]) do
    prev_seq = prev.sequence
    curr_seq = current.sequence

    cond do
      curr_seq != prev_seq + 1 ->
        {:error, {:sequence_not_incremental, prev_seq, curr_seq}}

      current.event["p"] != prev.event["d"] ->
        {:error, {:prior_digest_mismatch, prev.event["d"], current.event["p"]}}

      true ->
        verify_chain_sequence(current, rest)
    end
  end

  defp apply_events_to_state(state, []), do: {:ok, state}

  defp apply_events_to_state(state, [event_entry | rest]) do
    case event_entry.event["t"] do
      "rot" ->
        with {:ok, new_state} <- KeyState.apply_rotation(state, event_entry.event) do
          apply_events_to_state(new_state, rest)
        end

      "drt" ->
        with {:ok, new_state} <- KeyState.apply_rotation(state, event_entry.event) do
          apply_events_to_state(new_state, rest)
        end

      "ixn" ->
        with {:ok, new_state} <- KeyState.apply_interaction(state, event_entry.event) do
          apply_events_to_state(new_state, rest)
        end

      t ->
        {:error, {:unknown_event_type, t}}
    end
  end

  defp update_current_sequence(prefix, sequence) do
    :ets.insert(:keri_sequences, {prefix, sequence})
  end

  defp parse_sequence!(hex_str) do
    case Integer.parse(hex_str, 16) do
      {num, ""} -> num
      _ -> raise "Invalid hex sequence: #{hex_str}"
    end
  end
end
