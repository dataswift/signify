defmodule Signify.KERITest do
  use ExUnit.Case, async: false

  alias Signify.KERI
  alias Signify.KERI.KEL.Log, as: KEL
  alias Signify.KERI.Events.Inception

  setup do
    # Clear ETS tables for clean test state
    # KEL GenServer is already started by Application supervisor
    try do
      :ets.delete_all_objects(:keri_events)
      :ets.delete_all_objects(:keri_sequences)
    rescue
      # Tables might not exist yet
      ArgumentError -> :ok
    end

    :ok
  end

  describe "create_identifier/1" do
    test "creates a new KERI identifier" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer,
          witnesses: [],
          witness_threshold: 0
        })

      assert is_binary(aid.prefix)
      assert String.starts_with?(aid.prefix, "E")
      assert aid.sequence == 0
      assert length(aid.keys) == 1
      assert aid.threshold == 1
      assert aid.witnesses == []
      assert aid.witness_threshold == 0
    end

    test "creates identifier with witnesses" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      witnesses = ["BWitness1", "BWitness2", "BWitness3"]

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer,
          witnesses: witnesses,
          witness_threshold: 2
        })

      assert aid.witnesses == witnesses
      assert aid.witness_threshold == 2
    end

    test "stores inception event in KEL" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer
        })

      {:ok, events} = KERI.get_events(aid.prefix)

      assert length(events) == 1

      [inception] = events
      assert inception.sequence == 0
      assert inception.event["t"] == "icp"
      assert inception.event["i"] == aid.prefix
      assert length(inception.signatures) == 1
    end
  end

  describe "get_key_state/1" do
    test "retrieves current key state" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer
        })

      {:ok, key_state} = KERI.get_key_state(aid.prefix)

      assert key_state.prefix == aid.prefix
      assert key_state.sequence == 0
      assert key_state.keys == aid.keys
      assert key_state.threshold == aid.threshold
      assert key_state.last_event_type == :icp
    end

    test "returns error for non-existent identifier" do
      assert {:error, :no_events} = KERI.get_key_state("EnonexistentPrefix")
    end
  end

  describe "verify_identifier/1" do
    test "validates a valid identifier chain" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer
        })

      assert {:ok, :valid} = KERI.verify_identifier(aid.prefix)
    end
  end

  describe "identifier_exists?/1" do
    test "returns true for existing identifier" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer
        })

      assert KERI.identifier_exists?(aid.prefix)
    end

    test "returns false for non-existent identifier" do
      refute KERI.identifier_exists?("EnonexistentPrefix")
    end
  end

  describe "sign_event/2 and verify_event_signature/3" do
    test "signs and verifies an event" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, inception_event} = Inception.from_signer(signer, next_signer)

      {:ok, signature} = KERI.sign_event(inception_event, signer)

      assert is_binary(signature)
      assert byte_size(signature) == 64

      {:ok, verfer} = Signify.Signer.verfer(signer)
      {:ok, valid?} = KERI.verify_event_signature(inception_event, signature, verfer)

      assert valid?
    end

    test "rejects invalid signature" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, other_signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, inception_event} = Inception.from_signer(signer, next_signer)

      # Sign with different key
      {:ok, wrong_signature} = KERI.sign_event(inception_event, other_signer)

      {:ok, verfer} = Signify.Signer.verfer(signer)
      {:ok, valid?} = KERI.verify_event_signature(inception_event, wrong_signature, verfer)

      refute valid?
    end
  end

  describe "export_identifier/1 and import_identifier/1" do
    test "exports and imports an identifier" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer
        })

      # Export
      {:ok, export} = KERI.export_identifier(aid.prefix)

      assert export["version"] == "1.0"
      assert export["prefix"] == aid.prefix
      assert is_list(export["events"])
      assert length(export["events"]) == 1

      # Clear the KEL
      KEL.clear_prefix(aid.prefix)

      # Import
      {:ok, imported_prefix} = KERI.import_identifier(export)

      assert imported_prefix == aid.prefix

      # Verify imported identifier
      {:ok, key_state} = KERI.get_key_state(imported_prefix)
      assert key_state.prefix == aid.prefix
      assert key_state.sequence == 0
      assert {:ok, :valid} = KERI.verify_identifier(imported_prefix)
    end
  end

  describe "stats/0" do
    test "returns KEL statistics" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, _aid1} =
        KERI.create_identifier(%{
          signer: signer,
          next_signer: next_signer
        })

      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, next_signer2} = Signify.Signer.new_random(true)

      {:ok, _aid2} =
        KERI.create_identifier(%{
          signer: signer2,
          next_signer: next_signer2
        })

      stats = KERI.stats()

      assert stats.total_prefixes >= 2
      assert stats.total_events >= 2
      assert is_number(stats.memory_bytes)
      assert is_number(stats.memory_mb)
    end
  end

  describe "validate_event/1" do
    test "validates a correct inception event" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, inception_event} = Inception.from_signer(signer, next_signer)

      assert :ok = KERI.validate_event(inception_event)
    end

    test "rejects invalid event structure" do
      assert {:error, :invalid_event_structure} = KERI.validate_event(%{})
    end

    test "rejects unsupported event type" do
      assert {:error, {:unsupported_event_type, "xyz"}} = KERI.validate_event(%{"t" => "xyz"})
    end
  end

  describe "digest/1" do
    test "computes BLAKE3-256 digest" do
      {:ok, digest} = KERI.digest("test data")

      assert is_binary(digest)
      # BLAKE3_256 code
      assert String.starts_with?(digest, "E")
    end

    test "produces consistent digests" do
      data = "consistent test data"

      {:ok, digest1} = KERI.digest(data)
      {:ok, digest2} = KERI.digest(data)

      assert digest1 == digest2
    end

    test "produces different digests for different data" do
      {:ok, digest1} = KERI.digest("data1")
      {:ok, digest2} = KERI.digest("data2")

      assert digest1 != digest2
    end
  end
end
