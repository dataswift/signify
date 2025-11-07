defmodule Signify.KERIPhase2Test do
  use ExUnit.Case, async: false

  alias Signify.KERI
  alias Signify.KERI.Events.Rotation
  alias Signify.KERI.Events.Interaction

  setup do
    # Clear ETS tables for clean test state
    try do
      :ets.delete_all_objects(:keri_events)
      :ets.delete_all_objects(:keri_sequences)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  describe "rotate_keys/2" do
    test "rotates keys successfully" do
      # Create initial identifier
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer1,
          next_signer: signer2
        })

      # Rotate keys
      {:ok, key_state} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3
        })

      assert key_state.sequence == 1
      assert key_state.last_event_type == :rot
      assert length(key_state.keys) == 1
      assert length(key_state.next_keys_digest) == 1
    end

    test "rotation increments sequence number" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})

      {:ok, key_state_before} = KERI.get_key_state(aid.prefix)
      assert key_state_before.sequence == 0

      {:ok, key_state_after} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3
        })

      assert key_state_after.sequence == 1
    end

    test "rotation updates keys" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})

      {:ok, verfer2} = Signify.Signer.verfer(signer2)
      {:ok, key2_qb64} = Signify.Verfer.to_qb64(verfer2)

      {:ok, key_state} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3
        })

      assert key2_qb64 in key_state.keys
    end

    test "multiple rotations work correctly" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)
      {:ok, signer4} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})

      # First rotation
      {:ok, key_state1} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3
        })

      assert key_state1.sequence == 1

      # Second rotation
      {:ok, key_state2} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer2,
          new_signer: signer3,
          next_signer: signer4
        })

      assert key_state2.sequence == 2
      assert key_state2.last_event_type == :rot
    end

    test "rotation with witness changes" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)

      {:ok, aid} =
        KERI.create_identifier(%{
          signer: signer1,
          next_signer: signer2,
          witnesses: ["witness1", "witness2"],
          witness_threshold: 2
        })

      {:ok, key_state} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3,
          witness_cuts: ["witness1"],
          witness_adds: ["witness3"]
        })

      assert key_state.witnesses == ["witness2", "witness3"]
    end
  end

  describe "create_interaction/2" do
    test "creates interaction event successfully" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer, next_signer: next_signer})

      {:ok, key_state} = KERI.create_interaction(aid.prefix, %{signer: signer})

      assert key_state.sequence == 1
      assert key_state.last_event_type == :ixn
    end

    test "interaction increments sequence number" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer, next_signer: next_signer})

      {:ok, key_state_before} = KERI.get_key_state(aid.prefix)
      assert key_state_before.sequence == 0

      {:ok, key_state_after} = KERI.create_interaction(aid.prefix, %{signer: signer})

      assert key_state_after.sequence == 1
    end

    test "interaction does not change keys" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer, next_signer: next_signer})

      {:ok, key_state_before} = KERI.get_key_state(aid.prefix)
      keys_before = key_state_before.keys

      {:ok, key_state_after} = KERI.create_interaction(aid.prefix, %{signer: signer})

      assert key_state_after.keys == keys_before
    end

    test "interaction with anchors" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer, next_signer: next_signer})

      anchors = [
        %{"i" => "credential1", "s" => "0", "d" => "EabcDEF123"}
      ]

      {:ok, key_state} = KERI.create_interaction(aid.prefix, %{signer: signer, anchors: anchors})

      assert key_state.sequence == 1
      assert key_state.last_event_type == :ixn
    end

    test "multiple interactions work correctly" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer, next_signer: next_signer})

      # First interaction
      {:ok, key_state1} = KERI.create_interaction(aid.prefix, %{signer: signer})
      assert key_state1.sequence == 1

      # Second interaction
      {:ok, key_state2} = KERI.create_interaction(aid.prefix, %{signer: signer})
      assert key_state2.sequence == 2

      # Third interaction
      {:ok, key_state3} = KERI.create_interaction(aid.prefix, %{signer: signer})
      assert key_state3.sequence == 3
    end
  end

  describe "mixed rotation and interaction" do
    test "rotation then interaction" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})

      # Rotate
      {:ok, key_state1} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3
        })

      assert key_state1.sequence == 1
      assert key_state1.last_event_type == :rot

      # Interact
      {:ok, key_state2} = KERI.create_interaction(aid.prefix, %{signer: signer2})

      assert key_state2.sequence == 2
      assert key_state2.last_event_type == :ixn
    end

    test "interaction then rotation" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})

      # Interact
      {:ok, key_state1} = KERI.create_interaction(aid.prefix, %{signer: signer1})

      assert key_state1.sequence == 1
      assert key_state1.last_event_type == :ixn

      # Rotate
      {:ok, key_state2} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3
        })

      assert key_state2.sequence == 2
      assert key_state2.last_event_type == :rot
    end

    test "complex event sequence" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)
      {:ok, signer4} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})
      assert aid.sequence == 0

      # seq 1: interaction
      {:ok, ks1} = KERI.create_interaction(aid.prefix, %{signer: signer1})
      assert ks1.sequence == 1

      # seq 2: interaction
      {:ok, ks2} = KERI.create_interaction(aid.prefix, %{signer: signer1})
      assert ks2.sequence == 2

      # seq 3: rotation
      {:ok, ks3} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer1,
          new_signer: signer2,
          next_signer: signer3
        })

      assert ks3.sequence == 3

      # seq 4: interaction
      {:ok, ks4} = KERI.create_interaction(aid.prefix, %{signer: signer2})
      assert ks4.sequence == 4

      # seq 5: rotation
      {:ok, ks5} =
        KERI.rotate_keys(aid.prefix, %{
          current_signer: signer2,
          new_signer: signer3,
          next_signer: signer4
        })

      assert ks5.sequence == 5
    end
  end

  describe "Rotation event validation" do
    test "validates correct rotation event" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})

      {:ok, key_state} = KERI.get_key_state(aid.prefix)

      {:ok, verfer2} = Signify.Signer.verfer(signer2)
      {:ok, key2} = Signify.Verfer.to_qb64(verfer2)

      {:ok, rotation} =
        Rotation.from_key_state(
          key_state,
          [key2],
          ["next_key"],
          []
        )

      assert :ok = Rotation.validate(rotation)
    end

    test "rejects rotation with invalid type" do
      rotation = %{
        "v" => "KERI10JSON000160_",
        "t" => "wrong",
        "d" => "E123",
        "i" => "E123",
        "s" => "1",
        "p" => "E123",
        "kt" => "1",
        "k" => ["D123"],
        "nt" => "1",
        "n" => ["E123"],
        "bt" => "0",
        "br" => [],
        "ba" => [],
        "a" => []
      }

      assert {:error, {:invalid_type, "wrong"}} = Rotation.validate(rotation)
    end

    test "rejects rotation with sequence 0" do
      rotation = %{
        "v" => "KERI10JSON000160_",
        "t" => "rot",
        "d" => "E123",
        "i" => "E123",
        "s" => "0",
        "p" => "E123",
        "kt" => "1",
        "k" => ["D123"],
        "nt" => "1",
        "n" => ["E123"],
        "bt" => "0",
        "br" => [],
        "ba" => [],
        "a" => []
      }

      assert {:error, :rotation_requires_nonzero_sequence} = Rotation.validate(rotation)
    end
  end

  describe "Interaction event validation" do
    test "validates correct interaction event" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer, next_signer: next_signer})

      {:ok, key_state} = KERI.get_key_state(aid.prefix)

      {:ok, interaction} = Interaction.from_key_state(key_state, [])

      assert :ok = Interaction.validate(interaction)
    end

    test "rejects interaction with invalid type" do
      interaction = %{
        "v" => "KERI10JSON000120_",
        "t" => "wrong",
        "d" => "E123",
        "i" => "E123",
        "s" => "1",
        "p" => "E123",
        "a" => []
      }

      assert {:error, {:invalid_type, "wrong"}} = Interaction.validate(interaction)
    end

    test "rejects interaction with sequence 0" do
      interaction = %{
        "v" => "KERI10JSON000120_",
        "t" => "ixn",
        "d" => "E123",
        "i" => "E123",
        "s" => "0",
        "p" => "E123",
        "a" => []
      }

      assert {:error, :interaction_requires_nonzero_sequence} = Interaction.validate(interaction)
    end
  end

  describe "validate_event/1 for Phase 2" do
    test "validates rotation events" do
      {:ok, signer1} = Signify.Signer.new_random(true)
      {:ok, signer2} = Signify.Signer.new_random(true)
      {:ok, signer3} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer1, next_signer: signer2})

      {:ok, key_state} = KERI.get_key_state(aid.prefix)

      {:ok, verfer2} = Signify.Signer.verfer(signer2)
      {:ok, key2} = Signify.Verfer.to_qb64(verfer2)

      {:ok, verfer3} = Signify.Signer.verfer(signer3)
      {:ok, key3} = Signify.Verfer.to_qb64(verfer3)

      {:ok, rotation} = Rotation.from_key_state(key_state, [key2], [key3], [])

      assert :ok = KERI.validate_event(rotation)
    end

    test "validates interaction events" do
      {:ok, signer} = Signify.Signer.new_random(true)
      {:ok, next_signer} = Signify.Signer.new_random(true)

      {:ok, aid} = KERI.create_identifier(%{signer: signer, next_signer: next_signer})

      {:ok, key_state} = KERI.get_key_state(aid.prefix)

      {:ok, interaction} = Interaction.from_key_state(key_state, [])

      assert :ok = KERI.validate_event(interaction)
    end
  end
end
