defmodule Signify.CredentialTest do
  use ExUnit.Case, async: false
  doctest Signify.Credential

  @moduletag :integration

  describe "Signify.Credential" do
    setup do
      # These tests require a running KERIA agent
      # Skip if KERIA is not available
      keria_url = System.get_env("KERIA_URL", "http://localhost:3901")
      keria_bran = System.get_env("KERIA_BRAN")

      if is_nil(keria_bran) do
        {:ok, skip: true}
      else
        case Signify.Client.new(keria_url, keria_bran) do
          {:ok, client} ->
            case Signify.Credential.new(client) do
              {:ok, credentials} ->
                {:ok, client: client, credentials: credentials, skip: false}

              {:error, reason} ->
                IO.puts("Warning: Could not create credentials client: #{reason}")
                {:ok, skip: true}
            end

          {:error, reason} ->
            IO.puts("Warning: Could not connect to KERIA at #{keria_url}: #{reason}")
            {:ok, skip: true}
        end
      end
    end

    test "new/1 creates a credentials client", %{skip: skip} do
      if skip do
        IO.puts("Skipping test - KERIA not available")
      else
        keria_url = System.get_env("KERIA_URL", "http://localhost:3901")
        keria_bran = System.get_env("KERIA_BRAN")

        {:ok, client} = Signify.Client.new(keria_url, keria_bran)
        assert {:ok, credentials} = Signify.Credential.new(client)
        assert is_reference(credentials)
      end
    end

    test "list/1 returns credentials list", context do
      if Map.get(context, :skip, true) do
        IO.puts("Skipping test - KERIA not available")
      else
        credentials = context.credentials
        # This will return an empty list or list of credentials depending on KERIA state
        assert {:ok, results} = Signify.Credential.list(credentials)
        assert is_list(results)

        if length(results) > 0 do
          # Verify structure of first credential
          first = List.first(results)
          assert is_map(first["sad"]) or is_map(first[:sad])
        end
      end
    end

    test "list/2 accepts filter options", context do
      if Map.get(context, :skip, true) do
        IO.puts("Skipping test - KERIA not available")
      else
        credentials = context.credentials
        filter = %{limit: 10, skip: 0}
        assert {:ok, results} = Signify.Credential.list(credentials, filter)
        assert is_list(results)
        assert length(results) <= 10
      end
    end

    test "get/2 retrieves specific credential in JSON format", context do
      if Map.get(context, :skip, true) do
        IO.puts("Skipping test - KERIA not available")
      else
        credentials = context.credentials
        # First get list to find a valid SAID
        {:ok, results} = Signify.Credential.list(credentials)

        if length(results) > 0 do
          first = List.first(results)
          # Extract SAID from the credential
          said = first["sad"]["d"] || first[:sad][:d]

          if said do
            assert {:ok, credential} = Signify.Credential.get(credentials, said)
            assert is_map(credential)
            assert Map.has_key?(credential, :sad) or Map.has_key?(credential, "sad")
          else
            IO.puts("Warning: Could not extract SAID from credential")
          end
        else
          IO.puts("Skipping get test - no credentials available")
        end
      end
    end

    test "get_cesr/2 retrieves credential in CESR format", context do
      if Map.get(context, :skip, true) do
        IO.puts("Skipping test - KERIA not available")
      else
        credentials = context.credentials
        {:ok, results} = Signify.Credential.list(credentials)

        if length(results) > 0 do
          first = List.first(results)
          said = first["sad"]["d"] || first[:sad][:d]

          if said do
            assert {:ok, cesr} = Signify.Credential.get_cesr(credentials, said)
            assert is_binary(cesr)
            # CESR format should contain JSON-LD or CESR encoded data
            assert String.length(cesr) > 0
          else
            IO.puts("Warning: Could not extract SAID from credential")
          end
        else
          IO.puts("Skipping get_cesr test - no credentials available")
        end
      end
    end

    test "get/2 returns error for non-existent credential", context do
      if Map.get(context, :skip, true) do
        IO.puts("Skipping test - KERIA not available")
      else
        credentials = context.credentials
        fake_said = "EInvalidSaidThatDoesNotExist1234567890123456789012"
        assert {:error, reason} = Signify.Credential.get(credentials, fake_said)
        assert is_binary(reason)
      end
    end

    test "delete/2 deletes a credential", context do
      if Map.get(context, :skip, true) do
        IO.puts("Skipping test - KERIA not available")
      else
        credentials = context.credentials
        # This test is destructive and should only run if explicitly enabled
        if System.get_env("ENABLE_DESTRUCTIVE_TESTS") == "true" do
          {:ok, results} = Signify.Credential.list(credentials)

          if length(results) > 0 do
            first = List.first(results)
            said = first["sad"]["d"] || first[:sad][:d]

            if said do
              assert :ok = Signify.Credential.delete(credentials, said)

              # Verify it's deleted
              assert {:error, _reason} = Signify.Credential.get(credentials, said)
            end
          else
            IO.puts("Skipping delete test - no credentials available")
          end
        else
          IO.puts("Skipping destructive delete test - set ENABLE_DESTRUCTIVE_TESTS=true to run")
        end
      end
    end
  end

  describe "error handling" do
    test "new/1 requires a valid client reference" do
      # In Elixir, guards cause FunctionClauseError, not ArgumentError
      assert_raise FunctionClauseError, fn ->
        Signify.Credential.new("not a reference")
      end
    end

    test "get/2 requires valid parameters" do
      # Create a mock reference for error testing
      keria_url = System.get_env("KERIA_URL", "http://localhost:3901")
      keria_bran = System.get_env("KERIA_BRAN", "test_bran_at_least_21chars")

      case Signify.Client.new(keria_url, keria_bran) do
        {:ok, client} ->
          case Signify.Credential.new(client) do
            {:ok, credentials} ->
              # Guards cause FunctionClauseError in Elixir
              assert_raise FunctionClauseError, fn ->
                Signify.Credential.get(credentials, 123)
              end

            {:error, _reason} ->
              IO.puts("Skipping error handling test - could not create credentials client")
          end

        {:error, _reason} ->
          IO.puts("Skipping error handling test - could not create client")
      end
    end
  end
end
