defmodule Signify.CESRTest do
  use ExUnit.Case, async: true

  alias Signify.{CESR, Verfer}

  describe "load_keys_from_file/1" do
    test "loads keys from valid CESR credential file" do
      # Use the credential.cesr file in the project root
      file_path = Path.join([File.cwd!(), "credential.cesr"])

      assert {:ok, result} = CESR.load_keys_from_file(file_path)
      assert is_reference(result.verfer)
      assert is_binary(result.identifier)
      assert is_binary(result.did)
      assert String.starts_with?(result.did, "did:keri:")
      assert String.contains?(result.did, result.identifier)

      # Verify we can export the verfer to QB64
      assert {:ok, qb64} = Verfer.to_qb64(result.verfer)
      assert is_binary(qb64)
      assert String.length(qb64) > 0
    end

    test "returns error for non-existent file" do
      assert {:error, error} = CESR.load_keys_from_file("/nonexistent/file.cesr")
      assert error =~ "File not found"
    end

    test "returns error for empty file" do
      # Create a temporary empty file
      tmp_path = Path.join([System.tmp_dir!(), "empty.cesr"])
      File.write!(tmp_path, "")

      assert {:error, error} = CESR.load_keys_from_file(tmp_path)
      assert is_binary(error)

      # Cleanup
      File.rm(tmp_path)
    end

    test "returns error for invalid CESR data" do
      # Create a temporary file with invalid data
      tmp_path = Path.join([System.tmp_dir!(), "invalid.cesr"])
      File.write!(tmp_path, "not a valid CESR file")

      assert {:error, error} = CESR.load_keys_from_file(tmp_path)
      assert is_binary(error)

      # Cleanup
      File.rm(tmp_path)
    end
  end

  describe "parse/1" do
    test "parses CESR data from string" do
      # Read the credential file
      file_path = Path.join([File.cwd!(), "credential.cesr"])
      cesr_data = File.read!(file_path)

      assert {:ok, result} = CESR.parse(cesr_data)
      assert is_reference(result.verfer)
      assert is_binary(result.identifier)
      assert is_binary(result.did)
      assert String.starts_with?(result.did, "did:keri:")

      # Verify we can export the verfer to QB64
      assert {:ok, qb64} = Verfer.to_qb64(result.verfer)
      assert is_binary(qb64)
    end

    test "returns error for empty string" do
      assert {:error, error} = CESR.parse("")
      assert is_binary(error)
    end

    test "returns error for invalid CESR string" do
      assert {:error, error} = CESR.parse("not valid CESR")
      assert is_binary(error)
    end

    test "load_keys_from_file and parse return same result" do
      file_path = Path.join([File.cwd!(), "credential.cesr"])

      {:ok, result1} = CESR.load_keys_from_file(file_path)

      cesr_data = File.read!(file_path)
      {:ok, result2} = CESR.parse(cesr_data)

      # Both should have the same identifier and DID
      assert result1.identifier == result2.identifier
      assert result1.did == result2.did

      # Both verfers should export to the same QB64
      {:ok, qb64_1} = Verfer.to_qb64(result1.verfer)
      {:ok, qb64_2} = Verfer.to_qb64(result2.verfer)
      assert qb64_1 == qb64_2
    end
  end
end
