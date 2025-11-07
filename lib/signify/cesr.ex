defmodule Signify.CESR do
  @moduledoc """
  CESR (Composable Event Streaming Representation) file parsing utilities.

  This module provides functions for loading KERI credentials and events
  from CESR-encoded files.

  ## Examples

      # Load keys from a CESR credential file
      {:ok, result} = Signify.CESR.load_keys_from_file("credential.cesr")

      # Access the public key verifier
      {:ok, valid} = Signify.Verfer.verify(result.verfer, signature, message)

      # Access the KERI identifier
      IO.puts("DID: \#{result.did}")
      IO.puts("Identifier: \#{result.identifier}")
  """

  alias Signify.{Native, Verfer}

  @type load_result :: %{
          public_key: binary(),
          identifier: String.t(),
          did: String.t()
        }

  @doc """
  Loads public key and identifier from a CESR/KERI credential file.

  Parses a KERI event stream file and extracts the public key from the
  inception event (icp or dip). The public key is returned as raw bytes.

  **Note:** CESR files only contain public keys, not private keys. For
  signing operations, you need to use `Signify.Signer.new()` or load
  keys from a secure keystore.

  **Implementation:** Uses signify_rs with cesride library for
  better CESR compatibility.

  ## Parameters

    * `file_path` - Path to the CESR credential file

  ## Returns

    * `{:ok, result}` - A map containing:
      * `:public_key` - The 32-byte Ed25519 public key
      * `:identifier` - The KERI identifier (AID)
      * `:did` - The DID representation (did:keri:<identifier>)
    * `{:error, reason}` - If the file cannot be read or parsed

  ## Examples

      # Load from file
      {:ok, %{public_key: pub_key, identifier: id, did: did}} =
        Signify.CESR.load_keys_from_file("credential.cesr")

      # You can create a Verfer from the public key if needed
      # (requires implementing Verfer.from_raw_bytes first)

      # Use the identifier
      IO.puts("KERI ID: \#{id}")
      IO.puts("DID: \#{did}")
      IO.puts("Public key: \#{Base.encode16(pub_key)}")
  """
  @spec load_keys_from_file(String.t()) :: {:ok, load_result()} | {:error, term()}
  def load_keys_from_file(file_path) when is_binary(file_path) do
    with {:ok, cesr_data} <- File.read(file_path),
         {:ok, {public_key, identifier}} <- parse_cesr_nif(cesr_data) do
      {:ok,
       %{
         public_key: public_key,
         identifier: identifier,
         did: "did:keri:#{identifier}"
       }}
    else
      {:error, :enoent} ->
        {:error, "File not found: #{file_path}"}

      {:error, :eacces} ->
        {:error, "Permission denied: #{file_path}"}

      {:error, reason} when is_binary(reason) ->
        {:error, reason}

      {:error, reason} ->
        {:error, "Failed to load keys: #{inspect(reason)}"}
    end
  end

  # Helper to call the NIF and handle errors
  # Now uses signify_rs with cesride for better CESR compatibility
  # Returns {verfer_resource, identifier} from NIF
  defp parse_cesr_nif(cesr_data) do
    case Native.parse_cesr_file(cesr_data) do
      {verfer_resource, identifier} when is_reference(verfer_resource) ->
        # Get QB64 public key from verfer
        case Verfer.to_qb64(verfer_resource) do
          {:ok, qb64} ->
            # Decode QB64 to get raw public key bytes
            # QB64 format: first char is code, rest is base64
            case Base.url_decode64(String.slice(qb64, 1..-1//1), padding: false) do
              {:ok, pub_key} ->
                {:ok, {pub_key, identifier}}

              _ ->
                {:error, "Failed to decode QB64 public key"}
            end

          {:error, reason} ->
            {:error, "Failed to get QB64: #{inspect(reason)}"}
        end

      {:error, reason} ->
        {:error, to_string(reason)}

      other ->
        {:error, "Unexpected NIF return: #{inspect(other)}"}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  @doc """
  Parses CESR data from a string.

  Similar to `load_keys_from_file/1` but takes the CESR data directly
  as a string instead of reading from a file.

  ## Parameters

    * `cesr_data` - The CESR/KERI event stream data as a string

  ## Returns

    * `{:ok, result}` - A map containing public_key, identifier, and did
    * `{:error, reason}` - If parsing fails

  ## Examples

      cesr_data = File.read!("credential.cesr")
      {:ok, %{public_key: pub_key, identifier: id, did: did}} = Signify.CESR.parse(cesr_data)
  """
  @spec parse(String.t()) :: {:ok, load_result()} | {:error, term()}
  def parse(cesr_data) when is_binary(cesr_data) do
    with {:ok, {public_key, identifier}} <- parse_cesr_nif(cesr_data) do
      {:ok,
       %{
         public_key: public_key,
         identifier: identifier,
         did: "did:keri:#{identifier}"
       }}
    else
      {:error, reason} when is_binary(reason) ->
        {:error, reason}

      {:error, reason} ->
        {:error, "Failed to parse CESR data: #{inspect(reason)}"}
    end
  end
end
