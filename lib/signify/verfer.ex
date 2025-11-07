defmodule Signify.Verfer do
  @moduledoc """
  Elixir wrapper for the Verfer cryptographic primitive.

  A Verfer represents an Ed25519 public key that can verify signatures.
  Verfers are derived from Signers or imported from QB64 encoded strings.

  ## Examples

      # Import from QB64
      {:ok, verfer} = Signify.Verfer.from_qb64("BKxy...")

      # Verify a signature
      {:ok, valid} = Signify.Verfer.verify(verfer, signature, "Hello, World!")

      # Export as QB64
      {:ok, qb64} = Signify.Verfer.to_qb64(verfer)
  """

  alias Signify.Native

  @type t :: reference()
  @type signature :: binary()
  @type message :: binary() | String.t()

  @doc """
  Creates a Verfer from a QB64 encoded string.

  ## Parameters

    * `qb64` - The QB64 encoded public key

  ## Returns

    * `{:ok, verfer}` - A verfer reference
    * `{:error, reason}` - If the QB64 string is invalid
  """
  @spec from_qb64(String.t()) :: {:ok, t()} | {:error, String.t()}
  def from_qb64(qb64) when is_binary(qb64) do
    try do
      resource = Native.verfer_from_qb64(qb64)
      {:ok, resource}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Exports the Verfer to a QB64 encoded string.

  ## Parameters

    * `verfer` - The verfer reference

  ## Returns

    * `{:ok, qb64}` - The QB64 encoded public key
    * `{:error, reason}` - If export fails
  """
  @spec to_qb64(t()) :: {:ok, String.t()} | {:error, String.t()}
  def to_qb64(verfer) when is_reference(verfer) do
    try do
      qb64 = Native.verfer_qb64(verfer)
      {:ok, qb64}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Verifies a signature against a message.

  ## Parameters

    * `verfer` - The verfer reference
    * `signature` - The signature to verify (binary)
    * `message` - The original message (binary or string)

  ## Returns

    * `{:ok, true}` - If the signature is valid
    * `{:ok, false}` - If the signature is invalid
    * `{:error, reason}` - If verification fails
  """
  @spec verify(t(), signature(), message()) :: {:ok, boolean()} | {:error, String.t()}
  def verify(verfer, signature, message) when is_reference(verfer) and is_binary(signature) do
    try do
      message_bytes = if is_binary(message), do: message, else: to_string(message)

      result =
        Native.verfer_verify(
          verfer,
          :binary.bin_to_list(signature),
          :binary.bin_to_list(message_bytes)
        )

      {:ok, result}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end
end
