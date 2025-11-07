defmodule Signify.Signer do
  @moduledoc """
  Elixir wrapper for the Signer cryptographic primitive.

  A Signer represents an Ed25519 private key that can sign messages and derive
  verification keys. Signers can be either transferable or non-transferable based
  on the KERI protocol requirements.

  ## Examples

      # Create a new random signer
      {:ok, signer} = Signify.Signer.new_random(true)

      # Sign a message
      {:ok, signature} = Signify.Signer.sign(signer, "Hello, World!")

      # Get the verification key
      {:ok, verfer} = Signify.Signer.verfer(signer)

      # Export as QB64
      {:ok, qb64} = Signify.Signer.to_qb64(signer)

      # Import from QB64
      {:ok, signer} = Signify.Signer.from_qb64(qb64, true)
  """

  alias Signify.Native

  @type t :: reference()
  @type signature :: binary()
  @type message :: binary() | String.t()

  @doc """
  Creates a new random Signer.

  ## Parameters

    * `transferable` - Whether the signer is transferable (default: true)

  ## Returns

    * `{:ok, signer}` - A new signer reference
    * `{:error, reason}` - If creation fails
  """
  @spec new_random(boolean()) :: {:ok, t()} | {:error, String.t()}
  def new_random(transferable \\ true) do
    try do
      resource = Native.signer_new_random(transferable)
      {:ok, resource}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Creates a Signer from a QB64 encoded string.

  ## Parameters

    * `qb64` - The QB64 encoded private key
    * `transferable` - Whether the signer is transferable (default: true)

  ## Returns

    * `{:ok, signer}` - A signer reference
    * `{:error, reason}` - If the QB64 string is invalid
  """
  @spec from_qb64(String.t(), boolean()) :: {:ok, t()} | {:error, String.t()}
  def from_qb64(qb64, transferable \\ true) when is_binary(qb64) do
    try do
      resource = Native.signer_from_qb64(qb64, transferable)
      {:ok, resource}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Exports the Signer to a QB64 encoded string.

  ## Parameters

    * `signer` - The signer reference

  ## Returns

    * `{:ok, qb64}` - The QB64 encoded private key
    * `{:error, reason}` - If export fails
  """
  @spec to_qb64(t()) :: {:ok, String.t()} | {:error, String.t()}
  def to_qb64(signer) when is_reference(signer) do
    try do
      qb64 = Native.signer_qb64(signer)
      {:ok, qb64}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Signs a message with the Signer.

  ## Parameters

    * `signer` - The signer reference
    * `message` - The message to sign (binary or string)

  ## Returns

    * `{:ok, signature}` - The signature as a binary
    * `{:error, reason}` - If signing fails
  """
  @spec sign(t(), message()) :: {:ok, signature()} | {:error, String.t()}
  def sign(signer, message) when is_reference(signer) do
    try do
      message_bytes = if is_binary(message), do: message, else: to_string(message)
      signature_list = Native.signer_sign(signer, :binary.bin_to_list(message_bytes))
      {:ok, :binary.list_to_bin(signature_list)}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Derives the verification key (Verfer) from the Signer.

  ## Parameters

    * `signer` - The signer reference

  ## Returns

    * `{:ok, verfer}` - The verfer reference
    * `{:error, reason}` - If derivation fails
  """
  @spec verfer(t()) :: {:ok, Signify.Verfer.t()} | {:error, String.t()}
  def verfer(signer) when is_reference(signer) do
    try do
      verfer = Native.signer_verfer(signer)
      {:ok, verfer}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end
end
