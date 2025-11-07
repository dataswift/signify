defmodule Signify.Credential do
  @moduledoc """
  Elixir wrapper for KERIA Credentials API.

  This module provides high-level access to credential operations through the KERIA agent,
  including listing, retrieving, and deleting verifiable credentials in both JSON and CESR formats.

  ## Examples

      # Create a client and credentials instance
      {:ok, client} = Signify.Client.new("http://localhost:3901", "GCiBGAhduxcggJE4qJeaA")
      {:ok, creds} = Signify.Credential.new(client)

      # List all credentials
      {:ok, credentials} = Signify.Credential.list(creds)

      # Get a specific credential in JSON format
      {:ok, credential} = Signify.Credential.get(creds, "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg")

      # Get a credential in CESR format
      {:ok, cesr} = Signify.Credential.get_cesr(creds, "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg")

      # Delete a credential
      :ok = Signify.Credential.delete(creds, "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg")
  """

  alias Signify.Native

  @type t :: reference()
  @type said :: String.t()
  @type credential_result :: %{
          sad: map(),
          status: map() | nil,
          schema: String.t() | nil
        }
  @type filter :: %{
          filter: map() | nil,
          sort: list() | nil,
          skip: non_neg_integer() | nil,
          limit: non_neg_integer() | nil
        }

  @doc """
  Creates a new Credentials API client.

  ## Parameters

    * `client` - A SignifyClient reference from `Signify.Client.new/2`

  ## Returns

    * `{:ok, credentials}` - A new credentials client reference
    * `{:error, reason}` - If creation fails

  ## Examples

      {:ok, client} = Signify.Client.new("http://localhost:3901", "GCiBGAhduxcggJE4qJeaA")
      {:ok, creds} = Signify.Credential.new(client)
  """
  @spec new(Signify.Client.t()) :: {:ok, t()} | {:error, String.t()}
  def new(client) when is_reference(client) do
    try do
      resource = Native.credentials_new(client)
      {:ok, resource}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Lists credentials with optional filtering.

  ## Parameters

    * `credentials` - The credentials client reference
    * `filter` - Optional filter map with keys:
      * `:filter` - MongoDB-style filter query
      * `:sort` - List of sort criteria
      * `:skip` - Number of results to skip (pagination)
      * `:limit` - Maximum number of results to return

  ## Returns

    * `{:ok, [credential_result]}` - List of credential results
    * `{:error, reason}` - If the request fails

  ## Examples

      # List all credentials
      {:ok, all_creds} = Signify.Credential.list(creds)

      # List with filter and limit
      filter = %{limit: 10, skip: 0}
      {:ok, limited} = Signify.Credential.list(creds, filter)
  """
  @spec list(t(), filter() | nil) :: {:ok, [credential_result()]} | {:error, String.t()}
  def list(credentials, filter \\ nil) when is_reference(credentials) do
    try do
      filter_json =
        if filter do
          Jason.encode!(filter)
        else
          nil
        end

      result_json = Native.credentials_list(credentials, filter_json)
      result = Jason.decode!(result_json)
      {:ok, result}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Retrieves a specific credential by SAID in JSON format.

  ## Parameters

    * `credentials` - The credentials client reference
    * `said` - The Self-Addressing Identifier (SAID) of the credential

  ## Returns

    * `{:ok, credential_result}` - The credential data with metadata
    * `{:error, reason}` - If the credential is not found or request fails

  ## Examples

      {:ok, cred} = Signify.Credential.get(creds, "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg")
      IO.inspect(cred.sad)  # Credential data
      IO.inspect(cred.status)  # Status information
  """
  @spec get(t(), said()) :: {:ok, credential_result()} | {:error, String.t()}
  def get(credentials, said) when is_reference(credentials) and is_binary(said) do
    try do
      result_json = Native.credentials_get_json(credentials, said)
      result = Jason.decode!(result_json, keys: :atoms)
      {:ok, result}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Retrieves a specific credential by SAID in CESR format.

  CESR (Composable Event Streaming Representation) format is useful for:
  - Cryptographic verification
  - Compact serialization
  - Interoperability with other KERI tools

  ## Parameters

    * `credentials` - The credentials client reference
    * `said` - The Self-Addressing Identifier (SAID) of the credential

  ## Returns

    * `{:ok, cesr_string}` - The credential in CESR format
    * `{:error, reason}` - If the credential is not found or request fails

  ## Examples

      {:ok, cesr} = Signify.Credential.get_cesr(creds, "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg")
      # cesr contains CESR-encoded credential data
  """
  @spec get_cesr(t(), said()) :: {:ok, String.t()} | {:error, String.t()}
  def get_cesr(credentials, said) when is_reference(credentials) and is_binary(said) do
    try do
      cesr = Native.credentials_get_cesr(credentials, said)
      {:ok, cesr}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Deletes a credential by SAID.

  ## Parameters

    * `credentials` - The credentials client reference
    * `said` - The Self-Addressing Identifier (SAID) of the credential

  ## Returns

    * `:ok` - If the credential was successfully deleted
    * `{:error, reason}` - If the deletion fails

  ## Examples

      :ok = Signify.Credential.delete(creds, "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg")
  """
  @spec delete(t(), said()) :: :ok | {:error, String.t()}
  def delete(credentials, said) when is_reference(credentials) and is_binary(said) do
    try do
      Native.credentials_delete(credentials, said)
      :ok
    rescue
      e -> {:error, Exception.message(e)}
    end
  end
end
