defmodule Signify.Client do
  @moduledoc """
  Elixir wrapper for the SignifyClient.

  SignifyClient provides HTTP communication with a KERIA agent, implementing
  HTTP Signatures authentication for secure API access.

  ## Examples

      # Create a new client
      {:ok, client} = Signify.Client.new("http://localhost:3901", "GCiBGAhduxcggJE4qJeaA")

      # Get the URL
      {:ok, url} = Signify.Client.url(client)
  """

  alias Signify.Native

  @type t :: reference()

  @doc """
  Creates a new SignifyClient instance.

  ## Parameters

    * `url` - The KERIA agent URL (e.g., "http://localhost:3901")
    * `bran` - A QB64-encoded passcode for authentication

  ## Returns

    * `{:ok, client}` - A new client reference
    * `{:error, reason}` - If creation fails

  ## Examples

      {:ok, client} = Signify.Client.new("http://localhost:3901", "GCiBGAhduxcggJE4qJeaA")
  """
  @spec new(String.t(), String.t()) :: {:ok, t()} | {:error, String.t()}
  def new(url, bran) when is_binary(url) and is_binary(bran) do
    try do
      resource = Native.client_new(url, bran)
      {:ok, resource}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Gets the URL of the KERIA agent.

  ## Parameters

    * `client` - The client reference

  ## Returns

    * `{:ok, url}` - The KERIA agent URL
    * `{:error, reason}` - If retrieval fails

  ## Examples

      {:ok, url} = Signify.Client.url(client)
      # => {:ok, "http://localhost:3901"}
  """
  @spec url(t()) :: {:ok, String.t()} | {:error, String.t()}
  def url(client) when is_reference(client) do
    try do
      url = Native.client_url(client)
      {:ok, url}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end
end
