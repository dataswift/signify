defmodule Signify.Habery do
  @moduledoc """
  Elixir wrapper for the Habery identifier manager.

  Habery is a high-level manager for creating and managing KERI identifiers (AIDs).
  It handles key generation, inception events, and witness configuration.

  ## Examples

      # Create a new Habery
      {:ok, habery} = Signify.Habery.new("my-habery", "GCiBGAhduxcggJE4qJeaA")

      # Get the name
      {:ok, name} = Signify.Habery.name(habery)

      # Create a new identifier
      {:ok, identifier} = Signify.Habery.make_hab(habery, "my-identifier")
  """

  alias Signify.Native

  @type t :: reference()

  @doc """
  Creates a new Habery instance.

  ## Parameters

    * `name` - The name for this Habery instance
    * `passcode` - A QB64-encoded passcode for key derivation

  ## Returns

    * `{:ok, habery}` - A new Habery reference
    * `{:error, reason}` - If creation fails

  ## Examples

      {:ok, habery} = Signify.Habery.new("my-habery", "GCiBGAhduxcggJE4qJeaA")
  """
  @spec new(String.t(), String.t()) :: {:ok, t()} | {:error, String.t()}
  def new(name, passcode) when is_binary(name) and is_binary(passcode) do
    try do
      resource = Native.habery_new(name, passcode)
      {:ok, resource}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Gets the name of the Habery instance.

  ## Parameters

    * `habery` - The Habery reference

  ## Returns

    * `{:ok, name}` - The name of the Habery
    * `{:error, reason}` - If retrieval fails

  ## Examples

      {:ok, name} = Signify.Habery.name(habery)
      # => {:ok, "my-habery"}
  """
  @spec name(t()) :: {:ok, String.t()} | {:error, String.t()}
  def name(habery) when is_reference(habery) do
    try do
      name = Native.habery_name(habery)
      {:ok, name}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  @doc """
  Creates a new KERI identifier (AID).

  This generates an inception event with keys derived from the Habery's passcode
  and creates a complete KERI identifier.

  ## Parameters

    * `habery` - The Habery reference
    * `name` - The name for the new identifier

  ## Returns

    * `{:ok, identifier}` - The new AID prefix (identifier)
    * `{:error, reason}` - If creation fails

  ## Examples

      {:ok, aid} = Signify.Habery.make_hab(habery, "my-identifier")
      # => {:ok, "EKxy..."}
  """
  @spec make_hab(t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def make_hab(habery, name) when is_reference(habery) and is_binary(name) do
    try do
      aid = Native.habery_make_hab(habery, name)
      {:ok, aid}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end
end
