defmodule Signify.Native do
  @moduledoc """
  Native interface to signify-rs through Rustler NIFs.

  This module provides low-level access to the Rust implementation.
  For most use cases, use the higher-level wrapper modules instead:
  - `Signify.Signer`
  - `Signify.Verfer`
  - `Signify.Habery`
  - `Signify.Client`
  """

  use Rustler, otp_app: :signify, crate: "signify_rs"

  # Signer NIFs
  def signer_new_random(_transferable), do: :erlang.nif_error(:nif_not_loaded)
  def signer_from_qb64(_qb64, _transferable), do: :erlang.nif_error(:nif_not_loaded)
  def signer_qb64(_resource), do: :erlang.nif_error(:nif_not_loaded)
  def signer_sign(_resource, _message), do: :erlang.nif_error(:nif_not_loaded)
  def signer_verfer(_resource), do: :erlang.nif_error(:nif_not_loaded)

  # Verfer NIFs
  def verfer_from_qb64(_qb64), do: :erlang.nif_error(:nif_not_loaded)
  def verfer_qb64(_resource), do: :erlang.nif_error(:nif_not_loaded)
  def verfer_verify(_resource, _signature, _message), do: :erlang.nif_error(:nif_not_loaded)

  # Habery NIFs
  def habery_new(_name, _passcode), do: :erlang.nif_error(:nif_not_loaded)
  def habery_name(_resource), do: :erlang.nif_error(:nif_not_loaded)
  def habery_make_hab(_resource, _name), do: :erlang.nif_error(:nif_not_loaded)

  # Client NIFs
  def client_new(_url, _bran), do: :erlang.nif_error(:nif_not_loaded)
  def client_url(_resource), do: :erlang.nif_error(:nif_not_loaded)

  # Credentials NIFs
  def credentials_new(_client_resource), do: :erlang.nif_error(:nif_not_loaded)
  def credentials_list(_resource, _filter_json), do: :erlang.nif_error(:nif_not_loaded)
  def credentials_get_json(_resource, _said), do: :erlang.nif_error(:nif_not_loaded)
  def credentials_get_cesr(_resource, _said), do: :erlang.nif_error(:nif_not_loaded)
  def credentials_delete(_resource, _said), do: :erlang.nif_error(:nif_not_loaded)

  # CESR File Parsing NIFs
  def parse_cesr_file(_cesr_data), do: :erlang.nif_error(:nif_not_loaded)

  # Utility NIFs
  def blake3_digest(_data), do: :erlang.nif_error(:nif_not_loaded)
  def version(), do: :erlang.nif_error(:nif_not_loaded)
  def ready(), do: :erlang.nif_error(:nif_not_loaded)
end
