defmodule SignifyNifTest do
  use ExUnit.Case
  doctest Signify

  alias Signify.{Signer, Verfer, Habery, Client}

  describe "Signify module" do
    test "version/0 returns version string" do
      assert is_binary(Signify.version())
    end

    test "ready?/0 checks NIF is loaded" do
      assert {:ok, true} = Signify.ready?()
    end

    test "rust_version/0 returns Rust library version" do
      assert {:ok, version} = Signify.rust_version()
      assert is_binary(version)
    end
  end

  describe "Signer" do
    test "new_random/1 creates a random signer" do
      assert {:ok, signer} = Signer.new_random(true)
      assert is_reference(signer)
    end

    test "to_qb64/1 exports signer to QB64" do
      {:ok, signer} = Signer.new_random(true)
      assert {:ok, qb64} = Signer.to_qb64(signer)
      assert is_binary(qb64)
      assert String.length(qb64) > 0
    end

    test "from_qb64/2 imports signer from QB64" do
      {:ok, signer1} = Signer.new_random(true)
      {:ok, qb64} = Signer.to_qb64(signer1)

      assert {:ok, signer2} = Signer.from_qb64(qb64, true)
      assert is_reference(signer2)
    end

    test "sign/2 signs a message" do
      {:ok, signer} = Signer.new_random(true)
      message = "Hello, KERI!"

      assert {:ok, signature} = Signer.sign(signer, message)
      assert is_binary(signature)
      assert byte_size(signature) == 64
    end

    test "verfer/1 derives verification key" do
      {:ok, signer} = Signer.new_random(true)

      assert {:ok, verfer} = Signer.verfer(signer)
      assert is_reference(verfer)
    end
  end

  describe "Verfer" do
    test "to_qb64/1 exports verfer to QB64" do
      {:ok, signer} = Signer.new_random(true)
      {:ok, verfer} = Signer.verfer(signer)

      assert {:ok, qb64} = Verfer.to_qb64(verfer)
      assert is_binary(qb64)
      assert String.length(qb64) > 0
    end

    test "from_qb64/1 imports verfer from QB64" do
      {:ok, signer} = Signer.new_random(true)
      {:ok, verfer1} = Signer.verfer(signer)
      {:ok, qb64} = Verfer.to_qb64(verfer1)

      assert {:ok, verfer2} = Verfer.from_qb64(qb64)
      assert is_reference(verfer2)
    end

    test "verify/3 verifies a valid signature" do
      {:ok, signer} = Signer.new_random(true)
      {:ok, verfer} = Signer.verfer(signer)
      message = "Hello, KERI!"
      {:ok, signature} = Signer.sign(signer, message)

      assert {:ok, true} = Verfer.verify(verfer, signature, message)
    end

    test "verify/3 rejects an invalid signature" do
      {:ok, signer} = Signer.new_random(true)
      {:ok, verfer} = Signer.verfer(signer)
      message = "Hello, KERI!"
      {:ok, signature} = Signer.sign(signer, message)

      # Modify the message
      wrong_message = "Wrong message"
      assert {:ok, false} = Verfer.verify(verfer, signature, wrong_message)
    end

    test "verify/3 rejects signature from different key" do
      {:ok, signer1} = Signer.new_random(true)
      {:ok, signer2} = Signer.new_random(true)
      {:ok, verfer2} = Signer.verfer(signer2)

      message = "Hello, KERI!"
      {:ok, signature} = Signer.sign(signer1, message)

      # Signature from signer1, but verifying with verfer2
      assert {:ok, false} = Verfer.verify(verfer2, signature, message)
    end
  end

  describe "Habery" do
    test "new/2 creates a Habery instance" do
      assert {:ok, habery} = Habery.new("test-habery", "GCiBGAhduxcggJE4qJeaA")
      assert is_reference(habery)
    end

    test "name/1 returns the Habery name" do
      {:ok, habery} = Habery.new("test-habery", "GCiBGAhduxcggJE4qJeaA")

      assert {:ok, name} = Habery.name(habery)
      assert name == "test-habery"
    end

    test "make_hab/2 creates a new identifier" do
      {:ok, habery} = Habery.new("test-habery", "GCiBGAhduxcggJE4qJeaA")

      assert {:ok, aid} = Habery.make_hab(habery, "my-identifier")
      assert is_binary(aid)
      assert String.length(aid) > 0
      # KERI AIDs typically start with 'E' for Ed25519 derivation
      assert String.starts_with?(aid, "E")
    end

    test "make_hab/2 creates different AIDs for different names" do
      {:ok, habery} = Habery.new("test-habery", "GCiBGAhduxcggJE4qJeaA")

      {:ok, aid1} = Habery.make_hab(habery, "identifier-1")
      {:ok, aid2} = Habery.make_hab(habery, "identifier-2")

      assert aid1 != aid2
    end
  end

  describe "Client" do
    test "new/2 creates a SignifyClient instance" do
      assert {:ok, client} = Client.new("http://localhost:3901", "GCiBGAhduxcggJE4qJeaA")
      assert is_reference(client)
    end

    test "url/1 returns the client URL" do
      url = "http://localhost:3901"
      {:ok, client} = Client.new(url, "GCiBGAhduxcggJE4qJeaA")

      assert {:ok, ^url} = Client.url(client)
    end
  end

  describe "Integration: Sign and Verify workflow" do
    test "complete signing and verification workflow" do
      # Create a signer
      {:ok, signer} = Signer.new_random(true)

      # Get the verifier
      {:ok, verfer} = Signer.verfer(signer)

      # Sign a message
      message = "KERI Protocol Test Message"
      {:ok, signature} = Signer.sign(signer, message)

      # Verify the signature
      assert {:ok, true} = Verfer.verify(verfer, signature, message)

      # Export and re-import
      {:ok, signer_qb64} = Signer.to_qb64(signer)
      {:ok, verfer_qb64} = Verfer.to_qb64(verfer)

      {:ok, restored_signer} = Signer.from_qb64(signer_qb64, true)
      {:ok, restored_verfer} = Verfer.from_qb64(verfer_qb64)

      # Sign with restored signer
      {:ok, new_signature} = Signer.sign(restored_signer, message)

      # Verify with restored verfer
      assert {:ok, true} = Verfer.verify(restored_verfer, new_signature, message)
    end

    test "Habery identifier creation workflow" do
      # Create Habery
      {:ok, habery} = Habery.new("integration-test", "GCiBGAhduxcggJE4qJeaA")

      # Verify name
      {:ok, name} = Habery.name(habery)
      assert name == "integration-test"

      # Create multiple identifiers
      {:ok, aid1} = Habery.make_hab(habery, "user-alice")
      {:ok, aid2} = Habery.make_hab(habery, "user-bob")
      {:ok, aid3} = Habery.make_hab(habery, "user-charlie")

      # All should be valid KERI AIDs
      assert String.starts_with?(aid1, "E")
      assert String.starts_with?(aid2, "E")
      assert String.starts_with?(aid3, "E")

      # All should be unique
      assert aid1 != aid2
      assert aid2 != aid3
      assert aid1 != aid3
    end
  end
end
