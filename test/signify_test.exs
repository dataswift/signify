defmodule SignifyTest do
  use ExUnit.Case
  doctest Signify

  alias Signify.{Signer, Credentials}

  describe "keypair generation" do
    test "generates valid Ed25519 keypair" do
      assert {:ok, keys} = Signer.generate_keypair()
      assert byte_size(keys.private_key) == 32
      assert byte_size(keys.public_key) == 32
      assert String.starts_with?(keys.did, "did:keri:")
    end

    test "generates unique keypairs" do
      {:ok, keys1} = Signer.generate_keypair()
      {:ok, keys2} = Signer.generate_keypair()

      assert keys1.private_key != keys2.private_key
      assert keys1.public_key != keys2.public_key
      assert keys1.did != keys2.did
    end
  end

  describe "DID operations" do
    test "extracts public key from DID" do
      {:ok, keys} = Signer.generate_keypair()
      {:ok, extracted_pubkey} = Signer.extract_public_key_from_did(keys.did)

      assert extracted_pubkey == keys.public_key
    end

    test "fails to extract from invalid DID" do
      assert {:error, _reason} = Signer.extract_public_key_from_did("invalid:did:format")
    end
  end

  describe "basic signing and verification" do
    test "signs and verifies JSON data" do
      {:ok, keys} = Signer.generate_keypair()

      data = %{
        message: "Hello, Signify!",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        counter: 42
      }

      {:ok, proof} = Signer.sign(keys, data)

      assert is_binary(proof.proof_value)
      assert String.starts_with?(proof.proof_value, "z")
      assert proof.verification_method == "#{keys.did}#0"

      json = Jason.encode!(data)
      {:ok, valid?} = Signer.verify_json(keys.public_key, json, proof.proof_value)

      assert valid? == true
    end

    test "verification fails for tampered data" do
      {:ok, keys} = Signer.generate_keypair()

      data = %{message: "original"}
      {:ok, proof} = Signer.sign(keys, data)

      tampered_data = %{message: "tampered"}
      json = Jason.encode!(tampered_data)
      {:ok, valid?} = Signer.verify_json(keys.public_key, json, proof.proof_value)

      assert valid? == false
    end

    test "verifies using extracted public key from DID" do
      {:ok, keys} = Signer.generate_keypair()

      data = %{test: "data"}
      {:ok, proof} = Signer.sign(keys, data)

      {:ok, extracted_pubkey} = Signer.extract_public_key_from_did(keys.did)
      json = Jason.encode!(data)
      {:ok, valid?} = Signer.verify_json(extracted_pubkey, json, proof.proof_value)

      assert valid? == true
    end
  end

  describe "verifiable credentials" do
    test "creates and signs a basic credential" do
      {:ok, keys} = Signer.generate_keypair()

      credential_subject = %{
        id: keys.did,
        email: "test@example.com",
        role: "tester"
      }

      {:ok, credential} = Credentials.create_and_sign(
        credential_subject,
        keys,
        issuer: %{id: keys.did, name: "Test Issuer"}
      )

      assert credential["@context"] == ["https://www.w3.org/2018/credentials/v1"]
      assert "VerifiableCredential" in credential.type
      assert credential.credentialSubject.id == keys.did
      assert credential.credentialSubject.email == "test@example.com"
      assert is_map(credential.proof)
      assert credential.proof.type == "Ed25519Signature2020"
    end

    test "creates credential with custom type" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, credential} = Credentials.create_and_sign(
        %{id: keys.did, role: "agripreneur"},
        keys,
        issuer: %{id: keys.did, name: "Test"},
        type: ["VerifiableCredential", "AgripreneurCredential"]
      )

      assert "VerifiableCredential" in credential.type
      assert "AgripreneurCredential" in credential.type
    end

    test "creates credential with expiration date" do
      {:ok, keys} = Signer.generate_keypair()
      expiration = ~U[2026-01-01 00:00:00Z]

      {:ok, credential} = Credentials.create_and_sign(
        %{id: keys.did},
        keys,
        issuer: %{id: keys.did, name: "Test"},
        expiration_date: expiration
      )

      assert credential.expirationDate == DateTime.to_iso8601(expiration)
    end

    test "verifies valid credential" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, credential} = Credentials.create_and_sign(
        %{id: keys.did, email: "verify@example.com"},
        keys,
        issuer: %{id: keys.did, name: "Test Issuer"}
      )

      assert {:ok, true} = Credentials.verify_credential(credential)
    end

    test "detects tampered credential" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, credential} = Credentials.create_and_sign(
        %{id: keys.did, email: "original@example.com"},
        keys,
        issuer: %{id: keys.did, name: "Test"}
      )

      tampered_credential = Map.put(
        credential,
        :credentialSubject,
        %{id: keys.did, email: "hacked@example.com"}
      )

      assert {:ok, false} = Credentials.verify_credential(tampered_credential)
    end

    test "creates credential with multiple subject fields" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, credential} = Credentials.create_and_sign(
        %{
          id: keys.did,
          email: "demo@dataswyft.com",
          role: "agripreneur",
          first_name: "John",
          last_name: "Doe",
          ap_score: 967,
          region: "Coast"
        },
        keys,
        issuer: %{id: keys.did, name: "Kuza Biashara Limited"},
        type: ["VerifiableCredential", "AgripreneurRoleCredential"]
      )

      subject = credential.credentialSubject
      assert subject.email == "demo@dataswyft.com"
      assert subject.role == "agripreneur"
      assert subject.ap_score == 967
      assert subject.region == "Coast"
    end
  end

  describe "verifiable presentations" do
    test "creates presentation with single credential" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, credential} = Credentials.create_and_sign(
        %{id: keys.did, role: "tester"},
        keys,
        issuer: %{id: keys.did, name: "Test"}
      )

      {:ok, presentation} = Credentials.create_and_sign_presentation(
        [credential],
        keys,
        challenge: "test-challenge",
        domain: "https://example.com"
      )

      assert presentation["@context"] == ["https://www.w3.org/2018/credentials/v1"]
      assert "VerifiablePresentation" in presentation.type
      assert length(presentation.verifiableCredential) == 1
      assert is_map(presentation.proof)
      assert presentation.proof.challenge == "test-challenge"
      assert presentation.proof.domain == "https://example.com"
    end

    test "creates presentation with multiple credentials" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, cred1} = Credentials.create_and_sign(
        %{id: keys.did, role: "agripreneur"},
        keys,
        issuer: %{id: keys.did, name: "Test"},
        type: ["VerifiableCredential", "RoleCredential"]
      )

      {:ok, cred2} = Credentials.create_and_sign(
        %{id: keys.did, first_name: "John", last_name: "Doe"},
        keys,
        issuer: %{id: keys.did, name: "Test"},
        type: ["VerifiableCredential", "ProfileCredential"]
      )

      {:ok, presentation} = Credentials.create_and_sign_presentation(
        [cred1, cred2],
        keys,
        challenge: "multi-cred-test"
      )

      assert length(presentation.verifiableCredential) == 2
    end

    test "creates presentation with custom payload" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, credential} = Credentials.create_and_sign(
        %{id: keys.did},
        keys,
        issuer: %{id: keys.did, name: "Test"}
      )

      custom_payload = %{
        ap_spg_score: 967,
        ap_spg_percentile: 60,
        email: "demo@example.com"
      }

      {:ok, presentation} = Credentials.create_and_sign_presentation(
        [credential],
        keys,
        challenge: "custom-test",
        custom_payload: custom_payload
      )

      assert presentation.ap_spg_score == 967
      assert presentation.ap_spg_percentile == 60
      assert presentation.email == "demo@example.com"
    end

    test "verifies valid presentation" do
      {:ok, keys} = Signer.generate_keypair()

      {:ok, credential} = Credentials.create_and_sign(
        %{id: keys.did, test: "data"},
        keys,
        issuer: %{id: keys.did, name: "Test"}
      )

      {:ok, presentation} = Credentials.create_and_sign_presentation(
        [credential],
        keys,
        challenge: "verify-test"
      )

      assert {:ok, true} = Credentials.verify_presentation(presentation)
    end
  end

  describe "vLEI credentials" do
    test "creates vLEI credential with LEI data" do
      {:ok, keys} = Signer.generate_keypair()

      lei_data = %{
        LEI: "98450012E89468BE9808",
        legalName: "TEST ENTITY LIMITED",
        entityStatus: "ACTIVE",
        entityCategory: "GENERAL",
        entityCreationDate: "2011-10-14T01:00:00+01:00",
        legalAddress: %{
          addressLines: ["123 Test Street"],
          city: "Test City",
          country: "KE",
          postalCode: "00100",
          region: "KE-30",
          language: "en"
        },
        legalForm: %{
          code: "8888",
          label: "Private Limited Company"
        }
      }

      {:ok, vlei_credential} = Credentials.create_vlei_credential(
        lei_data,
        keys,
        issuer: %{
          id: keys.did,
          name: "Test QVI",
          LEI: "529900T8BM49AURSDO55"
        }
      )

      assert "LegalEntityvLEICredential" in vlei_credential.type
      assert vlei_credential.credentialSubject[:LEI] == "98450012E89468BE9808"
      assert vlei_credential.credentialSubject.legalName == "TEST ENTITY LIMITED"
      assert is_map(vlei_credential.proof)
    end

    test "creates vLEI credential with full address data" do
      {:ok, keys} = Signer.generate_keypair()

      lei_data = %{
        LEI: "98450012E89468BE9808",
        legalName: "KUZA BIASHARA LIMITED",
        entityStatus: "ACTIVE",
        legalAddress: %{
          addressLines: [
            "P.O BOX 1772 SARIT CENTRE",
            "GENERAL MATHENGE DRIVE, BUILDING: 43"
          ],
          city: "WESTLANDS DISTRICT",
          country: "KE",
          postalCode: "00100",
          region: "KE-30",
          language: "en"
        },
        headquartersAddress: %{
          addressLines: ["HQ Address"],
          city: "Nairobi",
          country: "KE",
          postalCode: "00100",
          region: "KE-30",
          language: "en"
        },
        registrationAuthority: %{
          jurisdiction: "KE",
          registrationAuthorityID: "RA000417",
          registrationAuthorityEntityID: "CPR/2011/58834"
        }
      }

      {:ok, vlei_credential} = Credentials.create_vlei_credential(
        lei_data,
        keys,
        issuer: %{id: keys.did, name: "Test QVI", LEI: "529900T8BM49AURSDO55"},
        expiration_date: ~U[2025-08-15 10:45:00Z]
      )

      subject = vlei_credential.credentialSubject
      assert subject.legalName == "KUZA BIASHARA LIMITED"
      assert is_map(subject.legalAddress)
      assert is_map(subject.headquartersAddress)
      assert is_map(subject.registrationAuthority)
      assert vlei_credential.expirationDate == "2025-08-15T10:45:00Z"
    end
  end

  describe "CESR file handling" do
    test "generates test keypair matches expected format" do
      {:ok, keys} = Signer.generate_keypair()

      # Keys should be raw bytes
      assert is_binary(keys.private_key)
      assert is_binary(keys.public_key)
      assert byte_size(keys.private_key) == 32
      assert byte_size(keys.public_key) == 32

      # DID should be properly formatted
      assert String.starts_with?(keys.did, "did:keri:")
      assert String.length(keys.did) > 15
    end
  end

  describe "canonical JSON signing" do
    test "signs canonical JSON directly" do
      {:ok, keys} = Signer.generate_keypair()

      data = %{b: 2, a: 1}
      canonical = Jason.encode!(data)

      {:ok, proof} = Signer.sign_canonical_json(
        keys.private_key,
        keys.public_key,
        canonical
      )

      assert is_binary(proof.proof_value)
      assert String.starts_with?(proof.proof_value, "z")
    end

    test "verifies canonical JSON signature" do
      {:ok, keys} = Signer.generate_keypair()

      data = %{test: "canonical"}
      canonical = Jason.encode!(data)

      {:ok, proof} = Signer.sign_canonical_json(
        keys.private_key,
        keys.public_key,
        canonical
      )

      {:ok, valid?} = Signer.verify_signature(
        keys.public_key,
        canonical,
        proof.proof_value
      )

      assert valid? == true
    end
  end
end
