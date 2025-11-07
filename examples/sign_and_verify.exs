#!/usr/bin/env elixir

# Example: Verify signed VP using public key from credential.cesr
# Usage: mix run examples/sign_and_verify.exs

IO.puts("\n=== 🔐 Signify: Verify VP with KERI Credential ===\n")

# Path to your CESR file
cesr_file = "credential.cesr"

# 1️⃣ Load public key from KERI credential file
IO.puts("1. Loading public key from KERI credential.cesr...")
{:ok, keys} = Signify.Signer.load_keys_from_file(cesr_file)

IO.puts("   ✅ Loaded!")
IO.puts("   • DID: #{keys.did}")
IO.puts("   • Public key: #{byte_size(keys.public_key)} bytes")
IO.puts("   • This public key will be used for verification")

# 2️⃣ Example: We have a Verifiable Presentation to verify
# In production, this would come from an API, database, or file
IO.puts("\n2. Loading a Verifiable Presentation for verification...")

# This is an example VP that was supposedly signed
signed_vp = %{
  "@context" => [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.gleif.org/vlei/v1"
  ],
  "type" => "VerifiablePresentation",
  "id" => "urn:uuid:b896e823-4e0a-4b49-b656-7823e0e89e10",
  "holder" => keys.did,  # Claims to be signed by credential.cesr holder
  "customPayload" => %{
    "ap_spg_percentile" => 60,
    "ap_spg_score" => 967,
    "ap_transactions_number" => 10,
    "ap_transactions_sum" => 620379.04,
    "email" => "demo+agri2@dataswyft.com",
    "role" => "agripreneur"
  },
  "verifiableCredential" => [],
  "proof" => %{
    "type" => "Ed25519Signature2020",
    "created" => "2025-10-28T11:49:43.021779Z",
    "verificationMethod" => "#{keys.did}#0",
    "proofPurpose" => "authentication",
    "challenge" => "efae261a-89ec-428e-a854-c2d64037270c",
    "domain" => "https://trade-portal.kuzabiashara.co.ke",
    "proofValue" => "zExampleSignatureThisIsNotRealJustForDemo12345678901234567890123456789012345"
  }
}

IO.puts("   ✅ VP loaded")
IO.puts("   • Holder claims: #{signed_vp["holder"]}")
IO.puts("   • Challenge: #{signed_vp["proof"]["challenge"]}")
IO.puts("   • Domain: #{signed_vp["proof"]["domain"]}")

# 3️⃣ Verify the signature using public key from credential.cesr
IO.puts("\n3. Verifying signature with public key from credential.cesr...")

case Signify.Credentials.verify_presentation(signed_vp) do
  {:ok, true} ->
    IO.puts("   ✅ SIGNATURE VALID!")
    IO.puts("   ✅ This VP was really signed by: #{keys.did}")
    IO.puts("   ✅ The holder has the private key matching credential.cesr")

  {:ok, false} ->
    IO.puts("   ❌ SIGNATURE INVALID!")
    IO.puts("   ❌ This VP was NOT signed by: #{keys.did}")
    IO.puts("   ❌ Someone tried to fake the signature!")

  {:error, reason} ->
    IO.puts("   ❌ VERIFICATION FAILED: #{reason}")
    IO.puts("   This is expected - example signature is not real")
end

# 4️⃣ Show the code needed for verification
IO.puts("\n=== 📚 How to Use credential.cesr for Verification ===\n")

IO.puts("Step 1: Load public key from credential.cesr")
IO.puts("```elixir")
IO.puts("{:ok, keys} = Signify.Signer.load_keys_from_file(\"credential.cesr\")")
IO.puts("# keys.did = \"#{keys.did}\"")
IO.puts("# keys.public_key = 32 bytes")
IO.puts("```\n")

IO.puts("Step 2: Verify a signed VP")
IO.puts("```elixir")
IO.puts("# Receive signed VP from API/file")
IO.puts("signed_vp = %{")
IO.puts("  \"holder\" => \"#{keys.did}\",")
IO.puts("  \"customPayload\" => %{...},")
IO.puts("  \"proof\" => %{")
IO.puts("    \"proofValue\" => \"z...\",")
IO.puts("    \"challenge\" => \"...\",")
IO.puts("    \"domain\" => \"...\"")
IO.puts("  }")
IO.puts("}")
IO.puts("")
IO.puts("# Verify signature")
IO.puts("{:ok, valid?} = Signify.Credentials.verify_presentation(signed_vp)")
IO.puts("```\n")

IO.puts("Step 3: Alternative - Verify with DID directly")
IO.puts("```elixir")
IO.puts("# Extract data without proof")
IO.puts("data = Map.delete(signed_vp, \"proof\")")
IO.puts("signature = signed_vp[\"proof\"][\"proofValue\"]")
IO.puts("")
IO.puts("# Verify with DID from credential.cesr")
IO.puts("{:ok, valid?} = Signify.Signer.verify(")
IO.puts("  \"#{keys.did}\",")
IO.puts("  data,")
IO.puts("  signature")
IO.puts(")")
IO.puts("```\n")

IO.puts("=== ✅ Summary ===")
IO.puts("✅ credential.cesr provides PUBLIC KEY for signature verification")
IO.puts("✅ No private key needed for verification")
IO.puts("✅ Can verify if VP was signed by holder of DID: #{keys.did}")
IO.puts("")
IO.puts("💡 Where is the private key?")
IO.puts("   • KERI credential files NEVER contain private keys")
IO.puts("   • Private keys are stored in secure wallets/HSM")
IO.puts("   • Only the holder has the private key")
IO.puts("   • Public key in credential.cesr is enough to verify!")
IO.puts("")
