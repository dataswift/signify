#!/usr/bin/env elixir

# Example: Loading KERI credential.cesr file
# Usage: mix run examples/load_keri_cesr.exs

IO.puts("\n=== 🔐 Loading KERI Credential File ===\n")

# Path to CESR file
cesr_file = "credential.cesr"

IO.puts("Loading file: #{cesr_file}\n")

# Load and parse CESR file
case Signify.Signer.load_keys_from_file(cesr_file) do
  {:ok, keys} ->
    IO.puts("✅ SUCCESSFULLY loaded!")
    IO.puts("\n📋 Information:")
    IO.puts("   DID: #{keys.did}")
    IO.puts("   Public key: #{byte_size(keys.public_key)} bytes")
    IO.puts("   Public key (hex): #{Base.encode16(keys.public_key, case: :lower) |> String.slice(0..31)}...")

    IO.puts("\n⚠️  IMPORTANT:")
    IO.puts("   KERI credential files do NOT contain private keys!")
    IO.puts("   Private key is set to MOCK (zeros)")
    IO.puts("   For signing you need to:")
    IO.puts("     1. Get private key from secure wallet")
    IO.puts("     2. Create CESRKeys with real private_key")
    IO.puts("     3. Use it for signing")

    IO.puts("\n✅ Now this DID and public key can be used for:")
    IO.puts("   • Signature verification")
    IO.puts("   • Creating VP (if you provide real private key)")

  {:error, reason} ->
    IO.puts("❌ ERROR: #{reason}")
end

IO.puts("\n=== Done ===\n")
