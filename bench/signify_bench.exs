# Benchmark for Signify main operations
# Run with: mix run bench/signify_bench.exs
# Or: make bench

IO.puts("\nSignify Performance Benchmarks\n")
IO.puts("Testing 3 main operations:")
IO.puts("  1. generate_keypair() - Ed25519 keypair generation")
IO.puts("  2. sign() - JSON document signing")
IO.puts("  3. verify() - Signature verification\n")

# Prepare test data
{:ok, keys} = Signify.Signer.generate_keypair()

test_data = %{
  "@context" => ["https://www.w3.org/2018/credentials/v1"],
  "type" => ["VerifiableCredential"],
  "id" => "urn:uuid:test-credential-123",
  "issuer" => %{"id" => keys.did, "name" => "Test Issuer"},
  "issuanceDate" => DateTime.utc_now() |> DateTime.to_iso8601(),
  "credentialSubject" => %{
    "id" => keys.did,
    "email" => "test@example.com",
    "role" => "agripreneur",
    "organization" => "Test Org"
  }
}

{:ok, proof} = Signify.Signer.sign(keys, test_data)

# Run benchmarks
Benchee.run(
  %{
    "generate_keypair" => fn ->
      {:ok, _keys} = Signify.Signer.generate_keypair()
    end,
    "sign_json" => fn ->
      {:ok, _proof} = Signify.Signer.sign(keys, test_data)
    end,
    "verify_signature" => fn ->
      {:ok, _valid} = Signify.Signer.verify(keys.did, test_data, proof.proof_value)
    end
  },
  time: 5,
  memory_time: 2,
  warmup: 2,
  formatters: [
    {Benchee.Formatters.Console, extended_statistics: true}
  ]
)
