# Benchmark for Signify signify_rs operations
# Run with: mix run bench/signify_rs_bench.exs

IO.puts("\nSignify signify_rs Performance Benchmarks\n")
IO.puts("Testing core cryptographic operations:")
IO.puts("  1. Signer.new_random() - Ed25519 key generation")
IO.puts("  2. Signer.sign() - Message signing")
IO.puts("  3. Verfer.verify() - Signature verification")
IO.puts("  4. KERI.create_identifier() - Full identifier inception")
IO.puts("  5. KERI.rotate_keys() - Key rotation event\n")

# Prepare test data
{:ok, signer1} = Signify.Signer.new_random(true)
{:ok, signer2} = Signify.Signer.new_random(true)
{:ok, verfer} = Signify.Signer.verfer(signer1)

message = "Hello, Signify!"
{:ok, signature} = Signify.Signer.sign(signer1, message)

# Create identifier for rotation benchmarks
{:ok, aid} =
  Signify.KERI.create_identifier(%{
    signer: signer1,
    next_signer: signer2,
    witnesses: [],
    witness_threshold: 0
  })

# Run benchmarks
Benchee.run(
  %{
    "Signer.new_random" => fn ->
      {:ok, _signer} = Signify.Signer.new_random(true)
    end,
    "Signer.sign" => fn ->
      {:ok, _sig} = Signify.Signer.sign(signer1, message)
    end,
    "Verfer.verify" => fn ->
      {:ok, _valid} = Signify.Verfer.verify(verfer, signature, message)
    end,
    "KERI.create_identifier" => fn ->
      {:ok, s1} = Signify.Signer.new_random(true)
      {:ok, s2} = Signify.Signer.new_random(true)

      {:ok, _aid} =
        Signify.KERI.create_identifier(%{
          signer: s1,
          next_signer: s2,
          witnesses: [],
          witness_threshold: 0
        })
    end,
    "KERI.rotate_keys" => fn ->
      {:ok, s3} = Signify.Signer.new_random(true)

      {:ok, _state} =
        Signify.KERI.rotate_keys(aid.prefix, %{
          current_signer: signer2,
          new_signer: s3,
          next_signer: signer1
        })
    end
  },
  time: 5,
  memory_time: 2,
  warmup: 2,
  formatters: [
    {Benchee.Formatters.Console, extended_statistics: true}
  ]
)

IO.puts("\n✅ Benchmarks complete!")
IO.puts("\nNotes:")
IO.puts("  - All operations use Rust NIFs for cryptography")
IO.puts("  - BLAKE3-256 hashing for KERI events")
IO.puts("  - Resource-based architecture for thread safety")
