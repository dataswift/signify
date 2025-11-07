#!/usr/bin/env elixir

# Script to generate boilerplate for Signify Rust and Elixir modules
# This accelerates development by creating all module scaffolds

defmodule SignifyGenerator do
  @rust_modules [
    # Core primitives
    {"core/diger.rs", :diger},
    {"core/salter.rs", :salter},
    {"core/signer.rs", :signer},
    {"core/verfer.rs", :verfer},
    {"core/cipher.rs", :cipher},
    {"core/prefixer.rs", :prefixer},
    {"core/saider.rs", :saider},
    {"core/indexer.rs", :indexer},
    {"core/counter.rs", :counter},
    {"core/seqner.rs", :seqner},
    {"core/tholder.rs", :tholder},
    {"core/serder.rs", :serder},
    {"core/eventing.rs", :eventing},
    {"core/manager.rs", :manager},

    # App layer
    {"app/mod.rs", :app_mod},
    {"app/habery.rs", :habery},
    {"app/controller.rs", :controller},
    {"app/client.rs", :client},
    {"app/credentials.rs", :credentials},
    {"app/operations.rs", :operations},
    {"app/contacts.rs", :contacts},
    {"app/groups.rs", :groups},
    {"app/delegations.rs", :delegations},
    {"app/exchanges.rs", :exchanges},
    {"app/notifications.rs", :notifications},
    {"app/escrowing.rs", :escrowing},

    # HTTP
    {"http/mod.rs", :http_mod},
    {"http/auth.rs", :http_auth},
    {"http/client.rs", :http_client}
  ]

  @elixir_modules [
    {"lib/signify/core/matter.ex", :elixir_matter},
    {"lib/signify/core/salter.ex", :elixir_salter},
    {"lib/signify/core/signer.ex", :elixir_signer},
    {"lib/signify/core/verfer.ex", :elixir_verfer},
    {"lib/signify/core/diger.ex", :elixir_diger},
    {"lib/signify/core/serder.ex", :elixir_serder},
    {"lib/signify/core/eventing.ex", :elixir_eventing},
    {"lib/signify/app/habery.ex", :elixir_habery},
    {"lib/signify/app/client.ex", :elixir_client},
    {"lib/signify/app/credentials.ex", :elixir_credentials},
    {"lib/signify/native.ex", :elixir_native}
  ]

  def run do
    IO.puts("Generating Signify module scaffolds...")

    # Generate Rust modules
    Enum.each(@rust_modules, fn {path, type} ->
      generate_rust_module(path, type)
    end)

    # Generate Elixir modules
    Enum.each(@elixir_modules, fn {path, type} ->
      generate_elixir_module(path, type)
    end)

    IO.puts("\n✅ Generated #{length(@rust_modules)} Rust modules")
    IO.puts("✅ Generated #{length(@elixir_modules)} Elixir modules")
    IO.puts("\nNext steps:")
    IO.puts("1. Implement TODO sections in each module")
    IO.puts("2. Run: cd native/signify_rs && cargo build")
    IO.puts("3. Run: mix compile")
    IO.puts("4. Run: mix test")
  end

  defp generate_rust_module(path, type) do
    full_path = Path.join("native/signify_rs/src", path)
    File.mkdir_p!(Path.dirname(full_path))

    content = rust_template(type, Path.basename(path, ".rs"))

    if File.exists?(full_path) do
      IO.puts("⏭️  Skipping #{path} (already exists)")
    else
      File.write!(full_path, content)
      IO.puts("✓ Created #{path}")
    end
  end

  defp generate_elixir_module(path, type) do
    full_path = path
    File.mkdir_p!(Path.dirname(full_path))

    content = elixir_template(type, path)

    if File.exists?(full_path) do
      IO.puts("⏭️  Skipping #{path} (already exists)")
    else
      File.write!(full_path, content)
      IO.puts("✓ Created #{path}")
    end
  end

  defp rust_template(type, module_name) do
    case type do
      :diger -> rust_diger_template()
      :salter -> rust_salter_template()
      :signer -> rust_signer_template()
      :verfer -> rust_verfer_template()
      :cipher -> rust_cipher_template()
      :serder -> rust_serder_template()
      :eventing -> rust_eventing_template()
      :habery -> rust_habery_template()
      :client -> rust_client_template()
      _ -> rust_generic_template(module_name)
    end
  end

  defp rust_generic_template(module_name) do
    """
    //! #{String.capitalize(module_name)} module
    //! TODO: Implement based on signify-ts reference

    use crate::error::{Result, SignifyError};

    // TODO: Add structures and implementations
    """
  end

  defp rust_diger_template do
    """
    //! Diger - Cryptographic digest operations

    use crate::error::{Result, SignifyError};
    use crate::core::{Matter, MatterOpts, matter_codes};
    use blake3;

    /// Diger handles cryptographic digests (hashes) with CESR encoding
    #[derive(Debug, Clone)]
    pub struct Diger {
        matter: Matter,
    }

    impl Diger {
        /// Create Diger from raw bytes
        pub fn from_raw(raw: &[u8], code: &str) -> Result<Self> {
            let matter = Matter::from_raw(raw, code)?;
            Ok(Self { matter })
        }

        /// Create Diger by computing digest of serialization
        pub fn new(code: &str, ser: &[u8]) -> Result<Self> {
            let digest = match code {
                matter_codes::BLAKE3_256 => {
                    let hash = blake3::hash(ser);
                    hash.as_bytes().to_vec()
                },
                _ => return Err(SignifyError::UnsupportedAlgorithm(code.to_string())),
            };

            Self::from_raw(&digest, code)
        }

        /// Verify that digest matches serialization
        pub fn verify(&self, ser: &[u8]) -> Result<bool> {
            let computed = Self::new(self.matter.code(), ser)?;
            Ok(computed.matter.raw() == self.matter.raw())
        }

        /// Get the Matter representation
        pub fn matter(&self) -> &Matter {
            &self.matter
        }

        /// Get qb64 encoding
        pub fn qb64(&self) -> &str {
            self.matter.qb64()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_diger_blake3() {
            let data = b"test data";
            let diger = Diger::new(matter_codes::BLAKE3_256, data).unwrap();

            assert_eq!(diger.matter().code(), matter_codes::BLAKE3_256);
            assert!(diger.verify(data).unwrap());

            let wrong_data = b"wrong data";
            assert!(!diger.verify(wrong_data).unwrap());
        }
    }
    """
  end

  # Add more templates...

  defp elixir_template(type, path) do
    module_name =
      path
      |> Path.basename(".ex")
      |> Macro.camelize()

    """
    defmodule Signify.#{module_name} do
      @moduledoc \"\"\"
      #{module_name} module for Signify
      TODO: Implement based on Rust NIF
      \"\"\"

      # TODO: Add functions
    end
    """
  end

  # Helper to generate all templates
  defp rust_salter_template, do: "// TODO: Implement Salter\n"
  defp rust_signer_template, do: "// TODO: Implement Signer\n"
  defp rust_verfer_template, do: "// TODO: Implement Verfer\n"
  defp rust_cipher_template, do: "// TODO: Implement Cipher\n"
  defp rust_serder_template, do: "// TODO: Implement Serder\n"
  defp rust_eventing_template, do: "// TODO: Implement Eventing\n"
  defp rust_habery_template, do: "// TODO: Implement Habery\n"
  defp rust_client_template, do: "// TODO: Implement Client\n"
end

SignifyGenerator.run()
