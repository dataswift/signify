defmodule Signify.MixProject do
  use Mix.Project

  def project do
    [
      app: :signify,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {Signify.Application, []},
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.34.0"},

      # JSON
      {:jason, "~> 1.4"},

      # Development and testing
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:benchee, "~> 1.3.0", only: :dev}
    ]
  end

  defp description do
    """
    W3C Verifiable Credentials signing and verification using Ed25519 and CESR.
    Trust-based identity verification for legal entities and individuals.
    """
  end

  defp package do
    [
      name: "signify",
      files: ~w(lib native .formatter.exs mix.exs README.md LICENSE),
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/dataswyft/signify"}
    ]
  end

  defp docs do
    [
      main: "Signify",
      extras: ["README.md"]
    ]
  end
end
