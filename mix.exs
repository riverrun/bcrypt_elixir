defmodule BcryptElixir.Mixfile do
  use Mix.Project

  @version "2.3.0"

  @description """
  Bcrypt password hashing algorithm for Elixir
  """

  def project do
    [
      app: :bcrypt_elixir,
      version: @version,
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_targets: ["all"],
      make_clean: ["clean"],
      description: @description,
      package: package(),
      source_url: "https://github.com/riverrun/bcrypt_elixir",
      deps: deps(),
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:comeonin, "~> 5.3"},
      {:elixir_make, "~> 0.6", runtime: false},
      {:ex_doc, "~> 0.23", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0.0", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      files: ["lib", "c_src", "mix.exs", "Makefile*", "README.md", "LICENSE"],
      maintainers: ["David Whitlock"],
      licenses: ["BSD"],
      links: %{"GitHub" => "https://github.com/riverrun/bcrypt_elixir"}
    ]
  end
end
