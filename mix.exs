defmodule LDAP.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ldap,
      version: "8.6.0",
      description: "ldap Financial Information Exchange",
      compilers: [:asn1] ++ Mix.compilers(),
      asn1_paths: ["src"],
      package: package(),
      elixir: "~> 1.7",
      deps: deps()
    ]
  end

  def package do
    [
      files: ~w(doc include src mix.exs LICENSE),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ldap,
      links: %{"GitHub" => "https://github.com/enterprizing/ldap"}
    ]
  end


  def application() do
    [mod: {:eds_app, []}]
  end

  def deps() do
    [
      {:asn1ex, github: "vicentfg/asn1ex", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
