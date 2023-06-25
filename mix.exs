defmodule LDAP.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ldap,
      version: "8.6.2",
      description: "LDAP Directory and Identity Server",
      package: package(),
      elixir: "~> 1.7",
      deps: deps()
    ]
  end

  def package do
    [
      files: ~w(doc lib include src man priv mix.exs LICENSE index.html README.md),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ldap,
      links: %{"GitHub" => "https://github.com/enterprizing/ldap"}
    ]
  end


  def application() do
    [
      mod: {:eds_app, []},
      extra_applications: [:eldap]
    ]
  end

  def deps() do
    [
#      {:asn1ex, github: "vicentfg/asn1ex", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
