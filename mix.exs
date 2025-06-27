defmodule LDAP.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ldap,
      version: "14.6.26",
      description: "LDAP  CXC 138 22 Directory Server",
      package: package(),
      elixir: "~> 1.15",
      deps: deps(),
      releases: [ldap: [include_executables_for: [:unix], cookie: "SYNRC:LDAP"]]
    ]
  end

  def package do
    [
      files: ~w(doc lib include src man priv mix.exs LICENSE index.html README.md),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ldap,
      links: %{"GitHub" => "https://github.com/synrc/ldap"}
    ]
  end


  def application() do
    [
      mod: {LDAP, []},
      extra_applications: [:eldap,:asn1]
    ]
  end

  def deps() do
    [
      {:ex_doc, "~> 0.11", only: :dev},
      {:exqlite, "~> 0.13.14"}
    ]
  end
end
