defmodule LDAP.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ldap,
      version: "15.4.14",
      description: "LDAP  CXC 138 22 Directory Server",
      package: package(),
      deps: deps(),
      releases: [ldap: [include_executables_for: [:unix], cookie: "SYNRC:LDAP"]]
    ]
  end

  def package do
    [
      files: ~w(lib include src man priv mix.exs LICENSE index.html README.md),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ldap,
      links: %{"GitHub" => "https://github.com/synrc/ldap"}
    ]
  end

  def application() do
    [
      mod: {LDAP, []},
      extra_applications: [:eldap, :asn1, :crypto]
    ]
  end

  def deps() do
    [
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:exqlite, "~> 0.36.0"}
    ]
  end
end
