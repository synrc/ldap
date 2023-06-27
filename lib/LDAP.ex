defmodule LDAP do
  require Record
  def testConnection() do
#     {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 389}, {:ssl, false}])
      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 636}, {:ssl, true}])
      :eldap.start_tls(conn, [])
      :ok = :eldap.simple_bind(conn, 'cn=admin,dc=synrc,dc=com', 'secret')
      filter   = {:filter, :eldap.and([ ])}
      scope    = {:scope, :wholeSubtree}
      base     = {:base, 'dc=synrc,dc=com'}
      attrs    = {:attributes, ['cn','mail']}
      {:ok, x} = :eldap.search(conn, [base, scope, filter, attrs])
      :lists.map(fn {:eldap_entry, dn, attrs} ->
                    {:dn,dn,attrs} end, :erlang.element(2, x))
  end

end
