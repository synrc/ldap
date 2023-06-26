defmodule LDAP do
  require Record
  def testConnection() do
#      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 389}, {:ssl, false}])
      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 636}, {:ssl, true},
                    {:sslopts, [{:verify,:verify_none},
                                {:cacertfile,'/home/maxim/depot/chat/priv/mosquitto/caroot.pem'},
                                {:certs_keys, %{certfile: '/home/maxim/depot/chat/priv/mosquitto/client.pem',
                                                keyfile: '/home/maxim/depot/chat/priv/mosquitto/client.key'}}]}])
      :ok = :eldap.simple_bind(conn, 'cn=admin,dc=synrc,dc=com', 'secret')
      filter = :eldap.and([ ])
      scope = :wholeSubtree
      base = 'dc=synrc,dc=com'
      attrs = ['cn','mail']
      {:ok, {:eldap_search_result, entries, []}} =
             :eldap.search(conn, base: base, scope: scope,
                    filter: filter, attributes: attrs)

      :lists.map(fn {:eldap_entry, dn, attrs} -> {:dn,dn,attrs} end, entries)
  end

end
