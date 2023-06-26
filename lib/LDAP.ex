defmodule LDAP do
  require Record
#-rw-r--r-- 1 maxim maxim  379 Jun 15 05:16 caroot.key
#-rw-r--r-- 1 maxim maxim  782 Jun 15 05:16 caroot.pem
#-rw-r--r-- 1 maxim maxim  288 Jun 15 05:16 client.key
#-rw-r--r-- 1 maxim maxim  891 Jun 15 05:16 client.pem
#-rw-r--r-- 1 maxim maxim  232 Jun 15 05:17 mosquitto.conf
#-rw------- 1 maxim maxim  595 Jun 15 05:32 mosquitto.log
#-rwxr-xr-x 1 maxim maxim  103 Jun 15 05:16 pub.sh
#-rwxr-xr-x 1 maxim maxim   28 Jun 15 05:16 run.sh
#-rw-r--r-- 1 maxim maxim  288 Jun 15 05:16 server.key
#-rw-r--r-- 1 maxim maxim 1212 Jun 15 05:16 server.pem

  def testConnection() do
      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 389}, {:ssl, false}])
#      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 636}, {:ssl, true},
 #                   {:sslopts, [{:verify,:verify_none},
  #                              {:cacertfile,'/home/maxim/depot/chat/priv/mosquitto/caroot.pem'},
   #                             {:certs_keys, %{certfile: '/home/maxim/depot/chat/priv/mosquitto/client.pem',
    #                                            keyfile: '/home/maxim/depot/chat/priv/mosquitto/client.key'}}]}])
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
