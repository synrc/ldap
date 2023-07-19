defmodule LDAP.Test do
  require Record

  def testConnection() do
      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 636}, {:ssl, true}])
#      :eldap.start_tls(conn, [])
      :ok = :eldap.simple_bind(conn, 'cn=admin,dc=synrc,dc=com', 'secret')
      filter = :eldap.and([ :eldap.substrings('cn',[{:any, '100000'}]) ])
      scope = :wholeSubtree
      base = 'dc=synrc,dc=com'
      attrs = ['cn','mail']
      {time,{:ok, x}} = :timer.tc(fn -> :eldap.search(conn, base: base, scope: scope, filter: filter, attributes: attrs) end)
      :io.format 'Time: ~p~n', [time]
      entries = :erlang.element(2, x)
      :lists.map(fn {:eldap_entry, dn, attrs} -> {:dn,dn,attrs} end, entries)
  end

  def loop1M() do
      :lists.map(fn i -> create(i) end, :lists.seq(1,1_000_000))
  end

  def timestamp() do
      {m, s, u} = :os.timestamp()
      (m*1000000 + s)*1000 + Float.floor(u/1000)
  end

  def create(no0) do
#      LDAP.TCP.start
#      :timer.sleep(500)
      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 1489}])
#      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 636}, {:ssl, true}])
#      :eldap.start_tls(conn, [])
      :eldap.simple_bind(conn, 'cn=admin,dc=synrc,dc=com', 'secret')
      case rem(no0,100) do
           0 -> :io.format 'Client bind: ~p ~p~n', [no0,timestamp()]
           _ -> :ok end
      no = case no0 do x when is_integer(x) -> :erlang.integer_to_list(x) ; _ -> :io_lib.format('~s',[no0]) end
      name = 'user_' ++ no
      {time,res} = :timer.tc(fn -> :eldap.add(conn, 'cn='++name++', ou=People, dc=synrc, dc=com',
       [{ 'objectClass', ['person','inetorgperson']},
        { 'givenName', ['givenName ' ++ no]},
        { 'cn', [name]},
        { 'sn', ['surname ' ++ no]},
        { 'telephoneNumber', ['+380670001122']}]
      ) end)
#      :io.format 'Time: ~p~n', [time]
      :eldap.close(conn)
  end

end
