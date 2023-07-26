defmodule LDAP.Client do
  @moduledoc "The LDAPv3 client implementation module."
  require Record

  def testConnection() do
      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 636}, {:ssl, true}])
      :eldap.start_tls(conn, [])
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
      :lists.map(fn i -> create(i) end, :lists.seq(1,10))
  end

  def timestamp() do
      {m, s, u} = :os.timestamp()
      (m*1000000 + s)*1000 + Float.floor(u/1000)
  end

  def create(no) do
      {:ok, conn} = :eldap.open(['127.0.0.1'], [{:port, 1489}])
      :eldap.simple_bind(conn, 'cn=admin,dc=synrc,dc=com', 'secret')
      case rem(no,100) do
           0 -> :io.format 'Client bind: ~p ~p~n', [no,timestamp()]
           _ -> :ok end
      seq = :erlang.integer_to_list(no)
      name = 'user_' ++ seq
      {time,res} = :timer.tc(fn -> :eldap.add(conn, 'cn='++name++', ou=People, dc=synrc, dc=com',
       [{ 'objectClass', ['person','inetorgperson']},
        { 'givenName', ['givenName ' ++ seq]},
        { 'cn', [name]},
        { 'sn', ['surname ' ++ seq]},
        { 'telephoneNumber', ['+380670001122']}]
      ) end)
      :eldap.close(conn)
  end

end
