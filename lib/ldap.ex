defmodule LDAP.TCP do
   require LDAP

#   def hash(x), do: :base64.encode(:crypto.hash(:md5,x))
   def hash(x), do: x
   def code(), do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
   def replace(s,a,b), do: :re.replace(s,a,b,[:global,{:return,:list}])

   def qdn(rdn) do
       trim = replace(:erlang.binary_to_list(rdn)," ",[])
       :erlang.iolist_to_binary('/'++:string.join(:lists.reverse(:string.tokens(trim,',')),'/'))
   end

   def collect(db,st,:done, acc), do: acc
   def collect(db,st,{:row,x}, acc), do: collect(db,st,Exqlite.Sqlite3.step(db,st),[:erlang.list_to_tuple(x)|acc])

   def list(name) do
       {:ok, db} = Exqlite.Sqlite3.open name
       {:ok, st} = Exqlite.Sqlite3.prepare(db, "select * from ldap")
       res = Exqlite.Sqlite3.step(db,st)
       collect(db,st,res,[])
   end

   def start() do
       instance = code()
       :io.format 'SYNRC LDAP Instance: ~p~n', [instance]
       :erlang.spawn(fn -> listen(1489,instance) end)
   end

   def listen(port,path) do
       {:ok, conn} = Exqlite.Sqlite3.open(path)
       Exqlite.Sqlite3.execute(conn, "create table ldap (uid integer primary key, rdn text, att text, val binary)")
       {:ok, statement} = Exqlite.Sqlite3.prepare(conn, "insert into ldap (rdn,att,val) values (?1,?2,?3)")
       :ok = Exqlite.Sqlite3.bind(conn, statement, [hash(qdn("cn=admin,dc=synrc,dc=com")),"cn","admin"])
       :done = Exqlite.Sqlite3.step(conn, statement)
       {:ok, statement} = Exqlite.Sqlite3.prepare(conn, "insert into ldap (rdn,att,val) values (?1,?2,?3)")
       :ok = Exqlite.Sqlite3.bind(conn, statement, [hash(qdn("cn=admin,dc=synrc,dc=com")),"rootpw","secret"])
       :done = Exqlite.Sqlite3.step(conn, statement)
       {:ok, socket} = :gen_tcp.listen(port,
         [:binary, {:packet, 0}, {:active, false}, {:reuseaddr, true}])
       accept(socket,conn)
   end

   def accept(socket,conn) do
       {:ok, fd} = :gen_tcp.accept(socket)
       :erlang.spawn(fn -> loop(fd, conn) end)
       accept(socket,conn)
   end

   def message(no, socket, {:bindRequest, {_,_,"cn=admin,dc=synrc,dc=com" = dn,{:simple, "secret"}}}, db) do
       response = LDAP."BindResponse"(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(response, no, :bindResponse, socket)
   end

   def message(no, socket, {:bindRequest, {_,_,bindDN,{:simple, password}}}, db) do
       {:ok, statement} = Exqlite.Sqlite3.prepare(db,
           "select rdn, att from ldap where rdn = ?1 and att = 'rootpw' and val = ?2")
       Exqlite.Sqlite3.bind(db, statement, [hash(qdn(bindDN)),password])
       case Exqlite.Sqlite3.step(db, statement) do
           :done ->  code = :invalidCredentials
#                     :io.format 'BIND Error: ~p~n', [code]
                     response = LDAP."BindResponse"(resultCode: code,
                         matchedDN: bindDN, diagnosticMessage: 'ERROR')
                     answer(response, no, :bindResponse, socket)
            {:row,[dn,password]} ->
#                     :io.format 'BIND DN: ~p~n', [bindDN]
                     response = LDAP."BindResponse"(resultCode: :success,
                          matchedDN: bindDN, diagnosticMessage: 'OK')
                     answer(response, no, :bindResponse, socket)
       end
   end

   def message(no, socket, {:bindRequest, {_,_,bindDN,creds}}, db) do
       code = :authMethodNotSupported
#       :io.format 'BIND ERROR: ~p~n', [code]
       response = LDAP."BindResponse"(resultCode: code,
          matchedDN: bindDN, diagnosticMessage: 'ERROR')
       answer(response, no, :bindResponse, socket)
   end

   def message(no, socket, {:searchRequest, {_,bindDN,scope,_,limit,_,_,filter,attributes}}, db) do
#       :io.format 'SEARCH DN: ~p~n', [bindDN]
#       :io.format 'SEARCH Scope: ~p~n', [scope]
#       :io.format 'SEARCH Filter: ~p~n', [filter]
#       :io.format 'SEARCH Attr: ~p~n', [attributes]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: bindDN, diagnosticMessage: 'OK')
       :lists.map(fn [cn: commonName, email: email] ->
          cn = {:'PartialAttribute', "cn", [commonName]}
          mail = {:'PartialAttribute', "mail", [email]}
          response = {:'SearchResultEntry', commonName, [cn,mail]}
          answer(response,no,:searchResEntry,socket)
       end, [[cn: "tonpa", email: 'tonpa@n2o.dev'],
             [cn: "rocco", email: 'rocco@n2o.dev']])
       answer(resp, no, :searchResDone,socket)
   end

   def message(no, socket, {:modDNRequest, {_,dn,rdn,old,_}}, db) do
#       :io.format 'MOD RDN DN: ~p~n', [dn]
#       :io.format 'MOD RDN newRDN: ~p~n', [rdn]
#       :io.format 'MOD RDN oldRDN: ~p~n', [old]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :modDNResponse, socket)
   end

   def message(no, socket, {:modifyRequest, {_,dn, attributes}}, db) do
#       :io.format 'MOD DN: ~p~n', [dn]
#       :io.format 'MOD Attr: ~p~n', [attributes]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :modifyResponse, socket)
   end

   def message(no, socket, {:compareRequest, {_,dn, assertion}}, db) do
#       :io.format 'CMP DN: ~p~n', [dn]
#       :io.format 'CMP Assertion: ~p~n', [assertion]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :compareResponse, socket)
   end

   def message(no, socket, {:addRequest, {_,dn, attributes}}, db) do
#       :io.format 'ADD REQ: ~p~n', [dn]
      {:ok, statement} = Exqlite.Sqlite3.prepare(db, "select rdn, att, val from ldap where rdn = ?1")
      Exqlite.Sqlite3.bind(db, statement, [hash(qdn(dn))])
      case Exqlite.Sqlite3.step(db, statement) do
            {:row, _} ->
#                :io.format 'ADD ERROR: ~p~n', [dn]
                resp = LDAP.'LDAPResult'(resultCode: :entryAlreadyExists, matchedDN: dn, diagnosticMessage: 'ERROR')
                answer(resp, no, :addResponse, socket)
            :done ->
                normalized =
                :lists.foldr(fn {:PartialAttribute, att, vals}, acc ->
                     :lists.map(fn val -> [hash(qdn(dn)),att,val] end, vals) ++ acc end, [], attributes)
                {_,patt} = :lists.foldr(fn [d,a,v], {acc,res}  -> {acc + 3, res ++ case res do [] -> [] ; _ -> ',' end
                        ++ :io_lib.format('(NULL,?~p,?~p,?~p)',[acc+1,acc+2,acc+3])} end, {0,[]}, normalized)
                {:ok, statement} = Exqlite.Sqlite3.prepare(db, 'insert into ldap (uid,rdn,att,val) values ' ++ patt)
                :ok = Exqlite.Sqlite3.bind(db, statement, :lists.flatten(normalized))
                :done = Exqlite.Sqlite3.step(db, statement)
#                :io.format 'ADD DN: ~p~n', [dn]
                resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
                answer(resp, no, :addResponse, socket)
       end
   end

   def message(no, socket, {:delRequest, dn}, sql) do
#       :io.format 'DEL DN: ~p~n', [dn]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :delResponse, socket)
   end

   def message(no, socket, {:extendedReq,{_,oid,val}} = msg, db) do
#       :io.format 'EXT: ~p~n', [msg]
       res = LDAP.'ExtendedResponse'(resultCode: :unavailable, diagnosticMessage: 'ERROR',
        responseName: oid, responseValue: val)
       answer(res, no, :extendedResp, socket)
   end

   def message(no, socket, {:abandonRequest, _}, db), do: :gen_tcp.close(socket)
   def message(no, socket, {:unbindRequest, _}, db), do: :gen_tcp.close(socket)

   def message(no, socket, msg, sql) do
       :io.format 'Invalid LDAP Message: ~p~n', [msg]
       :gen_tcp.close(socket)
   end

   def answer(response, no, op, socket) do
       message = LDAP."LDAPMessage"(messageID: no, protocolOp: {op, response})
#       :io.format '~p~n', [message]
       {:ok, bytes} = :'LDAP'.encode(:'LDAPMessage', message)
       :gen_tcp.send(socket, :erlang.iolist_to_binary(bytes))
   end

   def loop(socket, db) do
       case :gen_tcp.recv(socket, 0) do
            {:ok, data} ->
                 case :'LDAP'.decode(:'LDAPMessage',data) do
                      {:ok,decoded} ->
                          {:'LDAPMessage', no, payload, _} = decoded
                          :erlang.spawn(fn ->
                              res = :timer.tc(fn -> message(no, socket, payload, db) end)
#                              :io.format 'Time: ~p~n', [res]
                          end)
                          loop(socket, db)
                      {:error,_} -> :exit
                 end
            {:error, :closed} -> :exit
       end
   end
end