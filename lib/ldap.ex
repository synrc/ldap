defmodule LDAP.TCP do
   import Exqlite.Sqlite3
   require LDAP

   def hash(x),        do: x
   def attr(k,v),      do: {:PartialAttribute, k, v}
   def string(rdn),    do: :erlang.binary_to_list(rdn)
   def binary(rdn),    do: :erlang.iolist_to_binary(rdn)
   def tok(rdn, del),  do: :string.tokens(rdn, del)
   def rev(list),      do: :lists.reverse(list)
   def code(),         do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
   def replace(s,a,b), do: :re.replace(s,a,b,[:global,{:return,:list}])
   def qdn(rdn),       do: binary('/'++:string.join(rev(tok(replace(string(rdn)," ",[]),',')),'/'))

   def collect(db,st,:done, acc),    do: acc
   def collect(db,st,{:row,x}, acc), do: collect(db,st,step(db,st),[:erlang.list_to_tuple(x)|acc])

   def list(name) do
       {:ok, db} = open(name)
       {:ok, st} = prepare(db, "select * from ldap")
       res = step(db,st)
       collect(db,st,res,[])
   end

   def start() do
       instance = code()
       :io.format 'SYNRC LDAP Instance: ~p~n', [instance]
       :erlang.spawn(fn -> listen(1489,instance) end)
   end

   def initDB(path) do
       {:ok, conn} = Exqlite.Sqlite3.open(path)
       Exqlite.Sqlite3.execute(conn, "create table ldap (uid integer primary key,rdn text,att text,val binary)")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA journal_mode = OFF;")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA temp_store = MEMORY;")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA cache_size = 1000000;")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA synchronous = 0;")
       conn
   end

   def listen(port,path) do
       conn = initDB(path)
       createDN(conn, "cn=admin,dc=synrc,dc=com", [attr("rootpw",["secret"]),attr("cn",["admin"])])
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
       {:ok, statement} = prepare(db,
           "select rdn, att from ldap where rdn = ?1 and att = 'rootpw' and val = ?2")
       bind(db, statement, [hash(qdn(bindDN)),password])
       case step(db, statement) do
           :done ->  code = :invalidCredentials
                     :logger.error 'BIND Error: ~p', [code]
                     response = LDAP."BindResponse"(resultCode: code,
                         matchedDN: bindDN, diagnosticMessage: 'ERROR')
                     answer(response, no, :bindResponse, socket)
            {:row,[dn,password]} ->
                     :logger.info 'BIND DN: ~p', [bindDN]
                     response = LDAP."BindResponse"(resultCode: :success,
                          matchedDN: bindDN, diagnosticMessage: 'OK')
                     answer(response, no, :bindResponse, socket)
       end
   end

   def message(no, socket, {:bindRequest, {_,_,bindDN,creds}}, db) do
       code = :authMethodNotSupported
       :logger.info 'BIND ERROR: ~p', [code]
       response = LDAP."BindResponse"(resultCode: code,
          matchedDN: bindDN, diagnosticMessage: 'ERROR')
       answer(response, no, :bindResponse, socket)
   end

   def message(no, socket, {:searchRequest, {_,bindDN,scope,_,limit,_,_,filter,attributes}}, db) do
       :logger.info 'SEARCH DN: ~p', [bindDN]
       :logger.info 'SEARCH Scope: ~p', [scope]
       :logger.info 'SEARCH Filter: ~p', [filter]
       :logger.info 'SEARCH Attr: ~p', [attributes]
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
       :logger.info 'MOD RDN DN: ~p~n', [dn]
       :logger.info 'MOD RDN newRDN: ~p~n', [rdn]
       :logger.info 'MOD RDN oldRDN: ~p~n', [old]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :modDNResponse, socket)
   end

   def message(no, socket, {:modifyRequest, {_,dn, attributes}}, db) do
       :logger.info 'MOD DN: ~p~n', [dn]
       :logger.info 'MOD Attr: ~p~n', [attributes]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :modifyResponse, socket)
   end

   def message(no, socket, {:compareRequest, {_,dn, assertion}}, db) do
       :logger.info 'CMP DN: ~p~n', [dn]
       :logger.info 'CMP Assertion: ~p~n', [assertion]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :compareResponse, socket)
   end

   def message(no, socket, {:addRequest, {_,dn, attributes}}, db) do
       :logger.info 'ADD REQ: ~p~n', [dn]
      {:ok, statement} = prepare(db, "select rdn, att, val from ldap where rdn = ?1")
      bind(db, statement, [hash(qdn(dn))])
      case Exqlite.Sqlite3.step(db, statement) do
            {:row, _} ->
                :logger.info 'ADD ERROR: ~p~n', [dn]
                resp = LDAP.'LDAPResult'(resultCode: :entryAlreadyExists, matchedDN: dn, diagnosticMessage: 'ERROR')
                answer(resp, no, :addResponse, socket)
            :done ->
                createDN(db, dn, attributes)
                :logger.info 'ADD DN: ~p ~p', [dn,attributes]
                resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
                answer(resp, no, :addResponse, socket)
       end
   end

   def message(no, socket, {:delRequest, dn}, sql) do
       :logger.info 'DEL DN: ~p', [dn]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :delResponse, socket)
   end

   def message(no, socket, {:extendedReq,{_,oid,val}} = msg, db) do
       :logger.info 'EXT: ~p', [msg]
       res = LDAP.'ExtendedResponse'(resultCode: :unavailable, diagnosticMessage: 'ERROR',
        responseName: oid, responseValue: val)
       answer(res, no, :extendedResp, socket)
   end

   def message(no, socket, {:abandonRequest, _}, db), do: :gen_tcp.close(socket)
   def message(no, socket, {:unbindRequest, _}, db), do: :gen_tcp.close(socket)

   def message(no, socket, msg, sql) do
       :logger.info 'Invalid LDAP Message: ~p~n', [msg]
       :gen_tcp.close(socket)
   end

   def answer(response, no, op, socket) do
       message = LDAP."LDAPMessage"(messageID: no, protocolOp: {op, response})
       {:ok, bytes} = :'LDAP'.encode(:'LDAPMessage', message)
       :gen_tcp.send(socket, :erlang.iolist_to_binary(bytes))
   end

   def appendNotEmpty([]),  do: []
   def appendNotEmpty(res) do
       res ++ case res do [] -> [] ; _ -> ',' end
   end

   def createDN(db, dn, attributes) do
       norm  = :lists.foldr(fn {:PartialAttribute, att, vals}, acc ->
               :lists.map(fn val -> [hash(qdn(dn)),att,val] end, vals) ++ acc end, [], attributes)
       {_,p} = :lists.foldr(fn x, {acc,res}  -> {acc + length(x), appendNotEmpty(res) ++
               :io_lib.format('(?~p,?~p,?~p)',[acc+1,acc+2,acc+3])} end, {0,[]}, norm)
       {:ok, statement} = prepare(db, 'insert into ldap (rdn,att,val) values ' ++ p ++ '')
       :ok = bind(db, statement, :lists.flatten(norm))
       :done = step(db, statement)
   end

   def initDB(path) do
       {:ok, conn} = Exqlite.Sqlite3.open(path)
       :ok = Exqlite.Sqlite3.execute(conn, "create table ldap (uid integer primary key,rdn text,att text,val binary)")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA journal_mode = OFF;")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA temp_store = MEMORY;")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA cache_size = 1000000;")
       :ok = Exqlite.Sqlite3.execute(conn, "PRAGMA synchronous = 0;")
       conn
   end

   def loop(socket, db) do
       case :gen_tcp.recv(socket, 0) do
            {:ok, data} ->
                 case :'LDAP'.decode(:'LDAPMessage',data) do
                      {:ok,decoded} ->
                          {:'LDAPMessage', no, payload, _} = decoded
                          :erlang.spawn(fn ->
                              message(no, socket, payload, db)
                          end)
                          loop(socket, db)
                      {:error,_} -> :exit
                 end
            {:error, :closed} -> :exit
       end
   end
end