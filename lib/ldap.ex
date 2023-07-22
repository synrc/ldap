defmodule LDAP.TCP do
   import Exqlite.Sqlite3
   require LDAP

   def hash(x),        do: x
   def attr(k,v),      do: {:PartialAttribute, k, v}
   def node(dn,attrs), do: {:SearchResultEntry, dn, attrs}
   def string(rdn),    do: :erlang.binary_to_list(rdn)
   def binary(rdn),    do: :erlang.iolist_to_binary(rdn)
   def tok(rdn, del),  do: :string.tokens(rdn, del)
   def rev(list),      do: :lists.reverse(list)
   def code(),         do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
   def replace(s,a,b), do: :re.replace(s,a,b,[:global,{:return,:list}])
   def qdn(rdn),       do: binary('/'++:string.join(rev(tok(replace(string(rdn)," ",[]),',')),'/'))

   def collect(db,st,:done, acc),    do: acc
   def collect(db,st,{:row,x}, acc), do: collect(db,st,step(db,st),[:erlang.list_to_tuple(x)|acc])

#09:12:30.882 [info] SEARCH Filter: {:and,
# [
#   or: [
#     equalityMatch: {:AttributeValueAssertion, "objectClass", "top"},
#     substrings: {:SubstringFilter, "cn", [final: "a"]},
#     present: "objectClass"
#   ],
#   substrings: {:SubstringFilter, "objectClass", [any: "a"]}
# ]}

   def query(name) do
       {:ok, db} = open(name)
       {:ok, st} = prepare(db, "select * from ldap where rdn in (select rdn from ldap where " <>
                               " (att = 'objectClass' and val like '%a%') " <>
                               " and " <>
                               " ((att = 'objectClass') or " <>
                                 "(att = 'cn' and val like '%a%') or" <>
                                 "(att = 'objectClass' and val='top')))" )
       res = step(db,st)
       collect(db,st,res,[])
   end

   def list(name) do
       {:ok, db} = open(name)
       {:ok, st} = prepare(db, "select * from ldap")
       res = step(db,st)
       collect(db,st,res,[])
   end

   def start() do
       instance = code()
       :erlang.spawn(fn -> listen(1489,instance) end)
   end

   def initDB(path) do
       {:ok, conn} = open(path)
       :logger.info 'SYNRC LDAP Instance: ~p Connection: ~p', [path,conn]
       execute(conn, "create table ldap (rdn text,att text,val binary)")
       :ok = execute(conn, "PRAGMA journal_mode = OFF;")
       :ok = execute(conn, "PRAGMA temp_store = MEMORY;")
       :ok = execute(conn, "PRAGMA cache_size = 1000000;")
       :ok = execute(conn, "PRAGMA synchronous = 0;")
       conn
   end

   def listen(port,path) do
       conn = initDB(path)
       createDN(conn, "cn=admin,dc=synrc,dc=com", [attr("rootpw",["secret"]),attr("cn",["admin"])])
       createDN(conn, "dc=synrc,dc=com", [attr("dc",["synrc"]),attr("objectClass",["top","domain"])])
       createDN(conn, "ou=schema", [attr("ou",["schema"]),attr("objectClass",["top","domain"])])
       {:ok, socket} = :gen_tcp.listen(port,
         [:binary, {:packet, 0}, {:active, false}, {:reuseaddr, true}])
       accept(socket,conn)
   end

   def accept(socket,conn) do
       {:ok, fd} = :gen_tcp.accept(socket)
       :erlang.spawn(fn -> loop(fd, conn) end)
       accept(socket,conn)
   end

   def message(no, socket, {:bindRequest, {_,_,bindDN,{:simple, password}}}, db) do
       {:ok, statement} = prepare(db,
           "select rdn, att from ldap where rdn = ?1 and att = 'rootpw' and val = ?2")
       bind(db, statement, [hash(qdn(bindDN)),password])
       case step(db, statement) do
           :done ->  code = :invalidCredentials
                     :logger.error 'BIND Error: ~p', [code]
                     response = LDAP."BindResponse"(resultCode: code,
                         matchedDN: "", diagnosticMessage: 'ERROR')
                     answer(response, no, :bindResponse, socket)
            {:row,[dn,password]} ->
                     :logger.info 'BIND DN: ~p', [bindDN]
                     response = LDAP."BindResponse"(resultCode: :success,
                          matchedDN: "", diagnosticMessage: 'OK')
                     answer(response, no, :bindResponse, socket)
       end
   end

   def message(no, socket, {:bindRequest, {_,_,bindDN,creds}}, db) do
       code = :authMethodNotSupported
       :logger.info 'BIND ERROR: ~p', [code]
       response = LDAP."BindResponse"(resultCode: code,
          matchedDN: "", diagnosticMessage: 'ERROR')
       answer(response, no, :bindResponse, socket)
   end

   def message(no, socket, {:searchRequest, {_,"",scope,_,limit,_,_,filter,attributes}}, db) do
       :logger.info 'DSE Scope: ~p', [scope]
       :logger.info 'DSE Filter: ~p', [filter]
       :logger.info 'DSE Attr: ~p', [attributes]

       :lists.map(fn response -> answer(response,no,:searchResEntry,socket) end,
         [ node("", [
              attr("supportedLDAPVersion", ['3']),
              attr("namingContexts", ['dc=synrc,dc=com','ou=schema']),
              attr("supportedControl", ['1.3.6.1.4.1.4203.1.10.1']),
              attr("supportedFeatures", ['1.3.6.1.1.14', '1.3.6.1.4.1.4203.1.5.1']),
              attr("supportedExtensions", ['1.3.6.1.4.1.4203.1.11.3']),
              attr("altServer", ['ldap.synrc.com']),
              attr("subschemaSubentry", ['ou=schema']),
              attr("vendorName", ['SYNRC LDAP']),
              attr("vendorVersion", ['1.0']),
              attr("supportedSASLMechanisms", ['SIMPLE']),
              attr("objectClass", ['top','extensibleObject']),
              attr("entryUUID", [code()])])])

       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: 'OK')
       answer(resp, no, :searchResDone,socket)
   end

   def message(no, socket, {:searchRequest, {_,"dc=synrc,dc=com",scope,_,limit,_,_,filter,attributes}}, db) do
       bindDN = "dc=synrc,dc=com"
       :logger.info 'SEARCH DN: ~p', [bindDN]
       :logger.info 'SEARCH Scope: ~p', [scope]
       :logger.info 'SEARCH Filter: ~p', [filter]
       :logger.info 'SEARCH Attr: ~p', [attributes]

       synrc = 
            [node("dc=synrc,dc=com", [
                attr("dc",["synrc"]),
                attr("objectClass",['domain','top'])])
            ]

        users =
            [node("cn=admin,dc=synrc,dc=com", [
                attr("cn",["admin"]),
                attr("dn",["dc=synrc,dc=com"]),
                attr("uid",['1000']),
                attr("objectClass",['inetOrgPerson','posixAccount'])]),

            node("cn=rocco,dc=synrc,dc=com", [
                attr("cn",["rocco"]),
                attr("dn",["dc=synrc,dc=com"]),
                attr("uid",['2000']),
                attr("objectClass",['inetOrgPerson','posixAccount'])])]

       :lists.map(fn response -> answer(response,no,:searchResEntry,socket) end,

           case scope do
             :baseObject -> synrc
             :singleLevel -> users
             :wholeSubtree -> synrc ++ users

           end)

       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: 'OK')
       answer(resp, no, :searchResDone,socket)
   end

   def message(no, socket, {:searchRequest, {_,"ou=schema",scope,_,limit,_,_,filter,attributes}}, db) do
       bindDN = "ou=schema"
       :logger.info 'SEARCH DN: ~p', [bindDN]
       :logger.info 'SEARCH Scope: ~p', [scope]
       :logger.info 'SEARCH Filter: ~p', [filter]
       :logger.info 'SEARCH Attr: ~p', [attributes]

       schema = [
            node("ou=schema", [
                attr("ou",["schema"]),
                attr("objectClass",['organizationalUnit','top'])])
            ]


       :lists.map(fn response -> answer(response,no,:searchResEntry,socket) end,

           case scope do
             :wholeSubtree -> schema
             :baseObject -> schema
             :singleLevel -> []
            end
         )

       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: 'OK')
       answer(resp, no, :searchResDone,socket)
   end

   def message(no, socket, {:searchRequest, {_,bindDN,scope,_,limit,_,_,filter,attributes}}, db) do

       :logger.info 'SEARCH DN: ~p', [bindDN]
       :logger.info 'SEARCH Scope: ~p', [scope]
       :logger.info 'SEARCH Filter: ~p', [filter]
       :logger.info 'SEARCH Attr: ~p', [attributes]

       admin =
            [node("cn=admin,dc=synrc,dc=com", [
                attr("cn",["admin"]),
                attr("uid",['1000']),
                attr("objectClass",['inetOrgPerson','posixAccount'])])]

       rocco =
            [node("cn=rocco,dc=synrc,dc=com", [
                attr("cn",["rocco"]),
                attr("uid",['2000']),
                attr("objectClass",['inetOrgPerson','posixAccount'])])]

       :lists.map(fn response -> answer(response,no,:searchResEntry,socket) end, 

         case scope do
            :baseObject ->
                case bindDN do
                   "cn=rocco,dc=synrc,dc=com" -> rocco
                   "cn=admin,dc=synrc,dc=com" -> admin
                end
            _ -> []

         end

       )

       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: 'OK')
       answer(resp, no, :searchResDone,socket)
   end

   def message(no, socket, {:modDNRequest, {_,dn,rdn,old,_}}, db) do
       :logger.info 'MOD RDN DN: ~p', [dn]
       :logger.info 'MOD RDN newRDN: ~p', [rdn]
       :logger.info 'MOD RDN oldRDN: ~p', [old]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :modDNResponse, socket)
   end

   def message(no, socket, {:modifyRequest, {_,dn, attributes}}, db) do
      {:ok, statement} = prepare(db, "select rdn, att, val from ldap where rdn = ?1")
      bind(db, statement, [hash(qdn(dn))])
      case step(db, statement) do
           {:row, _} -> :logger.info 'MOD DN: ~p', [dn]
                        modifyDN(db, dn, attributes)
                        resp = LDAP.'LDAPResult'(resultCode: :success,
                            matchedDN: dn, diagnosticMessage: 'OK')
                        answer(resp, no, :modifyResponse, socket)
           :done ->     :logger.info 'MOD ERROR: ~p', [dn]
                        resp = LDAP.'LDAPResult'(resultCode: :noSuchObject,
                           matchedDN: dn, diagnosticMessage: 'ERROR')
                        answer(resp, no, :modifyResponse, socket)
      end
   end

   def message(no, socket, {:compareRequest, {_,dn, assertion}}, db) do
       :logger.info 'CMP DN: ~p', [dn]
       :logger.info 'CMP Assertion: ~p', [assertion]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :compareResponse, socket)
   end

   def message(no, socket, {:addRequest, {_,dn, attributes}}, db) do
      {:ok, statement} = prepare(db, "select rdn, att, val from ldap where rdn = ?1")
      bind(db, statement, [hash(qdn(dn))])
      case step(db, statement) do
            {:row, _} ->
                :logger.info 'ADD ERROR: ~p', [dn]
                resp = LDAP.'LDAPResult'(resultCode: :entryAlreadyExists,
                       matchedDN: dn, diagnosticMessage: 'ERROR')
                answer(resp, no, :addResponse, socket)
            :done ->
                createDN(db, dn, attributes)
                :logger.info 'ADD DN: ~p', [dn]
                resp = LDAP.'LDAPResult'(resultCode: :success,
                       matchedDN: dn, diagnosticMessage: 'OK')
                answer(resp, no, :addResponse, socket)
       end
   end

   def message(no, socket, {:delRequest, dn}, db) do
       :logger.info 'DEL DN: ~p', [dn]
       deleteDN(db, dn)
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
       :logger.info 'Invalid LDAP Message: ~p', [msg]
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

   def modifyDN(db, dn, attributes), do:
       :lists.map(fn {_, :add, x}     -> modifyAdd(db,dn,x)
                     {_, :replace, x} -> modifyReplace(db,dn,x)
                     {_, :delete, x}  -> modifyDelete(db,dn,x) end, attributes)

   def modifyAdd(db, dn, {_,att,[val]}) do
       {:ok, st} = prepare(db, "insert into ldap (rdn,att,val) values (?1,?2,?3)")
       :logger.info 'MOD ADD RDN: ~p', [hash(qdn(dn))]
       bind(db, st, [hash(qdn(dn)),att,val])
       step(db,st)
   end

   def modifyReplace(db, dn, {_,att,[val]}) do
       {:ok, st} = prepare(db, "update ldap set val = ?1 where rdn = ?2 and att = ?3")
       :logger.info 'MOD REPLACE RDN: ~p', [hash(qdn(dn))]
       bind(db, st, [val,hash(qdn(dn)),att])
       step(db,st)
   end

   def modifyDelete(db, dn, {_,att,_}) do
       {:ok, st} = prepare(db, "delete from ldap where rdn = ?1 and att = ?2")
       :logger.info 'MOD DEL RDN: ~p', [hash(qdn(dn))]
       bind(db, st, [hash(qdn(dn)),att])
       res = step(db,st)
       collect(db,st,res,[])
   end

   def deleteDN(db, dn) do
       {:ok, st} = prepare(db, "delete from ldap where rdn = ?1")
       bind(db, st, [hash(qdn(dn))])
       res = step(db,st)
       collect(db,st,res,[])
   end

   def compareDN(db, dn, assertions) do
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

   def loop(socket, db) do
       case :gen_tcp.recv(socket, 0) do
            {:ok, data} ->
                 case :'LDAP'.decode(:'LDAPMessage',data) do
                      {:ok,decoded} ->
                          {:'LDAPMessage', no, payload, _} = decoded
                          message(no, socket, payload, db)
                          loop(socket, db)
                      {:error,reason} ->
                         :logger.error 'ERROR: ~p', [reason]
                        :exit
                 end
            {:error, :closed} -> :exit
       end
   end
end