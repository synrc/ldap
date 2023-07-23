defmodule LDAP do
    import Exqlite.Sqlite3
    require DS
    use Application
    use Supervisor

    def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
    def start(_type, _args) do
        :logger.add_handlers(:ldap)
        :supervisor.start_link({:local, __MODULE__}, __MODULE__, [])
    end

    # Prelude

    def hash(x),        do: x
    def attr(k,v),      do: {:PartialAttribute, k, v}
    def node(dn,attrs), do: {:SearchResultEntry, dn, attrs}
    def string(rdn),    do: :erlang.binary_to_list(rdn)
    def binary(rdn),    do: :erlang.iolist_to_binary(rdn)
    def tok(rdn, del),  do: :string.tokens(rdn, del)
    def rev(list),      do: :lists.reverse(list)
    def code(),         do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
    def replace(s,a,b), do: :re.replace(s,a,b,[:global,{:return,:list}])
    def qdn(rdn),       do: binary(:string.join(rev(tok(replace(string(rdn)," ",[]),',')),'/'))
    def qdn0(rdn),      do: binary(:string.join(rev(tok(string(rdn),'/')),','))
    def bin(x) when is_integer(x), do: :erlang.integer_to_binary(x)
    def bin(x) when is_list(x), do: :erlang.iolist_to_binary(x)
    def bin(x), do: x
    def collect0(db,st,:done, acc),    do: acc
    def collect0(db,st,{:row,x}, acc), do: collect0(db,st,step(db,st),[:erlang.list_to_tuple(x)|acc])

    def collect(socket,no,db,st,:done, dn, att, values, attributes, nodes) do
        answer(node(qdn0(dn),[attr(att,values)|attributes]),no,:searchResEntry,socket)
        [node(dn,[attr(att,values)|attributes])|nodes]
    end

    def collect(socket,no,db,st,{:row,[xrdn,xatt,yval]}, dn, att, values, attributes, nodes) do
        xval = bin(yval)
        next = step(db,st)
        case xrdn == dn do
           false ->
              answer(node(qdn0(dn),[attr(att,values)|attributes]),no,:searchResEntry,socket)
              collect(socket,no,db,st,next,xrdn,xatt,[xval],[],[node(dn,[attr(att,values)|attributes])|nodes])
           true ->
              case xatt == att do
                 true -> collect(socket,no,db,st,next,dn,xatt,[xval|values],attributes,nodes)
                 false -> collect(socket,no,db,st,next,dn,xatt,[xval],[attr(att,values)|attributes],nodes)
              end
        end
    end

    def query(:baseObject,q,dn), do:
        "select * from ldap where rdn = '#{dn}'"

    def query(:singleLevel,q,dn), do:
        "select * from ldap where rdn in (select rdn from ldap where (rdn like '#{dn}/%') and " <> match(q) <> ")"

    def query(:wholeSubtree,q,dn), do:
        "select * from ldap where rdn in (select rdn from ldap where (rdn like '#{dn}%') and " <> match(q) <> ")"

    def join(list, op), do:
        :string.join(:lists.map(fn x -> :erlang.binary_to_list("(" <> match(x) <> ")") end, list), op)
        |> :erlang.iolist_to_binary

    def match({:equalityMatch, {_, a, v}}),         do: "(att = '#{a}' and val    = '#{v}')"
    def match({:substrings, {_, a, [final: v]}}),   do: "(att = '#{a}' and val like '#{v}%')"
    def match({:substrings, {_, a, [initial: v]}}), do: "(att = '#{a}' and val like '%#{v}')"
    def match({:substrings, {_, a, [any: v]}}),     do: "(att = '#{a}' and val like '%#{v}%')"
    def match({:present, a}),                       do: "(att = '#{a}')"
    def match({:and, list}),                        do: "(" <> join(list, 'and') <> ")"
    def match({:or,  list}),                        do: "(" <> join(list, 'or')  <> ")"
    def match({:not, x}),                           do: "(not(" <> match(x) <> "))"

    def select(socket, no, db, filter, scope, dn) do
        {:ok, st} = prepare(db, query(scope, filter, dn))
        case step(db,st) do
             :done -> []
             {:row, [dn,att,val]} -> collect(socket,no,db,st,{:row,[dn,att,val]},dn,att,[],[],[])
        end
    end

    def list(name) do
        {:ok, db} = open(name)
        {:ok, st} = prepare(db, "select * from ldap")
        res = step(db,st)
        collect0(db,st,res,[])
    end

    def start() do
        instance = code()
        :erlang.spawn(fn -> listen(:application.get_env(:ldap,:port,1489),instance) end)
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
        createDN(conn, "dc=synrc,dc=com", [attr("dc",["synrc"]),attr("objectClass",["top","domain"])])
        createDN(conn, "ou=schema", [attr("ou",["schema"]),attr("objectClass",["top","domain"])])
        createDN(conn, "cn=tonpa,dc=synrc,dc=com", [attr("cn",["tonpa"]),attr("uid",["1000"]),attr("objectClass",["inetOrgPerson","posixAccount"])])
        createDN(conn, "cn=rocco,dc=synrc,dc=com", [attr("cn",["rocco"]),attr("uid",["1001"]),attr("objectClass",["inetOrgPerson","posixAccount"])])
        createDN(conn, "cn=admin,dc=synrc,dc=com", [attr("rootpw",["secret"]),attr("cn",["admin"]),attr("objectClass",["inetOrgPerson"])])
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
                      response = DS."BindResponse"(resultCode: code,
                          matchedDN: "", diagnosticMessage: 'ERROR')
                      answer(response, no, :bindResponse, socket)
             {:row,[dn,password]} ->
                      :logger.info 'BIND DN: ~p', [bindDN]
                      response = DS."BindResponse"(resultCode: :success,
                           matchedDN: "", diagnosticMessage: 'OK')
                      answer(response, no, :bindResponse, socket)
        end
    end

    def message(no, socket, {:bindRequest, {_,_,bindDN,creds}}, db) do
        code = :authMethodNotSupported
        :logger.info 'BIND ERROR: ~p', [code]
        response = DS."BindResponse"(resultCode: code,
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

        resp = DS.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: 'OK')
        answer(resp, no, :searchResDone,socket)
    end

    def message(no, socket, {:searchRequest, {_,bindDN,scope,_,limit,_,_,filter,attributes}}, db) do
        :logger.info 'SEARCH DN: ~p', [qdn(bindDN)]
        :logger.info 'SEARCH Scope: ~p', [scope]
        :logger.info 'SEARCH Filter: ~p', [query(scope, filter, qdn(bindDN))]
        :logger.info 'SEARCH Attr: ~p', [attributes]
        select(socket, no, db, filter, scope, qdn(bindDN))
        resp = DS.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: 'OK')
        answer(resp, no, :searchResDone, socket)
    end

    def message(no, socket, {:modDNRequest, {_,dn,rdn,old,_}}, db) do
        :logger.info 'MOD RDN DN: ~p', [dn]
        :logger.info 'MOD RDN newRDN: ~p', [rdn]
        :logger.info 'MOD RDN oldRDN: ~p', [old]
        resp = DS.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
        answer(resp, no, :modDNResponse, socket)
    end

    def message(no, socket, {:modifyRequest, {_,dn, attributes}}, db) do
       {:ok, statement} = prepare(db, "select rdn, att, val from ldap where rdn = ?1")
       bind(db, statement, [hash(qdn(dn))])
       case step(db, statement) do
            {:row, _} -> :logger.info 'MOD DN: ~p', [dn]
                         modifyDN(db, dn, attributes)
                         resp = DS.'LDAPResult'(resultCode: :success,
                             matchedDN: dn, diagnosticMessage: 'OK')
                         answer(resp, no, :modifyResponse, socket)
            :done ->     :logger.info 'MOD ERROR: ~p', [dn]
                         resp = DS.'LDAPResult'(resultCode: :noSuchObject,
                            matchedDN: dn, diagnosticMessage: 'ERROR')
                         answer(resp, no, :modifyResponse, socket)
       end
    end

    def message(no, socket, {:compareRequest, {_,dn, assertion}}, db) do
        :logger.info 'CMP DN: ~p', [dn]
        :logger.info 'CMP Assertion: ~p', [assertion]
        result = compareDN(db, db, assertion)
        response = DS.'LDAPResult'(resultCode: result, matchedDN: dn, diagnosticMessage: 'OK')
        answer(response, no, :compareResponse, socket)
    end

    def message(no, socket, {:addRequest, {_,dn, attributes}}, db) do
        {:ok, statement} = prepare(db, "select rdn, att, val from ldap where rdn = ?1")
        bind(db, statement, [hash(qdn(dn))])
        case step(db, statement) do
             {:row, _} ->
                 :logger.info 'ADD ERROR: ~p', [dn]
                 resp = DS.'LDAPResult'(resultCode: :entryAlreadyExists,
                        matchedDN: dn, diagnosticMessage: 'ERROR')
                 answer(resp, no, :addResponse, socket)
             :done ->
                 createDN(db, dn, attributes)
                 :logger.info 'ADD DN: ~p', [dn]
                 resp = DS.'LDAPResult'(resultCode: :success,
                        matchedDN: dn, diagnosticMessage: 'OK')
                 answer(resp, no, :addResponse, socket)
        end
    end

    def message(no, socket, {:delRequest, dn}, db) do
        :logger.info 'DEL DN: ~p', [dn]
        deleteDN(db, dn)
        resp = DS.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
        answer(resp, no, :delResponse, socket)
    end

    def message(no, socket, {:extendedReq,{_,oid,val}} = msg, db) do
        :logger.info 'EXT: ~p', [msg]
        res = DS.'ExtendedResponse'(resultCode: :unavailable, diagnosticMessage: 'ERROR',
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
        message = DS."LDAPMessage"(messageID: no, protocolOp: {op, response})
        {:ok, bytes} = :'LDAP'.encode(:'LDAPMessage', message)
        send = :gen_tcp.send(socket, :erlang.iolist_to_binary(bytes))
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
        collect0(db,st,res,[])
    end

    def deleteDN(db, dn) do
        {:ok, st} = prepare(db, "delete from ldap where rdn = ?1")
        bind(db, st, [hash(qdn(dn))])
        res = step(db,st)
        collect0(db,st,res,[])
    end

    def compareDN(db, dn, assertion) do
        :compareFalse
    end

    def createDN(db, dn, attributes) do
        norm  = :lists.foldr(fn {:PartialAttribute, att, vals}, acc ->
                :lists.map(fn val -> [qdn(dn),att,val] end, vals) ++ acc end, [], attributes)
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
