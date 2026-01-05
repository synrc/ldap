defmodule LDAP do
    @moduledoc """
    The LDAPv3 server implementation module.
    """

    import Exqlite.Sqlite3
    require LDAP.DS
    use Application
    use Supervisor

    def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
    def start(_type, _args) do
       :logger.add_handlers(:ldap)
        LDAP.start
        :supervisor.start_link({:local, LDAP}, LDAP, [])
    end

    # Prelude

    defp hash(x),        do: x
    defp string(rdn),    do: :erlang.binary_to_list(rdn)
    defp binary(rdn),    do: :erlang.iolist_to_binary(rdn)
    defp tok(rdn, del),  do: :string.tokens(rdn, del)
    defp rev(list),      do: :lists.reverse(list)
    defp code(),         do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
    defp replace(s,a,b), do: :re.replace(s,a,b,[:global,{:return,:list}])
    defp qdn(rdn),       do: binary(:string.join(rev(tok(replace(string(rdn)," ",[]),~c",")),~c"/"))
    defp qdn0(rdn),      do: binary(:string.join(rev(tok(string(rdn),~c"/")),~c","))
    defp bin(x) when is_integer(x), do: :erlang.integer_to_binary(x)
    defp bin(x) when is_list(x), do: :erlang.iolist_to_binary(x)
    defp bin(x), do: x
    defp collect0(_db,_st,:done, acc),    do: acc
    defp collect0(db,st,{:row,x}, acc), do: collect0(db,st,step(db,st),[:erlang.list_to_tuple(x)|acc])

    # Prelude

    @doc "The `PartialAttribute` ASN.1 constructor."
    def attr(k,v),      do: {:PartialAttribute, k, v}
    @doc "The `SearchResultEntry` ASN.1 constructor."
    def node(dn,attrs), do: {:SearchResultEntry, dn, attrs}

    # Collect results from Search Query

    defp collect(socket,no,_db,_st,:done, dn, att, values, attributes, nodes) do
        answer(node(qdn0(dn),[attr(att,values)|attributes]),no,:searchResEntry,socket)
        [node(dn,[attr(att,values)|attributes])|nodes]
    end

    defp collect(socket,no,db,st,{:row,[xrdn,xatt,yval]}, dn, att, values, attributes, nodes) do
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

    # SQL query

    defp query(:baseObject,_q,dn), do:
        "select * from ldap where rdn = '#{dn}'"

    defp query(:singleLevel,q,dn), do:
        "select * from ldap where rdn in (select rdn from ldap where (rdn like '#{dn}/%') and " <> match(q) <> ")"

    defp query(:wholeSubtree,q,dn), do:
        "select * from ldap where rdn in (select rdn from ldap where (rdn like '#{dn}%') and " <> match(q) <> ")"

    defp join(list, op), do:
        :string.join(:lists.map(fn x -> :erlang.binary_to_list("(" <> match(x) <> ")") end, list), op)
        |> :erlang.iolist_to_binary


    defp match({:equalityMatch, {_, a, v}}),         do: "(att = '#{a}' and val    = '#{v}')"
    defp match({:substrings, {_, a, [final: v]}}),   do: "(att = '#{a}' and val like '#{v}%')"
    defp match({:substrings, {_, a, [initial: v]}}), do: "(att = '#{a}' and val like '%#{v}')"
    defp match({:substrings, {_, a, [any: v]}}),     do: "(att = '#{a}' and val like '%#{v}%')"
    defp match({:present, a}),                       do: "(att = '#{a}')"
    defp match({:and, list}),                        do: "(" <> join(list, ~c"and") <> ")"
    defp match({:or,  list}),                        do: "(" <> join(list, ~c"or")  <> ")"
    defp match({:not, x}),                           do: "(not(" <> match(x) <> "))"

    # Search

    defp search(socket, no, db, filter, scope, dn) do
        {:ok, st} = prepare(db, query(scope, filter, dn))
        case step(db,st) do
             :done -> []
             {:row, [dn,att,val]} -> collect(socket,no,db,st,{:row,[dn,att,val]},dn,att,[],[],[])
        end
    end

    # Dump database

    @doc "Dump database."
    def list(name) do
        {:ok, db} = open(name)
        {:ok, st} = prepare(db, "select * from ldap")
        res = step(db,st)
        collect0(db,st,res,[])
    end

    # Start

    @doc "Start server base on `:port` and `:instance` application environment parameters."
    def start() do
        :logger.info ~c"Instance: ~p", [code()]
        :erlang.spawn(fn ->
            listen(:application.get_env(:ldap,:port,1489),
                   :application.get_env(:ldap,:instance,code())) end)
    end

    # Create table and tune SQL settings

    defp initDB(path) do
        {:ok, conn} = open(path)
        execute(conn, "create table ldap (rdn text,att text,val binary)")
        :ok = execute(conn, "PRAGMA journal_mode = OFF;")
        :ok = execute(conn, "PRAGMA temp_store = MEMORY;")
        :ok = execute(conn, "PRAGMA cache_size = 1000000;")
        :ok = execute(conn, "PRAGMA synchronous = 0;")
        conn
    end

    # TCP listen

    defp listen(port,path) do
        conn = initDB(path)
        createDN(conn, "dc=synrc,dc=com", [attr("dc",["synrc"]),attr("objectClass",["top","domain"])])
        createDN(conn, "dc=mil,dc=gov", [attr("dc",["mil"]),attr("objectClass",["top","domain"])])
        createDN(conn, "cn=Vampire,dc=mil,dc=gov", [attr("cn",["Vampire"]),attr("uid",["1"]),attr("objectClass",[])])
        createDN(conn, "cn=PD2,dc=mil,dc=gov", [attr("cn",["PD2"]),attr("uid",["2"]),attr("objectClass",[])])
        createDN(conn, "ou=schema", [attr("ou",["schema"]),attr("objectClass",["top","domain"])])
        createDN(conn, "cn=tonpa,dc=synrc,dc=com", [attr("cn",["tonpa"]),attr("uid",["1000"]),attr("objectClass",["inetOrgPerson","posixAccount"])])
        createDN(conn, "cn=rocco,dc=synrc,dc=com", [attr("cn",["rocco"]),attr("uid",["1001"]),attr("objectClass",["inetOrgPerson","posixAccount"])])
        createDN(conn, "cn=admin,dc=synrc,dc=com", [attr("rootpw",["secret"]),attr("cn",["admin"]),attr("objectClass",["inetOrgPerson"])])
        {:ok, socket} = :gen_tcp.listen(port,
          [:binary, {:packet, 0}, {:active, false}, {:reuseaddr, true}])
        accept(socket,conn)
    end

    # TCP accept

    defp accept(socket,conn) do
        {:ok, fd} = :gen_tcp.accept(socket)
        mod = :application.get_env(:ldap,:module,LDAP)
        :erlang.spawn(fn -> loop(fd, conn, mod) end)
        accept(socket,conn)
    end

    # TCP looper

    defp loop(socket, db, mod) do
        case :gen_tcp.recv(socket, 0) do
             {:ok, data} ->
                  case :'LDAP'.decode(:'LDAPMessage',data) do
                       {:ok,decoded} ->
                           {:'LDAPMessage', no, payload, _} = decoded
                           mod.message(no, socket, payload, db)
                           loop(socket, db, mod)
                       {:error,reason} ->
                          :logger.error ~c"ERROR: ~p", [reason]
                         :exit
                  end
             {:error, :closed} -> :exit
        end
    end

    # LDAP protocol messagae handler

    @doc "The public LDAPv3 protocol handler function."

    def message(no, socket, {:bindRequest, {_,_,bindDN,{:simple, password}}}, db) do
        {:ok, statement} = prepare(db,
            "select rdn, att from ldap where rdn = ?1 and att = 'rootpw' and val = ?2")
        bind(db, statement, [hash(qdn(bindDN)),password])
        case step(db, statement) do
            :done ->  code = :invalidCredentials
                      :logger.error ~c"BIND Error: ~p", [code]
                      response = LDAP.DS."BindResponse"(resultCode: code,
                          matchedDN: "", diagnosticMessage: ~c"ERROR")
                      answer(response, no, :bindResponse, socket)
             {:row,[_dn,_password]} ->
                      :logger.info ~c"BIND DN: ~p", [bindDN]
                      response = LDAP.DS."BindResponse"(resultCode: :success,
                           matchedDN: "", diagnosticMessage: ~c"OK")
                      answer(response, no, :bindResponse, socket)
        end
    end

    def message(no, socket, {:bindRequest, {_,_,_bindDN,_creds}}, _db) do
        code = :authMethodNotSupported
        :logger.info ~c"BIND ERROR: ~p", [code]
        response = LDAP.DS."BindResponse"(resultCode: code,
           matchedDN: "", diagnosticMessage: ~c"ERROR")
        answer(response, no, :bindResponse, socket)
    end

    def message(no, socket, {:searchRequest, {_,"",scope,_,_limit,_,_,filter,attributes}}, _db) do
        :logger.info ~c"DSE Scope: ~p", [scope]
        :logger.info ~c"DSE Filter: ~p", [filter]
        :logger.info ~c"DSE Attr: ~p", [attributes]

        :lists.map(fn response -> answer(response,no,:searchResEntry,socket) end,
          [ node("", [
              attr("supportedLDAPVersion", [~c"3"]),
              attr("namingContexts", [~c"dc=synrc,dc=com",~c"ou=schema",~c"dc=mil,dc=gov"]),
              attr("supportedControl", [~c"1.3.6.1.4.1.4203.1.10.1"]),
              attr("supportedFeatures", [~c"1.3.6.1.1.14", ~c"1.3.6.1.4.1.4203.1.5.1"]),
              attr("supportedExtensions", [~c"1.3.6.1.4.1.4203.1.11.3"]),
              attr("altServer", [~c"ldap.synrc.com"]),
              attr("subschemaSubentry", [~c"ou=schema"]),
              attr("vendorName", [~c"SYNRC LDAP"]),
              attr("vendorVersion", [~c"13.7.24"]),
              attr("supportedSASLMechanisms", [~c"SIMPLE"]),
              attr("objectClass", [~c"top",~c"extensibleObject"]),
              attr("entryUUID", [code()])])])

        resp = LDAP.DS.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: ~c"OK")
        answer(resp, no, :searchResDone,socket)
    end

    def message(no, socket, {:searchRequest, {_,bindDN,scope,_,_limit,_,_,filter,attributes}}, db) do
        :logger.info ~c"SEARCH DN: ~p", [qdn(bindDN)]
        :logger.info ~c"SEARCH Scope: ~p", [scope]
        :logger.info ~c"SEARCH Filter: ~p", [filter]
        :logger.info ~c"SEARCH Attr: ~p", [attributes]
        search(socket, no, db, filter, scope, qdn(bindDN))
        resp = LDAP.DS.'LDAPResult'(resultCode: :success, matchedDN: "", diagnosticMessage: ~c"OK")
        answer(resp, no, :searchResDone, socket)
    end

    def message(no, socket, {:modDNRequest, {_,dn,new,del,_}}, db) do
        :logger.info ~c"MOD RDN DN: ~p", [dn]
        :logger.info ~c"MOD RDN newRDN: ~p", [new]
        :logger.info ~c"MOD RDN deleteOldRDN: ~p", [del]
        modifyRDN(socket, no, db, dn, new, del)
        resp = LDAP.DS.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: ~c"OK")
        answer(resp, no, :modDNResponse, socket)
    end

    def message(no, socket, {:modifyRequest, {_,dn, attributes}}, db) do
       {:ok, statement} = prepare(db, "select rdn, att, val from ldap where rdn = ?1")
       bind(db, statement, [hash(qdn(dn))])
       case step(db, statement) do
            {:row, _} -> :logger.info ~c"MOD DN: ~p", [dn]
                         modifyDN(db, dn, attributes)
                         resp = LDAP.DS.'LDAPResult'(resultCode: :success,
                             matchedDN: dn, diagnosticMessage: ~c"OK")
                         answer(resp, no, :modifyResponse, socket)
            :done ->     :logger.info ~c"MOD ERROR: ~p", [dn]
                         resp = LDAP.DS.'LDAPResult'(resultCode: :noSuchObject,
                            matchedDN: dn, diagnosticMessage: ~c"ERROR")
                         answer(resp, no, :modifyResponse, socket)
       end
    end

    def message(no, socket, {:compareRequest, {_,dn, assertion}}, db) do
        :logger.info ~c"CMP DN: ~p", [dn]
        :logger.info ~c"CMP Assertion: ~p", [assertion]
        result = compareDN(db, dn, assertion)
        response = LDAP.DS.'LDAPResult'(resultCode: result, matchedDN: dn, diagnosticMessage: ~c"OK")
        answer(response, no, :compareResponse, socket)
    end

    def message(no, socket, {:addRequest, {_,dn, attributes}}, db) do
        {:ok, statement} = prepare(db, "select rdn, att, val from ldap where rdn = ?1")
        bind(db, statement, [hash(qdn(dn))])
        case step(db, statement) do
             {:row, _} ->
                 :logger.info ~c"ADD ERROR: ~p", [dn]
                 resp = LDAP.DS.'LDAPResult'(resultCode: :entryAlreadyExists,
                        matchedDN: dn, diagnosticMessage: ~c"ERROR")
                 answer(resp, no, :addResponse, socket)
             :done ->
                 createDN(db, dn, attributes)
                 :logger.info ~c"ADD DN: ~p", [dn]
                 resp = LDAP.DS.'LDAPResult'(resultCode: :success,
                        matchedDN: dn, diagnosticMessage: ~c"OK")
                 answer(resp, no, :addResponse, socket)
        end
    end

    def message(no, socket, {:delRequest, dn}, db) do
        :logger.info ~c"DEL DN: ~p", [dn]
        deleteDN(db, dn)
        resp = LDAP.DS.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: ~c"OK")
        answer(resp, no, :delResponse, socket)
    end

    def message(no, socket, {:extendedReq,{_,oid,val}} = msg, _db) do
        :logger.info ~c"EXT: ~p", [msg]
        res = LDAP.DS.'ExtendedResponse'(resultCode: :unavailable, diagnosticMessage: ~c"ERROR",
              responseName: oid, responseValue: val)
        answer(res, no, :extendedResp, socket)
    end

    def message(_no, socket, {:abandonRequest, _}, _db), do: :gen_tcp.close(socket)
    def message(_no, socket, {:unbindRequest, _}, _db), do: :gen_tcp.close(socket)

    def message(_no, socket, msg, _sql) do
        :logger.info ~c"Invalid LDAP Message: ~p", [msg]
        :gen_tcp.close(socket)
    end

    # LDAP protocol message answer

    defp answer(response, no, op, socket) do
        message = LDAP.DS."LDAPMessage"(messageID: no, protocolOp: {op, response})
        {:ok, bytes} = :'LDAP'.encode(:'LDAPMessage', message)
        _send = :gen_tcp.send(socket, :erlang.iolist_to_binary(bytes))
    end

    defp appendNotEmpty([]),  do: []
    defp appendNotEmpty(res) do
        res ++ case res do [] -> [] ; _ -> ~c"," end
    end

    defp modifyRDN(_socket, _no, db, dn, new, _del) do
        {:ok, st} = prepare(db, "update ldap set rdn = ?1 where rdn = ?2")
        :logger.info ~c"MODIFY RDN UPDATE: ~p", [hash(qdn(dn))]
        bind(db, st, [new,hash(qdn(dn))])
        step(db,st)
    end

    defp modifyDN(db, dn, attributes), do:
        :lists.map(fn {_, :add, x}     -> modifyAdd(db,dn,x)
                      {_, :replace, x} -> modifyReplace(db,dn,x)
                      {_, :delete, x}  -> modifyDelete(db,dn,x) end, attributes)

    defp modifyAdd(db, dn, {_,att,[val]}) do
        {:ok, st} = prepare(db, "insert into ldap (rdn,att,val) values (?1,?2,?3)")
        :logger.info ~c"MOD ADD RDN: ~p", [hash(qdn(dn))]
        bind(db, st, [hash(qdn(dn)),att,val])
        step(db,st)
    end

    defp modifyReplace(db, dn, {_,att,[val]}) do
        {:ok, st} = prepare(db, "update ldap set val = ?1 where rdn = ?2 and att = ?3")
        :logger.info ~c"MOD REPLACE RDN: ~p", [hash(qdn(dn))]
        bind(db, st, [val,hash(qdn(dn)),att])
        step(db,st)
    end

    defp modifyDelete(db, dn, {_,att,_}) do
        {:ok, st} = prepare(db, "delete from ldap where rdn = ?1 and att = ?2")
        :logger.info ~c"MOD DEL RDN: ~p", [hash(qdn(dn))]
        bind(db, st, [hash(qdn(dn)),att])
        res = step(db,st)
        collect0(db,st,res,[])
    end

    defp deleteDN(db, dn) do
        {:ok, st} = prepare(db, "delete from ldap where rdn = ?1")
        bind(db, st, [hash(qdn(dn))])
        res = step(db,st)
        collect0(db,st,res,[])
    end

    defp compareDN(db, dn, assertion) do
        {:AttributeValueAssertion, a, v} = assertion
        {:ok, st} = prepare(db, "select * from ldap where (rdn = '#{hash(qdn(dn))}') " <>
                                "and (att = '#{a}') and (val = '#{v}')")
        case step(db,st) do
             :done -> :compareFalse
             {:row,[_dn,_a,_v]} -> :compareTrue
        end
    end

    defp createDN(db, dn, attributes) do
        norm  = :lists.foldr(fn {:PartialAttribute, att, vals}, acc ->
                :lists.map(fn val -> [qdn(dn),att,val] end, vals) ++ acc end, [], attributes)
        {_,p} = :lists.foldr(fn x, {acc,res}  -> {acc + length(x), appendNotEmpty(res) ++
                :io_lib.format(~c"(?~p,?~p,?~p)",[acc+1,acc+2,acc+3])} end, {0,[]}, norm)
        {:ok, statement} = prepare(db, ~c"insert into ldap (rdn,att,val) values " ++ p ++ ~c"")
        :ok = bind(db, statement, :lists.flatten(norm))
        :done = step(db, statement)
    end

end
