defmodule LDAP.TCP do
   require LDAP

   def start(), do: :erlang.spawn(fn -> listen(1489) end)

   def listen(port) do
       {:ok, socket} = :gen_tcp.listen(port,
         [:binary, {:packet, 0}, {:active, false}, {:reuseaddr, true}])
       accept(socket)
   end

   def accept(socket) do
       {:ok, fd} = :gen_tcp.accept(socket)
       :erlang.spawn(fn -> loop(fd, []) end)
       accept(socket)
   end

   def message(no, socket, {:abandonRequest, _}) do
       :gen_tcp.close(socket)
   end

   def message(no, socket, {:unbindRequest, _}) do
       :gen_tcp.close(socket)
   end

   def message(no, socket, {:bindRequest, {_,_,bindDN,{:simple, password}}}) do
       :io.format 'BIND DN: ~p~n', [bindDN]
       response = LDAP."BindResponse"(resultCode: :success, matchedDN: bindDN, diagnosticMessage: 'OK')
       answer(response, no, :bindResponse, socket)
   end

   def message(no, socket, {:bindRequest, {_,_,bindDN,creds}}) do
       code = :authMethodNotSupported
       :io.format 'BIND ERROR: ~p~n', [code]
       response = LDAP."BindResponse"(resultCode: code, matchedDN: bindDN, diagnosticMessage: 'ERROR')
       answer(response, no, :bindResponse, socket)
   end

   def message(no, socket, {:searchRequest, {_,bindDN,scope,_,limit,_,_,filter,attributes}}) do
       :io.format 'SEARCH DN: ~p~n', [bindDN]
       :io.format 'SEARCH Scope: ~p~n', [scope]
       :io.format 'SEARCH Filter: ~p~n', [filter]
       :io.format 'SEARCH Attr: ~p~n', [attributes]
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

   def message(no, socket, {:modDNRequest, {_,dn,rdn,old,_}}) do
       :io.format 'MOD RDN DN: ~p~n', [dn]
       :io.format 'MOD RDN newRDN: ~p~n', [rdn]
       :io.format 'MOD RDN oldRDN: ~p~n', [old]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :modDNResponse, socket)
   end

   def message(no, socket, {:modifyRequest, {_,dn, attributes}}) do
       :io.format 'MOD DN: ~p~n', [dn]
       :io.format 'MOD Attr: ~p~n', [attributes]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :modifyResponse, socket)
   end

   def message(no, socket, {:compareRequest, {_,dn, assertion}}) do
       :io.format 'CMP DN: ~p~n', [dn]
       :io.format 'CMP Assertion: ~p~n', [assertion]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :compareResponse, socket)
   end

   def message(no, socket, {:addRequest, {_,dn, attributes}}) do
       :io.format 'ADD DN: ~p~n', [dn]
       :io.format 'ADD Attr: ~p~n', [attributes]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :addResponse, socket)
   end

   def message(no, socket, {:delRequest, dn}) do
       :io.format 'DEL DN: ~p~n', [dn]
       resp = LDAP.'LDAPResult'(resultCode: :success, matchedDN: dn, diagnosticMessage: 'OK')
       answer(resp, no, :delResponse, socket)
   end

   def answer(response, no, op, socket) do
       message = LDAP."LDAPMessage"(messageID: no, protocolOp: {op, response})
       {:ok, bytes} = :'LDAP'.encode(:'LDAPMessage', message)
       :gen_tcp.send(socket, :erlang.iolist_to_binary(bytes))
   end

   def loop(socket, dn) do
       case :gen_tcp.recv(socket, 0) do
            {:ok, data} ->
                 case :'LDAP'.decode(:'LDAPMessage',data) do
                      {:ok,decoded} ->
                          {:'LDAPMessage', no, payload, _} = decoded
                          spawn(fn -> message(no, socket, payload) end)
                          loop(socket, dn)
                      {:error,_} -> :exit
                 end
            {:error, :closed} -> :exit
       end
   end
end