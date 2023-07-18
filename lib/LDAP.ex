defmodule LDAP.TCP do
   require LDAP

   def start(), do: :erlang.spawn(fn -> listen(389) end)

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

   def abandon(socket) do
       :gen_tcp.close(socket)
   end

   def bind(no, socket, bindDN, {:simple, password}) do
       response = LDAP."BindResponse"(resultCode: :success, matchedDN: bindDN, diagnosticMessage: 'OK')
       answer(response, no, :bindResponse, socket)
   end

   def bind(no, socket, bindDN, _) do
       code = :authMethodNotSupported
       response = LDAP."BindResponse"(resultCode: code, matchedDN: bindDN, diagnosticMessage: 'ERROR')
       answer(response, no, :bindResponse, socket)
   end

   def search(no, socket, bindDN, _scope, _sizeLimit, _filter, _attributes) do
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

   def modifydn(no, socket, dn, _newRDN, _deleteOldRDN) do
       :io.format 'BIND DN: ~p~n', [dn]
   end

   def modify(no, socket, dn, _attributes) do
       :io.format 'MODIFY DN: ~p~n', [dn]
   end

   def compare(no, socket, dn, _assertion) do
       :io.format 'COMPARE DN: ~p~n', [dn]
   end

   def add(no, socket, dn, _attributes) do
       :io.format 'ADD DN: ~p~n', [dn]
   end

   def delete(no, socket, dn) do
       :io.format 'DEL DN: ~p~n', [dn]
   end

   def message(no, {:unbindRequest, _}, x),                    do: abandon(x)
   def message(no, {:bindRequest, {_,_,newBindDN, creds}}, x), do: bind(no, x, newBindDN, creds)
   def message(no, {:searchRequest, {_,b,s,_,l,_,_,f,a}}, x),  do: search(no, x, b, s, l, f, a)
   def message(no, {:modifyRequest, {_,dn,attributes}}, x),    do: modify(no, x, dn, attributes)
   def message(no, {:abandonRequest, _}, x),                   do: abandon(x)
   def message(no, {:addRequest, {_,dn,attributes}}, x),       do: add(no, x, dn, attributes)
   def message(no, {:delRequest, dn}, x),                      do: delete(no, x, dn)
   def message(no, {:modDNRequest, {_,dn,newRDN,d,_}}, x),     do: modifydn(no, x, dn, newRDN, d)
   def message(no, {:compareRequest, {_,dn,a}}, x),            do: compare(no, x, dn, a)

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
                          {:'LDAPMessage',no, payload, _} = decoded
                          message(no, payload, socket)
                          loop(socket, dn)
                      {:error,_} -> :exit
                 end
            {:error, :closed} -> :exit
       end
   end
end