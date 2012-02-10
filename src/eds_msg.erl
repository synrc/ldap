%% @author Oleg Smirnov <oleg.smirnov@gmail.com>
%% @doc LDAP Message

-module(eds_msg).

-export([encode/1, decode/1]).

-include("LDAP.hrl").

-spec decode(binary()) -> {tuple(), integer()}.
decode(Envelope) ->
    case asn1rt:decode('LDAP', 'LDAPMessage', Envelope) of
        {ok, {'LDAPMessage', MessageID, ProtocolOp,_}} ->
	    {ProtocolOp, MessageID};
	Error -> {error_decoding, Error}
    end.

-spec encode({tuple(), integer()}) -> list().
encode({ProtocolOp, MessageID}) when is_tuple(ProtocolOp), is_integer(MessageID) ->
    Message = #'LDAPMessage'{messageID = MessageID, protocolOp = ProtocolOp},
    case asn1rt:encode('LDAP', 'LDAPMessage', Message) of
        {ok, Envelope} -> Envelope;
        Error -> {error_encoding, Error}
    end.
