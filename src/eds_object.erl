-module(eds_object).

-export([modify/3, get/2, insert/3, delete/2, to_attr/1, to_record/1]).

-compile({no_auto_import,[get/1]}).

-type key() :: list() | bitstring().
-type value() :: list() | bitstring() | tuple().
-type object() :: list().

-explort_type([key/0, value/0, object/0]).

%% @doc Replace an attribute:value pair in an LDAP object
-spec modify(key(), value(), object()) -> object().
modify(Key, Value, Object) when is_list(Key) ->
    modify(list_to_bitstring(Key), Value, Object);
modify(Key, Value, Object) when is_bitstring(Key), is_list(Value) ->
    modify(Key, list_to_bitstring(Value), Object);
modify(Key, Value, Object) when is_bitstring(Key), is_bitstring(Value) orelse is_tuple(Value) ->
    lists:keyreplace(Key, 1, Object, {Key, Value}).

%% @doc Get an attribute:value pair from an LDAP object
-spec get(key(), object()) -> value().
get(Key, Object) when is_list(Key) ->
    get(list_to_bitstring(Key), Object);
get(Key, Object) when is_bitstring(Key) ->
    element(2, lists:keyfind(Key, 1, Object)).

%% @doc Insert a new attribute:value pair into an LDAP object
-spec insert(key(), value(), object()) -> object().
insert(Key, Value, Object) when is_list(Key) ->
    insert(list_to_bitstring(Key), Value, Object);
insert(Key, Value, Object) when is_bitstring(Key), is_list(Value) ->
    insert(Key, list_to_bitstring(Value), Object);
insert(Key, Value, Object) when is_bitstring(Key), is_bitstring(Value) orelse is_tuple(Value) ->
    [{Key, Value} | Object].

%% @doc Delete an attribute:value pair from an LDAP object
-spec delete(key(), object()) -> object().
delete(Key, Object) when is_list(Key) ->
    delete(list_to_bitstring(Key), Object);
delete(Key, Object) when is_bitstring(Key) ->
    lists:keydelete(Key, 1, Object).

%% @doc Convert eMongo item representation into a PartialAttribute
-spec to_attr({binary(), any()}) -> list().
to_attr({_Name, {oid, _}}) -> [];
to_attr({<<"_rdn">>,_}) -> [];
to_attr({Name, Value}) when is_bitstring(Name), is_bitstring(Value) ->
    {'PartialAttribute', bitstring_to_list(Name), [bitstring_to_list(Value)]};
to_attr({Name, {array, Value}}) when is_bitstring(Name), is_list(Value) ->
    lists:map(fun(V) -> 
		      {'PartialAttribute', bitstring_to_list(Name), [bitstring_to_list(V)]}
	      end, Value).

%% @doc Convert a PartialAttribute representation into an eMongo item
-spec to_record({atom(), list(), list()}) -> {binary(), binary() | tuple()}.
to_record({'PartialAttribute', Name, [Value]}) when is_list(Name), is_list(Value) ->
    {list_to_bitstring(Name), list_to_bitstring(Value)};
to_record({'PartialAttribute', Name, Value}) when is_list(Name), is_list(Value) ->
    {list_to_bitstring(Name), {array, [list_to_bitstring(V) || V <- Value]}}.
