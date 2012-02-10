%% @author Oleg Smirnov <oleg.smirnov@gmail.com>
%% @doc Workers pool

-module(eds_pool).

-export([init/0, insert/3, lookup_k/2, lookup_v/2, 
	 take_k/2, take_v/2, delete_k/2, delete_v/2]).

-type pool(K, V) :: {KVTree::rbtree:tree(K), VKTree::rbtree:tree(V)}.

%% @doc Create an empty pool
-spec init() -> pool(any(), any()).
init() ->
    {{}, {}}.

%% @doc Get KV tree from a pool
-spec kv_tree(pool(K, term())) -> rbtree:tree(K).
kv_tree(Pool) -> 
    element(1, Pool).

%% @doc Get VK tree from a pool
-spec vk_tree(pool(term(), V)) -> rbtree:tree(V).
vk_tree(Pool) ->
    element(2, Pool).

%% @doc Insert a worker into a pool
-spec insert(K, V, pool(K, V)) -> pool(K, V).
insert(Key, Value, Pool) ->    
    {rbtree:insert(Key, Value, kv_tree(Pool)),
     rbtree:insert(Value, Key, vk_tree(Pool))}.

%% @doc Look up a worker by pid
-spec lookup_k(K, pool(K, V)) -> {} | V.
lookup_k(Key, Pool) ->
    rbtree:lookup(Key, kv_tree(Pool)).

%% @doc Look up a worker ops id
-spec lookup_v(V, pool(K, V)) -> {} | K.
lookup_v(Value, Pool) ->
    rbtree:lookup(Value, vk_tree(Pool)).

%% @doc Delete a worker by pid
-spec delete_k(K, pool(K, V)) -> pool(K, V).
delete_k(Key, Pool) ->
    case lookup_k(Key, Pool) of
	{} -> Pool;
	{Key, Value} ->
	    {rbtree:delete(Key, kv_tree(Pool)),
	     rbtree:delete(Value, vk_tree(Pool))}
    end.

%% @doc Delete a worker by ops id
-spec delete_v(V, pool(K, V)) -> pool(K, V).
delete_v(Value, Pool) ->
    case lookup_v(Value, Pool) of
	{} -> Pool;
	{Value, Key} ->
	    {rbtree:delete(Key, kv_tree(Pool)),
	     rbtree:delete(Value, vk_tree(Pool))}
    end.

%% @doc Drop a worker by pid
-spec take_k(K, pool(K, V)) -> false | {K, V, pool(K, V)}.
take_k(Key, Pool) ->
    case lookup_k(Key, Pool) of
	{} -> false;
	{Key, Value} -> {Key, Value,
			 {rbtree:delete(Key, kv_tree(Pool)),
			  rbtree:delete(Value, vk_tree(Pool))}}
    end.

%% @doc Drop a worker by ops id
-spec take_v(V, pool(K, V)) -> false | {V, K, pool(K, V)}.
take_v(Value, Pool) ->
    case lookup_v(Value, Pool) of
	{} -> false;
	{Value, Key} -> {Value, Key,
			 {rbtree:delete(Key, kv_tree(Pool)),
			  rbtree:delete(Value, vk_tree(Pool))}}
    end.
