-module(eds_filter).

-export([filter/1, scope/2, fields/1, limit/1]).

-spec compile_all(list(), list()) -> list().
compile_all([Token|Tail], Acc) ->
    compile_all(Tail, [compile(Token)|Acc]);
compile_all([], Acc) -> 
    lists:reverse(Acc).

-spec compile(tuple() | list()) -> list().
compile(Tokens) when is_list(Tokens) -> compile_all(Tokens, []);

compile({'and', Arg}) -> lists:flatten(compile(Arg));
compile({'or', Arg}) -> [{<<"$or">>, compile(Arg)}];
compile({'not', Arg}) -> [{<<"$not">>, compile(Arg)}];

compile({equalityMatch, {_, Arg1, Arg2}}) -> [{Arg1, Arg2}];
compile({approxMatch, {_, Arg1, Arg2}}) -> [{Arg1, Arg2}];
compile({greaterOrEqual, {_, Arg1, Arg2}}) -> [{Arg1, [{gte, Arg2}]}];
compile({lessOrEqual, {_, Arg1, Arg2}}) -> [{Arg1, [{lte, Arg2}]}];
compile({present, Arg}) -> [{Arg, [{exists, true}]}];

compile({substrings, {_, Arg1, Arg2}}) -> 
    [{Arg1, {regexp, lists:flatten(compile(Arg2)), ""}}];

compile({initial, Arg}) -> "^" ++ Arg;
compile({final, Arg}) -> ".*" ++ Arg ++ "$$";
compile({any, Arg}) -> ".*" ++ Arg;

compile(Token) -> {unknown_token, Token}.

-spec scope(list(), atom()) -> list().
scope(BaseObject, wholeSubtree) -> 
    [{"_rdn", {regexp, "^" ++ lists:reverse(BaseObject), []}}];
scope(BaseObject, baseObject) ->
    [{"_rdn", {regexp, "^" ++ lists:reverse(BaseObject) ++ "$$", []}}];
scope(BaseObject, singleLevel) ->
    [{"_rdn", {regexp, "^" ++ lists:reverse(BaseObject) ++ ",[\\d\\w\\s=]+$$", []}}].

-spec fields(list()) -> list().
fields([]) -> [];
fields(Attrs) -> [{fields, ["dn" | Attrs]}].

-spec limit(integer()) -> list().
limit(0) -> [];
limit(SizeLimit) -> [{limit, SizeLimit}].

-spec filter(list()) -> list().
filter(Tokens) -> compile(Tokens).
