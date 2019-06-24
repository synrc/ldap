%% @author Oleg Smirnov <oleg.smirnov@gmail.com>
%% @doc LDAP Operations

-module(eds_ops).

-behaviour(gen_server).

-export([start_link/1, dispatch/5]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-include("LDAP.hrl").

-record(state, {coll}).

-type maybe_list() :: list() | atom().

-spec start_link(list()) -> {ok, pid()}.
start_link(Coll) ->
    gen_server:start_link(?MODULE, [Coll], []).

-spec init(list()) -> {ok, #state{}}.
init([Coll]) ->
    {ok, #state{coll=Coll}}.

%% @doc Dispatch a message to eds_ops worker
-spec dispatch(pid(), tuple(), integer(), list(), pid()) -> ok.
dispatch(Pid, ProtocolOp, MessageID, BindDN, From) ->
    gen_server:cast(Pid, {ProtocolOp, MessageID, BindDN, From}).

%% @doc Process BindRequest
-spec bind(list(), tuple(), list()) -> maybe_list().
bind(BindDN, {simple, Password}, Coll) ->
    Filter = {equalityMatch, 
	      {'AttributeValueAssertion', "userPassword", Password}},
    search(BindDN, BindDN, baseObject, 1, Filter, [], Coll);
bind(_BindDN,_Creds,_Coll) ->
    authMethodNotSupported.

%% @doc Process a reply from bind/3 and notify FSM on new BindDN if required
-spec bind_reply(pid(), maybe_list(), integer()) -> atom().
bind_reply(_From, BindResult,_MessageID) when is_atom(BindResult) ->
    BindResult;
bind_reply(_From, [],_MessageID) ->
    invalidCredentials;
bind_reply(From, [BindResult],_MessageID) when is_list(BindResult) ->
    BindDN = bitstring_to_list(eds_object:get("dn", BindResult)),
    eds_fsm:set_bind(From, BindDN),
    success.

%% @doc Process SearchRequest
-spec search(maybe_list(), list(), atom(), integer(), tuple() | list(), list(), list()) -> maybe_list().
search(undefined,_BaseObject,_Scope,_SizeLimit,_Filter,_Attributes,_Coll) ->
    insufficientAccessRights;
search(_BindDN, BaseObject, Scope, SizeLimit, Filter, Attributes, Coll) ->
    ScopeFilter = eds_filter:scope(BaseObject, Scope),
    EntryFilter = eds_filter:filter(Filter),
    FieldsOption = eds_filter:fields(Attributes),
    LimitOption = eds_filter:limit(SizeLimit),
    emongo:find_all(eds, Coll, 
		    ScopeFilter ++ EntryFilter,
		    FieldsOption ++ LimitOption).

%% @doc Process a reply from search/6, send resulting entries to FSM if required
-spec search_reply(pid(), maybe_list(), integer()) -> atom().
search_reply(_From, SearchResult,_MessageID) when is_atom(SearchResult) ->
    SearchResult;
search_reply(From, [Item|Result], MessageID) ->
    Attrs = lists:flatten(lists:map(fun eds_object:to_attr/1, Item)),
    {value, {_, "dn", [DN]}, PartialAttrs} = lists:keytake("dn", 2, Attrs),
    Entry = {'SearchResultEntry', DN, PartialAttrs},
    eds_fsm:reply(From, {{searchResEntry, Entry}, MessageID}),
    search_reply(From, Result, MessageID);
search_reply(_From, [],_MessageID) ->
    success.

%% @doc Process ModifyDNRequest
-spec modifydn(maybe_list(), list(), list(), list(), list()) -> atom().
modifydn(_BindDN, DN, NewRDN,_DeleteOldRDN, Coll) ->
    case emongo:find_one(eds, Coll, [{"_rdn", rdn(DN)}]) of
	[] -> noSuchObject;
	[Entry] ->
	    OldDN = bitstring_to_list(eds_object:get(<<"dn">>, Entry)),
	    BaseDN = lists:dropwhile(fun(C) -> C =/= $, end, OldDN),
	    NewDN = NewRDN ++ BaseDN,	   
	    ModDN = eds_object:modify(<<"dn">>, NewDN, Entry),
	    NewEntry = eds_object:modify(<<"_rdn">>, rdn(NewDN), ModDN),
	    Response = emongo:update_sync(eds, Coll, [{<<"_rdn">>, rdn(DN)}], NewEntry, false),
	    parse_response(Response)
    end.	

%% @doc Process AddRequest
-spec add(maybe_list(), list(), list(), list()) -> atom().
add(_BindDN, DN, Attrs, Coll) ->
    case emongo:find_one(eds, Coll, [{"_rdn", rdn(DN)}]) of
	[_Entry] -> entryAlreadyExists;
	[] ->
	    Entry = lists:map(fun eds_object:to_record/1, Attrs),
	    AddDN = eds_object:insert(<<"dn">>, DN, Entry),
	    NewEntry = eds_object:insert(<<"_rdn">>, rdn(DN), AddDN),	    
	    Response = emongo:insert_sync(eds, Coll, NewEntry),
	    parse_response(Response)
    end.

%% @doc Process DelRequest
-spec delete(maybe_list(), list(), list()) -> atom().
delete(_BindDN, DN, Coll) ->
    case emongo:find_one(eds, Coll, [{"_rdn", rdn(DN)}]) of
	[] -> noSuchObject;
	[_Entry] ->
	    Response = emongo:delete_sync(eds, Coll, [{<<"_rdn">>, rdn(DN)}]),
	    parse_response(Response)
    end.    

%% @doc Process ModifyRequest
-spec modify(maybe_list(), list(), list(), list()) -> atom().
modify(_BindDN, DN, Attrs, Coll) ->
    case emongo:find_one(eds, Coll, [{"_rdn", rdn(DN)}]) of
	[] -> noSuchObject;
	[Entry] ->
	    NewEntry = lists:foldl(fun modify_apply/2, Entry, Attrs),
	    Response = emongo:update_sync(eds, Coll, [{<<"_rdn">>, rdn(DN)}], NewEntry, false),
	    parse_response(Response)
    end.    

%% @doc Apply ModifyRequest change atoms to an object
-spec modify_apply(tuple(), list()) -> list().
modify_apply({'ModifyRequest_changes_SEQOF', add, Change}, Entry) ->
    {Key, Value} = eds_object:to_record(Change),
    eds_object:insert(Key, Value, Entry);
modify_apply({'ModifyRequest_changes_SEQOF', replace, Change}, Entry) ->
    {Key, Value} = eds_object:to_record(Change),
    eds_object:modify(Key, Value, Entry);
modify_apply({'ModifyRequest_changes_SEQOF', delete, Change}, Entry) ->
    {Key,_Value} = eds_object:to_record(Change),
    eds_object:delete(Key, Entry).

%% @doc Process CompareRequest
-spec compare(maybe_list(), list(), list(), list()) -> atom().
compare(BindDN, BaseDN, Assertion, Coll) ->
    Filter = {equalityMatch, Assertion},
    case search(BindDN, BaseDN, baseObject, 1, Filter, [], Coll) of
	O when is_atom(O) ->
		  O;
	[] -> compareFalse;
	_ -> compareTrue
    end.

%% @doc Parse eMongo response code
-spec parse_response(list()) -> atom().
parse_response([Response]) ->
    case lists:keyfind(<<"err">>, 1, Response) of
	{<<"err">>, undefined} -> success;
	_Else -> protocolError
    end.

%% @doc Create a reveresed DN from a DN
-spec rdn(list()) -> list().
rdn(DN) ->
    lists:reverse(DN).

-spec process(tuple(), list()) -> maybe_list().
process({{bindRequest, Options}, _, _BindDN, _}, Coll) ->
    {'BindRequest',_, NewBindDN, Creds} = Options,
    bind(NewBindDN, Creds, Coll);
process({{searchRequest, Options}, _, BindDN, _}, Coll) ->
    {'SearchRequest', BaseObject, Scope, _, SizeLimit, _, _, Filter, Attributes} = Options,
    search(BindDN, BaseObject, Scope, SizeLimit, Filter, Attributes, Coll);
process({{modifyRequest, Options}, _, BindDN, _}, Coll) ->
    {'ModifyRequest', DN, Attributes} = Options,
    modify(BindDN, DN, Attributes, Coll);
process({{addRequest, Options}, _, BindDN, _}, Coll) ->
    {'AddRequest', DN, Attributes} = Options,
    add(BindDN, DN, Attributes, Coll);
process({{delRequest, Options}, _, BindDN, _}, Coll) ->
    DN = Options,
    delete(BindDN, DN, Coll);
process({{modDNRequest, Options}, _, BindDN, _}, Coll) ->
    {'ModifyDNRequest', DN, NewRDN, DeleteOldRDN,_} = Options,
    modifydn(BindDN, DN, NewRDN, DeleteOldRDN, Coll);
process({{compareRequest, Options}, _, BindDN, _}, Coll) ->
    {'CompareRequest', DN, Assertion} = Options,
    compare(BindDN, DN, Assertion, Coll).

-spec response(tuple(), maybe_list()) -> atom().
response({{bindRequest, _}, MessageID, _, From}, Result) ->
    Code = bind_reply(From, Result, MessageID),
    #'BindResponse'{resultCode = Code, matchedDN = "", diagnosticMessage = ""};
response({{searchRequest, _}, MessageID, _, From}, Result) ->
    Code = search_reply(From, Result, MessageID),
    #'LDAPResult'{resultCode = Code, matchedDN = "", diagnosticMessage = ""};
response(_, Result) ->
    #'LDAPResult'{resultCode = Result, matchedDN = "", diagnosticMessage = ""}.

-spec message(tuple(), tuple()) -> tuple().
message({{bindRequest, _}, MessageID, _, _}, Response) ->
    {{bindResponse, Response}, MessageID};
message({{searchRequest, _}, MessageID, _, _}, Response) ->
    {{searchResDone, Response}, MessageID};
message({{modifyRequest, _}, MessageID, _, _}, Response) ->
    {{modifyResponse, Response}, MessageID};
message({{addRequest, _}, MessageID, _, _}, Response) ->
    {{addResponse, Response}, MessageID};
message({{delRequest, _}, MessageID, _, _}, Response) ->
    {{delResponse, Response}, MessageID};
message({{modDNRequest, _}, MessageID, _, _}, Response) ->
    {{modDNResponse, Response}, MessageID};
message({{compareRequest, _}, MessageID, _, _}, Response) ->
    {{compareResponse, Response}, MessageID}.

-spec handle_cast(tuple(), #state{}) -> {stop, normal, #state{}}.
handle_cast(Request, #state{coll=Coll} = State) ->
    Result = process(Request, Coll),
    Response = response(Request, Result),
    Message = message(Request, Response),
    {_, _, _, From} = Request,
    eds_fsm:reply(From, Message),
    {stop, normal, State}.

-spec handle_call(any(), any(), #state{}) -> {stop, tuple(), #state{}}.
handle_call(Request,_From, State) ->
    {stop, {unknown_call, Request}, State}.

-spec handle_info(any(), #state{}) -> {stop, any(), #state{}} | {noreply, #state{}}.
handle_info({'EXIT',_, Reason}, State) ->
    {stop, Reason, State};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(any(), #state{}) -> ok.
terminate(_Reason,_State) ->
    ok.

-spec code_change(any(), #state{}, any()) -> {ok, #state{}}.
code_change(_OldVsn, State,_Extra) ->
    {ok, State}.
