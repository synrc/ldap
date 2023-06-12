-module(eds_app).

-behaviour(application).

-export([start_client/0, start_ops/0]).

-export([start/2, stop/1, init/1]).

-define(MAX_RESTART, 5).
-define(MAX_TIME, 60).

-define(DEF_LDAP_PORT, 389).
-define(DEF_EMONGO_HOST, "localhost").
-define(DEF_EMONGO_PORT, 27017).
-define(DEF_EMONGO_DB, "eds").
-define(DEF_EMONGO_POOL, 3).
-define(DEF_EMONGO_COLL, "root").

-spec start_client() -> {ok, Child :: pid() | undefined} | {error, term()}.
start_client() ->
    supervisor:start_child(client_sup, []).

-spec start_ops() -> {ok, Child :: pid() | undefined} | {error, term()}.
start_ops() ->
    supervisor:start_child(ops_sup, []).

-spec start_emongo() -> {ok, Pid :: pid()}.
start_emongo() ->
    EmongoHost = get_app_env(emongo_host, ?DEF_EMONGO_HOST),
    EmongoPort = get_app_env(emongo_port, ?DEF_EMONGO_PORT),
    EmongoDB = get_app_env(emongo_db, ?DEF_EMONGO_DB),
    EmongoPool = get_app_env(emongo_pool, ?DEF_EMONGO_POOL),
    ok = application:start(emongo),
    emongo:add_pool(eds, EmongoHost, EmongoPort, EmongoDB, EmongoPool).

-spec start(any(), any()) -> {ok, pid()}.
start(_Type, _Args) ->
    start_emongo(),
    LdapPort = get_app_env(ldap_port, ?DEF_LDAP_PORT),
    supervisor:start_link({local, ?MODULE}, ?MODULE, [LdapPort, eds_fsm]).

-spec stop(any()) -> ok.
stop(_S) ->
    ok.

-spec init(list()) -> tuple().
init([Port, Module]) ->
    TCPListener = {
      tcp_server_sup, 
      {tcp_listener, start_link, [Port, Module]},
      permanent, 2000, worker,
      [tcp_listener]},
    ClientSup = { 
      client_sup,
      {supervisor, start_link, [{local, client_sup}, ?MODULE, client_sup]},
      permanent, infinity, supervisor,
      []},
    OpsSup = { 
      ops_sup,
      {supervisor, start_link, [{local, ops_sup}, ?MODULE, ops_sup]},
      permanent, infinity, supervisor,
      []},
    {ok, {{one_for_one, ?MAX_RESTART, ?MAX_TIME}, [TCPListener, ClientSup, OpsSup]}};

init(client_sup) ->
    Client = {
      undefined, 
      {eds_fsm, start_link, []},
      temporary, 2000, worker,
      []},
    {ok, {{simple_one_for_one, ?MAX_RESTART, ?MAX_TIME}, [Client]}};

init(ops_sup) ->
    EmongoColl = get_app_env(emongo_coll, ?DEF_EMONGO_COLL),
    Ops = {
      undefined, 
      {eds_ops, start_link, [EmongoColl]},
      temporary, 2000, worker,
      []},
    {ok, {{simple_one_for_one, ?MAX_RESTART, ?MAX_TIME}, [Ops]}}.

-spec get_app_env(term(), term()) -> term().
get_app_env(Opt, Default) ->
    {ok, App} = application:get_application(),
    case application:get_env(App, Opt) of
	{ok, Val} -> Val;
	_ ->
	    case init:get_argument(Opt) of
		{'ok', [[Val]]} -> Val;
		error       -> Default
	    end
    end.
