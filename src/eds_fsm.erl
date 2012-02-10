%% @author Oleg Smirnov <oleg.smirnov@gmail.com>
%% @doc Client FSM

-module(eds_fsm).

-behaviour(gen_fsm).

-export([start_link/0, set_socket/2, reply/2, set_bind/2]).

-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
	 terminate/3, code_change/4]).

-export([listen/2, read/2]).

-record(state, {socket, addr, pool, binddn}). 

-define(TIMEOUT, 120000).

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_fsm:start_link(?MODULE, [], []).

-spec set_socket(pid(), port()) -> ok.
set_socket(Pid, Socket) when is_pid(Pid), is_port(Socket) ->
    gen_fsm:send_event(Pid, {socket_ready, Socket}).

-spec reply(pid(), any()) -> ok.
reply(Pid, Message) when is_pid(Pid)  ->
    gen_fsm:send_event(Pid, {out, Message}).

-spec set_bind(pid(), any()) -> ok.
set_bind(Pid, BindDN) when is_pid(Pid)  ->
    gen_fsm:send_event(Pid, {set_bind, BindDN}).

-spec init([]) -> {ok, listen, #state{}}.
init([]) ->
    process_flag(trap_exit, true),
    {ok, listen, #state{binddn=undefined, pool=eds_pool:init()}}.

-spec listen(any(), #state{}) -> {atom(), atom(), #state{}, _}.
listen({socket_ready, Socket}, State) when is_port(Socket) ->
    inet:setopts(Socket, [{active, once}, {packet, 0}, binary]),
    {ok, {IP, _Port}} = inet:peername(Socket),
    {next_state, read, State#state{socket=Socket, addr=IP}, ?TIMEOUT};

listen(Other, State) ->
    error_logger:error_msg("Unexpected message: ~p\n", [Other]),
    {next_state, listen, State, ?TIMEOUT}.

-spec read(any(), #state{}) -> {next_state, any(), #state{}, _} | {stop, any(), #state{}}.
read({set_bind, BindDN}, State) ->
    {next_state, read, State#state{binddn=BindDN}, ?TIMEOUT};

read({in, {{abandonRequest, Options},_}}, #state{pool=Pool} = State) ->
    {'AbandonRequest', MessageID} = Options,
    case eds_pool:take_k(MessageID, Pool) of
	{MessageID, Pid, NewPool} -> exit(Pid, 'EXIT');
	false -> NewPool = Pool
    end,
    {next_state, read, State#state{pool=NewPool}, ?TIMEOUT};

read({in, {{unbindRequest,_},_}}, State) ->
    {stop, normal, State};

read({in, {ProtocolOp, MessageID}}, #state{pool=Pool, binddn=BindDN} = State) ->
    {ok, Pid} = eds_app:start_ops(),
    NewPool = eds_pool:insert(MessageID, Pid, Pool),
    erlang:link(Pid),
    eds_ops:dispatch(Pid, ProtocolOp, MessageID, BindDN, self()),
    {next_state, read, State#state{pool=NewPool}, ?TIMEOUT};

read({out, Message}, #state{socket=S} = State) ->
    Bytes = list_to_binary(eds_msg:encode(Message)),
    gen_tcp:send(S, Bytes),
    {next_state, read, State, ?TIMEOUT};

read(timeout, State) ->
    error_logger:error_msg("Client connection timeout: ~p\n", [State]),
    {stop, normal, State};

read(_Data,  State) ->
    {stop, normal, State}.

-spec handle_event(any(), atom(), #state{}) -> {stop, tuple(), #state{}}.
handle_event(Event, StateName, State) ->
    {stop, {StateName, undefined_event, Event}, State}.

-spec handle_sync_event(any(), any(), atom(), #state{}) -> {stop, tuple(), #state{}}.
handle_sync_event(Event, _From, StateName, State) ->
    {stop, {StateName, undefined_event, Event}, State}.

-spec handle_info(any(), atom(), #state{}) -> {atom(), atom(), #state{}}.
handle_info({tcp, S, Bin}, StateName, #state{socket=S} = State) ->
    inet:setopts(S, [{active, once}]),
    ?MODULE:StateName({in, eds_msg:decode(Bin)}, State);

handle_info({tcp_closed,_S}, _StateName, State) ->
    {stop, normal, State};

handle_info({bind, BindDN}, StateName, State) ->
    {next_state, StateName, State#state{binddn=BindDN}};

handle_info({'EXIT', Pid,_}, StateName, #state{pool=Pool} = State) ->
    NewPool = eds_pool:delete_v(Pid, Pool),
    {next_state, StateName, State#state{pool=NewPool}};

handle_info(_Info, StateName, State) ->
    {noreply, StateName, State}.

-spec terminate(any(), atom(), #state{}) -> ok.
terminate(_Reason,_StateName, #state{socket=S}) ->
    (catch gen_tcp:close(S)),
    ok.

-spec code_change(any(), atom(), #state{}, any()) -> {ok, atom(), #state{}}.
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.
