%% -*- erlang -*-
%%% @author Moritz <emoritz@usat-chrmiller.usatoday.us.ad.gannett.com>
%%% @copyright (C) 2013, Moritz
%%% @doc
%%%
%%% A basho bench driver for minimogrify.  It is a wrapper around the 
%%% basho_bench_driver_http driver
%%% 
%%% @end
%%% Created :  9 Aug 2013 by Moritz <emoritz@usat-chrmiller.usatoday.us.ad.gannett.com>

-module(mm_basho_bench_driver).

-compile(export_all).

-export([
	 new/1,
	 run/4
	]).

-record(state, {http_driver_state, mm_key}).
-type http_driver_state() :: {state, string()}. %% this is the shape of the http
                                                %% driver's state
-type int_gen() :: fun(() -> integer()).

new(Id) ->
    application:start(crypto),

    MMSecret = basho_bench_config:get(mm_key, ""),
    %io:format("~s~n", [MMSecret]),
    case basho_bench_driver_http:new(Id) of 
	{ok, HttpState} ->
	    {ok, #state{http_driver_state=HttpState, mm_key=MMSecret}};
	Other ->
	    Other
    end.

run(
  {get, {Host, Port, Headers, Source, SourceParams, ImgPath}},
  KeyGen, 
  ValueGen, 
  State) ->
    Path   = gen_path(KeyGen, State#state.mm_key, Source, SourceParams, ImgPath),
    %io:format("~s~n", [Path]),
    HttpResult = basho_bench_driver_http:run(
     		   {get, {Host, Port, Path}, Headers},
     		   KeyGen, ValueGen, 
     		   State#state.http_driver_state),
    X = run_result(HttpResult, State),
    %io:format("~p~n", [X]),
    X.

	
    
%%====================================================================
%% Internal
%%====================================================================
dummy_int_gen() ->
    random:uniform(100000).


-spec gen_path(int_gen(), iodata(), iodata(), iodata(), iodata()) -> iodata().
gen_path(IntGen, Secret, Source, SourceParams, ImgPath) ->
    Actions = actions(IntGen),
    Hmac    = security_key(Secret, Actions, Source, SourceParams),
    mm_path(Hmac, Actions, Source, SourceParams, ImgPath). 

mm_path(Hmac, Actions, Source, SourceParams, ImgPath) ->
    ["/-mm-/", Hmac, "/", Actions, "/", Source, "/", SourceParams,
     "/", ImgPath].


-spec actions(int_gen()) -> iodata().
actions(IntGen) ->
    ActionCount = int_between(IntGen, 5), % get between 1 and 5 actions
    gen_actions(IntGen, ActionCount).

gen_actions(IntGen, Count) ->
    gen_actions(IntGen, Count-1, [action(IntGen)]).

gen_actions(_IntGen, 0, Accum) ->
    Accum;
gen_actions(IntGen, N, Accum) ->
    gen_actions(IntGen, N-1, [[action(IntGen), "&"]|Accum]).

    
-spec action(int_gen()) -> iodata().
action(IntGen) ->
    Fun = choose(IntGen, 
		 [
		  %fun() -> crop_action(IntGen) end,
		  fun() -> resize_action(IntGen) end
		 ]),
    Fun().

resize_action(IntGen) ->
    Width  = integer_to_list(gen_dimension(IntGen)),
    Height = integer_to_list(gen_dimension(IntGen)),
    ["r=", Width, "x", Height].

crop_action(IntGen) ->
    ["c=", span(IntGen), "-", span(IntGen)].

span(IntGen) ->
    [X, Y] = lists:sort([gen_dimension(IntGen), gen_dimension(IntGen)]),
    % regenerate if the dimensions are equal
    if X == Y ->
	    span(IntGen);
       true ->
	    [integer_to_list(X), "-", integer_to_list(Y)]
    end.

gen_dimension(IntGen) ->
    int_between(IntGen, 1000).

int_between(IntGen, Max) ->
    abs(IntGen()) rem Max + 1.
			     
choose(IntGen, Choices) ->
    lists:nth(
      int_between(IntGen, length(Choices)), 
      Choices).



-spec security_key(iodata(), iodata(), iodata(), iodata()) -> iodata().
security_key(Secret, Actions, Source, SourceParams) ->
    hexdigest(
      crypto:hmac_final(
	crypto:hmac_update(
	  crypto:hmac_init(sha, Secret),
	  [Actions, Source, SourceParams]))).

-spec hexdigest(binary()) -> iodata().
hexdigest(Binary) ->
    string:to_lower(binary_to_list(iolist_to_binary([io_lib:format("~2.16.0B", [B]) || B <- binary_to_list(Binary)]))).
	  

%%--------------------------------------------------------------------
%% @doc
%% Convert the HTTP driver's run result into ours
%% @end
%%--------------------------------------------------------------------
-spec run_result(
	{ok, http_driver_state()} | {error, any(), http_driver_state()},
	#state{}) ->
    {ok, #state{}} | {error, any(), #state{}}.
run_result({ok, S2}, State) ->
    {ok, State#state{http_driver_state=S2}};
run_result({error, Reason, S2}, State) ->
    {error, Reason, State#state{http_driver_state=S2}}.

