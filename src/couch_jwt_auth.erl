%   Copyright 2015 Matti Eerola
%
%   Licensed under the Apache License, Version 2.0 (the "License");
%   you may not use this file except in compliance with the License.
%   You may obtain a copy of the License at
%
%       http://www.apache.org/licenses/LICENSE-2.0
%
%   Unless required by applicable law or agreed to in writing, software
%   distributed under the License is distributed on an "AS IS" BASIS,
%   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%   See the License for the specific language governing permissions and
%   limitations under the License.

-module(couch_jwt_auth).
-behaviour(gen_server).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-export([jwt_authentication_handler/1]).
-export([decode/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("couch/include/couch_db.hrl").

-import(couch_httpd, [header_value/2]).

%% @doc token authentication handler.
%
% This handler allows creation of a userCtx object from a JSON Web Token (JWT).
jwt_authentication_handler(Req) ->
  case header_value(Req, "Authorization") of
    "Bearer " ++ Token -> 
      try
        token_auth_user(Req, decode(Token))
      catch
        % return generic error message (https://www.owasp.org/index.php/Authentication_Cheat_Sheet#Authentication_Responses)
        throw:_ -> throw({unauthorized, <<"Token rejected">>});
        error:_ -> throw({unauthorized, <<"Token rejected">>})
      end;
    _ -> Req
  end.

start_link(Config) ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

start_link() ->
   Config = couch_config:get("jwt_auth"),
   start_link(Config).

init([]) ->
{ok, {invalid_jwk, empty_initialization}};

init(Config) ->
   try init_jwk_from_config(Config) of 
     {JWK, Alg} -> {ok, {valid_jwk, JWK, Alg, Config}}
   catch
      _:Error -> {ok, {invalid_jwk, Error}}
   end.

handle_call({decode, Token}, _From, State) ->
  case State of 
    {valid_jwk, JWK, Alg, Config} -> 
      try decode(Token, JWK, Alg, Config) of
        TokenList -> {reply, {ok, TokenList}, State}
      catch
        _:Error -> {reply, {error, Error}, State}
      end;
    {invalid_jwk, _, _, _} -> {reply, {error, no_jwk_initialized}, State}
  end;

handle_call({init_jwk, Config}, _From, State) ->
   try init_jwk_from_config(Config) of 
     {JWK, Alg} -> {reply, {ok}, {valid_jwk, JWK, Alg, Config}}
   catch
      _:Error -> {reply, {error, Error}, State}
   end.

handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    {noreply, State}.
handle_info(_Msg, State) ->
    {noreply, State}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
terminate(_Reason, _State) ->
    ok.

init_jwk_from_config(Config) ->
   {JWK, Alg} = case {couch_util:get_value("hs_secret", Config, nil), couch_util:get_value("rs_public_key", Config, nil)} of
     {nil, nil} -> throw(no_token_secret_given);
     {HsSecret, nil} -> {#{
          <<"kty">> => <<"oct">>,
          <<"k">> => HsSecret 
        }, <<"HS256">>};
     {nil, RsPublicKey} -> {jose_jwk:from_pem(list_to_binary(RsPublicKey)), <<"RS256">>};
     {_, _} -> throw(hs_and_rs_configuration_conflict)
   end,
 {JWK, Alg}.

decode(Token, JWK, Alg, Config) ->
   case jose_jwt:verify_strict(JWK, [Alg], list_to_binary(Token)) of
     {false, _, _} -> throw(signature_not_valid);
     {true, {jose_jwt, Jwt}, _} -> validate(lists:map(fun({Key, Value}) -> 
                                                          {?b2l(Key), Value}
                                                          end, maps:to_list(Jwt)), posix_time(calendar:universal_time()), Config)
   end.

%% @doc decode and validate JWT using CouchDB config
-spec decode(Token :: binary()) -> list().
decode(Token) ->
  %decode(Token, couch_config:get("jwt_auth")).
  case gen_server:call(?MODULE, {decode, Token}) of
    {ok, TokenList} -> TokenList;
    {error, Error} -> throw(Error)
  end.

init_jwk(Config) ->
  case gen_server:call(?MODULE, {init_jwk, Config}) of
    {ok} -> ok;
    {error, Error} -> throw(Error)
  end.

% Config is list of key value pairs:
% [{"hs_secret","..."},{"roles_claim","roles"},{"username_claim","sub"}]
-spec decode(Token :: binary(), Config :: list()) -> list().
decode(Token, Config) ->
  init_jwk(Config),
  decode(Token).

posix_time({Date,Time}) -> 
    PosixEpoch = {{1970,1,1},{0,0,0}}, 
    calendar:datetime_to_gregorian_seconds({Date,Time}) - calendar:datetime_to_gregorian_seconds(PosixEpoch). 

readValidationConfig(Config) -> 
  ClaimsConfig = couch_util:get_value("validated_claims", Config, ""),
  Claims = string:tokens(ClaimsConfig,","),
    lists:map(fun(ClaimName) ->
        {ClaimName, couch_util:get_value(string:concat("validate_claim_", ClaimName), Config)}
      end, Claims). 

validate(TokenInfo, NowSeconds, Config) ->
  ValidationConfig = readValidationConfig(Config),
  Expiration = couch_util:get_value("exp", TokenInfo),
  NotBefore = couch_util:get_value("nbf", TokenInfo),
  NotValid = lists:any(fun({ClaimName, ValidValuesJSON}) ->
        ValidValues = ?JSON_DECODE(ValidValuesJSON),
        Values = case couch_util:get_value(ClaimName, TokenInfo) of
          List when is_list(List) -> List;
          _String -> [_String]
        end,
        lists:all(fun(Value) ->
          not lists:member(Value, ValidValues)
        end, Values)
      end, ValidationConfig),
  if
    NotValid -> throw(token_rejected);
    (Expiration /= undefined) and (Expiration =< NowSeconds) -> throw(token_rejected);
    (NotBefore /= undefined) and (NowSeconds < NotBefore) -> throw(token_rejected);
    true -> TokenInfo
  end.
    
token_auth_user(Req, User) ->
  {UserName, Roles} = get_userinfo_from_token(User, couch_config:get("jwt_auth")),
  Req#httpd{user_ctx=#user_ctx{name=UserName, roles=Roles}}.

get_userinfo_from_token(User, Config) ->
  UserName = couch_util:get_value(couch_util:get_value("username_claim", Config, "sub"), User, null),
  Roles = couch_util:get_value(couch_util:get_value("roles_claim", Config, "roles"), User, []),
  {UserName, Roles}.



% UNIT TESTS
-ifdef(TEST).

-define (NilConfig, []).
-define (EmptyConfig, [{"hs_secret",""}]).
-define (BasicConfig, [{"hs_secret","c2VjcmV0"}]).
-define (ConflictingConfig, [{"hs_secret","c2VjcmV0"}, {"rs_public_key", ".."}]).
-define (BasicTokenInfo, [{"sub",<<"1234567890">>},{"name",<<"John Doe">>},{"admin",true}]).
-define (RS256Config, [{"rs_public_key","-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----"}]).
-define (RS256TokenInfo, [{"sub",<<"1234567890">>},{"name",<<"John Doe">>},{"admin",true}]).

init_jwk_from_config_nil_test() ->
  ?assertThrow(no_token_secret_given, init_jwk_from_config(?NilConfig)).

init_jwk_conflicting_config_test() ->
  ?assertThrow(hs_and_rs_configuration_conflict, init_jwk_from_config(?ConflictingConfig)).

decode_malformed_empty_test() ->
  start_link(?EmptyConfig),
  ?assertThrow({badarg,_}, decode("", ?EmptyConfig)).

decode_malformed_dots_test() ->
  ?assertThrow({badarg,_}, decode("...", ?EmptyConfig)).

decode_malformed_nosignature1_test() ->
  ?assertThrow({badarg,_}, decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlfQ", ?BasicConfig)).

decode_malformed_nosignature2_test() ->
  ?assertThrow(signature_not_valid, decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlfQ.", ?BasicConfig)).

decode_simple_test() ->
  TokenInfo = ?BasicTokenInfo,
  %compare maps here since we don't care about the order of the keys
  ?assertEqual(maps:from_list(TokenInfo), maps:from_list(decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ", ?BasicConfig))).

decode_unsecured_test() ->
  ?assertThrow(signature_not_valid, decode("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.", ?BasicConfig)).

decode_rs256_test() ->
  TokenInfo = ?RS256TokenInfo,
  %compare maps here since we don't care about the order of the keys
  ?assertEqual(maps:from_list(TokenInfo), maps:from_list(decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE", ?RS256Config))).

decode_rs256_speed_when_loading_jwk_on_each_decoding_test_() ->
  {timeout, 20, fun() -> lists:map(fun(_) -> 
                {JWK, Alg} = init_jwk_from_config(?RS256Config),
                decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE", JWK, Alg, ?RS256Config) end, lists:seq(1, 10000)) end}.

decode_rs256_speed_when_using_gen_server_state_test_() ->
  {timeout, 20, fun() ->
                    init_jwk(?RS256Config),
                    lists:map(fun(_) -> decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE") end, lists:seq(1, 10000)) end}.

  validate_simple_test() ->
  TokenInfo = ?BasicTokenInfo,
  ?assertEqual(TokenInfo, validate(TokenInfo, 1000, ?EmptyConfig)).

validate_exp_nbf_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"exp",2000}, {"nbf",900}]]),
  ?assertEqual(TokenInfo, validate(TokenInfo, 1000, ?EmptyConfig)).

validate_exp_rejected_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"exp",2000}]]),
  ?assertThrow(token_rejected, validate(TokenInfo, 3000, ?EmptyConfig)).

validate_nbf_rejected_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"nbf",2000}, {"exp",3000}]]),
  ?assertThrow(token_rejected, validate(TokenInfo, 1000, ?EmptyConfig)).

validate_aud1_rejected_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"aud",<<"123">>}]]),
  Config = lists:append([?EmptyConfig, [{"validated_claims", "aud"}, {"validate_claim_aud", "[\"456\"]"}]]),
  ?assertThrow(token_rejected, validate(TokenInfo, 1000, Config)).

validate_aud2_rejected_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"aud",[<<"123">>,<<"234">>]}]]),
  Config = lists:append([?EmptyConfig, [{"validated_claims", "aud"}, {"validate_claim_aud", "[\"456\"]"}]]),
  ?assertThrow(token_rejected, validate(TokenInfo, 1000, Config)).

validate_aud_pass_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"aud",[<<"123">>,<<"234">>]}]]),
  Config = lists:append([?EmptyConfig, [{"validated_claims", "aud"}, {"validate_claim_aud", "[\"123\",\"456\"]"}]]),
  ?assertEqual(TokenInfo, validate(TokenInfo, 1000, Config)).

validate_claims_pass_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"aud",<<"123">>}, {"iss",<<"abc">>}]]),
  Config = lists:append([?EmptyConfig, [{"validated_claims", "aud,iss"}, {"validate_claim_aud", "[\"123\"]"},{"validate_claim_iss", "[\"abc\"]"}]]),
  ?assertEqual(TokenInfo, validate(TokenInfo, 1000, Config)).

posix_time1_test() ->
  ?assertEqual(31536000, posix_time({{1971,1,1}, {0,0,0}})).

posix_time2_test() ->
  ?assertEqual(31536001, posix_time({{1971,1,1}, {0,0,1}})).

get_userinfo_from_token_default_test() ->
  TokenInfo = ?BasicTokenInfo,
  {UserName, Roles} = get_userinfo_from_token(TokenInfo, ?EmptyConfig),
  ?assertEqual([], Roles),
  ?assertEqual(<<"1234567890">>, UserName).

get_userinfo_from_token_configured_test() ->
  TokenInfo = ?BasicTokenInfo,
  Config = lists:append([?EmptyConfig, [{"username_claim", "name"}]]),
  {UserName, Roles} = get_userinfo_from_token(TokenInfo, Config),
  ?assertEqual([], Roles),
  ?assertEqual(<<"John Doe">>, UserName).

% user context is created with null username if username claim is not found from token
get_userinfo_from_token_name_not_found_test() ->
  TokenInfo = lists:append([?BasicTokenInfo,[{"roles",[<<"123">>]}]]),
  Config = lists:append([?EmptyConfig, [{"username_claim", "doesntexist"}]]),
  {UserName, Roles} = get_userinfo_from_token(TokenInfo, Config),
  ?assertEqual([<<"123">>], Roles),
  ?assertEqual(null, UserName).
-endif.
