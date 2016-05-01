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

-export([start_link/0, start_link/1, stop/0, init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-export([jwt_authentication_handler/1]).
-export([init_jwk_from_config/1]).
-export([init_jwk/1]).
-export([decode/1]).
-export([decode/2]).
-export([decode/4]).
-export([validate/3]).

-export([posix_time/1]).
-export([get_userinfo_from_token/2]).

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

handle_call({get_jwk}, _From, State) ->
  {reply, State, State};

handle_call({init_jwk, Config}, _From, State) ->
   try init_jwk_from_config(Config) of 
     {JWK, Alg} -> {reply, {ok}, {valid_jwk, JWK, Alg, Config}}
   catch
      _:Error -> {reply, {error, Error}, State}
   end;

handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.
handle_info(_Msg, State) ->
    {noreply, State}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
terminate(_Reason, _State) ->
    ok.

init_jwk_from_config(Config) ->
   {JWK, Alg} = case {couch_util:get_value("hs_secret", Config, nil), couch_util:get_value("rs_public_key", Config, nil), couch_util:get_value("openid_authority", Config, nil)} of
     {nil, nil, nil} -> throw(no_token_secret_given);
     {HsSecret, nil, nil} -> {#{
          <<"kty">> => <<"oct">>,
          <<"k">> => HsSecret 
        }, <<"HS256">>};
     {nil, RsPublicKey, nil} -> {jose_jwk:from_pem(list_to_binary(RsPublicKey)), <<"RS256">>};
     {nil, nil, OpenIdAuthority} -> 
                    ConfigUri = OpenIdAuthority ++ ".well-known/openid-configuration",
                    ?LOG_INFO("Loading public key from  ~s", [ConfigUri]),
                    {openid_connect_configuration:load_jwk_from_config_url(ConfigUri), <<"RS256">>};
     {_, _, _} -> throw(token_provider_configuration_conflict)
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
  case gen_server:call(?MODULE, {get_jwk}) of
    {valid_jwk, JWK, Alg, Config} ->
      try decode(Token, JWK, Alg, Config) of
        TokenList -> TokenList 
      catch
        _:Error -> throw(Error) 
      end;
    {invalid_jwk, Error} -> throw(Error)
  end.

init_jwk(Config) ->
  case gen_server:call(?MODULE, {init_jwk, Config}) of
    {ok} -> ok;
    {error, Error} -> throw(Error)
  end.

stop() ->
  gen_server:call(?MODULE, stop).

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
