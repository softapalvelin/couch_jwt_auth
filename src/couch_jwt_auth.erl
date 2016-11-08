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


-ifndef(LOG_INFO).
%we're most certainly compiling for CouchDB 2.0
-define(LOG_INFO(Format, Args), couch_log:info(Format, Args)).
-define(CONFIG_GET(Section), config:get(Section)).
-else.
-define(CONFIG_GET(Section), couch_config:get(Section)).
-endif.

-ifndef(JSON_DECODE).
%on CouchDB 2.0 JSON_DECODE is no longer defined
-define(LOG_INFO(Format, Args), couch_log:info(Format, Args)).
-define(JSON_DECODE(Json), jsx:decode(list_to_binary(Json))).
-endif.

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
   Config = ?CONFIG_GET("jwt_auth"),
   start_link(Config).

init([]) ->
{ok, {invalid_jwk, empty_initialization}};

init(Config) ->
   try init_jwk_from_config(Config) of 
     JwkSet -> {ok, {valid_jwk, JwkSet, Config}}
   catch
      _:Error -> {ok, {invalid_jwk, Error}}
   end.

handle_call({get_jwk}, _From, State) ->
  {reply, State, State};

handle_call({init_jwk, Config}, _From, State) ->
   try init_jwk_from_config(Config) of 
     JwkSet -> {reply, {ok}, {valid_jwk, JwkSet, Config}}
   catch
      _:Error -> {reply, {error, Error}, State}
   end;

handle_call({reload_jwk, Config}, _From, State) ->
   try load_jwk_set_from_url_in_config(Config) of 
     RsJwkSet ->
       {valid_jwk, #{hs256 := HsKeys, rs256 := RsKeys}, _} = State, 
       NewJwkSet = #{hs256 => HsKeys, rs256 => maps:merge(RsKeys, RsJwkSet)},
       {reply, {ok}, {valid_jwk, NewJwkSet, Config}}
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
  jose:json_module(jsx),
  HsKeys = case couch_util:get_value("hs_secret", Config, nil) of
             nil -> #{};
             HsSecret -> #{default => 
                           #{
                               <<"kty">> => <<"oct">>,
                               <<"k">> => HsSecret 
                              }}
           end,

  RsPEMKey = case couch_util:get_value("rs_public_key", Config, nil) of
               nil -> #{};
               RsPublicKey -> #{default => jose_jwk:from_pem(list_to_binary(RsPublicKey))}
             end,

  RSOpenIdKeys = load_jwk_set_from_url_in_config(Config), 
  #{hs256 => HsKeys, rs256 => maps:merge(RsPEMKey, RSOpenIdKeys)}.

load_jwk_set_from_url_in_config(Config) ->
  case couch_util:get_value("openid_authority", Config, nil) of 
    nil -> #{};
    OpenIdAuthority -> 
      ConfigUri = OpenIdAuthority ++ ".well-known/openid-configuration",
      ?LOG_INFO("Loading public key from  ~s", [ConfigUri]),

      try
	      KeySet = openid_connect_configuration:load_jwk_set_from_config_url(ConfigUri),
	      maps:from_list(lists:map(fun(Key) ->  case Key of
							    {jose_jwk, _, _, #{<<"kid">> := Kid}} -> {Kid, Key};
							    {jose_jwk, _, _, _} -> {default, Key}
						    end end, KeySet))
      catch 
	      _:_-> ?LOG_INFO("Failed loading public key from ~s", [ConfigUri]),
		    #{} %return an empty map 
      end
  end.

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
  try jose_jwt:peek_protected(list_to_binary(Token)) of
    TokenProtected -> case TokenProtected of
                        {jose_jws, {jose_jws_alg_hmac, 'HS256'}, _, #{<<"kid">> := Kid}} -> decode(Token, hs256, Kid);
                        {jose_jws, {jose_jws_alg_hmac, 'HS256'}, _, _} -> decode(Token, hs256, default);
                        {jose_jws, {jose_jws_alg_rsa_pkcs1_v1_5, 'RS256'}, _, #{<<"kid">> := Kid ,<<"typ">> := <<"JWT">>}} -> decode(Token, rs256, Kid); 
                        {jose_jws, {jose_jws_alg_rsa_pkcs1_v1_5, 'RS256'}, _, _} -> decode(Token, rs256, default);
                        _ -> throw(signature_not_valid)
                      end
  catch
    _:Error -> throw(Error)
  end.

decode(Token, Alg, Kid) ->
  case {Alg, gen_server:call(?MODULE, {get_jwk})} of
    {hs256, {valid_jwk, JwkSet, Config}} ->
      case maps:find(Kid, maps:get(Alg, JwkSet)) of
        {ok, Jwk} ->decode(Token, Jwk, <<"HS256">>, Config);
        error -> throw(key_not_found) %no way of getting a new key on HS256
      end;
    {rs256, {valid_jwk, JwkSet, Config}} ->
      case maps:find(Kid, maps:get(Alg, JwkSet)) of
        {ok, Jwk} ->decode(Token, Jwk, <<"RS256">>, Config);
        error -> %key wasn't found. we reload from openid_authority to see if it's a new key after a key rotation 
          case gen_server:call(?MODULE, {reload_jwk, Config}) of
            {ok} -> ok;
            {error, ReloadError} -> throw(ReloadError)
          end,
          case gen_server:call(?MODULE, {get_jwk}) of
            {valid_jwk, NewJwkSet, _} -> 
              case maps:find(Kid, maps:get(Alg, NewJwkSet)) of
                {ok, NewJwk} -> decode(Token, NewJwk, <<"RS256">>, Config);
                error -> throw(key_not_find)
              end; 
            {invalid_jwk, Error} -> throw(Error)
          end;
        {invalid_jwk, Error} -> throw(Error)
      end;
    {_, {invalid_jwk, Error}} -> throw(Error)
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
  {UserName, Roles} = get_userinfo_from_token(User, ?CONFIG_GET("jwt_auth")),
  Req#httpd{user_ctx=#user_ctx{name=UserName, roles=Roles}}.

get_userinfo_from_token(User, Config) ->
  UserName = couch_util:get_value(couch_util:get_value("username_claim", Config, "sub"), User, null),
  Roles = couch_util:get_value(couch_util:get_value("roles_claim", Config, "roles"), User, []),
  {UserName, Roles}.
