-module(openid_connect_configuration).
-export([load_jwk_from_config_url/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

load_jwk_from_config_url(ConfigurationUrl) -> 
  {ok, { {_, 200, _}, _, ConfigurationJson}} = httpc:request(ConfigurationUrl),
  Configuration = jsx:decode(list_to_binary(ConfigurationJson), [return_maps]),
  #{<<"jwks_uri">> := JwksUri} = Configuration,
  {ok, { {_, 200, _}, _, JwksJson}} = httpc:request(binary_to_list(JwksUri)),
  jose_jwk:from(list_to_binary(JwksJson)).


% UNIT TESTS
-ifdef(TEST).
-define (PrivateRSAKey, "-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEArrS5prfIX1AaFEzmL1wq/k3k5hiAKnJZz5ev+iIivcUCAwEAAQIg
JJRektPENoC1FS8MuznXHlNpkYjvJ49mOfJQUSp9HIECEQDXY7Tq8V6j/HqgFSe8
Qx51AhEAz6VUgN0H5+1xwyOBtq/YEQIRANO6cLLvOFBNNaG9igT3ma0CEQClL7lR
6oRnlRVzT8PZOXqBAhEAssLyiaIABERKr2aGrKyE9A==
-----END RSA PRIVATE KEY-----").

load_jwk_from_config_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
      {"should load jwk from link in openid configuration", fun() ->
                                                               PrivateJwk = jose_jwk:from_pem(list_to_binary(?PrivateRSAKey)),
                                                               {_, JwkJson} = jose_jwk:to_binary(PrivateJwk),
                                                               
                                                               meck:new(httpc),
                                                               meck:expect(httpc, request, [{["http://localhost/.well-known/openid-configuration"],
                                                                                                {ok, { {"Version",200, "Reason"}, [], "{'jwks_uri': 'http://localhost/jwks'}"}}},
                                                                                               {["http://localhost/jwks"],
                                                                                                {ok, { {"Version",200, "Reason"}, [], binary_to_list(JwkJson)}}}
                                                                                              ]), 
                                                               try
                                                                JwkLoaded = load_jwk_from_config_url("http://localhost/.well-known/openid-configuration"),
                                                                ?assertEqual(PrivateJwk, JwkLoaded)
                                                               after
                                                                 meck:validate(httpc),
                                                                 meck:unload(httpc) 
                                                               end
                                                           end} 
    ]}.

setup() ->
  {ok, _} = application:ensure_all_started(inets),
  {ok, _} = application:ensure_all_started(ssl).

cleanup(_) ->
  ok.

-endif.
