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
  case Jwk = jose_jwk:from(list_to_binary(JwksJson)) of
	{jose_jwk, undefined, _, _} -> Jwk;%single key
	{jose_jwk, {jose_jwk_set, KeySet}, _, _} -> 
		  %key set, take first key
		  [FirstKey | _] = KeySet,
		  FirstKey
	end.


% UNIT TESTS
-ifdef(TEST).
-define (PrivateRSAKey, "-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEArrS5prfIX1AaFEzmL1wq/k3k5hiAKnJZz5ev+iIivcUCAwEAAQIg
JJRektPENoC1FS8MuznXHlNpkYjvJ49mOfJQUSp9HIECEQDXY7Tq8V6j/HqgFSe8
Qx51AhEAz6VUgN0H5+1xwyOBtq/YEQIRANO6cLLvOFBNNaG9igT3ma0CEQClL7lR
6oRnlRVzT8PZOXqBAhEAssLyiaIABERKr2aGrKyE9A==
-----END RSA PRIVATE KEY-----").

-define (KeySetJson, "{'keys':[{'kid':'HCVGNTNQFL1IA56BHLSPMMTZ8UHXXUO_9UNZ3UAO','use':'sig','kty':'RSA','alg':'RS256','e':'EQ','n':'hcVgNTNQFL1Ia56bhlSPmmTZ8UhXxUO_9UNZ3uAOdh6jOpXczGJFLSK8SuOnm4JuiTcC5gsqf6uMgwJl-TywWVo_GC026MzfCu4NOaKmVx7p3Hs4DzXqaAQwv9Q6sFzF50QK-uMrdStS2Mqd_eT-dtXN2-dT9CQZfP_vHVl6UBAuUiocts5ielHo95FTnLMVC9TEOyCKnQ_u_335p5LEhgTvhXPPO7EV7H8cVGmAOl7Z_2qS2LwS6MKJaQJmMybM3YGVrz-TGJKg-5qCBOzcevsdjgyJlUuKpgzMKuxAC4lFSvuMeCD1ml-zRNsGrcCMyfbIa4xkIwPMvaf_ZfCzaw'}]}").

-define (PEMKeyInKeySet, "-----BEGIN RSA PUBLIC KEY-----
MIIBCAKCAQEAhcVgNTNQFL1Ia56bhlSPmmTZ8UhXxUO/9UNZ3uAOdh6jOpXczGJF
LSK8SuOnm4JuiTcC5gsqf6uMgwJl+TywWVo/GC026MzfCu4NOaKmVx7p3Hs4DzXq
aAQwv9Q6sFzF50QK+uMrdStS2Mqd/eT+dtXN2+dT9CQZfP/vHVl6UBAuUiocts5i
elHo95FTnLMVC9TEOyCKnQ/u/335p5LEhgTvhXPPO7EV7H8cVGmAOl7Z/2qS2LwS
6MKJaQJmMybM3YGVrz+TGJKg+5qCBOzcevsdjgyJlUuKpgzMKuxAC4lFSvuMeCD1
ml+zRNsGrcCMyfbIa4xkIwPMvaf/ZfCzawIBEQ==
-----END RSA PUBLIC KEY-----").

%don't use test generator pattern here, otherwise we run into a funny meck issue
%when trying to mock openid_connect_configuration module lateron:
%https://github.com/eproxus/meck/issues/133
load_single_jwk_from_config_test() ->
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
  end.

load_first_jwk_from_set_from_config_test() ->
  meck:new(httpc),
  meck:expect(httpc, request, [{["http://localhost/.well-known/openid-configuration"],
                                {ok, { {"Version",200, "Reason"}, [], "{'jwks_uri': 'http://localhost/jwks'}"}}},
                               {["http://localhost/jwks"],
                                {ok, { {"Version",200, "Reason"}, [], ?KeySetJson}}}
                              ]), 
  try
    JwkLoaded = load_jwk_from_config_url("http://localhost/.well-known/openid-configuration"),
    ?assertEqual(jose_jwk:to_pem(jose_jwk:from_pem(list_to_binary(?PEMKeyInKeySet))), jose_jwk:to_pem(JwkLoaded))
  after
    meck:validate(httpc),
    meck:unload(httpc) 
  end.
%setup() ->
%  {ok, _} = application:ensure_all_started(inets),
%  {ok, _} = application:ensure_all_started(ssl).

%cleanup(_) ->
%  ok.

-endif.
