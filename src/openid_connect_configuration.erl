-module(openid_connect_configuration).
-export([load_jwk_set_from_config_url/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

load_jwk_set_from_config_url(ConfigurationUrl) -> 
  {ok, { {_, 200, _}, _, ConfigurationJson}} = httpc:request(ConfigurationUrl),
  Configuration = jsx:decode(list_to_binary(ConfigurationJson), [return_maps]),
  #{<<"jwks_uri">> := JwksUri} = Configuration,
  {ok, { {_, 200, _}, _, JwksJson}} = httpc:request(binary_to_list(JwksUri)),
  case Jwk = jose_jwk:from(list_to_binary(JwksJson)) of
    {jose_jwk, {jose_jwk_set, KeySet}, _, _} -> KeySet; 
    {jose_jwk, undefined, _, _} -> [Jwk]%single key
  end.


% UNIT TESTS
-ifdef(TEST).
-define (PrivateRSAKey, "-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEArrS5prfIX1AaFEzmL1wq/k3k5hiAKnJZz5ev+iIivcUCAwEAAQIg
JJRektPENoC1FS8MuznXHlNpkYjvJ49mOfJQUSp9HIECEQDXY7Tq8V6j/HqgFSe8
Qx51AhEAz6VUgN0H5+1xwyOBtq/YEQIRANO6cLLvOFBNNaG9igT3ma0CEQClL7lR
6oRnlRVzT8PZOXqBAhEAssLyiaIABERKr2aGrKyE9A==
-----END RSA PRIVATE KEY-----").

-define (KeySetJson, "{
'keys': [
{
 'kty': 'RSA',
 'alg': 'RS256',
 'use': 'sig',
 'kid': '2e4c1fcf6e968282397fe03ab848d4e9c9c27bb3',
 'n': 'wD49pRcnhqqvg3elGfH-oP6VSKuaf9ELSYwKSq4pXPwp01lIGtareYLT0gYQw_PXOQLN_ttt8JmvPVwijr3UQ6eCiVhWnFDJFpNlaYOyCfpKEJU0q25ZiPkbQYnG1cpM9Um1YjaB7at_pdBFdkMfO0H7yHVyypmfdcHQRdMN_AdeIwfsYnR3sk83I0JzT_DB28n6YlHfsk8tfF7MIRZ6TZbhIJf_3n_RnV-i6ymY6r_818Zv9gnhYRjadVGT0vvXE0lIWTRDcYuBhlLF_Uhi_KVUr6pMVhjVFvswBh2ixAL3Aet-OK8qQj13OhC9bBVVz7lAarLhhxyG5UMdHWhIhw',
 'e': 'AQAB'
},
{
 'kty': 'RSA',
 'alg': 'RS256',
 'use': 'sig',
 'kid': '5243b429de18f456856093046740e05664c42996',
 'n': '5FZPC-na4vUy-Q9n0yXtMctyf8RqMcU0lAEzGgfFintDXBmMREw3-4K8XcgfpGibyG_05sGTbuVb058FgudfKmHe5rfD-Fy37R4jtpPy1Gnqhw26ytehZPhq5MWjH9sYPaTb1CFd7rZRrArTksk4iceGAyGWX2pvCVE0r5-_UWUoVW289SDqRBrv6MnxD8FYUX5-NGLThM-07AsXHtN04q19_mMKV4TfTwkUlZb-EGa88YKia16HxiVZeRaE2NVpGMJYxd-TizMtACjdd616kSt2ZUNV4Tx1C8HM779yXyu-5kiqO2niQkPnUvSLOWMcJSaE-osVHaqoLrRcEU3ugQ',
 'e': 'AQAB'
},
{
 'kty': 'RSA',
 'alg': 'RS256',
 'use': 'sig',
 'kid': 'f596800f80b253fcd7fa6eb50c0dd60a32cb29ec',
 'n': '5gCnR8CDlMunqB5EdXYpFhRBeTXbf-88P7CTN8v7_wPVuuXjhTuP6gnP0BnSI3l4JcYVOP65nvRzkKJVEqP2Wrom1kwQYQBkjLTze_jsYEtTaNocA9anl0OprhVy4DkytEpZ4b3EfYpr4BNxkMTEhefgUmM-HNyDUw-IHaR37tbzopcJ4dnv8K94p1mwnwb78wxLEViGXuOFCe6Nwf6K68idliekUVdQSFUocwVznCi4OffZQcsWP6wtELqBRYqmBvnHAuygZCet7rLwBy-i82f0vGZhpQvnWP8yltgvCqSGJ5J0lS0fJ9e92aD_RBb2HV9LY72z2kIeQ30p9vVOvQ',
 'e': 'AQAB'
}
]
}").

%don't use test generator pattern here, otherwise we run into a funny meck issue
%when trying to mock openid_connect_configuration module lateron:
%https://github.com/eproxus/meck/issues/133
load_single_jwk_from_config_test() ->
  jose:json_module(jsx),
  PrivateJwk = jose_jwk:from_pem(list_to_binary(?PrivateRSAKey)),
  {_, JwkJson} = jose_jwk:to_binary(PrivateJwk),

  meck:new(httpc),
  meck:expect(httpc, request, [{["http://localhost/.well-known/openid-configuration"],
                                {ok, { {"Version",200, "Reason"}, [], "{'jwks_uri': 'http://localhost/jwks'}"}}},
                               {["http://localhost/jwks"],
                                {ok, { {"Version",200, "Reason"}, [], binary_to_list(JwkJson)}}}
                              ]), 
  try
    JwkLoaded = load_jwk_set_from_config_url("http://localhost/.well-known/openid-configuration"),
    ?assertEqual([PrivateJwk], JwkLoaded)
  after
    meck:validate(httpc),
    meck:unload(httpc) 
  end.

load_jwk_set_from_from_config_test() ->
  meck:new(httpc),
  meck:expect(httpc, request, [{["http://localhost/.well-known/openid-configuration"],
                                {ok, { {"Version",200, "Reason"}, [], "{'jwks_uri': 'http://localhost/jwks'}"}}},
                               {["http://localhost/jwks"],
                                {ok, { {"Version",200, "Reason"}, [], ?KeySetJson}}}
                              ]), 
  try
    JwkLoaded = load_jwk_set_from_config_url("http://localhost/.well-known/openid-configuration"),
    {jose_jwk, {jose_jwk_set, KeySet}, _, _} = jose_jwk:from(list_to_binary(?KeySetJson)),
    ?assertEqual(KeySet, JwkLoaded)
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
