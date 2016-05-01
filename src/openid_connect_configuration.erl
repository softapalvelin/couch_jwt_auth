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

%Set of Google keys as of April 30 2016.
%Quick and dirty approach to testing, test will fail once Google change their keys. 
-define (GoogleJwk, {jose_jwk,{jose_jwk_set,[{jose_jwk,undefined,
                                              {jose_jwk_kty_rsa,{'RSAPublicKey',20206560680338767966113549800092864444815226395364321118810492063125077232472726130026157875619038715958927265601322339310166323162412293093211851469723779575522576466296478566790747995780410098571744471878323937448645573393799654878349438130854284659811893569111373873227493475199456374892951853689365519614169586464843255523436575946022077125295883638933581666742449113039099591769210025714286073302286758273862925269047851682708672135770642709064117060149558805245180906038583088131620476785661270604325423755298411912486722600991370383679800980249390767569969763750539090229703190168094445793264267808336779990059,
                                                                 65537}},
                                              #{<<"alg">> => <<"RS256">>,
                                                <<"kid">> => <<"225038926437474586a7bcd302b06694e9d70733">>,
                                                <<"use">> => <<"sig">>}},
                                             {jose_jwk,undefined,
                                              {jose_jwk_kty_rsa,{'RSAPublicKey',23057364752339592387136431039591833247815320249115920080891100289620278805852536284027635618114699005339098620472360194835114382896398817355924696759257721908424490779772199553649363807728476991453601444338567461874061798086043217971021947782206212438615786452801531112195267535798912116270886899785585331030698336380098736448360775545570371716003476414126501361187359607038623392527667825820035625377025785657841602136549202456722129978768350261691227033539821412280231303717786830482708766431502430886533945121478791201757452016728731956367280993909631426542805588267882542261363135351403804590666438077263901561561,
                                                                 65537}},
                                              #{<<"alg">> => <<"RS256">>,
                                                <<"kid">> => <<"0c0e73cd83b43b1243bb05eccbf4f2908416d1d4">>,
                                                <<"use">> => <<"sig">>}}]},
                     undefined,#{}}).

load_jwk_from_config_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
      {"should load jwk from google openid configuration", fun() -> 
                                                               ?assertEqual(?GoogleJwk, load_jwk_from_config_url("https://accounts.google.com/.well-known/openid-configuration")) end} 
    ]}.

setup() ->
  {ok, _} = application:ensure_all_started(inets),
  {ok, _} = application:ensure_all_started(ssl).

cleanup(_) ->
  ok.

-endif.
