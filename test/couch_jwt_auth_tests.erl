-module(couch_jwt_auth_tests).
-include_lib("eunit/include/eunit.hrl").

-import(couch_jwt_auth, [start_link/1, decode/1, decode/2, decode/4, validate/3]).
-import(couch_jwt_auth, [init_jwk_from_config/1, init_jwk/1]).
-import(couch_jwt_auth, [posix_time/1, get_userinfo_from_token/2]).

-define (NilConfig, []).
-define (EmptyConfig, [{"hs_secret",""}]).
-define (BasicConfig, [{"hs_secret","c2VjcmV0"}]).
-define (ConflictingConfig, [{"hs_secret","c2VjcmV0"}, {"rs_public_key", ".."}]).
-define (BasicTokenInfo, [{"sub",<<"1234567890">>},{"name",<<"John Doe">>},{"admin",true}]).
-define (RS256Config, [{"rs_public_key","-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----"}]).
-define (RS256TokenInfo, [{"sub",<<"1234567890">>},{"name",<<"John Doe">>},{"admin",true}]).
-define (RS256Token, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE").

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
  ?assertEqual(maps:from_list(TokenInfo), maps:from_list(decode(?RS256Token, ?RS256Config))).

decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler() -> 
  lists:map(fun(_) -> 
                {JWK, Alg} = init_jwk_from_config(?RS256Config),
                decode(?RS256Token, JWK, Alg, ?RS256Config) end, lists:seq(1, 10000)).

decode_rs256_speed_when_loading_jwk_on_each_decoding_test_() ->
  {timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0}.

decode_rs256_speed_when_loading_jwk_on_each_decoding_parallel_test_() ->
  {inparallel, [{timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0}, 
                {timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0},
                {timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0}]}.

decode_rs256_speed_when_using_gen_server_state_test_handler() ->
  init_jwk(?RS256Config),
  lists:map(fun(_) -> decode(?RS256Token) end, lists:seq(1, 10000)).

decode_rs256_speed_when_using_gen_server_state_test_() ->
  {timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}.

decode_rs256_speed_when_using_gen_server_state_parallel_test_() ->
  {inparallel, [{timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}, 
                {timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}, 
                {timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}]}.

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
