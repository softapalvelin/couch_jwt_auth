-module(couch_jwt_auth_tests).
-include_lib("eunit/include/eunit.hrl").

-import(couch_jwt_auth, [start_link/1, stop/0, decode/1, decode/2, decode/4, validate/3]).
-import(couch_jwt_auth, [init_jwk_from_config/1, init_jwk/1]).
-import(couch_jwt_auth, [posix_time/1, get_userinfo_from_token/2]).

-define (NilConfig, []).
-define (EmptyConfig, [{"hs_secret",""}]).
-define (BasicConfig, [{"hs_secret","c2VjcmV0"}]).
-define (ConflictingConfig, [{"hs_secret","c2VjcmV0"}, {"rs_public_key", ".."}]).
-define (BasicTokenInfo, [{"sub",<<"1234567890">>},{"name",<<"John Doe">>},{"admin",true}]).
-define (SimpleToken, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ").
-define (NoSignatureToken,  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlfQ").
-define (NoSignatureToken2, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlfQ.").
-define (UnsecuredToken, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.").

-define (RS256Config, [{"rs_public_key","-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----"}]).
-define (RS256TokenInfo, [{"sub",<<"1234567890">>},{"name",<<"John Doe">>},{"admin",true}]).
-define (RS256Token, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE").

-define (OpenIdConfig, [{"openid_authority","http://localhost/"}]).
-define (PrivateRSAKey, "-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----").
-define (TokenForPrivateRSAKey, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE").

-define (PrivateRSAKey2, "-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCqdXgjtv85R+z4K+ghXY9AcFKFtSKme0I3wU7pdlyhiAPiRh+C
KM3ubb42fk0leH977UXhCiTzmtNYK9N9F6VpegmysDl3WD1M7LnpUA8JPlnGU0Nj
1pA1iYvP82o9SKNvOMG8Va1dCnv6ZKA0/4CJJCmpA/xjKx3JUHMY83uGOQIDAQAB
AoGAezm6ZQ84iB8/5tRO1jf9hBbvASvF5dY7M3UyZ8GiCz/5ls0coAqBfHinRlud
x5XJizwnBR1BQz3MxPPByq+aamxAmWEE+2Z0iFAfuumikNSZMTzzY0k9w/m+760/
n/x5KAdwNjKycsLPhK5JYrhP/jho+LUhF1O7wAzbnZT6jyUCQQDdQte6wMwj8km+
pkeYIsaGbPs+K48GtJeCIm1W/nA4+6N+ujrN5f02Sa407H6N4x13wh5tXHYP/rnr
rAs5JVmLAkEAxTi63UXPH8glqrDxTz0szRW28WI0DM8Gq3H1TaXSeZLLk9uhva4n
ZMlLd/6e8h3Fiq4uI9LiQbkoR1uEUecvywJAGqawgYgzjqjihRpWSVb2/r4lzSlG
AxLBpSUscmwXbGWzHdKkvqRTSbS6TRmnbMPMit5Q9+9JMUgHcQG6IFoFXQJATE6n
1mdlPWnGUSXHKB6GUA9/yiNx+ia78OfVvqZTKmDGzb2j9e0FJvTPc20b+JfWT9MW
3RuCGWXXlMxvBPWLQwJAV1XSMxwRaRm55zVqE78xwGzCOp1PIHHAyYqXmBknn/Mv
5DXn3l3kxcZVj4DEn2FAEmrpHRtKSf9X+GvPrt8rGQ==
-----END RSA PRIVATE KEY-----").

-define (TokenForPrivateRSAKey2WithKida, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.HoqbCf0x8cm0pbtS7PpQz21amq4w7zgApsflrvkChXUt3mvfJI_Aa46HlpAPUWOSnmeri5NRxPjEK-FSk9S1lanDnUCrXJBHQT94W6NLbtem3oNngm-BbIThEZjCi0gJxclXxO1BvtibiRxvMA-tskuxGpZBWpdMNRHgCqUlccU").

decoding_using_gen_server_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"load public key from openid configuration url", fun() ->
                                                              PublicKey = [jose_jwk:to_public(jose_jwk:from_pem(list_to_binary(?PrivateRSAKey)))],
                                                              meck:new(openid_connect_configuration, [no_link]),
                                                              meck:expect(openid_connect_configuration, 
                                                                          load_jwk_set_from_config_url, [{ ["http://localhost/.well-known/openid-configuration"], PublicKey}]),
                                                              try
                                                                init_jwk(?OpenIdConfig),
                                                                decode(?TokenForPrivateRSAKey)
                                                              after
                                                                 meck:validate(openid_connect_configuration),
                                                                 meck:unload(openid_connect_configuration) 
                                                              end
                                                            end},
        {"reload public key from openid configuration url when first attempt of loading failed", fun() ->
                                                              meck:new(openid_connect_configuration, [no_link]),
                                                              meck:expect(openid_connect_configuration, 
                                                                          load_jwk_set_from_config_url, fun("http://localhost/.well-known/openid-configuration") -> meck:exception(error, stupid_error) end),
                                                              try
                                                                init_jwk(?OpenIdConfig)
                                                              after
                                                                 meck:validate(openid_connect_configuration),
                                                                 meck:unload(openid_connect_configuration) 
                                                              end,
                                                                
                                                              meck:new(openid_connect_configuration, [no_link]),
                                                              {_, PrivateKeyMap} = jose_jwk:to_map(jose_jwk:from_pem(list_to_binary(?PrivateRSAKey2))),
                                                              PublicKeyWithKid = [jose_jwk:to_public(jose_jwk:from_map(maps:put(<<"kid">>, <<"a">>, PrivateKeyMap)))],
                                                              meck:expect(openid_connect_configuration, 
                                                                          load_jwk_set_from_config_url, [{ ["http://localhost/.well-known/openid-configuration"], PublicKeyWithKid}]),
                                                              try
                                                                decode(?TokenForPrivateRSAKey2WithKida)
                                                              after
                                                                meck:validate(openid_connect_configuration),
                                                                meck:unload(openid_connect_configuration) 
                                                              end
                                                            end},
        {"reload public key from openid configuration url when token with new kid is given", fun() ->
                                                              PublicKey = [jose_jwk:to_public(jose_jwk:from_pem(list_to_binary(?PrivateRSAKey)))],
                                                              meck:new(openid_connect_configuration, [no_link]),
                                                              meck:expect(openid_connect_configuration, 
                                                                          load_jwk_set_from_config_url, [{ ["http://localhost/.well-known/openid-configuration"], PublicKey}]),
                                                              try
                                                                init_jwk(?OpenIdConfig),
                                                                decode(?TokenForPrivateRSAKey)
                                                              after
                                                                 meck:validate(openid_connect_configuration),
                                                                 meck:unload(openid_connect_configuration) 
                                                              end,
                                                                
                                                              meck:new(openid_connect_configuration, [no_link]),
                                                              {_, PrivateKeyMap} = jose_jwk:to_map(jose_jwk:from_pem(list_to_binary(?PrivateRSAKey2))),
                                                              PublicKeyWithKid = [jose_jwk:to_public(jose_jwk:from_map(maps:put(<<"kid">>, <<"a">>, PrivateKeyMap)))],
                                                              meck:expect(openid_connect_configuration, 
                                                                          load_jwk_set_from_config_url, [{ ["http://localhost/.well-known/openid-configuration"], PublicKeyWithKid}]),
                                                              try
                                                                decode(?TokenForPrivateRSAKey2WithKida)
                                                              after
                                                                meck:validate(openid_connect_configuration),
                                                                meck:unload(openid_connect_configuration) 
                                                              end
                                                            end},

        {"decode malformed token, only dots", fun() -> ?assertThrow({badarg,_}, decode("...", ?EmptyConfig)) end},
        
        {"decode malformed token, no signature", fun() -> ?assertThrow({badarg,_}, decode(?NoSignatureToken, ?BasicConfig)) end},
        
        {"decode malformed token, no signature 2", fun() -> ?assertThrow(signature_not_valid, decode(?NoSignatureToken2, ?BasicConfig)) end},
        
        %compare maps here since we don't care about the order of the keys
        {"decode simple", fun () -> ?assertEqual(maps:from_list(?BasicTokenInfo), maps:from_list(decode(?SimpleToken, ?BasicConfig))) end},
        
        {"decode unsecured", fun () -> ?assertThrow(signature_not_valid, decode(?UnsecuredToken, ?BasicConfig)) end},
        
        %compare maps here since we don't care about the order of the keys
        {"decode rs256", fun () -> ?assertEqual(maps:from_list(?RS256TokenInfo), maps:from_list(decode(?RS256Token, ?RS256Config))) end},
        
        {"decode rs256 test speed when using loading jwk on each decoding", 
         {timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0}},

        {"decode rs256 test speed when using loading jwk on each decoding and running in parallel", 
         {inparallel, [{timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0}, 
                       {timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0},
                       {timeout, 20, fun decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler/0}]}},
        
        {"decode rs256 test speed when using gen_server state", 
         {timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}},
        
        {"decode rs256 test speed when using gen server state and running in parallel", 
         {inparallel, [{timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}, 
                       {timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}, 
                       {timeout, 20, fun decode_rs256_speed_when_using_gen_server_state_test_handler/0}]}}
    ]}.

setup() ->
  {ok, Pid} = start_link(?EmptyConfig),
  Pid.

cleanup(_) ->
  stop().

decode_rs256_speed_when_loading_jwk_on_each_decoding_test_handler() -> 
  lists:map(fun(_) -> 
                #{rs256 := #{default := JWK}} = init_jwk_from_config(?RS256Config),
                decode(?RS256Token, JWK, <<"RS256">>, ?RS256Config) end, lists:seq(1, 10000)).

decode_rs256_speed_when_using_gen_server_state_test_handler() ->
  init_jwk(?RS256Config),
  lists:map(fun(_) -> decode(?RS256Token) end, lists:seq(1, 10000)).


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
