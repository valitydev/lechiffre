-module(lechiffre_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-record('BankCard', {
    token :: binary()
}).

-export([struct_info/1]).
-export([record_name/1]).

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([
    encode_binary_ok_test/1,
    unknown_decrypt_key_test/1,
    wrong_key_test/1,
    wrong_encrypted_key_format_test/1,
    encrypt_hide_secret_key_ok_test/1,
    encode_with_params_ok_test/1,
    lechiffre_init_jwk_no_kid_test/1
]).

-type config() :: [{atom(), term()}].

-spec all() -> [atom()].
all() ->
    [
        encode_binary_ok_test,
        encrypt_hide_secret_key_ok_test,
        unknown_decrypt_key_test,
        wrong_key_test,
        wrong_encrypted_key_format_test,
        encode_with_params_ok_test,
        lechiffre_init_jwk_no_kid_test
    ].

-spec groups() -> list().
groups() ->
    [].

-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    Config.

-spec end_per_suite(config()) -> ok.
end_per_suite(_C) ->
    ok.

-spec init_per_testcase(atom(), config()) -> config().
init_per_testcase(_Name, Config) ->
    FileSource1 = get_source_binary(<<"oct">>, <<"1">>, <<"A128GCMKW">>),
    FileSource2 = get_source_binary(<<"oct">>, <<"2">>, <<"A128GCMKW">>),
    Options = #{
        encryption_source => {json, FileSource1},
        decryption_sources => [
            {json, FileSource1},
            {json, FileSource2}
        ]
    },
    ChildSpec = lechiffre:child_spec(lechiffre, Options),
    {ok, SupPid} = genlib_adhoc_supervisor:start_link({one_for_all, 0, 1}, [ChildSpec]),
    _ = unlink(SupPid),
    Config ++ [{sup_pid, SupPid}].

-spec end_per_testcase(atom(), config()) -> config().
end_per_testcase(_Name, Config) ->
    {_, SupPid} = lists:keyfind(sup_pid, 1, Config),
    exit(SupPid, shutdown),
    Config.

-spec get_source_binary(binary(), undefined | binary(), binary()) -> binary().
get_source_binary(Kty, Kid, Alg) ->
    K = jose_base64url:encode(crypto:strong_rand_bytes(32)),
    Map = genlib_map:compact(#{
        <<"alg">> => Alg,
        <<"kty">> => Kty,
        <<"k">> => K,
        <<"kid">> => Kid
    }),
    {_, JwkBin} = jose_jwk:to_binary(jose_jwk:from(Map)),
    JwkBin.

%% TESTS

-spec encode_binary_ok_test(config()) -> ok.
-spec encrypt_hide_secret_key_ok_test(config()) -> ok.
-spec unknown_decrypt_key_test(config()) -> ok.
-spec wrong_key_test(config()) -> ok.
-spec wrong_encrypted_key_format_test(config()) -> ok.
-spec encode_with_params_ok_test(config()) -> ok.
-spec lechiffre_init_jwk_no_kid_test(config()) -> ok.

encode_binary_ok_test(_Config) ->
    Token = <<"TestTestTest">>,
    {ok, EncryptedToken} = lechiffre:encode(Token),
    {ok, Value} = lechiffre:decode(EncryptedToken),
    ?assertEqual(Token, Value).

encrypt_hide_secret_key_ok_test(_Config) ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken),
    {ok, Value} = lechiffre:decode(ThriftType, EncryptedToken),
    ?assertEqual(PaymentToolToken, Value).

unknown_decrypt_key_test(_Config) ->
    JWK1 = get_source_binary(<<"oct">>, <<"1">>, <<"A128GCMKW">>),
    JWK2 = get_source_binary(<<"oct">>, <<"2">>, <<"A128GCMKW">>),
    Options = #{
        encryption_source => {json, JWK1},
        decryption_sources => [{json, JWK2}]
    },
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    SecretKeys = lechiffre:read_secret_keys(Options),
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKeys),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKeys),
    ?assertEqual({error, {decryption_failed, {kid_notfound, <<"1">>}}}, ErrorDecode).

wrong_key_test(_Config) ->
    JWK1 = get_source_binary(<<"oct">>, <<"1">>, <<"A128GCMKW">>),
    JWK2 = get_source_binary(<<"oct">>, <<"1">>, <<"A128GCMKW">>),
    Options = #{
        encryption_source => {json, JWK1},
        decryption_sources => [{json, JWK2}]
    },
    SecretKeys = lechiffre:read_secret_keys(Options),
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKeys),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKeys),
    ?assertEqual({error, {decryption_failed, unknown}}, ErrorDecode).

wrong_encrypted_key_format_test(_Config) ->
    {ThriftType, _PaymentToolToken} = payment_tool_token(),
    Header = crypto:strong_rand_bytes(32),
    Body = crypto:strong_rand_bytes(32),
    EncryptedToken = <<Header/binary, ".", Body/binary>>,
    JWK1 = get_source_binary(<<"oct">>, <<"1">>, <<"A128GCMKW">>),
    Options = #{
        decryption_sources => [{json, JWK1}]
    },
    SecretKeys = lechiffre:read_secret_keys(Options),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKeys),
    ?assertMatch({error, {decryption_failed, {bad_jwe_format, _Jwe}}}, ErrorDecode).

lechiffre_init_jwk_no_kid_test(_Config) ->
    Source = get_source_binary(<<"oct">>, undefined, <<"A128GCMKW">>),
    Options = #{
        encryption_source => {json, Source},
        decryption_sources => [{json, Source}]
    },
    try
        lechiffre:read_secret_keys(Options)
    catch
        _Type:Error ->
            ?assertMatch({invalid_jwk, _Path, missing_kid}, Error)
    end.

-spec payment_tool_token() -> {term(), term()}.
payment_tool_token() ->
    Type = {struct, struct, {?MODULE, 'BankCard'}},
    Token = #'BankCard'{
        token = <<"TOKEN">>
    },
    {Type, Token}.

encode_with_params_ok_test(_Config) ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken),
    {ok, Value} = lechiffre:decode(ThriftType, EncryptedToken),
    ?assertEqual(PaymentToolToken, Value).

%% For Thrift compile

-type struct_flavour() :: struct | exception | union.
-type field_num() :: pos_integer().
-type field_name() :: atom().
-type field_req() :: required | optional | undefined.

-type type_ref() :: {module(), atom()}.
-type field_type() ::
    bool
    | byte
    | i16
    | i32
    | i64
    | string
    | double
    | {enum, type_ref()}
    | {struct, struct_flavour(), type_ref()}
    | {list, field_type()}
    | {set, field_type()}
    | {map, field_type(), field_type()}.

-type struct_field_info() ::
    {field_num(), field_req(), field_type(), field_name(), any()}.

-type struct_info() ::
    {struct, struct_flavour(), [struct_field_info()]}.

-type struct_name() ::
    'BankCard'.

-spec struct_info(struct_name()) -> struct_info() | no_return().
struct_info('BankCard') ->
    {struct, struct, [
        {1, required, string, 'token', undefined}
    ]};
struct_info(_) ->
    erlang:error(badarg).

-spec record_name(struct_name()) -> atom() | no_return().
record_name('BankCard') ->
    'BankCard'.
