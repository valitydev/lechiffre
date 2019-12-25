-module(lechiffre_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-include_lib("jose/include/jose_jwk.hrl").

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

-export([test/0]).

-export([
    unknown_decrypt_key_test/1,
    wrong_key_test/1,
    wrong_encrypted_key_format_test/1,
    encrypt_hide_secret_key_ok_test/1,
    encode_with_params_ok_test/1,

    lechiffre_crypto_encode_ok_test/1,
    lechiffre_crypto_decode_ok_test/1,
    lechiffre_init_jwk_ok_test/1,
    lechiffre_init_jwk_no_kid_test/1
]).

-type config() :: [{atom(), term()}].

-spec all() ->
    [atom()].

all() ->
    [
        unknown_decrypt_key_test,
        wrong_key_test,
        wrong_encrypted_key_format_test,
        encrypt_hide_secret_key_ok_test,
        encode_with_params_ok_test,
        lechiffre_crypto_encode_ok_test,
        lechiffre_crypto_decode_ok_test,
        lechiffre_init_jwk_ok_test,
        lechiffre_init_jwk_no_kid_test
    ].

-spec groups() ->
    list().

groups() ->
    [].

-spec test() ->
    any().

test() ->
    ok.

-spec init_per_suite(config()) ->
    config().

init_per_suite(Config) ->
    Config.

-spec end_per_suite(config()) ->
    ok.

end_per_suite(_C) ->
    ok.

-spec init_per_testcase(atom(), config()) ->
    config().

init_per_testcase(_Name, Config) ->
    File1 = <<"jwk1.json">>,
    File2 = <<"jwk2.json">>,
    Password = <<"jwk.password">>,
    Options = #{
        encryption_key_path => {get_source(File1, Config), get_source(Password, Config)},
        decryption_key_paths => [
            {get_source(File1, Config), get_source(Password, Config)},
            {get_source(File2, Config), get_source(Password, Config)}
        ]
    },
    ChildSpec = lechiffre:child_spec(lechiffre, Options),
    {ok, SupPid} = genlib_adhoc_supervisor:start_link({one_for_all, 0, 1}, [ChildSpec]),
    _ = unlink(SupPid),
    Config ++ [{sup_pid, SupPid}].

-spec end_per_testcase(atom(), config()) ->
    config().

end_per_testcase(_Name, Config) ->
    {_, SupPid} = lists:keyfind(sup_pid, 1, Config),
    exit(SupPid, shutdown),
    Config.

-spec get_source(binary(), config()) ->
    binary().

get_source(FileName, Config) ->
    filename:join(?config(data_dir, Config), FileName).

%% TESTS

-spec encrypt_hide_secret_key_ok_test(config()) -> ok.
-spec unknown_decrypt_key_test(config()) -> ok.
-spec wrong_key_test(config()) -> ok.
-spec wrong_encrypted_key_format_test(config()) -> ok.
-spec encode_with_params_ok_test(config()) -> ok.

-spec lechiffre_crypto_encode_ok_test(config()) -> ok.
-spec lechiffre_crypto_decode_ok_test(config()) -> ok.
-spec lechiffre_init_jwk_ok_test(config()) -> ok.
-spec lechiffre_init_jwk_no_kid_test(config()) -> ok.

encrypt_hide_secret_key_ok_test(_Config) ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken),
    {ok, Value} = lechiffre:decode(ThriftType, EncryptedToken),
    ?assertEqual(PaymentToolToken, Value).

unknown_decrypt_key_test(Config) ->
    File1 = <<"jwk1.json">>,
    File2 = <<"jwk2.json">>,
    Password = <<"jwk.password">>,
    Options = #{
        encryption_key_path => {get_source(File2, Config), get_source(Password, Config)},
        decryption_key_paths => [
            {get_source(File1, Config), get_source(Password, Config)}
        ]
    },
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    EncryptionParams = #{iv => lechiffre_crypto:compute_random_iv()},
    SecretKeys = lechiffre:read_secret_keys(Options),
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, EncryptionParams, SecretKeys),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKeys),
    ?assertEqual({error, {decryption_failed, {kid_notfound, <<"222">>}}}, ErrorDecode).

wrong_key_test(Config) ->
    File1 = <<"jwk2.json">>,
    File2 = <<"jwk3.json">>,
    Password = <<"jwk.password">>,
    Options = #{
        encryption_key_path => {get_source(File1, Config), get_source(Password, Config)},
        decryption_key_paths => [
            {get_source(File2, Config), get_source(Password, Config)}
        ]
    },
    SecretKeys = lechiffre:read_secret_keys(Options),
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    EncryptionParams = #{iv => lechiffre_crypto:compute_random_iv()},

    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, EncryptionParams, SecretKeys),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKeys),
    ?assertEqual({error, {decryption_failed, unknown}}, ErrorDecode).

wrong_encrypted_key_format_test(Config) ->
    {ThriftType, _PaymentToolToken} = payment_tool_token(),
    Header = crypto:strong_rand_bytes(32),
    Body = crypto:strong_rand_bytes(32),
    EncryptedToken = <<Header/binary, ".", Body/binary>>,
    File1 = <<"jwk2.json">>,
    File2 = <<"jwk3.json">>,
    Password = <<"jwk.password">>,
    Options = #{
        encryption_key_path => {get_source(File1, Config), get_source(Password, Config)},
        decryption_key_paths => [
            {get_source(File2, Config), get_source(Password, Config)}
        ]
    },
    SecretKeys = lechiffre:read_secret_keys(Options),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKeys),
    ?assertMatch({error, {decryption_failed, {bad_jwe_format, _Jwe}}}, ErrorDecode).

lechiffre_crypto_encode_ok_test(_Config) ->
    KID = <<"123">>,
    Plain = <<"bukabjaka">>,
    K = crypto:strong_rand_bytes(32),
    JWK = jose_jwk:from(#{
        <<"kty">> => <<"oct">>,
        <<"kid">> => KID,
        <<"k">> => base64url:encode(K)
    }),
    EncryptionParams = #{
        iv => crypto:strong_rand_bytes(16)
    },
    {ok, EncBlock} = lechiffre_crypto:encrypt(JWK, Plain, EncryptionParams),
    {ok, EncBlock} = lechiffre_crypto:encrypt(JWK, Plain, EncryptionParams).

lechiffre_crypto_decode_ok_test(_Config) ->
    KID = <<"123">>,
    Plain = <<"bukabjaka">>,
    K = crypto:strong_rand_bytes(32),
    JWK = jose_jwk:from(#{
        <<"kty">> => <<"oct">>,
        <<"kid">> => KID,
        <<"k">> => base64url:encode(K)
    }),
    EncryptionParams = #{
        iv => crypto:strong_rand_bytes(16)
    },
    {ok, EncBlock} = lechiffre_crypto:encrypt(JWK, Plain, EncryptionParams),
    {ok, Plain} = lechiffre_crypto:decrypt(#{KID => JWK}, EncBlock).

lechiffre_init_jwk_ok_test(_Config) ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    Nonce = <<"idemp_key">>,
    EncryptionParams = #{iv => lechiffre:compute_iv(Nonce)},
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, EncryptionParams),
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, EncryptionParams),
    {ok, PaymentToolToken} = lechiffre:decode(ThriftType, EncryptedToken).

lechiffre_init_jwk_no_kid_test(Config) ->
    File1 = <<"jwk4.json">>,
    Password1 = <<"jwk.password">>,
    Options = #{
        encryption_key_path => {get_source(File1, Config), get_source(Password1, Config)},
        decryption_key_paths => [
            {get_source(File1, Config), get_source(Password1, Config)}
        ]
    },
    try
        lechiffre:read_secret_keys(Options)
    catch _Type:Error ->
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
    EncryptionParams = #{iv => lechiffre_crypto:compute_random_iv()},
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, EncryptionParams),
    {ok, Value} = lechiffre:decode(ThriftType, EncryptedToken),
    ?assertEqual(PaymentToolToken, Value).

%% For Thrift compile

-type struct_flavour() :: struct | exception | union.
-type field_num() :: pos_integer().
-type field_name() :: atom().
-type field_req() :: required | optional | undefined.

-type type_ref() :: {module(), atom()}.
-type field_type() ::
    bool | byte | i16 | i32 | i64 | string | double |
    {enum, type_ref()} |
    {struct, struct_flavour(), type_ref()} |
    {list, field_type()} |
    {set, field_type()} |
    {map, field_type(), field_type()}.

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
struct_info(_) -> erlang:error(badarg).

-spec record_name(struct_name()) -> atom() | no_return().

record_name('BankCard') ->
    'BankCard'.
