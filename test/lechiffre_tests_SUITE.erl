-module(lechiffre_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

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
    encrypt_hide_secret_key_ok_test/1
]).

-type config() :: [{atom(), term()}].

-spec all() ->
    [atom()].

all() ->
    [
        unknown_decrypt_key_test,
        wrong_key_test,
        wrong_encrypted_key_format_test,
        encrypt_hide_secret_key_ok_test
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

init_per_testcase(_Name, C) ->
    C.

-spec end_per_testcase(atom(), config()) ->
    config().

end_per_testcase(_Name, _C) ->
    ok.

-spec get_source(binary(), config()) ->
    binary().

get_source(FileName, Config) ->
    filename:join(?config(data_dir, Config), FileName).

%% TESTS

-spec encrypt_hide_secret_key_ok_test(config()) -> ok.
-spec unknown_decrypt_key_test(config()) -> ok.
-spec wrong_key_test(config()) -> ok.
-spec wrong_encrypted_key_format_test(config()) -> ok.

encrypt_hide_secret_key_ok_test(Config) ->
    Filename = <<"secret_key_1.file">>,
    Options = #{
        encryption_key_path => {1, get_source(Filename, Config)},
        decryption_key_path => #{
            1 => get_source(Filename, Config)
        }
    },
    lechiffre:start_link(Options),
    {ThriftType, PaymentToolToken} = payment_tool_token(),

    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken),
    {ok, Value} = lechiffre:decode(ThriftType, EncryptedToken),
    ?assertEqual(PaymentToolToken, Value).

unknown_decrypt_key_test(_Config) ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    Key = crypto:strong_rand_bytes(32),
    SecretKey = #{
        encryption_key => {1, Key},
        decryption_key => #{2 => Key}
    },
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKey),
    ?assertEqual({error, {decryption_failed, {unknown_key_version, 1}}}, ErrorDecode).

wrong_key_test(_Config) ->
   {ThriftType, PaymentToolToken} = payment_tool_token(),
    Key = crypto:strong_rand_bytes(32),
    WrongKey = crypto:strong_rand_bytes(32),
    SecretKey = #{
        encryption_key => {1, Key},
        decryption_key => #{1 => WrongKey}
    },
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKey),
    ?assertEqual({error, {decryption_failed, decryption_validation_failed}}, ErrorDecode).

wrong_encrypted_key_format_test(_Config) ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    Key = crypto:strong_rand_bytes(32),
    WrongKey = crypto:strong_rand_bytes(32),
    SecretKey = #{
        encryption_key => {1, Key},
        decryption_key => #{1 => WrongKey}
    },
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    <<_Format:6/binary, Tail/binary>> = EncryptedToken,
    BadEncryptedToken = <<"edf_v2", Tail/binary>>,
    ErrorDecode = lechiffre:decode(ThriftType, BadEncryptedToken, SecretKey),
    ?assertEqual({error, {decryption_failed, bad_encrypted_data_format}}, ErrorDecode).

-spec payment_tool_token() -> {term(), term()}.
payment_tool_token() ->
    Type = {struct, struct, {?MODULE, 'BankCard'}},
    Token = #'BankCard'{
        token = <<"TOKEN">>
    },
    {Type, Token}.

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
