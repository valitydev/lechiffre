-module(lechiffre).

-define(SECRET_KEYS_TABLE, ?MODULE).

-behaviour(gen_server).

-type options() :: #{
    encryption_key_path := {key_path(), key_password_path()},
    decryption_key_paths := [
        {key_path(), key_password_path()}
    ]
}.

-type key_path()          :: file:filename_all().
-type key_password_path() :: file:filename_all().
-type secret_keys() :: #{
    encryption_key  := lechiffre_crypto:jwk(),
    decryption_keys := lechiffre_crypto:decryption_keys()
}.
-type data()            :: term().
-type encoded_data()    :: lechiffre_crypto:jwe_compact().

-type encoding_error()  :: lechiffre_crypto:encryption_error() |
                           lechiffre_thrift_utils:serialization_error().

-type decoding_error()  :: lechiffre_crypto:decryption_error() |
                           lechiffre_thrift_utils:deserialization_error().

-type thrift_type()     :: lechiffre_thrift_utils:thrift_type().

-type encryption_params() :: lechiffre_crypto:encryption_params().

-export_type([encryption_params/0]).
-export_type([secret_keys/0]).
-export_type([encoding_error/0]).
-export_type([decoding_error/0]).

%% GenServer
-export([child_spec /2]).
-export([start_link /1]).
-export([init       /1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate  /2]).
-export([code_change/3]).

-export([encode/2]).
-export([encode/3]).
-export([encode/4]).
-export([decode/2]).
-export([decode/3]).
-export([compute_iv/1]).
-export([read_secret_keys/1]).

-spec child_spec(atom(), options()) ->
    supervisor:child_spec().

child_spec(ChildId, Options) ->
    #{
        id => ChildId,
        start => {?MODULE, start_link, [Options]},
        type => worker,
        restart => permanent
    }.

-spec start_link(options()) ->
    {ok, pid()}.

start_link(Options) ->
    gen_server:start_link(?MODULE, Options, []).

-spec read_secret_keys(options()) -> secret_keys().

read_secret_keys(Options) ->
    EncryptionPath = maps:get(encryption_key_path, Options),
    DecryptionKeyPaths = maps:get(decryption_key_paths, Options),
    DecryptionKeys = read_decryption_keys(DecryptionKeyPaths),
    EncryptionKey = read_encryption_key(EncryptionPath),
    #{
        encryption_key  => EncryptionKey,
        decryption_keys => DecryptionKeys
    }.

-spec compute_iv(binary()) ->
    lechiffre_crypto:iv().

compute_iv(Nonce) ->
    SecretKeys = lookup_secret_value(),
    EncryptionKey = maps:get(encryption_key, SecretKeys),
    lechiffre_crypto:compute_iv_hash(EncryptionKey, Nonce).

-spec encode(thrift_type(), data()) ->
    {ok, encoded_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data) ->
    EncryptionParams = #{
        iv => lechiffre_crypto:compute_random_iv()
    },
    encode(ThriftType, Data, EncryptionParams).

-spec encode(thrift_type(), data(), encryption_params()) ->
    {ok, encoded_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data, EncryptionParams) ->
    SecretKeys = lookup_secret_value(),
    encode(ThriftType, Data, EncryptionParams, SecretKeys).

-spec encode(thrift_type(), data(), encryption_params(), secret_keys()) ->
    {ok, encoded_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data, EncryptionParams, SecretKeys) ->
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin} ->
            EncryptionKey = maps:get(encryption_key, SecretKeys),
            lechiffre_crypto:encrypt(EncryptionKey, ThriftBin, EncryptionParams);
        {error, _} = SerializationError ->
            SerializationError
    end.

-spec decode(thrift_type(), encoded_data()) ->
    {ok, data()} |
    {error, decoding_error()}.

decode(ThriftType, EncryptedData) ->
    SecretKeys = lookup_secret_value(),
    decode(ThriftType, EncryptedData, SecretKeys).

-spec decode(thrift_type(), encoded_data(), secret_keys()) ->
    {ok, data()} |
    {error, decoding_error()}.

decode(ThriftType, EncryptedData, SecretKeys) ->
    DecryptionKeys = maps:get(decryption_keys, SecretKeys),
    case lechiffre_crypto:decrypt(DecryptionKeys, EncryptedData) of
        {ok, ThriftBin} ->
            lechiffre_thrift_utils:deserialize(ThriftType, ThriftBin);
        DecryptError ->
            DecryptError
    end.

%% Supervisor

-type st() :: #{
    options => options()
}.

-spec init(options()) ->
    {ok, st()}.

init(Options) ->
    SecretKeys = read_secret_keys(Options),
    ok = create_table(SecretKeys),
    {ok, #{options => Options}}.

-spec handle_call(term(), term(), st()) ->
    {reply, term(), st()} | {noreply, st()}.

handle_call(Call, _From, State) ->
    _ = logger:warning("unexpected call received: ~tp", [Call]),
    {noreply, State}.

-spec handle_cast(_, st()) ->
    {noreply, st()}.

handle_cast(Cast, State) ->
    _ = logger:warning("unexpected cast received: ~tp", [Cast]),
    {noreply, State}.

-spec handle_info(_, st()) ->
    {noreply, st()}.

handle_info(Info, State) ->
    _ = logger:warning("unexpected info received: ~tp", [Info]),
    {noreply, State}.

-spec terminate(Reason, atom()) ->
    ok when
        Reason :: normal | shutdown | {shutdown, term()} | term().

terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), term(), term()) -> {ok, atom()}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal

-spec read_decryption_keys([{key_path(), key_password_path()}]) ->
    lechiffre_crypto:decryption_keys() | no_return().

read_decryption_keys(Paths) ->
    lists:foldl(fun(Path, Acc) ->
        try
            {Kid, Jwk} = read_key_file(Path),
            add_jwk(Kid, Jwk, Acc)
        catch throw:{?MODULE, Reason} ->
            error({invalid_jwk, Path, Reason})
        end
    end, #{}, Paths).

-spec read_encryption_key({key_path(), key_password_path()}) ->
    lechiffre_crypto:jwk() | no_return().

read_encryption_key(Path) ->
    try
        {_, EncryptionKey} = read_key_file(Path),
        EncryptionKey
    catch throw:{?MODULE, Reason} ->
        error({invalid_jwk, Path, Reason})
    end.

-spec read_key_file({key_path(), key_password_path()}) ->
    {lechiffre_crypto:kid(), lechiffre_crypto:jwk()}.

read_key_file({KeyPath, KeyPassPath}) ->
    Password = read_file_password(KeyPassPath),
    {_Jwe, Jwk} = jose_jwk:from_file(Password, KeyPath),
    ok = verify_jwk(Jwk),
    Kid = get_jwk_kid(Jwk),
    {Kid, Jwk}.

-spec read_file_password(key_password_path()) ->
    binary() | no_return().

read_file_password(Path) ->
    Password = case file:read_file(Path) of
        {ok, Binary} ->
            Binary;
        {error, Reason} ->
            throw({?MODULE, {password_file_read_failed, Reason}})
    end,
    genlib_string:trim(Password).

-spec verify_jwk(lechiffre_crypto:jwk()) ->
    ok | no_return().

verify_jwk(Jwk) ->
    case lechiffre_crypto:verify_jwk_alg(Jwk) of
        ok ->
            ok;
        {error, {jwk_alg_unsupported, Alg}} ->
            throw({?MODULE, {jwk_alg_unsupported, Alg}})
    end.

-spec get_jwk_kid(lechiffre_crypto:jwk()) ->
    lechiffre_crypto:kid() | no_return().

get_jwk_kid(Jwk) ->
    case lechiffre_crypto:get_jwk_kid(Jwk) of
        notfound ->
            throw({?MODULE, missing_kid});
        Kid ->
            Kid
    end.

-spec add_jwk(binary(), lechiffre_crypto:jwk(), map()) ->
    map() | no_return().

add_jwk(KID, JWK, Map) ->
    case maps:is_key(KID, Map) of
        true ->
            throw({duplicate_jwk_kid, KID});
        false ->
            maps:put(KID, JWK, Map)
    end.

-spec create_table(secret_keys()) -> ok.

create_table(SecretKeys) ->
    _ = ets:new(?SECRET_KEYS_TABLE, [set, public, named_table, {read_concurrency, true}]),
    insert_secret_value(SecretKeys),
    ok.

-spec insert_secret_value(secret_keys()) -> ok.

insert_secret_value(SecretKeys) ->
    true = ets:insert(?SECRET_KEYS_TABLE, [{secret, SecretKeys}]),
    ok.

-spec lookup_secret_value() -> secret_keys().

lookup_secret_value() ->
    [{secret, SecretKeys}] = ets:lookup(?SECRET_KEYS_TABLE, secret),
    SecretKeys.
