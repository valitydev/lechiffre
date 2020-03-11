-module(lechiffre).

-define(SECRET_KEYS_TABLE, ?MODULE).

-behaviour(gen_server).

-type options() :: #{
    encryption_source  => key_source(),
    decryption_sources => [key_source()]
}.
-type key_source()  :: lechiffre_crypto:key_source().
-type secret_keys() :: #{
    encryption_key  => lechiffre_crypto:jwk(),
    decryption_keys := lechiffre_crypto:decryption_keys()
}.
-type data()            :: term().
-type encoded_data()    :: lechiffre_crypto:jwe_compact().
-type encoding_error()  :: lechiffre_crypto:encryption_error() |
                           lechiffre_thrift_utils:serialization_error().
-type decoding_error()  :: decryption_error() |
                           deserialization_error().
-type decryption_error() :: lechiffre_crypto:decryption_error().
-type deserialization_error() :: lechiffre_thrift_utils:deserialization_error().

-type thrift_type()     :: lechiffre_thrift_utils:thrift_type().

-export_type([secret_keys/0]).
-export_type([encoding_error/0]).
-export_type([decoding_error/0]).
-export_type([decryption_error/0]).
-export_type([deserialization_error/0]).

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
-export([decode/2]).
-export([decode/3]).
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
    EncryptionPath = genlib_map:get(encryption_source, Options),
    DecryptionKeyPaths = genlib_map:get(decryption_sources, Options, []),
    DecryptionKeys = read_decryption_keys(DecryptionKeyPaths),
    EncryptionKey = read_encryption_key(EncryptionPath),
    genlib_map:compact(#{
        encryption_key  => EncryptionKey,
        decryption_keys => DecryptionKeys
    }).

-spec encode(thrift_type(), data()) ->
    {ok, encoded_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data) ->
    SecretKeys = lookup_secret_value(),
    encode(ThriftType, Data, SecretKeys).

-spec encode(thrift_type(), data(), secret_keys()) ->
    {ok, encoded_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data, SecretKeys) ->
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin} ->
            EncryptionKey = maps:get(encryption_key, SecretKeys),
            lechiffre_crypto:encrypt(EncryptionKey, ThriftBin);
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

-spec read_decryption_keys([key_source()]) ->
    lechiffre_crypto:decryption_keys() | no_return().

read_decryption_keys(KeySources) ->
    lists:foldl(fun(Source, Acc) ->
        {Kid, Jwk} = read_jwk(Source),
        case maps:is_key(Kid, Acc) of
            true ->
                error({invalid_jwk, Source, {duplicate_jwk_kid, Kid}});
            false ->
                maps:put(Kid, Jwk, Acc)
        end
    end, #{}, KeySources).

-spec read_encryption_key(undefined | key_source()) ->
    undefined              |
    lechiffre_crypto:jwk() |
    no_return().

read_encryption_key(undefined) ->
    undefined;
read_encryption_key(KeySource) ->
    {_, Key} = read_jwk(KeySource),
    case lechiffre_crypto:is_algorithm_unsafe(Key) of
        ok ->
            Key;
        {error, {unsafe_algorithm, _} = Error} ->
            error({invalid_jwk, KeySource, Error})
    end.

-spec read_jwk(key_source()) ->
    {lechiffre_crypto:kid(), lechiffre_crypto:jwk()} |
    no_return().

read_jwk(KeySource) ->
    try
        Jwk = lechiffre_crypto:read_jwk(KeySource),
        ok = verify_jwk(Jwk),
        Kid = get_jwk_kid(Jwk),
        {Kid, Jwk}
    catch throw:{?MODULE, Reason} ->
        error({invalid_jwk, KeySource, Reason})
    end.

-spec verify_jwk(lechiffre_crypto:jwk()) ->
    ok | no_return().

verify_jwk(Jwk) ->
    case lechiffre_crypto:verify_jwk_alg(Jwk) of
        ok ->
            ok;
        {error, {jwk_alg_unsupported, _, _} = Error} ->
            throw({?MODULE, Error})
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
