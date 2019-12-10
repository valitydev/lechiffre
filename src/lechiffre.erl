-module(lechiffre).

-define(SECRET_KEYS_TABLE, ?MODULE).

-behaviour(gen_server).

-type options() :: #{
    encryption_key_path := {key_version(), key_path()},
    decryption_key_path := #{
        key_version() := key_path()
    }
}.

-type key_path()        :: binary().
-type key_version()     :: lechiffre_crypto:key_version().
-type secret_keys()     :: lechiffre_crypto:secret_keys().
-type data()            :: term().
-type encoded_data()    :: binary().

-type encoding_error()  :: {encryption_failed, lechiffre_crypto:encryption_error()} |
                           lechiffre_thrift_utils:thrift_error().

-type decoding_error()  :: {decryption_failed, lechiffre_crypto:decryption_error()} |
                           lechiffre_thrift_utils:thrift_error().

-type thrift_type()     :: lechiffre_thrift_utils:thrift_type().

-export_type([secret_keys/0]).
-export_type([encoding_error/0]).
-export_type([decoding_error/0]).

%% GenServer
-export([child_spec/2]).
-export([start_link/1]).
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

-spec encode(thrift_type(), data()) ->
    {ok, encoded_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data) ->
    SecretKeys = lookup_secret_value(),
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin} ->
            lechiffre_crypto:encrypt(SecretKeys, ThriftBin);
        {error, _} = Error ->
            {error, {serialization_failed, Error}}
    end.

-spec encode(thrift_type(), data(), secret_keys()) ->
    {ok, encoded_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data, SecretKeys) ->
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin}    ->
            lechiffre_crypto:encrypt(SecretKeys, ThriftBin);
        {error, _} = Error ->
            {error, {serialization_failed, Error}}
    end.

-spec decode(thrift_type(), encoded_data()) ->
    {ok, data()} |
    {error, decoding_error()}.

decode(ThriftType, EncryptedData) ->
    SecretKeys = lookup_secret_value(),
    case lechiffre_crypto:decrypt(SecretKeys, EncryptedData) of
        {ok, ThriftBin} ->
            lechiffre_thrift_utils:deserialize(ThriftType, ThriftBin);
        DecryptError ->
            DecryptError
    end.

-spec decode(thrift_type(), encoded_data(), secret_keys()) ->
    {ok, data()} |
    {error, decoding_error()}.

decode(ThriftType, EncryptedData, SecretKeys) ->
    case lechiffre_crypto:decrypt(SecretKeys, EncryptedData) of
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

%%

-spec read_secret_keys(options()) -> secret_keys().

read_secret_keys(Options) ->
    {Ver, EncryptionPath} = maps:get(encryption_key_path, Options),
    DecryptionKeysPath = maps:get(decryption_key_path, Options),
    DecryptionKeys = maps:fold(fun(KeyVer, Path, Acc) ->
        SecretKey = read_key_file(Path),
        Acc#{
            KeyVer => SecretKey
        }
        end, #{}, DecryptionKeysPath),
    EncryptionKey = read_key_file(EncryptionPath),
    #{
        encryption_key => {Ver, EncryptionKey},
        decryption_key => DecryptionKeys
    }.

-spec read_key_file(binary()) -> binary().

read_key_file(SecretPath) ->
    {ok, Secret} = file:read_file(SecretPath),
    genlib_string:trim(Secret).

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
