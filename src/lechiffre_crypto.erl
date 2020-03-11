-module(lechiffre_crypto).

-include_lib("jose/include/jose_jwk.hrl").

-define(IV_SIZE, 16).

-type kid()         :: binary().
-type jwk()         :: jose_jwk:key().
-type iv()          :: binary().
-type jwe()         :: map().
-type jwe_compact() :: ascii_string().
-type alg_enc()     :: binary().
-type key_source()  :: {representation(), binary()} |
                       {representation(), {file, file:filename_all()}}.

-type representation() :: json.

%% base62 string and '.'
-type ascii_string() :: binary().

-type decryption_keys() :: #{
    kid() := jwk()
}.

-type decryption_error() :: {decryption_failed,
    unknown |
    {kid_notfound, kid()} |
    {bad_jwe_header_format, _Reason} |
    {bad_jwe_format, _JweCompact}
}.
-type encryption_error() :: {encryption_failed, {invalid_jwk, encryption_unsupported}}.

-export_type([decryption_keys/0]).
-export_type([encryption_error/0]).
-export_type([decryption_error/0]).
-export_type([jwe_compact/0]).
-export_type([kid/0]).
-export_type([iv/0]).
-export_type([jwk/0]).
-export_type([key_source/0]).
-export_type([alg_enc/0]).

-export([encrypt/2]).
-export([decrypt/2]).
-export([get_jwe_kid/1]).
-export([get_jwk_kid/1]).
-export([get_jwk_alg/1]).
-export([read_jwk/1]).
-export([verify_jwk_alg/1]).
-export([compute_random_iv/0]).
-export([supported_algorithms/0]).
-export([supported_algorithms/1]).
-export([is_algorithm_unsafe/1]).

-spec compute_random_iv() -> iv().

compute_random_iv() ->
    crypto:strong_rand_bytes(?IV_SIZE).

-spec read_jwk(key_source()) -> jwk().

read_jwk({json, Source}) when is_binary(Source) ->
    Jwk = jose_jwk:from_binary(Source),
    Jwk;
read_jwk({json, {file, Source}}) ->
    Jwk = jose_jwk:from_file(Source),
    Jwk.

-spec encrypt(jwk(), binary()) ->
    {ok, jwe_compact()} |
    {error, encryption_error()}.

encrypt(Jwk, Plain) ->
    try
        #{<<"kid">> := KID} = Jwk#jose_jwk.fields,
        EncryptorWithoutKid = jose_jwk:block_encryptor(Jwk),
        Encryptor = EncryptorWithoutKid#{<<"kid">> => KID},
        {_, Result} = jose_jwe:block_encrypt(get_encryption_key(Jwk), Plain, Encryptor),
        {#{}, Compact} = jose_jwe:compact(Result),
        {ok, Compact}
    catch throw:{?MODULE, Error} ->
        {error, {encryption_failed, Error}}
    end.

-spec decrypt(decryption_keys(), jwe_compact()) ->
    {ok, binary()} |
    {error, decryption_error()}.

decrypt(SecretKeys, JweCompact) ->
    try
        Jwe = expand_jwe(JweCompact),
        Kid = get_jwe_kid(Jwe),
        Jwk = get_key(Kid, SecretKeys),
        case jose_jwe:block_decrypt(Jwk, Jwe) of
            {error, _JWE} ->
                {error, {decryption_failed, unknown}};
            {DecryptedData, _JWE} ->
                {ok, DecryptedData}
        end
    catch
        throw:{?MODULE, Error} ->
            {error, {decryption_failed, Error}};
        %% This error was catch For RSA-OAEP&RSA-OAEP-256
        %% if we try using wrong decryption key but with right kid
        error:decrypt_failed ->
            {error, {decryption_failed, unknown}}
    end.

%%% Internal functions

-spec expand_jwe(jwe_compact()) ->
    jwe() | no_return().

expand_jwe(JweCompact) ->
    try
        {#{}, Jwe} = jose_jwe:expand(JweCompact),
        Jwe
    catch _Type:_Error ->
        throw({?MODULE, {bad_jwe_format, JweCompact}})
    end.

-spec get_jwe_kid(jwe()) ->
    kid() | no_return().

get_jwe_kid(#{<<"protected">> := EncHeader}) ->
    try
        HeaderJson = base64url:decode(EncHeader),
        Header = jsx:decode(HeaderJson, [return_maps]),
        maps:get(<<"kid">>, Header)
    catch _Type:Error ->
        throw({?MODULE, {bad_jwe_header_format, Error}})
    end.

-spec get_jwk_kid(jwk()) -> kid() | notfound.

get_jwk_kid(Jwk) ->
    Fields = Jwk#jose_jwk.fields,
    maps:get(<<"kid">>, Fields, notfound).

-spec get_jwk_alg(jwk()) -> alg_enc() | notfound.

get_jwk_alg(Jwk) ->
    Fields = Jwk#jose_jwk.fields,
    maps:get(<<"alg">>, Fields, notfound).

-spec verify_jwk_alg(jwk()) ->
    ok |
    {error, {jwk_alg_unsafe, alg_enc()} |
            {jwk_alg_unsupported, alg_enc(), [alg_enc()]}
    }.

verify_jwk_alg(Jwk) ->
    AlgEnc = get_jwk_alg(Jwk),
    AlgList = supported_algorithms(),
    case lists:member(AlgEnc, AlgList) of
        true ->
            ok;
        false ->
            {error, {jwk_alg_unsupported, AlgEnc, AlgList}}
    end.

-spec is_algorithm_unsafe(jwk()) ->
    ok | {error, {unsafe_algorithm, binary()}}.

is_algorithm_unsafe(Jwk) ->
    case get_jwk_alg(Jwk) of
        <<"dir">> ->
            {error, {unsafe_algorithm, <<"dir">>}};
        _ ->
            ok
    end.

-spec get_key(kid(), decryption_keys()) ->
    jwk() | no_return().

get_key(KID, Keys) ->
    case maps:find(KID, Keys) of
        {ok, Key} ->
            Key;
        error ->
            throw({?MODULE, {kid_notfound, KID}})
    end.

-spec get_encryption_key(jwk()) ->
    jwk() | {jwk(), any()}.

get_encryption_key(Jwk) ->
    case get_jwk_alg(Jwk) of
        Alg when   Alg =:= <<"ECDH-ES">>
            orelse Alg =:= <<"ECDH-ES+A128KW">>
            orelse Alg =:= <<"ECDH-ES+A192KW">>
            orelse Alg =:= <<"ECDH-ES+A256KW">>
        ->
            % Constructing new ephemeral keypair one the same curve
            {Jwk, jose_jwk:generate_key(Jwk)};
        _ ->
            Jwk
    end.

%% Don't support A{128, 192, 256}KW
%% Smart dudes recommended: "Nobody should ever use AES-KW except when forced to for interop.
%% "(https://bugs.chromium.org/p/chromium/issues/detail?id=396407)
%% Deprecated RSA1_5

-type encryption_type() :: asymmetric | symmetric.
-spec supported_algorithms() -> list().

supported_algorithms() ->
    supported_algorithms(asymmetric) ++
    supported_algorithms(symmetric).

-spec supported_algorithms(encryption_type()) -> list().

supported_algorithms(asymmetric) ->
    [
        <<"ECDH-ES">>,
        <<"ECDH-ES+A128KW">>,
        <<"ECDH-ES+A192KW">>,
        <<"ECDH-ES+A256KW">>,
        <<"RSA-OAEP">>,
        <<"RSA-OAEP-256">>
    ];
supported_algorithms(symmetric) ->
    [
        <<"dir">>,
        <<"A128GCMKW">>,
        <<"A192GCMKW">>,
        <<"A256GCMKW">>
    ].