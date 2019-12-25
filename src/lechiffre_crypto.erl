-module(lechiffre_crypto).

-include_lib("jose/include/jose_jwk.hrl").

-define(IV_SIZE, 16).

-type kid()         :: binary().
-type jwk()         :: #jose_jwk{}.
-type iv()          :: binary().
-type jwe()         :: map().
-type jwe_compact() :: binary().

-type decryption_keys() :: #{
    kid() := jwk()
}.
-type encryption_params() :: #{
    iv := iv()
}.
-type decryption_error() :: {decryption_failed,
    unknown |
    {kid_notfound, kid()} |
    {bad_jwe_header_format, _Reason} |
    {bad_jwe_format, _JweCompact}
}.
-type encryption_error() :: {encryption_failed, {invalid_jwk, encryption_unsupported}}.

-export_type([encryption_params/0]).
-export_type([decryption_keys/0]).
-export_type([encryption_error/0]).
-export_type([decryption_error/0]).
-export_type([jwe_compact/0]).
-export_type([kid/0]).
-export_type([iv/0]).
-export_type([jwk/0]).

-export([encrypt/3]).
-export([decrypt/2]).
-export([get_jwe_kid/1]).
-export([get_jwk_kid/1]).
-export([verify_jwk_alg/1]).
-export([compute_random_iv/0]).
-export([compute_iv_hash/2]).

-spec compute_iv_hash(jwk(), binary()) -> iv().
%% WARNING: remove this code when deterministic behaviour no matter
compute_iv_hash(Jwk, Nonce) ->
    Type = sha256,
    JwkBin = erlang:term_to_binary(Jwk),
    crypto:hmac(Type, JwkBin, Nonce, ?IV_SIZE).

-spec compute_random_iv() -> iv().

compute_random_iv() ->
    crypto:strong_rand_bytes(16).

-spec encrypt(jwk(), binary(), encryption_params()) ->
    {ok, jwe_compact()} |
    {error, encryption_error()}.

encrypt(JWK, Plain, EncryptionParams) ->
    IV = iv(EncryptionParams),
    try
        #{<<"kid">> := KID} = JWK#jose_jwk.fields,
        EncryptorWithoutKid = unwrap({invalid_jwk, encryption_unsupported}, fun() -> jose_jwk:block_encryptor(JWK) end),
        JWE = EncryptorWithoutKid#{<<"kid">> => KID},
        {CEK, JWE1} = jose_jwe:next_cek(JWK, JWE),
        {_, JWE2} = jose_jwe:block_encrypt(JWK, Plain, CEK, IV, JWE1),
        {#{}, Compact} = jose_jwe:compact(JWE2),
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
        Result = jose_jwe:block_decrypt(Jwk, Jwe),
        case Result of
            {error, _JWE} ->
               {error, {decryption_failed, unknown}};
            {DecryptedData, _JWE} ->
                {ok, DecryptedData}
        end
    catch throw:{?MODULE, Error} ->
        {error, {decryption_failed, Error}}
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

-spec verify_jwk_alg(jwk()) ->  ok | {error, {jwk_alg_unsupported, _}}.
%% WARNING: remove this code when deterministic behaviour no matter
verify_jwk_alg(JWK) ->
    Fields = JWK#jose_jwk.fields,
    case maps:get(<<"alg">>, Fields, notfound) of
        <<"dir">> ->
            ok;
        <<"A256KW">> ->
            ok;
        <<"A256GCMKW">> ->
            ok;
        Alg ->
            {error, {jwk_alg_unsupported, Alg}}
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

-spec iv(encryption_params()) -> iv().

iv(#{iv := IV}) ->
    IV.

-spec unwrap(_, _) ->
    _ | no_return().

unwrap(Error, Fun) ->
    try Fun()
    catch error: _ ->
        throw({?MODULE, Error})
    end.
