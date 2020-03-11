# Le Chiffre



 ________________             _______________             ________
|                |           |               | encrypt   |        |
| VersionedToken | --------> | Thrift Binary | --------> | JWE    |
|                |           |               |           |        |
 ----------------             ---------------             --------

 ________              _______________               ________________
|        |  decrypt   |               |             |                |
| JWE    | ---------> | Thrift Binary | ----------> | VersionedToken |
|        |            |               |             |                |
 --------              ---------------               ----------------


## Создание JWK(using step-cli)
#### RFC:
1. [JWK](https://www.rfc-editor.org/rfc/rfc7517).
2. [JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638).
3. [JWA](https://www.rfc-editor.org/rfc/rfc7518.html).

## Current supported encryption algorithms:
- <<"ECDH-ES">>
- <<"ECDH-ES+A128KW">>
- <<"ECDH-ES+A192KW">>
- <<"ECDH-ES+A256KW">>
- <<"RSA-OAEP">>
- <<"RSA-OAEP-256">>
- <<"dir">> UNSAFE!!!
- <<"A128GCMKW">>
- <<"A192GCMKW">>
- <<"A256GCMKW">>

<<"dir">> небезопасный алгоритм, используется только для дешифровки данных на переходный период.

#### step-cli docs:
1. [SmallStep](https://smallstep.com/docs/cli/crypto/jwk/create/).

Пример создания JWK(симметричное шифрование):

`$ step crypto jwk create jwk_oct.pub.json jwk.json -kty=oct -size=32 -use=enc -alg=dir -kid=123 -no-password -insecure`

SmallStep kid автоматически не генерирует, при создание jwk с симметричным шифрованием.
> If unset, the JWK Thumbprint [RFC7638] is used as kid.
[см.здесь -kid](https://smallstep.com/docs/cli/crypto/jwk/create/)

Пример создания JWK(ассиметричное шифрование):

`$ step crypto jwk create jwk.publ.json jwk.priv.json -kty=EC -use=enc -no-password -insecure`

Kid указывать не нужно, он генерируется согласно [документации](https://www.rfc-editor.org/rfc/rfc7638#section-3).
C kid сгенерированным не по спецификации, шифрование работать не будет.
