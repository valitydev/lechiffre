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

В текущей версии ограничен список возможных алгоритмов.
Ограничение вызвано необходимостью детерминированости алгоритма шифрования.

Возможные значения "alg": "dir", "A256KW", "A256GCMKW".
Тип ключа шифрования симметричный `-kty=oct`.


Пример создание JWK:

    $ step crypto jwk create jwk_oct.pub.json jwk.json -kty=oct -size=32 -use=enc -alg=dir -kid=123 -password-file=jwk.password
