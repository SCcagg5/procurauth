# access-token

`access-token` makes and checks the identity tokens of ProcurAuth. It is a command-line tool. It helps the developer of a service to test the checks of protocol 9.4.

The tool has two subcommands:

- `make` signs a token. It also makes bad tokens, for the tests of a service.
- `check` runs the checks of protocol 9.2, 9.3 and 9.4 on a token. It prints the result of each check.

The tool does not use the network. It reads no environment variable. It reads the system clock only when you do not give `--now`.

## Build and test

Do not install Rust on the host. Use Docker, with the script of the repository.

```text
scripts/cargo.sh build --release -p access-token
scripts/cargo.sh test -p access-token
```

## Make a token

```text
access-token make --key FILE [--alg ALG] [--typ TYPE] [--kid ID]
    [--crit NAME] [--bad-signature] [--allow-bad-claims]
    [--format text|json] CLAIMS
```

`CLAIMS` is a JSON file with the claims. Use `-` to read the standard input. The tool writes the token on the standard output.

```text
$ access-token make --key examples/test-edge-ed25519.pem \
    --alg Ed25519 examples/claims.json > token.jwt
```

The key file holds a private key in PEM form (PKCS#8) for Ed25519 or for P-256. The key comes only from a file. The tool never prints a private key.

The tool is deterministic. It reads no clock, so the same input gives the same token. Write the times in the claims file.

### Claims

The claims are those of protocol 9.3: `iss`, `sub`, `aud`, `iat` and `exp`. A token for a key also has `owner`. Example files are `examples/claims.json` and `examples/claims-key.json`.

By default, `make` checks the claims. It refuses a claims file that breaks protocol 9.3, and it prints the findings on the standard error. It then makes no token and exits with 1. A warning does not stop the tool.

Use `--allow-bad-claims` to make the token in spite of the findings. Use it to make a token that lacks a claim.

### Bad tokens

Each row shows how to make one bad token. The last column shows the check that fails.

| Defect | How | Check | Rule |
| --- | --- | --- | --- |
| `exp` in the past | Write an old `exp` in the claims file. | `exp` | 9.4 |
| `iat` in the future | Write a late `iat` in the claims file. | `iat` | 9.4 |
| Life longer than the maximum age | Write `exp` far after `iat`. | `life` | 9.4 |
| `exp` before `iat` | Write `exp` before `iat`. | `life` | 9.4 |
| Another `typ` | `--typ at+jwt` | `typ` | 9.2 |
| Another algorithm name | `--alg EdDSA`, `--alg HS256` or `--alg RS256` | `alg` | 9.2 |
| `alg` is `none` | `--alg none` makes a token with no signature. | `alg` | 9.2 |
| Alg confusion | `--alg ES256` with an Ed25519 key, or the reverse. | `signature` | 9.4 |
| Bad signature | `--bad-signature` | `signature` | 9.4 |
| Header `crit` | `--crit NAME` | `header` | 9.4 |
| Unknown `kid` | `--kid NAME` with a name that the service does not hold. | `kid` | 9.4 |
| Absent claim | Remove the claim and add `--allow-bad-claims`. | `claims` and the claim | 9.3 |
| Wrong `iss` or `aud` | Write another value in the claims file. | `iss` or `aud` | 9.4 |
| Extra claim | Add the claim. The service must ignore it. | none | 9.4 |

The option `--alg` accepts `Ed25519`, `ES256`, `EdDSA`, `HS256`, `RS256` and `none`. The default is the algorithm of the key. The tool always signs with the real algorithm of the key. The option changes only the name in the header.

The option `--bad-signature` cannot go with `--alg none`, because that token has no signature.

## Check a token

```text
access-token check --config FILE [--format text|json] [--now UNIX_SECONDS] TOKEN
access-token check --config FILE [--format text|json] --print-config
```

`TOKEN` is a file with the token. Use `-` to read the standard input. The tool removes one line end at the end of the text.

```text
$ access-token check --config examples/service.json --now 1792569700 token.jwt
structure  ok   3 parts
header     ok   no `crit`
alg        ok   Ed25519
typ        ok   JWT
kid        ok   one key in the set
signature  ok   good
claims     ok   iss, sub, aud, iat, exp
iss        ok   https://edge.example
sub        ok   present
aud        ok   datastore
iat        ok   1792569600
exp        ok   1792569900
life       ok   life 300 s, max 300 s
$ echo $?
0
```

The tool prints one line for each of the 13 checks, always in the same order. A line has the name of the check, the result and a detail. The result is `ok`, `fail` or `skip`. A check is `skip` when an earlier check made it impossible. A failed line ends with the number of the rule, for example `(rule 9.2)`.

| Check | Rule | The check passes when |
| --- | --- | --- |
| `structure` | 9.4 | The token has three parts in base64url, and the header and the payload are JSON objects. |
| `header` | 9.4 | The header has no `crit` member. |
| `alg` | 9.2 | `alg` is `Ed25519` or `ES256`. |
| `typ` | 9.2 | `typ` is `JWT`. |
| `kid` | 9.4 | The key set has a key for the token. |
| `signature` | 9.4 | The signature is good, with the key and the algorithm of the header. |
| `claims` | 9.3 | The payload has `iss`, `sub`, `aud`, `iat` and `exp`. |
| `iss` | 9.4 | `iss` is the issuer of the configuration. |
| `sub` | 9.3 | `sub` is a string that is not empty. |
| `aud` | 9.4 | `aud` is the id of the service, or an array that holds it. |
| `iat` | 9.4 | `iat` is not later than the clock plus the skew. |
| `exp` | 9.4 | The clock is not later than `exp` plus the skew. |
| `life` | 9.4 | `exp` minus `iat` is not more than the maximum age. |

A token with an empty third part, as `alg: none` makes it, fails the check `alg`. It does not fail `structure`.

The JSON form has the members `result` (`pass` or `fail`), `now`, `checks` and `claims`. Each item of `checks` has `name`, `rule`, `outcome` (`pass`, `fail` or `not_run`) and `detail`.

### The clock

The check needs the time. Give it with `--now`, in whole seconds since the Unix epoch. Without this flag, the tool reads the system clock. Use `--now` in all tests, so that the result does not change with the time.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding. `make` made a token, or each check of `check` passed. |
| 1 | At least one finding. A check failed, or `make` refused the claims. |
| 2 | Usage error, or an input that the tool cannot read. |

The results go to the standard output. The diagnostics go to the standard error. The tool never writes colour.

## The configuration of the service

The file `--config` is one JSON object with the values of protocol 9.4. The schema is closed. An unknown member, a duplicate member, a wrong type or a value out of range stops the tool. The tool exits with the code 2 before it reads the token. Each error names the path of the member, the expected value and the value found.

The tool changes no value to make it fit. The file has no default value and no secret. The environment never gives a value.

| Member | Type | Meaning |
| --- | --- | --- |
| `token_header` | string | The name of the HTTP header with the token. It is not `Authorization`, `Proxy-Authorization` or `Cookie`. |
| `iss` | string | The value of `iss` that the service accepts. |
| `service_id` | string | The id of the service. The token must hold it in `aud`. |
| `max_age_seconds` | whole number, 1 or more | The longest life of a token. |
| `skew_seconds` | whole number, 0 or more | The clock skew. It applies to `iat` and to `exp`. |
| `jwks` | object | A JWK Set with the public keys of the edge. |
| `pem_keys` | array | Public keys in PEM form. Each item has `pem` and an optional `kid`. |

The file needs at least one key, in `jwks` or in `pem_keys` or in both. A key is Ed25519 or P-256. A JWK Set with a private member `d` is not valid. When the set holds more than one key, each key needs a `kid`, and the `kid` values are different. The token then needs a `kid` too (protocol 9.4).

The schema is `schemas/access-token-config.schema.json`. The examples are `examples/service.json` (one key) and `examples/service-two-keys.json` (two keys, in the two forms).

Use `--print-config` to check the file and to print the value that applies for each member. The tool then exits. Each value comes from the file.

## Test keys

The private keys in `examples/` are for tests only. Each key is public. Never use them for a real edge.

| File | Content |
| --- | --- |
| `test-edge-ed25519.pem` | A test private key for Ed25519. |
| `test-edge-ed25519.pub.pem` | Its public key. |
| `test-edge-es256.pem` | A test private key for ES256 (P-256). |
| `test-edge-es256.pub.pem` | Its public key. |

To make other keys, use `openssl` inside Docker. The tool has no key generator.

```text
docker run --rm procurauth-dev:1 openssl genpkey -algorithm ED25519 > edge.pem
docker run --rm procurauth-dev:1 openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 > edge.pem
docker run --rm -i procurauth-dev:1 openssl pkey -pubout < edge.pem > edge.pub.pem
```

Both commands write a PKCS#8 PEM file. Put the public key in `pem_keys` of the configuration.

## Tests

The tests call the function `run` of the library, with no process. The test names start with the number of the paragraph of the protocol, for example `p_9_4_a_bad_signature_fails_the_check_signature`.

| File | Content |
| --- | --- |
| `tests/p_9_tokens.rs` | Round trips, and each bad token with the check and the rule. |
| `tests/p_9_4_config.rs` | The reader of the configuration, and its agreement with the schema. |
| `tests/cli.rs` | Usage errors, exit codes, streams and the proof that no output holds a private key. |
| `tests/golden.rs` | The exact output, compared with the files in `tests/golden/`. |
