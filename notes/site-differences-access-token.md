# Differences from the site: access-token

This file lists the places where the tool `access-token` differs from the section `access-token` of `docs/tools.html`. The code does not change the site. The owner updates the site later. See also item 16 of `site-differences.md`.

## Output of check

1. The site shows 7 lines in this order: `signature`, `alg`, `typ`, `iss`, `aud`, `exp`, `iat`. The tool prints 13 lines in the order of the core: `structure`, `header`, `alg`, `typ`, `kid`, `signature`, `claims`, `iss`, `sub`, `aud`, `iat`, `exp`, `life`. The owner asked for one line for each check.
2. The site puts the life on the line of `exp`. The tool puts it on the line of `life`. The line of `exp` shows the value of `exp`.
3. The site shows no detail for `signature` and `iss`. The tool shows the detail of the core: `good` and the value of `iss`.
4. A failed line ends with the number of the rule, for example `(rule 9.2)`. A check that did not run shows `skip`. The site shows neither.
5. The JSON form is not on the site. It has `result`, `now`, `checks` and `claims`.

## Command line

6. The site shows `access-token check --config FILE [--format text|json] <token>`. The tool adds two flags. `--now UNIX_SECONDS` sets the clock for tests. `--print-config` checks the configuration, prints the value that applies for each member, and exits. With `--print-config`, the token is not needed.
7. The site shows `<token>` as a file. The tool reads a file, or the standard input for the argument `-`. A token text as an argument is not valid, because it cannot be told from a file name.
8. The site shows `<claims>` as a file. The tool also reads the standard input for the argument `-`.
9. The site has the flags `--key`, `--alg` and `--typ` for `make`. The tool adds `--kid ID`, `--crit NAME`, `--bad-signature`, `--allow-bad-claims` and `--format text|json`. They are the minimum to make each bad token of protocol 9.2 to 9.4. The claims file gives the other defects (old `exp`, future `iat`, long life, absent claim, extra claim).
10. The site shows `--alg Ed25519|ES256`. The tool also accepts `EdDSA`, `HS256`, `RS256` and `none`, to make bad tokens. The tool always signs with the real algorithm of the key. The name `none` makes a token with an empty signature.
11. `--typ` and `--kid` accept any text that is not empty.
12. By default, `make` refuses claims that break protocol 9.3. It prints the findings, makes no token and exits with 1. The site does not say this. `--allow-bad-claims` makes the token. A warning does not stop `make`, and the exit code stays 0.
13. `make --format json` writes `token`, `header`, `claims` and `findings`. The default output is the token alone, as on the site.
14. The tool has no key generator, because the site shows none. The README of the crate shows how to make test keys with `openssl` in Docker.
15. `--version` prints the version and the line `Apache-2.0`. `-V` does the same.

## Configuration of the service

16. The site names the file `service.json` and shows no format. The tool defines it. The schema is `schemas/access-token-config.schema.json`. The members are `token_header`, `iss`, `service_id`, `max_age_seconds`, `skew_seconds`, `jwks` and `pem_keys`. The schema is closed.
17. The configuration gives public keys as a JWK Set (`jwks`) or as PEM text (`pem_keys`).
18. The configuration refuses the header `Authorization`, `Proxy-Authorization` and `Cookie` for the token. Protocol 9.4 forbids them.

## Checks

19. A token with an empty third part (`alg: none` makes it) fails the check `alg`, with the rule 9.2. The core reports it as a failure of `structure`. The tool changes the empty part to a signature that no key accepts, before it calls the core. See `core-requests-access-token.md`.

## Repository

20. The schema name `access-token-config` is in the list `SCHEMA_NAMES` of the crate `procurauth-schema-check`.
21. The STE test of `conformance/schema-check/tests/ste.rs` reads the `README.md` of each crate. Before, it read only the README of the core.
