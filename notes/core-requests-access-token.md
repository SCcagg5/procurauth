# Requests to the core from access-token

This file lists what the tool `access-token` needs from `procurauth-core`, and what it does without.

## Changes already made

1. `PublicKey::from_spki_pem` reads a public key from a PEM text. The configuration of the service needs it for the member `pem_keys`. The error never holds the text.
2. `KeySet::into_keys` gives the keys of a set. The tool merges a JWK Set and the PEM keys into one set.

## Request

3. `inspect` reports a token with an empty third part as a failure of `structure`. A token with `alg: none` has such a part (RFC 7519, section 6). The check that the token breaks is `alg` (9.2).

The request is to read an empty third part as an empty signature. Then `alg` fails for `none`, and `signature` fails for another algorithm. The tool now changes the empty part before it calls `inspect`. The test `p_9_2_the_algorithm_none_is_refused` of the core has the old result, so the owner must decide.
