# Requests to the core from procurauth-pep

This file lists what the library `procurauth-pep` needs from `procurauth-core`.

## Changes already made

1. `identity::verify_for_pep` and `Claims::from_value_for_pep` read a token as a PEP does. An `owner` that is not a text, or that is empty, is read as no owner. The case U10 needs this: it sends a token with `"owner": 42` and expects the answer of the PDP. Protocol 9.5 says that a PEP never uses `owner`. `verify` and `Claims::from_value` keep their rules, so the tool `access-token` does not change. Tests of the core cover both functions.

## Request

2. The owner can decide that `verify` also ignores a bad `owner`. Then `verify_for_pep` is the same function, and the tool `access-token check` reports a bad `owner` as a warning. The library works in both cases.
3. A token with an empty third part (`alg: none`) fails the check `structure` in `verify`. See item 3 of `core-requests-access-token.md`. The PEP refuses the token in each case, and the test `p_9_2_the_algorithms_none_hs256_and_eddsa_are_refused` accepts the check `structure`.
