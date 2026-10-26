# Integration of the runner with the reference service and the reference edge

This file tells the integration agent what the reference service and the reference edge need so that `access-conformance` can test them. The crate `access-conformance` has example profiles in `crates/access-conformance/examples/`. The mock servers in `crates/access-conformance/tests/common/` are a worked example of each part.

## The command

Build the program with `scripts/cargo.sh build --release -p access-conformance`. The program is `access-conformance`. These commands run one series each.

```text
access-conformance --role pep  --profile pep.json  --url http://127.0.0.1:8000
access-conformance --role edge --profile edge.json --url http://127.0.0.1:8080
access-conformance --role pdp  --profile pdp-fake.json
```

Add `--format json` for a document. Add `--cases U01,U05` for some cases. Add `--print-config` to check the profile and the files. The exit code is 0, 1 or 2.

## Reference service (role pep)

Start the service before the runner. The service must call the test PDP of the runner and trust the keys of the test edge.

1. Give the service the public keys of the test edge. The JWK Set is `examples/edge-jwks.json`, with the `kid` values `edge-ed25519` and `edge-es256`. The private keys are `examples/test-edge-ed25519.pem` and `examples/test-edge-es256.pem`. They are public test keys.
2. Set the issuer to the value of `pep.token.iss`, the maximum age to `pep.token.max_age_seconds`, and the clock skew to `pep.token.skew_seconds`. Set the header of the token to `pep.token.header`. Set the id of the service to `pep.service`.
3. Set the address of the PDP to `pep.pdp.listen`, for example `127.0.0.1:8181`. The runner binds this address. Set the credential of the service to the content of `pep.pdp.credential_file`. The test PDP asks for it only when the profile names the file.
4. Make the action document declare each action that the profile names, and the action `mcp.session` when the service has an MCP endpoint (binding 3.6a).
5. Write the operations of the profile. Each operation needs a method, a path and the variables. The example `examples/pep.json` shows a service with each operation.
6. Declare each part that the service has. The key `options_type` says that the service has the options route. The key `mcp` says that it has an MCP endpoint. The key `answer_cache` says that it keeps answers.
7. When the service keeps state between requests, for example an answer cache, give a request in `pep.reset`. The runner sends it before each case. A cache that lasts from one case to the next gives false failures, because the cases share subjects.

### What the cases assume

- The answers of the test PDP follow the script of the case. A question that no rule matches is a fault of the case, and the PDP answers HTTP 500.
- The service must not use the claim `owner` of the token, also when it is not a text (case U10). The strict reader of the claims in `procurauth-core` gives an error for such a claim. The reference service must not use that error to refuse the token.
- A service whose action `mcp.session` lists a budget sets `pep.mcp.session_budget` to true.
- After a lost answer, the service must not send a question with `context.usage` again (protocol 10.6, case U68). The mock in `tests/common/mock_pep.rs` shows a client that obeys this rule.
- The question for a use with `usage` goes to `POST /access/v1/evaluation`. The test PDP also reads `POST /access/v1/evaluations` and the metadata at `/.well-known/authzen-configuration`.

## Reference edge (role edge)

Start the edge before the runner. The runner binds the listen addresses of the profile.

1. Give the edge the three key texts. The edge must know the text in `edge.keys.valid.text_file`, and its subject must be `edge.keys.valid.subject`, with the owner `edge.keys.valid.owner`. The example uses `key:ann-k1` and `ann`.
2. The edge must know the text in `edge.keys.no_access.text_file`. Its subject must have no true decision for `access` in the directory. The example uses `key:ann-k2`, which has `data.read` and no `access`.
3. The edge must not know the text in `edge.keys.unknown.text_file`.
4. Set the PDP of the edge to `edge.pdp.listen`. The runner starts `fake-pdp` there, with the directory `access.json` or the file of `edge.pdp.directory_file`. Set the credential of the edge to the content of `edge.pdp.credential_file`.
5. Set the upstream of the edge to `edge.upstream.listen`. The runner answers each request there with HTTP 200.
6. Set the service id to `edge.service`, the issuer to `edge.trust.iss` and the header of the token to `edge.token_header`. Give the public keys of the edge in `edge.trust.jwks_file`. The runner checks each token with them.
7. When the edge has an MCP route, set `edge.mcp_path`. When the edge keeps tokens, set `edge.token_cache` to true. With one key in the key set, the runner skips the case E13.

## Role pdp

The role pdp needs no service. `pdp-fake.json` starts `fake-pdp` in the process, and all 74 cases pass. To test another PDP, use `pdp-external.json` and the key `--url`. The PDP must offer a load request, or the runner skips the cases that need a clock or counters.

## Open points for the integration

- The runner uses plain HTTP. A target with TLS needs a proxy that ends TLS.
- The runner binds ports. Choose free ports for `pep.pdp.listen`, `edge.pdp.listen` and `edge.upstream.listen`.
- The runner makes tokens with the system clock. Run the service on a host with the same clock.
- A failed case prints its first failed check. Use `--format json` for all the failed checks.
