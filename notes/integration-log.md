# Log of the integration

This file records the work of the integration. The runner `access-conformance` ran against the reference service, against `fake-pdp` as a separate process, and against the reference edge. Each item gives the finding, the cause and the change.

## Results of the runs

The script `scripts/conformance.sh all` gives these results. The runs start every process in one container, on the loopback address.

| Run | Target | Cases passed | Failed | Skipped |
| --- | --- | --- | --- | --- |
| U, action `mcp.session` with a budget | `reference-service` | 99 | 0 | 0 |
| U, action `mcp.session` with no budget | `reference-service` | 98 | 0 | 1 (U95, `no_budget_session`) |
| D, `fake-pdp` in the process of the runner | `fake-pdp` | 74 | 0 | 0 |
| D, `fake-pdp` as a separate process | `fake-pdp` with `--admin` | 74 | 0 | 0 |
| E | `reference-edge` | 18 | 0 | 0 |

## Part A: the runner against the reference service

1. **First run of the series U.** All 99 cases passed on the first run, with the profile written from `PROFILE.md`. No case failed, so no cause needed a fix. The local runner in `crates/reference-service/tests/u_cases.rs` and the runner `access-conformance` agree.
2. **The runner can fail.** A check of the power of the run: a service that accepts a life of 7200 seconds fails the case U48, and only this case. A service with a wrong issuer fails the cases that need a good token.
3. **U95 was skipped.** The reference service listed no budget on the action `mcp.session`, so the condition `no_budget_session` was true. The service can support the budget, so it must. The new key `mcp_session_budget` makes the action list the budget `requests`. The script runs the service two times: with the key (99 cases pass) and without it (98 pass, U95 skipped with its reason). The key needs `mcp_path`, and the program stops at start when they contradict.
4. **The series D against a separate process.** The runner needs a way to load the data of a case in the PDP under test (`pdp.load`). `fake-pdp` had no such request, so the external mode could not run the cases that need a directory. The tool lacked this function.

The admin request `PUT /__fake/load` (and `POST`) now replaces the directory, the counters, the failures, the clock and the credentials of the services. It refuses a `metadata` member that differs from the values of the start. The credentials of the services had a fixed table, and the table is now behind a lock. The profile `crates/fake-pdp/examples/conformance-profile.json` uses this request. All 74 cases pass against the process.

## Part B: the reference edge

5. **First run of the series E.** All 18 cases passed on the first run. The key set of the profile has two keys and the edge sets `kid`, so E13 runs. The edge keeps tokens, so E15 and E16 run. No case is skipped.
6. **The runner can fail against the edge.** A check of the power of the run: an edge with no `kid` fails seven cases, and an edge with another issuer fails seven cases. Each failure names the check of the token that failed.
7. **The question for `access`.** The type `PdpClient` of `procurauth-pep` was not public, and `Pep` refuses an action that the document does not declare. An edge needs to ask `access`.

The library has a new module `access` with `AccessGate`. It uses the same link to the PDP as the PEP: the metadata, the credential, the timeouts, the connections and the retries. It never sends `context.usage`. The check `PdpConfig::check` is now public.
8. **The body of a refused request.** The edge decides on the head of the request. A refused request gets HTTP 401 with an empty body, and the connection closes.

The edge reads and drops the rest of the request for 2 seconds at most. Without this step, a client that sends a large body can get a reset before it reads the answer (case E09, body of 100,000 bytes). The test `p_9_8_a_refusal_needs_no_part_of_the_body` sends 5,000,000 bytes.
9. **No kept token without a decision.** The edge asks the PDP for each request, also when it keeps tokens (9.9). A kept token never replaces the question. The test `p_8_3_the_edge_asks_the_pdp_for_each_request_also_with_kept_tokens` checks this.

## The scripts

10. `scripts/cargo.sh` and `scripts/conformance.sh` share the settings in `scripts/docker-env.sh`: the image, the volumes and the user.
11. `scripts/conformance.sh` builds with `scripts/cargo.sh`. It then starts one container with `--network none`, `--rm` and `--init`, and the repository mounted read only. The script inside the container is `scripts/conformance-run.sh`. A `timeout` runs inside the container, and a second `timeout` runs on the host.
12. `scripts/ci.sh` runs `scripts/conformance.sh all` after the tests. It fails when a case fails.
