# Differences from the published site: access-conformance

This file lists the places where `access-conformance` differs from the section `access-conformance` of `docs/tools.html` and from `docs/conformance.html`. The tool does not change the site. The owner updates the site later. Item 19 of `site-differences.md` said that the profile was not defined. The README of the crate and the schema `conformance-profile` now define it.

## Command line

1. The page shows `--role`, `--url`, `--format` and `--cases`. The tool adds the mandatory option `--profile FILE`. The profile gives what the data model needs: the operations, the variables, the keys, the credentials and the listen addresses.
2. The tool adds `--series U|D|E`, `--cases-dir DIR` and `--print-config`. The series must fit the role. The option `--cases-dir` reads the cases from a directory, with the layout of `conformance/`. Without it, the program uses the copy that it holds.
3. The option `--url` is optional for the role pdp when the profile has `pdp.spawn_fake_pdp`. The runner then starts `fake-pdp` in the process. A URL and `spawn_fake_pdp` together stop the program.
4. The URL must have the scheme `http` and no path. The page shows `https://edge.example` for an edge. The tool has no TLS code, and it refuses an `https` URL.
5. The tool reads no environment variable. The profile is the only source, besides the options.
6. `--print-config` checks the profile and its files, prints the value that applies for each key, and exits. The program also writes these lines to the standard error at start, with the prefix `config:`. A secret never shows.

## Output

7. The page shows one paragraph in each line, and a short text for each case. The tool shows all the paragraphs of the case, with commas. The text is the title of the case, the reason of a skip, or the first failed check with its step.
8. The page has the results `pass`, `fail` and `skip`. The tool adds `warn`. The data model says that a runner reports the failure of a SHOULD case as a warning. A warning does not change the exit code.
9. The summary line has the form of the page. It adds `, N warned` when N is more than 0. The word `cases` does not change for one case.
10. The exit code 2 also covers a bad profile, bad data and a target that is not reachable. The page lists a usage error only.
11. The JSON form is not on the site. The schema is `schemas/conformance-report.schema.json`. The members come in the order of their names, because the JSON writer of the workspace sorts them.

## What the runner does

12. The page says that, for a PEP, the tool acts as the PDP with the parts of `fake-pdp`. The scripts of the cases need rules that `fake-pdp` does not have. The tool has its own scripted PDP. It uses `fake-pdp` for a case that has a directory, for the questions that no rule matches, and for the PDP of an edge.
13. The tool makes the identity tokens with the core library and not with the crate `access-token`. A case needs a header or a claim that is absent or null, and the library of `access-token` does not make it.
14. The data model does not define the defects of a token. The tool defines them. `expired` puts `exp` after the skew in the past. `future_iat` puts `iat` after the skew in the future. `long_life` makes a life above the maximum age and the skew. `bad_signature` changes the first byte of the signature.

    The other defects set the header `typ`, `alg` or `kid`, or the claim `iss` or `aud`, to a wrong value.
15. A good token has a life of half the maximum age of the profile, and at least one second.
16. The data model says that `pdp_connections` is the number of connections that the test PDP accepted since the start of the case. The tool counts the connections that carried a request during the case. A service that keeps a connection from an earlier case then counts one connection and not zero.
17. The test PDP follows the rules of the data model. It also gives metadata at the well-known path, with the default maxima. It answers HTTP 401 when the profile gives a credential and the request has another one.
18. The operations `read_actions` and `list_options` have a default route, so a profile does not need an entry for them. `list_options` needs the key `options_type`.

## Skips that the data model does not name

19. A step that uses an operation that the profile does not define is skipped. The case is skipped when no step can run. The reason names the operation.
20. A case with a token of the algorithm `ES256` is skipped when the profile has no ES256 key.
21. A PDP case that needs a clock, counters or a reset is skipped when the profile gives no way to set them. The reason names the key that is absent.

## Data

22. The program holds a copy of the cases and of the directory files. The copy comes from `conformance/` when the program is built.
23. The case U98 was wrong for a service whose action `mcp.session` lists a budget. The change is in `case-fixes.md`.
24. The directory check cannot prove the counters. It uses questions with no `context.usage`. A directory that has services with credentials is not checked, unless the profile has a credential.
