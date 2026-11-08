# Differences from the published site

This file lists the places where the code or the data of this repository differs from the pages `docs/tools.html`, `docs/conformance.html` and `docs/source.html`. The code does not change the site. The owner updates the site later.

## Repository layout

1. The site calls the directory of the protocol `spec/`. The repository has `protocol/`.
2. The site lists a directory `site/` and a file `IMPLEMENTATIONS.md`. The repository has neither. It has `docs/` for the site.
3. The site names the licence of the texts `LICENSE-docs`. The repository file is `LICENSE-TEXTS.txt`.
4. The site names a crate `procurauth-pep`. Phase 1 has the crates `procurauth-core` and `procurauth-schema-check`. A later phase adds the PEP library with the name that the owner chooses.
5. The site says that `cargo build --release` builds five programs. Phase 1 has no program yet.

## Schemas

6. The site lists five schemas: `action-document`, `options-answer`, `identity-token`, `evaluation` and `case`. The repository has eight. These names differ: `options-route-answer`, `identity-token-claims`, `evaluation-context` and `conformance-case`. Three are new: `key-format`, `limit-values` and `fake-pdp-data`.
7. The site says that the schema of the identity token checks the header and the claims. The schema `identity-token-claims` checks the claims. Its member `$defs.header` checks the header.
8. The schema `evaluation-context` holds the members `usage`, `limits`, `match`, `reason` and `retry_after`. The site lists the first four. It does not list `retry_after`.

## Conformance data

9. The site shows a case with the members `id`, `title`, `cites`, `role`, `directory`, `request` and `expect`. The data model has `id`, `title`, `role`, `paragraphs`, `requirement`, `skip_if`, `given`, `steps` and `notes`. A case has a list of steps, and each step has a request and an expect.
10. The site example is the case D07. The same rule is the case D05 in this repository. The directory file is `directories/datastore.json`, not `alice.json`.
11. The site cites the cases of the binding as "U18, U23, U25 to U28 and E01". The binding gives U25 to U31 as well. The data model reserves all of them.
12. The site says that the answer of the PEP cases is the HTTP answer. The data model also checks the questions that the test PDP receives (`pdp_questions`) and the request that reaches the service behind an edge (`upstream`).

## Tools

13. `keycheck`: the format file of the site has `prefix`, `length`, `alphabet` and `checksum`. The `key-format` schema adds one optional member, `checksum.covers`. Its default is `random`. The checksum is the CRC-32 of zlib of the 43 random characters, as the example format defines.
14. `keycheck`: the text of the failure is `length (expected 53 characters, found 47)`, as the site shows. The checker returns this text, and the tool adds the word `bad:`. The checker stops at the first cause, in the order prefix, length, alphabet, checksum.
15. `keycheck`: the hint is the first characters of the random part, 4 at most.
16. `access-token check`: the core runs 13 checks in a fixed order: `structure`, `header`, `alg`, `typ`, `kid`, `signature`, `claims`, `iss`, `sub`, `aud`, `iat`, `exp` and `life`. The site shows 7 lines. The site puts the life on the line of `exp`. The tool can print its own selection.
17. `access-lint`: each finding has a severity, a path, a rule, a stable code and a message. The site shows the path, the rule and the message. The core marks some findings as warnings, for example a document above the minimum size of 5.3c. The site does not describe warnings. The tool must decide their effect on the exit code.
18. `fake-pdp`: the data file has the members `clock`, `metadata`, `services`, `subjects`, `counters` and `failures`. The site says that the clock and the failures are in the data file, and this is the case. The site does not show the file format.
19. `access-conformance`: the profile of the service under test and the run configuration are not defined yet. The data model names the six operations and the four variables that they need.

## Approval profile

20. The page `specification.html` has no section 17, no paragraph 5.2b, and no change to 1.3, 10.1, 10.3, 11.1 and 12. The repository has them. The header of the protocol stays at version 1.0 (decision 75).
21. The page `mcp-binding.html` has the old 3.5a and the old case U30. The repository has a new 3.5a, the paragraphs 5.7, 5.7a and 5.7b, and a new U30. Its section 12 has two more items.
22. The site lists the schemas of the earlier lots. The repository adds `approval-submission`, `approval-verdict` and `approval-view`, and it changes `action-document`, `evaluation-context`, `fake-pdp-data` and `conformance-case`. The folder `docs/schemas` has no copy of them.
23. The page `conformance.html` and the README show 192 cases. The repository has 218: 110 for a PEP, 89 for a PDP and 19 for an edge. The runner skips 26 of them, with the condition `no_approval_support`. The image `docs/assets/conformance.svg` still shows 192.
24. The page `conformance.html` lists the skip conditions. The repository has one more: `no_approval_support`. It also has the operation variants, the script of the approval API, `pdp_approvals` and five new variables.
25. The page `mcp-binding.html` has the old 3.1 and the old open point 7. The repository has a new 3.1 and 3.5a, and the open points 7 to 10. They follow the contract of the MCP servers, section 9.
