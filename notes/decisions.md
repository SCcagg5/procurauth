# Technical decisions

Each item gives one choice and the reason in one sentence.

## Workspace

1. The workspace has the crates `procurauth-core` and `procurauth-schema-check`, so that each later tool depends on one shared library.
2. The data checks are in the crate `conformance/schema-check`, because the owner asked for that place and a library can serve later tools.
3. The core crate is a library with no command line, no clock and no environment access, because each tool must give these values.
4. The edition is 2024 and `rust-version` is 1.89, because the code uses `let` chains and a test dependency needs 1.89.
5. The workspace lints forbid `unsafe` code and warn about `unwrap`, `expect`, `panic` and print macros, because `-D warnings` makes each of them an error.
6. There is no `rust-toolchain.toml`, because the Docker image fixes the toolchain and a file on the host would make `rustup` install another one.
7. The image is `rust:1-bookworm` with `rustfmt` and `clippy` added in `scripts/Dockerfile.dev`, because the official image has neither component.
8. The cargo registry and the target directory are Docker volumes of the host user, so that the repository has no root-owned file.

## Dependencies

9. The core uses `ed25519-dalek` and `p256`, not `ring`, because they build without a C compiler for the five target platforms of the site.
10. The crates stay on `ed25519-dalek` 2.2, `p256` 0.13 and `sha2` 0.10, because these lines are mature and `Cargo.lock` pins them.
11. The tests use `jsonschema` 0.30 with no default features, because it checks the schemas offline and the production code does not use it.
12. The dependencies are `serde`, `serde_json`, `thiserror`, `sha2`, `base64`, `hex`, `ed25519-dalek` and `p256`, because each is well known and older than one year.
13. The core does not use the derive macros of `serde` to read documents, because a derived reader cannot give the JSON path of each error.

## Strict readers

14. The core has its own strict JSON reader, because `serde_json` keeps the last value of a duplicate member.
15. The reader makes a `serde_json::Value`, because the ecosystem reads that type, but the member order of an object is then the sorted order.
16. The reader refuses a depth above 64 levels, because a recursive reader must not overflow its stack on hostile input.
17. A parser returns every finding with its JSON path, because the tool `access-lint` must list each error and not only the first.
18. A finding is an error or a warning, because some rules of the protocol are SHOULD and a document that breaks them is still good.
19. A reader of a protocol document ignores an unknown member, except where the text says otherwise, because paragraph 1.2 tells a receiver to do so.
20. A reader of the data of a tool refuses an unknown member, because the rules for a configuration ask for a closed schema.
21. The core refuses `1.0` where a whole number is required, because the value in the file is the value that applies.
22. The functions take the time as an argument, because a test must give a fixed clock and a tool owns the system clock.

## Documents

23. The action document gives a warning for a count or a length above the minimum of 5.3c, because a reader MAY accept more.
24. The core treats the id of the service as a node id (4.1), because the service is the root node of the chain.
25. The percent-decoder for paths is strict, because paragraph 5.2 says that the encoded text is the only text form of an id.
26. A path must follow the parents of the document, and the same function checks a grant and a question.
27. A chain error gives the reason of 11.1 through `ChainError::reason`, so that each PDP answers in the same way.

## Limits and decisions

28. The checker warns about a budget on a grant other than `access`, because paragraph 8.3 says that the PDP ignores it.
29. A value that the PDP ignores is a warning in a grant file, because it is harmless but probably a mistake.
30. The retry time rounds up and has a minimum of 1, because paragraph 11.1 says so.
31. The coverage functions work on paths, because a grant covers a node when its path is the start of the path of the node.
32. The decision for a key and `subtree` looks for two grants on one line of the tree. This is the same as a search for one node that both sides cover.
33. The core does not count units, because the counters belong to the PDP and the test PDP can keep them in memory.

## Identity token

34. The token check returns the result of every check in a fixed order, because the tool `access-token check` prints each one.
35. The function `verify` gives only the first failure, because paragraph 9.4 gives HTTP 401 for each failure and the details are for logs.
36. The `alg` check accepts `Ed25519` and `ES256` only, because paragraph 9.2 names them and `EdDSA` is deprecated.
37. The key must match the algorithm of the header, because a token must not choose another algorithm for a key.
38. The JWK Set reader refuses a private member `d` and each unknown member, because an edge must publish public keys only.
39. The reader refuses a token of more than 16 KiB, because a token has about 1 KB and an unbounded input is a risk.
40. The reader refuses the header `crit`, because RFC 7515 says to refuse an extension that the reader does not know.
41. The claim `owner` is not part of the check of a PEP, because paragraph 9.5 forbids its use in a decision.
42. The function `profile_findings` is separate from the PEP checks, because a PEP must not read a meaning from a subject id (3.3).
43. The signing code can write a header that names another algorithm than the key, because the tool must make bad tokens for tests.
44. The keys for the tests come from fixed seeds, so that the crate needs no random number generator.

## Key format

45. The checker reads the format as data, because the protocol defines no format for the text of a key (3.8).
46. The checksum is the CRC-32 of zlib in base62 with the digits `0-9A-Za-z`, because the example format gives this rule.
47. The member `covers` is an addition to the format file of the site, because another system can cover the prefix too.
48. The checker stops at the first cause, in the order prefix, length, alphabet, checksum, because the site shows one cause for each bad text.
49. No error and no debug text holds the text of the key, because a key is a secret and a log must never hold it.
50. The hint is the first 4 characters of the random part, because the example format keeps at most 4 of them.
51. The format reader refuses contradictory members, for example a checksum that is too short for a 32-bit value, because a contradiction must stop the program.

## Test data

52. The data of the test PDP is a closed document, `fake-pdp-data`, because the tool reads one file and the cases share it.
53. A key can have the state `revoked` or `expired`, because paragraph 11.1 gives the reason `unknown_subject` for both.
54. The owner of a key can be absent from the data, because paragraph 11.1 gives `unknown_subject` for a key whose owner does not exist.
55. A failure is a rule with a kind, a `when` and a count, because a test must fail one question and not the next.
56. A grant that the document cannot hold is an error in the data, because a test with such a grant tests nothing.

## Conformance model

57. A matcher has one of five forms, `equals`, `absent`, `present`, `regex` and `one_of`, because the owner asked for a small closed vocabulary.
58. A PEP step names an abstract operation, because a case must not know the routes of the service under test.
59. The operations, the conditions to skip and the variables are closed lists in the schema, because a runner must know each one before it runs.
60. The test PDP of a PEP case follows a script, because a case must not depend on the data of the service under test.
61. A case counts the questions that the PEP sent, because most rules of the PEP are about the questions and not about the answer.
62. A reference PDP in the tests runs the cases of the series D, which proves that the expected results agree with the protocol.
63. The reference PDP also shows that the core has what a test PDP needs.
64. A table of rows gives the verdict of the schema and of the Rust reader. A difference shows a rule that a schema cannot state.
65. The tests check the cited paragraphs against the text, because a case that cites an absent or unused paragraph is a mistake.

## Style

66. A test checks the length of sentences and a short list of banned words, because the owner requires Simplified Technical English.

## Publication

67. A service publishes only the actions that it serves (5.2a), because a grant form must not offer a right that does nothing.

## Conformance runner

68. The runner and the cases send `Mcp-Method` and `Mcp-Name` on each MCP request, because the MCP server contract (2.5) requires them.
69. The profile of a PEP gives `use_ceiling` a request whose result does not go past `ceiling_value`. A PEP that applies the ceiling refuses a result past it, and U37 tests the acceptance of a ceiling.

## Effect of an approval

70. The resource in the effect is the path of 5.2 for `resources`. The service itself has the empty string, so the effect needs no second notation for a resource and no chain.
71. The number subset of `op` is the integers from -(2^53-1) to 2^53-1. Any other number makes `op` invalid with `invalid_op`, because the number formats of the languages differ.
72. `op` is a JSON object, because a `view` needs pointers into it and the paper gives an object in each example. The empty object is valid.
73. Section 17 has only the paragraph 17.3 in this version. The numbers 17.1 to 17.12 stay free for the approval profile, because a paragraph keeps its number.
74. The ids V01 and V02 name two groups of vectors, not cases of a series, because no runner uses a vector file in this version.
75. The header of the protocol stays at version 1.0. The changelog shows the changes as unreleased until a release, and the site pages show the version 1.0.

## Approval profile

76. Section 17 is optional (1.3), because a PDP or a service can follow the protocol with no approval. This ends decision 73: the paragraphs 17.1 to 17.12 are written.
77. The new paragraph of 5.2 has the letter b, not the letter d of the papers. The only paragraph before it is 5.2a, and the letters follow in order.
78. The PEP asks two questions for an action with an approval: one without usage, then one with usage. The papers split the call from the use, and 10.1 forbids a kept `true` to start a use.
79. A void approval gives `approval_required` to a question without usage, and `approval_expired` to a question with usage. An agent can then ask again at once, and the PEP keeps no state.
80. A refusal gives `approval_denied` during a deny time that the PDP publishes. The papers make the time a PDP value, so the test data gives the end of the time as `deny_until`.
81. The PEP sends `context.usage` for the use of an action with an approval, also when the action lists no budget (17.2). The PDP must know which question consumes the approval.
82. The answers `approval_required` and `approval_pending` carry `evaluation_id`, so that the PEP can submit again and get the same id and code. The PEP keeps no state.
83. A question with no effect for a grant with `confirm` gets `approval_required` with no `evaluation_id`. A PEP that does not know approvals then fails closed, and it cannot submit.
84. The query of each read of a request has `subject`. A request of another subject, of another service and an unknown request get the same 404, so that no verdict leaks.
85. A submission has exactly one of `approval_ref`, `lease_s` and `until` (17.4). A call to the MCP tool that does not follow this gets `invalid_argument`, because the papers give 422 for it at the PDP.
86. `confirm` has no effect on `access` and on a question with `context.match` equal to `subtree` (17.8). The edge decides only `access`, and a display must not hide a tool.
87. The binding has no code `approval_cancelled`. The PEP learns only `void` for a request that someone cancelled (17.12), so it gives `approval_expired`.
88. The tool `get_action_status` has no action and sends no question. The approval API checks the subject, and `tools/list` names the tool when it names a tool with an approval.
89. The API of the PDP uses the error `no_device` for an owner with no device, as the dialogue paper does. The confirmation paper says `no_phone`.
90. The result for a request that waits is not an error. It has a second content item that starts with `NOT EXECUTED`, as the paper recommends (question 9).
91. The `view` has the members `title`, `fields`, `body` and `body_label`. The paper shows them in its example, and a schema needs a closed list.
92. In the data of a PDP, the last entry of `approvals` for one subject, action, resource and effect is the latest approval. A list has an order, so no timestamp is needed.

## Case ids of the approval profile

93. The ids follow the rule of no gap. The paper ids U107 and U109 to U112 become U106 to U110, and the paper D90 becomes D89. The paper U106 is the case U30, which is rewritten.
94. The paper cases D88 and D89 stay out of the data, because the answer of a person is outside the protocol. A new case D88 tests `approval_pending`, which the paper had no case for.
95. A case of the approval profile has the condition `no_approval_support`. The runner holds it for each target until the lots S4a and S4b, so that the reference programs stay green.
96. The runner model reads the new members of a case now: `variant`, `approval_script`, `pdp_approvals` and the matcher `effect`. The runner loads each case, and one case that it cannot read stops the whole run.
97. The directory `approvals.json` is valid against the schema only. The reader of the core does not know `confirm` and `approvals` until the lot S4a, and the test of the data files skips this file.
98. The schema `conformance-case` has no endpoint `approval_requests` or `approval_status`. No case sends a request to the approval API of a PDP, because the API series stays with the tests of the PDP.
99. The variable `approval_ref` has the fixed value `ref_conformance_0001`, and the base call of the runner gives `lease_s` 900. A case then needs no value from the profile for the control arguments.
100. The reader of the core reads the member `approval` of an action (5.2b) and refuses another value. The schema and the lint examples of 5.2b need it, and the protocol makes it a rule for each reader.
