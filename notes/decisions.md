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
