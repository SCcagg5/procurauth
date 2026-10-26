# Conformance data

This directory holds the conformance cases of the ProcurAuth protocol, as data. The runner `access-conformance` reads them. The file `COVERAGE.md` lists the paragraphs that the cases test, and the rules that no case tests.

## Layout

| Path | Content |
| --- | --- |
| `cases/U/` | Cases for a PEP, the service side. |
| `cases/D/` | Cases for a PDP, the decision point. |
| `cases/E/` | Cases for an edge. |
| `directories/` | Data files for the test PDP. A case can name one. |
| `COVERAGE.md` | The cases of each paragraph, and the rules that no case tests. |
| `schema-check/` | A Rust crate. Its tests check each file of this directory. |

One file holds one case. The name of the file is the id of the case, for example `U03.json`. The schema `schemas/conformance-case.schema.json` defines the format.

## Ids

An id has the letter of the series and a number of two or three digits. The series U tests a PEP, the series D tests a PDP, and the series E tests an edge (protocol 15, item 2).

The numbers of a series have no gap. The MCP binding gives the ids U18, U23, U25 to U31 and E01 to the cases of its section 9. These cases are in this directory, and they have exactly these ids. Each of them cites a paragraph of the binding and has the condition `no_mcp_endpoint`.

## A case

A case has these members. Each member is required, except those that the table marks as optional.

| Member | Meaning |
| --- | --- |
| `id` | The id of the case. |
| `title` | One sentence that states the rule that the case tests. |
| `role` | `pep`, `pdp` or `edge`. The letter of the id decides it. |
| `paragraphs` | The paragraphs that the case tests, for example `["6.4", "10.3"]`. A paragraph of the MCP binding has the prefix `mcp:`. |
| `requirement` | `MUST` or `SHOULD`. It is the level of the rule in the text. |
| `skip_if` | Optional. A list of conditions. The runner skips the case when one is true. |
| `given` | The data that the runner sets up before the first step. |
| `steps` | The steps, in order. Each step sends one request and checks the result. |
| `notes` | Optional. A remark for the reader. |

The schema is closed. An unknown member is an error. The checks of this directory also make sure that each cited paragraph exists in the texts and is not unused. A case cites only a paragraph that its role must follow, and `COVERAGE.md` lists the case in the row of each paragraph.

A case tests one rule, and it has one reason to fail. A rule at the level SHOULD has a case with the requirement `SHOULD`. A runner reports the failure of such a case as a warning.

## Given

The member `given` can have these members.

| Member | Meaning |
| --- | --- |
| `directory` | The data of the test PDP. It is a file name in `directories/`, or the data itself. The schema `fake-pdp-data` defines the format. |
| `clock` | A fixed clock, `{"now": 1792569648}`. It replaces the clock of the directory. |
| `counters` | The first values of counters. They replace the entries of the directory for the same subject, limit and window. |
| `tokens` | The identity tokens that the steps send. Each token has a name. |
| `pdp_script` | For a PEP. The answers of the test PDP. |

A case in the series D loads its directory in the PDP under test before the first step. Each case starts with the counters of its directory and of its `counters`.

### Directory files

Each file validates against the schema `fake-pdp-data`. The reader of the core gives no warning for it. A case that needs a value that the PDP ignores has its directory in the case itself.

| File | Content |
| --- | --- |
| `datastore.json` | The data of protocol section 13: the service `datastore`, Alice and her key. It also has Bob, with a grant on `test1`, and his key, with a grant on `test2`. This pair shows the example of protocol 4.4. |
| `budgets.json` | The same service with a second budget, `write_requests`, that only `data.write` lists. Subjects with one to four windows, with no budget, and keys with owners that have budgets. It has counters for the cases of atomic use. |
| `ceilings.json` | Several grants of one action on one line of the tree, with different values. Keys and owners that give different ceilings. |
| `keys.json` | An active key, a revoked key, an expired key, a key whose owner does not exist, and keys with the longest and unusual local parts. |
| `subtree.json` | Persons and keys for the rule of protocol 4.4 on `subtree`. |
| `tree.json` | A service with four levels of types, nodes with special characters in their ids, and the same child id under two parents. |
| `services.json` | Three services with a credential each: two with a document and one with no good document. |
| `access.json` | Persons and keys with and without a grant of `access`. |
| `maxdoc.json` | A service with the largest document that a reader must accept (protocol 5.3c). |

### Tokens

The runner makes each token with the signing key of the test edge. It sets `iss`, `aud`, `iat` and `exp` from the configuration of the service under test. A case can override them in `claims`. The value `null` removes a member.

A token has a `subject`. It can have an `owner`, an `alg`, `claims`, `header` and one `defect`. The schema lists the defects. A defect makes a time relative to the clock of the run. For example, `expired` puts `exp` in the past, beyond the clock skew.

A step sends a token with the member `token`. The variable `{{token_<name>}}` gives the text of the token that has this name. A case uses it to put a token in a place that the operation does not use, for example in the header `Authorization`. A token that a case defines is used in one of these two ways.

### Script of the test PDP

A PEP case does not need to know the data of the service under test. It gives a script. Each rule has `when` and `respond`. The runner reads the rules in order. The first rule whose `when` matches the question gives the answer.

A `when` matches when each member that it has is equal to the question. The members are `subject`, `action`, `resource`, `usage` and `match`. The value `true` of `usage` matches a question with `context.usage`. The value `false` matches a question without it.

An empty `when` matches each question. A question that no rule matches gets the answer from the directory. Without a directory, this is a fault of the case.

A `respond` gives a `body` and an optional `status`, or it has `no_answer`. The status is 200 by default. For a request with items, a rule matches each item on its own.

The test PDP follows protocol 6.11. A request that has `context.usage` at any level and has items gets HTTP 400. The runner counts the items of such a request as questions.

## Steps

A step has an optional `name`, an optional `skip_if`, a `request` and an `expect`. The runner skips a step when one of its conditions is true. The other steps of the case still run.

### Request

A request names its target in one way.

| Member | Role | Meaning |
| --- | --- | --- |
| `operation` | PEP | A kind of use of the service under test. The runner maps it to a request with its profile. |
| `endpoint` | PDP | `evaluation`, `evaluations` or `metadata`. |
| `method` and `path` | Any | An HTTP request that the case writes in full. The path starts with a slash, or it is a variable. |

A request can also have `headers`, `body` or `body_text`, and `token`. For an operation, the runner adds the `headers` of the step to the request that it builds. The member `token` names a token of `given.tokens`. The runner sends it to a PEP in the header of the identity token.

These are the operations. The list is closed. A new operation needs a change of the schema.

| Operation | Meaning |
| --- | --- |
| `use_plain` | One use of an action that lists no budget, on a node below the service. |
| `use_budget` | One use of an action that lists a budget, on a node below the service. |
| `use_ceiling` | One use of an action that lists a ceiling. |
| `use_service` | One use on the service itself. |
| `use_multi` | One use of an action that lists a budget, and that needs one more permission, on another action or another node. |
| `read_actions` | A read of the action document. |
| `list_options` | A read of the first level of the options route. |
| `mcp_call_plain` | A `tools/call` of a tool whose action lists no budget. |
| `mcp_call_budget` | A `tools/call` of a tool whose action lists a budget. |
| `mcp_call_input` | A `tools/call` that ends with `InputRequiredResult`. |
| `mcp_call_multi` | A `tools/call` of a tool that needs two permissions. |
| `mcp_call_approval` | A `tools/call` of a tool whose action waits for an approval. |
| `mcp_approve` | The approval of the call of the step before, and the run of the tool. |
| `mcp_refuse` | The refusal of the approval of the call of the step before. |

The request of an MCP operation has the revision 2026-07-28 and the number 7 as its JSON-RPC id.

### Expect

A step expects the members that it gives. The runner checks each one.

| Member | Meaning |
| --- | --- |
| `status` | The HTTP status of the answer. |
| `headers` | The headers of the answer. The names have no case. |
| `body_text` | The body as text. An empty body is the empty text. |
| `json` | Members of a JSON body. Each name is a JSON Pointer. |
| `valid_as` | The body is a good document of a kind: `action_document` or `options_answer`. The value with the suffix `_no_warning` also needs a report with no warning. |
| `pdp_questions` | For a PEP. The questions that the test PDP received during the step. |
| `pdp_connections` | For a PEP. The number of connections that the test PDP accepted since the start of the case. |
| `upstream` | For an edge. The request that reached the service behind the edge. |

The member `valid_as` uses the readers of the core. The reader of the action document and the reader of the answer of the options route give the findings. An error is a failure. A warning is a failure for the value with the suffix `_no_warning`.

Each entry of `pdp_questions` has `json`, optional `headers` and `count`. The runner counts the questions that match each matcher of `json` and of `headers`. It compares the count with `count`. Without `count`, the entry expects exactly one question. The entry `{"json": {}, "count": {"equals": 0}}` says that the PEP sent no question.

The member `upstream` can have `count`, `headers`, `token_header` and `token_claims`. The runner acts as the service behind the edge. It checks the identity token with the public keys of the test edge, and then it reads its JOSE header and its claims.

## Matchers

A matcher checks one value. A matcher has exactly one member.

| Matcher | True when |
| --- | --- |
| `{"equals": V}` | The value is equal to the JSON value `V`. |
| `{"absent": true}` | The value does not exist. |
| `{"present": true}` | The value exists. A member with the value `null` exists. |
| `{"regex": "R"}` | The value exists and matches the expression `R`. The syntax is the one of the Rust crate `regex`. The match is not anchored. |
| `{"not_regex": "R"}` | The value does not exist, or it does not match the expression `R`. |
| `{"one_of": [V, W]}` | The value is equal to one item of the list. |

A regular expression reads the text of the value. A string is its own text. A number, a boolean and `null` have their JSON text. An object and an array have their compact JSON text. In a regular expression, the runner escapes the text of a variable.

## Variables

A case can write a variable as `{{name}}` in a string or in the name of a member. The runner replaces it before it uses the value. A string that is exactly one variable gets the JSON value of the variable. This is how `{{ancestors}}` gives an array.

| Variable | Value |
| --- | --- |
| `service` | The id of the service under test. |
| `action` | The action of the operation of the step. |
| `resource_type` | The type of the node of the operation. |
| `resource_id` | The id of the node of the operation. |
| `ancestors` | The chain of the node of the operation, as an array. |
| `tool` | The name of the tool of the MCP operation of the step. |
| `ceiling` | The name of a ceiling that the action of `use_ceiling` lists. |
| `ceiling_value` | A value of that ceiling, from its `min` to its `max`. |
| `options_type` | The type of the nodes at the first level of the options route. |
| `mcp_path` | The path of the MCP endpoint. |
| `token_header` | The name of the header of the identity token. |
| `unknown_key_text` | A text that has the format of a key, and that the edge does not know. |
| `valid_key_text` | The text of a key that the edge accepts. |
| `valid_key_subject` | The subject id of that key. |
| `valid_key_owner` | The owner of that key. |
| `no_access_key_text` | The text of a key that the edge knows, whose subject has no true decision for `access`. |
| `token_<name>` | The text of the token `<name>` of `given.tokens`. |

The variables `service` to `mcp_path` come from the profile of the service under test. The variable `token_header` and the four after it come from the configuration of the run against an edge. Some variables come from the operation of the step. In `given`, and in a step with no such operation, they come from the first step whose operation has them. These are `action`, `resource_type`, `resource_id`, `ancestors`, `tool`, `ceiling` and `ceiling_value`. The profile format and the configuration are the work of the tool `access-conformance`.

A service that has an options route lists at least one child at its first level. A child at that level has the type `options_type`.

## Conditions to skip a case

The member `skip_if` lists conditions. The runner skips the case, or the step, when one is true. A skipped case is not a failure.

| Condition | Meaning |
| --- | --- |
| `no_budget_action` | The service has no action that lists a budget. |
| `no_ceiling_action` | The service has no action that lists a ceiling. |
| `no_options_route` | The service does not publish the options route. |
| `no_answer_cache` | The PEP keeps no answer (protocol 10.1 says that it MAY). |
| `no_token_cache` | The edge keeps no identity token (protocol 9.9 says that it MAY). |
| `no_mcp_endpoint` | The service has no MCP endpoint. |
| `no_budget_session` | The action `mcp.session` lists no budget (binding 3.6a). |
| `no_input_tool` | The service has no tool that asks the client for input. |
| `no_approval_tool` | The service has no tool whose action waits for an approval. |
| `no_multi_action` | The service has no use that needs two permissions. |
| `single_key_set` | The key set of the edge holds one key only. |

The checks enforce these rules. A step that uses `use_budget`, `use_ceiling`, `use_multi`, `list_options`, an MCP operation, or the variables `mcp_path` and `options_type`, has the condition that goes with it. The condition is in the step or in the case.

## Add a case

1. Choose the series from the role. Take the next free number. The numbers have no gap.
2. Write the title as one sentence in Simplified Technical English. State the rule, not the test.
3. Cite each paragraph that the case tests. Cite only a paragraph that its role must follow.
4. Write `given`. Prefer a script for a PEP case. Prefer a directory file for a PDP case.
5. Write each step. Check only what the paragraph requires.
6. Add the case to the row of each cited paragraph in `COVERAGE.md`.
7. Run `scripts/cargo.sh test --workspace`. The tests check the case.

For a PDP case, the test `reference_pdp` in `crates/procurauth-core` also runs the case on a small reference PDP. It makes a wrong expectation in each case, and it checks that the test fails. If the reference PDP cannot run a new case, extend the reference PDP with functions of the core.

## Checks

The crate `schema-check` checks each file. A failed check names the case. These are the checks:

- the case is valid against the schema `conformance-case`;
- the id is the file name, and the directory is the series;
- the role fits the series, the numbers have no gap, and the cases of the MCP binding have their ids;
- each cited paragraph exists and is not unused, and its role must follow it;
- each regular expression compiles, and each variable is known;
- each token that a step uses exists, and each token is used;
- each condition that a step needs is in the step or in the case;
- each directory file that a case names exists and is valid;
- each series has at least six cases;
- `COVERAGE.md` has a row for each paragraph that a role must follow, and it agrees with the cases.

Run the checks with `scripts/cargo.sh test -p procurauth-schema-check`.
