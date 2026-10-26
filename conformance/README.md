# Conformance data

This directory holds the conformance cases of the ProcurAuth protocol, as data. The runner `access-conformance` reads them. A later phase writes the full list of cases. This phase gives the data model and 18 example cases.

## Layout

| Path | Content |
| --- | --- |
| `U/` | Cases for a PEP, the service side. |
| `D/` | Cases for a PDP, the decision point. |
| `E/` | Cases for an edge. |
| `directories/` | Data files for the test PDP. A case can name one. |
| `schema-check/` | A Rust crate. Its tests check each file of this directory. |

One file holds one case. The name of the file is the id of the case, for example `U03.json`. The schema `schemas/conformance-case.schema.json` defines the format.

## Ids

An id has the letter of the series and a number of two or three digits. The series U tests a PEP, the series D tests a PDP, and the series E tests an edge (protocol 15, item 2).

The MCP binding owns the ids U18, U23, U25 to U31 and E01. No case of this directory uses them. The series E starts at E02.

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

The schema is closed. An unknown member is an error. The checks of this directory also make sure that each cited paragraph exists in the texts and is not unused.

## Given

The member `given` can have these members.

| Member | Meaning |
| --- | --- |
| `directory` | The data of the test PDP. It is a file name in `directories/`, or the data itself. The schema `fake-pdp-data` defines the format. |
| `clock` | A fixed clock, `{"now": 1792569648}`. It replaces the clock of the directory. |
| `counters` | The first values of counters. They replace the entries of the directory for the same subject, limit and window. |
| `tokens` | The identity tokens that the steps send. Each token has a name. |
| `pdp_script` | For a PEP. The answers of the test PDP. |

The file `directories/datastore.json` holds the data of protocol section 13: the service `datastore`, Alice and her key. It also holds Bob and his key. Bob has a grant on `test1`. His key has a grant on `test2`. This pair shows the example of protocol 4.4.

### Tokens

The runner makes each token with the signing key of the test edge. It sets `iss`, `aud`, `iat` and `exp` from the configuration of the service under test. A case can override them in `claims`. The value `null` removes a member.

A token has a `subject`. It can have an `owner`, an `alg`, `claims`, `header` and one `defect`. The schema lists the defects. A defect makes a time relative to the clock of the run. For example, `expired` puts `exp` in the past, beyond the clock skew.

### Script of the test PDP

A PEP case does not need to know the data of the service under test. It gives a script. Each rule has `when` and `respond`. The runner reads the rules in order. The first rule whose `when` matches the question gives the answer.

A `when` matches when each member that it has is equal to the question. The members are `subject`, `action`, `resource`, `usage` and `match`. An empty `when` matches each question. A question that no rule matches gets the answer from the directory. Without a directory, this is a fault of the case.

A `respond` gives a `body` and an optional `status`, or it has `no_answer`. The status is 200 by default.

## Steps

A step has an optional `name`, a `request` and an `expect`.

### Request

A request names its target in one way.

| Member | Role | Meaning |
| --- | --- | --- |
| `operation` | PEP | A kind of use of the service under test. The runner maps it to a request with its profile. |
| `endpoint` | PDP | `evaluation`, `evaluations` or `metadata`. |
| `method` and `path` | Any | An HTTP request that the case writes in full. |

A request can also have `headers`, `body` or `body_text`, and `token`. The member `token` names a token of `given.tokens`.

These are the operations. The list is closed. A new operation needs a change of the schema.

| Operation | Meaning |
| --- | --- |
| `use_plain` | One use of an action that lists no budget, on a node below the service. |
| `use_budget` | One use of an action that lists a budget, on a node below the service. |
| `use_ceiling` | One use of an action that lists a ceiling. |
| `use_service` | One use on the service itself. |
| `read_actions` | A read of the action document. |
| `list_options` | A read of the first level of the options route. |

### Expect

A step expects the members that it gives. The runner checks each one.

| Member | Meaning |
| --- | --- |
| `status` | The HTTP status of the answer. |
| `headers` | The headers of the answer. The names have no case. |
| `body_text` | The body as text. An empty body is the empty text. |
| `json` | Members of a JSON body. Each name is a JSON Pointer. |
| `pdp_questions` | For a PEP. The questions that the test PDP received during the step. |
| `upstream` | For an edge. The request that reached the service behind the edge. |

Each entry of `pdp_questions` has `json` and `count`. The runner counts the questions that match each matcher of `json`. It compares the count with `count`. Without `count`, the entry expects exactly one question. The entry `{"json": {}, "count": {"equals": 0}}` says that the PEP sent no question.

The member `upstream` can have `count`, `headers` and `token_claims`. The runner acts as the service behind the edge. It checks the identity token with the public keys of the test edge, and then it reads its claims.

## Matchers

A matcher checks one value. A matcher has exactly one member.

| Matcher | True when |
| --- | --- |
| `{"equals": V}` | The value is equal to the JSON value `V`. |
| `{"absent": true}` | The value does not exist. |
| `{"present": true}` | The value exists. |
| `{"regex": "R"}` | The value matches the expression `R`. The syntax is the one of the Rust crate `regex`. The match is not anchored. |
| `{"one_of": [V, W]}` | The value is equal to one item of the list. |

A regular expression reads a string. For a number, it reads the decimal text. For example, `{"regex": "^2[0-9]{2}$"}` matches each status from 200 to 299.

## Variables

A case can write a variable as `{{name}}` in a string or in the name of a member. The runner replaces it before it uses the value. A string that is exactly one variable gets the JSON value of the variable. This is how `{{ancestors}}` gives an array.

| Variable | Value |
| --- | --- |
| `service` | The id of the service under test. |
| `action` | The action of the operation of the step. |
| `resource_type` | The type of the node of the operation. |
| `resource_id` | The id of the node of the operation. |
| `ancestors` | The chain of the node of the operation, as an array. |
| `token_header` | The name of the header of the identity token. |
| `unknown_key_text` | A text that has the format of a key, and that the edge does not know. |
| `valid_key_text` | The text of a key that the edge accepts. |
| `valid_key_subject` | The subject id of that key. |
| `valid_key_owner` | The owner of that key. |

The first six variables come from the profile of the service under test. The last four come from the configuration of the run against an edge. The profile format and the configuration are the work of the tool `access-conformance`.

## Conditions to skip a case

The member `skip_if` lists conditions. The runner skips the case when one is true. A skipped case is not a failure.

| Condition | Meaning |
| --- | --- |
| `no_budget_action` | The service has no action that lists a budget. |
| `no_ceiling_action` | The service has no action that lists a ceiling. |
| `no_options_route` | The service does not publish the options route. |
| `no_answer_cache` | The PEP keeps no answer (protocol 10.1 says that it MAY). |
| `no_token_cache` | The edge keeps no identity token (protocol 9.9 says that it MAY). |
| `no_mcp_endpoint` | The service has no MCP endpoint. |

A case that uses `use_budget` must have `no_budget_action`. A case that uses `list_options` must have `no_options_route`. The checks enforce this rule.

## Add a case

1. Choose the series from the role. Take the next free number. Do not use an id of the MCP binding.
2. Write the title as one sentence in Simplified Technical English. State the rule, not the test.
3. Cite each paragraph that the case tests. Cite only a paragraph that has a rule.
4. Write `given`. Prefer a script for a PEP case. Prefer a directory file for a PDP case.
5. Write each step. Check only what the paragraph requires.
6. Run `scripts/cargo.sh test --workspace`. The tests check the case.

For a PDP case, the test `reference_pdp` in `crates/procurauth-core` also runs the case on a small reference PDP. Add the case to the same series. A case that the reference PDP cannot run is a case for a later feature. Then extend the reference PDP.

## Checks

The crate `schema-check` checks each file. A failed check names the case. These are the checks:

- the case is valid against the schema `conformance-case`;
- the id is the file name, and the directory is the series;
- the role fits the series, and no case uses an id of the MCP binding;
- each cited paragraph exists and is not unused;
- each regular expression compiles, and each variable is known;
- each token that a step uses exists, and each token is used;
- each directory file that a case names exists and is valid;
- each series has at least six cases.

Run the checks with `scripts/cargo.sh test -p procurauth-schema-check`.
