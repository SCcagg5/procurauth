# Coverage of the conformance cases

This file lists each paragraph that a role must follow, and the cases that test it.
A role is a PEP (series U), a PDP (series D) or an edge (series E).
The paragraphs come from protocol 1.3 and 15 (item 2), and from binding 1.4.
The second table lists the vectors of files that are not cases. The third table lists the rules that no case tests, with the reason.

Section 17 of the protocol is mandatory for a service (protocol 1.3, 5.2b). A PEP runs the cases that cite it, and the cases of the series U never have the condition `no_approval_support`. A PDP or an edge that gives no approval skips the cases of the series D and E that cite section 17, with this condition.

## How to read the tables

- The paragraph is a number of the protocol, for example `6.4`. The prefix `mcp:` names a paragraph of the MCP binding.
- The role is `pep`, `pdp` or `edge`.
- A row with the word `none` in the column Cases has at least one row in the table Not testable.
- A row can have cases and also a row in the table Not testable. The cases then test the other part of the paragraph.
- A test of the crate `schema-check` reads these tables. It checks the ids, the paragraphs and the roles.

## Cases for each paragraph

| Paragraph | Role | Cases |
| --- | --- | --- |
| 3.1 | pdp | D08 |
| 3.2 | pdp | D09, D10 |
| 3.3 | pdp | D07 |
| 3.4 | pdp | D12, D16 |
| 3.5 | pdp | D03, D14, D15, D32, D33, D74, D84 |
| 3.7 | pdp | D08, D09 |
| 3.8 | pdp | D11, D55, D70 |
| 3.9 | pdp | none |
| 4.1 | pdp | D17, D18, D19, D21, D22, D23, D24, D36, D75 |
| 4.2 | pdp | D25 |
| 4.3 | pdp | D01, D02, D14, D25, D26, D27, D28, D29, D30 |
| 4.4 | pdp | D04, D31, D32, D33, D34, D35, D60, D83 |
| 4.5 | pdp | none |
| 5.1 | pdp | none |
| 5.2 | pdp | D19, D20, D24 |
| 5.2a | pdp | none |
| 5.2b | pdp | D76 |
| 5.3 | pdp | none |
| 5.3a | pdp | none |
| 5.3b | pdp | none |
| 5.3c | pdp | D38 |
| 5.4 | pdp | none |
| 5.5 | pdp | D49, D64 |
| 5.5a | pdp | D72, D95, D96 |
| 6.1 | pdp | D46, D56, D94 |
| 6.2 | pdp | D49, D68 |
| 6.3 | pdp | D41, D42, D43, D44, D47, D48 |
| 6.4 | pdp | D58 |
| 6.5 | pdp | D06, D49, D50, D55, D61, D81 |
| 6.6 | pdp | D06, D51, D72 |
| 6.7 | pdp | D45, D53, D54, D55, D56 |
| 6.8 | pdp | none |
| 6.9 | pdp | D90 |
| 6.10 | pdp | D52, D57 |
| 6.11 | pdp | D59, D60, D61, D62 |
| 6.12 | pdp | D52, D54, D63, D77 |
| 7.1 | pdp | D64 |
| 7.3 | pdp | D01, D05, D64, D65, D66, D67, D68, D72, D94 |
| 7.4 | pdp | none |
| 7.5 | pdp | D68 |
| 7.6 | pdp | D73 |
| 8.1 | pdp | D05, D64, D70 |
| 8.2 | pdp | D57, D65, D71 |
| 8.3 | pdp | D22, D39, D69, D74 |
| 8.4 | pdp | D05, D53, D55, D70, D71 |
| 10.7 | pdp | D90 |
| 10.7a | pdp | D90 |
| 11.1 | pdp | D06, D07, D08, D09, D11, D12, D13, D17, D18, D19, D20, D21, D23, D35, D36, D37, D39, D40, D41, D42, D43, D44, D45, D46, D48, D56, D75, D76, D84, D88 |
| 11.2 | pdp | D02, D30, D73 |
| 12 | pdp | D16, D40, D53, D55 |
| 17.1 | pdp | D76, D77, D78, D79, D80, D83, D84, D85, D86, D87, D88, D89 |
| 17.2 | pdp | D77, D78, D81 |
| 17.3 | pdp | none |
| 17.4 | pdp | none |
| 17.4a | pdp | D91 |
| 17.5 | pdp | none |
| 17.6 | pdp | D80, D85, D86, D87 |
| 17.8 | pdp | D76, D82, D83, D92, D93, D95, D96 |
| 17.9 | pdp | none |
| 17.9a | pdp | none |
| 17.10 | pdp | none |
| 17.11 | pdp | none |
| 17.12 | pdp | D89 |
| 3.3 | pep | U01, U07, U08 |
| 3.4 | pep | U09 |
| 4.1 | pep | U02, U11, U70, U87 |
| 4.4 | pep | U12 |
| 4.5 | pep | none |
| 5.1 | pep | U13, U14, U15 |
| 5.2 | pep | U16 |
| 5.2a | pep | none |
| 5.2b | pep | U100, U111, U112 |
| 5.3c | pep | U17 |
| 5.4 | pep | none |
| 5.5 | pep | U34 |
| 5.5a | pep | U34, U35, U96 |
| 5.6 | pep | U05, U70, U71, U72, U74, U83 |
| 5.7 | pep | U71, U75, U76, U77, U78, U79, U80, U81, U82 |
| 5.8 | pep | U72, U73, U82 |
| 6.1 | pep | U16 |
| 6.2 | pep | U16 |
| 6.4 | pep | U04, U18, U19, U20, U22, U95 |
| 6.11 | pep | U24 |
| 6.12 | pep | U32, U33, U92 |
| 7.1 | pep | U17 |
| 7.3 | pep | U37 |
| 7.4 | pep | none |
| 7.5 | pep | U36, U37, U39, U92 |
| 7.6 | pep | U38 |
| 8.3 | pep | U40 |
| 9.3 | pep | U43, U44, U46, U47, U49 |
| 9.4 | pep | U03, U14, U41, U42, U43, U44, U45, U46, U47, U48, U49, U50, U51, U52, U53, U54, U75, U85, U99 |
| 9.5 | pep | U10 |
| 9.6 | pep | U01, U09 |
| 9.7 | pep | U55 |
| 10.0 | pep | U53, U56, U59 |
| 10.1 | pep | U15, U21, U22, U57, U58, U59, U83, U84, U101, U104 |
| 10.1a | pep | U34, U35 |
| 10.1b | pep | none |
| 10.2 | pep | U36, U37 |
| 10.3 | pep | U04, U06, U23, U32, U36, U58, U60, U61, U62, U63, U64, U65, U66, U67, U74, U90, U105, U113 |
| 10.6 | pep | U68 |
| 10.7 | pep | U69 |
| 10.7a | pep | none |
| 11.1 | pep | U04, U08, U61, U62, U63, U67, U105 |
| 11.2 | pep | U60 |
| 15 | pep | U84 |
| 17.1 | pep | U30, U102, U103, U107 |
| 17.2 | pep | U102 |
| 17.3 | pep | U103, U108 |
| 17.3a | pep | U103, U108, U111 |
| 17.4 | pep | U100, U101, U109 |
| 17.7 | pep | U30, U100, U101, U102, U104, U106, U110, U115, U116, U117 |
| 17.7a | pep | U113, U114 |
| 17.9 | pep | U107, U108 |
| 17.9a | pep | U103, U109 |
| 17.12 | pep | U105, U109, U110 |
| mcp:1.3 | pep | U25 |
| mcp:3.1 | pep | none |
| mcp:3.2 | pep | U87 |
| mcp:3.3 | pep | U27, U85 |
| mcp:3.3a | pep | U27, U86 |
| mcp:3.4 | pep | U18 |
| mcp:3.5 | pep | U18, U117 |
| mcp:3.5a | pep | U30 |
| mcp:3.6 | pep | U18 |
| mcp:3.6a | pep | U29, U95, U114 |
| mcp:3.7 | pep | U34, U35, U96, U97 |
| mcp:4.1 | pep | U26, U88 |
| mcp:4.2 | pep | U26, U89 |
| mcp:4.3 | pep | none |
| mcp:4.3a | pep | none |
| mcp:4.4 | pep | none |
| mcp:5.1 | pep | U23, U26, U28, U29, U89, U90, U91, U94, U97, U114 |
| mcp:5.1a | pep | U92 |
| mcp:5.1b | pep | U29, U31 |
| mcp:5.2 | pep | U27, U86 |
| mcp:5.3 | pep | U23, U93 |
| mcp:5.3a | pep | U93 |
| mcp:5.4 | pep | U23 |
| mcp:5.5 | pep | U28, U91 |
| mcp:5.6 | pep | U94 |
| mcp:5.6a | pep | U27, U86 |
| mcp:5.7 | pep | U30, U100, U115, U116 |
| mcp:5.7a | pep | U105, U116 |
| mcp:5.7b | pep | U106, U110 |
| mcp:7.1 | pep | none |
| mcp:7.2 | pep | none |
| mcp:7.3 | pep | U98, U99 |
| mcp:7.4 | pep | none |
| 1.4 | edge | E08 |
| 8.3 | edge | E10, E19 |
| 9.1 | edge | E05, E06, E11 |
| 9.2 | edge | E12 |
| 9.3 | edge | E07, E14 |
| 9.4 | edge | E13 |
| 9.8 | edge | E01, E02, E03, E04, E09, E10, E11, E17 |
| 9.9 | edge | E15, E16 |
| 17.8 | edge | E19 |
| mcp:6.1 | edge | E01, E17 |
| mcp:6.2 | edge | E01, E18 |
| mcp:6.3 | edge | E01, E17 |

## Vectors

A vector file is not a case. It has no role, and no runner reads it in this version. The ids V01 and V02 name two groups of vectors of one file.

| Id | Paragraph | File | Content |
| --- | --- | --- | --- |
| V01 | 17.3 | `vectors/effect.json` | Inputs that give a canonical JCS text and an effect: the order of members, nested objects, the UTF-16 order of names, escapes, the limits of the integers, empty values, no Unicode normalisation, the form of the resource, and the `op` of a read, of an empty `op` and of a navigation (17.3a). |
| V02 | 17.3 | `vectors/effect.json` | Inputs that a PEP and a PDP refuse with `invalid_op`: floats, the integers 2^53 and -(2^53), an integer of more than 64 bits, the text `-0` and an `op` that is not an object. |

## Not testable

| Paragraph | Role | Rule | Reason |
| --- | --- | --- | --- |
| 3.5 | pdp | The key loses a right at the first decision after its owner loses the right. | A case has no step that changes the directory between two questions. |
| 3.8 | pdp | The system that makes keys chooses the local part and the format of the text of a key. | The rule is for the system that makes keys. This version has no series for it (protocol 15, item 2). |
| 3.9 | pdp | A PDP that decides from a copy of its directory bounds the age of the copy, and it answers false for each key when the copy is older. | The runner cannot make a copy old, and a PDP can read its directory with no copy. |
| 4.5 | pdp | The PEP builds the chain from its own data. | The paragraph states a rule for the PEP only. |
| 5.1 | pdp | A service publishes its document at /.well-known/procurauth/actions, with no authentication. | The rule is for the service. A case cannot see the read of the document by the PDP. |
| 5.2 | pdp | The document has the members and the checks of 5.2. | The directory of a case holds good documents only. A case cannot send a bad document to the PDP. |
| 5.2a | pdp | A service publishes only the actions that it serves. | The rule is for the service. A case cannot see the configuration of the service or the actions that it serves. |
| 5.3 | pdp | A bad document, or a failed read, keeps the last good document. | A case cannot make a service publish a bad document or fail a read. |
| 5.3a | pdp | The reader gives its maximum time in its documentation. | The rule is about documentation, and a case cannot wait for a long time. |
| 5.3b | pdp | A reader that reads at a fixed period spreads the reads at equal intervals. | A case cannot see the time of the reads of the PDP. The level of the rule is SHOULD. |
| 5.3c | pdp | A reader MAY accept more than the numbers of the rule. | The sentence gives a permission, not a requirement. |
| 5.4 | pdp | The labels and the descriptions are in English. | A program cannot check the language of a text. The rule is for the service. |
| 5.5 | pdp | A service MUST NOT ask two actions with context.usage for one operation. | The sentence states a rule for the PEP. The PDP part of the paragraph has cases. |
| 6.8 | pdp | A PDP with several instances counts each counter one time for all of them. | A case needs several instances of the PDP, and the runner sees one endpoint. |
| 6.9 | pdp | When the PDP cannot read or change a counter, it answers HTTP 503. | A case cannot make the store of the counters fail. The case D90 tests the published time. |
| 7.1 | pdp | A service MUST NOT declare a ceiling where a higher value is stricter. | The rule is for the document of the service. The lowest value of 8.1 depends on it, and its cases cover that part. |
| 7.4 | pdp | A ceiling applies to each use of the action, on each route of the service. | The sentence states a rule for the PEP. |
| 7.5 | pdp | A PEP that cannot apply a ceiling treats the answer as false. | The sentence states a rule for the PEP. The PDP part of the paragraph has cases. |
| 11.1 | pdp | A retry_after of 11.2 seconds gives 12. | The clock of a case has whole seconds, so the time to the end of a window has no fraction. |
| 12 | pdp | The credential of each service SHOULD have at least 128 random bits. The PDP SHOULD keep only its SHA-256 digest. | A case cannot see the credential or the way that the PDP stores it. |
| 12 | pdp | The PDP is a single point of failure, and the protocol accepts it. | The sentence is a remark. It states no rule for a case. |
| 12 | pdp | A client that sends a request again makes a new use, and the PDP counts it again. | The PDP cannot tell a request that a client sends again from a new request. |
| 17.3 | pdp | The PDP computes the effect as 17.3 gives. | The groups V01 and V02 of the vectors test this paragraph. A step of a case has no way to send a bad `op` to the PDP. |
| 17.4 | pdp | The PDP serves the narrow API with three routes, and only these routes. | A case has no endpoint for the approval API in this version. The tests of a PDP that gives approvals cover the routes. |
| 17.5 | pdp | The lease, the abandon, the end of a request and the revival of a request. | A case cannot make time pass during a request, and it has no step that answers or renews a request. |
| 17.6 | pdp | The PDP sets consume_before and the deny time from its own settings. The consume window is not shorter than lease_s. | The settings of the PDP give both times. The cases D80 and D85 test the end of each window. |
| 17.9 | pdp | The PDP checks each submission before it keeps it. A `view` has optional members, and `{}` is valid. | A case has no endpoint for the approval API in this version. The tests of `fake-pdp` cover a `view` with a title only and the object `{}`. |
| 17.9a | pdp | The explanation never enters the effect, and the PEP never sees it. | The agent gives the explanation to the PDP by a channel outside this protocol. A case has no step on that channel. |
| 17.10 | pdp | A PDP SHOULD encrypt the body at rest, delete it after a published time, and never write it in a log. | A case cannot see the storage or the logs of the PDP. The level of the rule is SHOULD. |
| 17.11 | pdp | The PDP accepts an answer only from the owner, with shown_effect equal to the effect. A refusal can have a text. | The answer of a person is outside the protocol. A case has no step that answers an approval. |
| 17.12 | pdp | The PDP gives the PEP the verdict, the id and the code only, through the approval API. | A case has no endpoint for the approval API in this version. The case D89 tests the evaluation API. |
| 4.1 | pep | The PEP does not encode an id. | The runner cannot choose the id of a node. The service decides its nodes. |
| 4.5 | pep | The PEP builds the chain from its own data and never takes it from a client. | A case cannot know where a service could read a chain from a client. The case U02 shows that the chain is equal to the data of the service. |
| 5.2 | pep | The service percent-encodes each id of a path. | The core reader checks this rule in the cases that give valid_as. The rule needs a node with a special character in its id. |
| 5.2a | pep | A service publishes only the actions that it serves. | A case cannot see the configuration of the service or the actions that it serves. The test of a service tool can compare its document with its routes. |
| 5.4 | pep | The labels and the descriptions are in English. | A program cannot check the language of a text. |
| 5.6 | pep | The service SHOULD bound the number of questions to the PDP for one request. | A case needs a node with many children that the subject cannot see, and the runner does not know the data of the service. |
| 5.6 | pep | The service MAY apply its own rules that remove more children. | The sentence gives a permission, not a requirement. |
| 5.7 | pep | The service decodes each %XX one time and does not read + as a space. A node that does not exist gets an answer with no items. | The rules depend on the nodes of the service. The runner knows only the type of the first level. |
| 5.8 | pep | The service does not encode the id of an item. | The runner cannot choose the id of a node. |
| 6.1 | pep | A name has the meaning that the paragraph gives: a plural noun for a budget, with no unit and no window. | A program cannot check the meaning of a name. |
| 6.2 | pep | To count one action separately, the service declares a second budget. | The sentence gives a design rule. The effect depends on the service. |
| 7.1 | pep | A service MUST NOT declare a ceiling where a higher value is stricter. | A program cannot judge the meaning of a ceiling. |
| 7.3 | pep | For a use of an action that lists a budget, the PEP applies the context.limits of the answer to the question with context.usage. | The effect of a ceiling depends on the function of the service. A case cannot see it. |
| 7.4 | pep | A ceiling applies to each use of the action, on each route of the service. | A case cannot see the effect of a ceiling. |
| 7.5 | pep | The PEP applies each ceiling that it understands. | A case cannot see the effect of a ceiling. The cases test the ceiling that the PEP cannot apply. |
| 9.4 | pep | The service MUST accept requests only through the edge. | The rule is a network rule. The runner acts as the edge, so it cannot make a request that goes around the edge. |
| 9.4 | pep | The skew also applies to exp: a token past exp by less than the skew is valid. | The runner does not know the clock skew of the service. |
| 9.4 | pep | The service can answer a read of the action document directly to the reader that the operator names. | The sentence gives a permission, not a requirement. |
| 9.7 | pep | A service MAY keep the result of a token check until the exp of the token. | The sentence gives a permission, not a requirement. |
| 10.0 | pep | The PEP gets the values from the operator, and it gives the operator the id of the service and the origin of its document. | The rule is about the configuration of the service. A case cannot see it. |
| 10.0 | pep | The PEP MUST secure the link to the PDP by adequate means, for example TLS. | The test PDP of the runner can use a plain link. A case cannot check the security of the link. |
| 10.1 | pep | The PEP MAY keep answers for cache_ttl at most. | The runner does not know cache_ttl, and a case cannot wait for it. |
| 10.1b | pep | The PEP bounds the number of kept answers, and it keeps no new answer when the table is full. | A case cannot see the memory of the PEP. |
| 10.2 | pep | The PEP applies the ceilings as 7.3 and 7.5 say. | A case cannot see the effect of a ceiling. The cases for 7.5 test the part that is visible. |
| 10.6 | pep | The PEP SHOULD wait for each answer longer than the longest time that the PDP publishes. | The model gives the test PDP no published time. |
| 10.7 | pep | The PEP closes an idle connection before the PDP does, after half of the idle time or less. | The model gives the test PDP no idle time. |
| 10.7a | pep | The PEP sends its questions in requests within the maxima of the PDP, and it splits them when necessary. | A case needs a service with more actions than the maximum of the test PDP. |
| 11.1 | pep | The PEP reads the reason invalid_request only in an item of an Access Evaluations answer. | The service decides when it sends a request with items. A case cannot make it send one. |
| 17.1 | pep | The PEP never reads the evaluation_id. | A case cannot see what the PEP reads. |
| 17.4 | pep | The PEP sends the credential of the service to the approval API. | The test PDP of the runner accepts any credential on its approval API. |
| 17.7 | pep | The PEP never reads an approval_ref or an intent. | A case cannot see what the PEP reads. |
| 17.3a | pep | The `op` of a call names the operation, has no value that changes at each call, and the PEP never cuts or hides a part of it. | A case cannot see how the PEP builds `op`. The case U108 compares the effect with the `op` of the profile. |
| 17.3a | pep | The size of `op` and `view` is not more than `max_command_bytes`. | The runner does not know the bound of the PDP. A PDP that gets a larger command answers 413 `command_too_large`, and the PEP gives the tool error `invalid_argument`. |
| 17.7a | pep | A person with an interactive session gets HTTP 403 with the code `approval_cannot_wait`. | The runner sends one identity token for a subject, and the PEP does not see a session. The cases U113 and U114 test the call that cannot wait for any subject. |
| 17.9 | pep | The PEP sends op, view and effect only in a submission, with the sizes that the PDP allows. | The runner does not know the largest size of the PDP. The cases U107 and U108 test the places and the pointers. |
| mcp:3.1 | pep | The service does the MCP work: the endpoint, the map of the tools, the list of the tools and the approvals. | The sentence is a summary. Each rule has its own paragraph with cases. |
| mcp:3.2 | pep | The map of the tools is not in the MCP messages. | A case cannot read the map of the service. |
| mcp:4.1 | pep | The service sends the questions of a tools/list in one Access Evaluations request. | The model counts questions, not requests. |
| mcp:4.3 | pep | For one subject, two requests give the same list while the answers of the PDP do not change. | A case cannot compare the answers of two steps. |
| mcp:4.3a | pep | The schema and the description of each tool in `tools/list` tell the control arguments and the retry. | The text is free, and a matcher cannot judge it. The runner reads no description. |
| mcp:4.4 | pep | The paragraph gives an example of the load on the PDP. | The paragraph is informative. It states no rule. |
| mcp:5.7 | pep | The service waits at most wait_s seconds for a verdict, and it bounds wait_s. | The bound is a setting of the service, and a case cannot wait. |
| mcp:5.7a | pep | The codes approval_unavailable, approval_rate_limited and invalid_argument, and HTTP 503 for another answer of the approval API. | A case for each one needs a step for each answer of the approval API. This version tests the codes that follow a reason of the PDP (U105). |
| mcp:7.1 | pep | For a request with a standalone key, the service asks the PDP no question. | The profile of the service under test has no standalone key in this version. |
| mcp:7.2 | pep | The text of a standalone key is mcp_ and 43 base64url characters. | The profile of the service under test has no standalone key in this version. |
| mcp:7.4 | pep | For a standalone key, the 401 and the 429 have an empty body, and the 429 has Retry-After. | The profile of the service under test has no standalone key in this version. |
| 1.4 | edge | This version defines no OAuth flow, and it has no hosted client. | The sentence says what the version does not define. A case cannot test an absent feature. |
| 9.2 | edge | The operator sets the life of the token (exp minus iat) to no more than the maximum age of each service. | The runner does not know the maximum age, and a matcher has no arithmetic. |
| 9.2 | edge | The edge uses its signing key only for the identity token. | A case cannot see the use of a key. |
| 9.4 | edge | The edge gives its public keys as a JWK Set. | The place of the key set is part of the configuration of the run. The runner reads it to check the tokens, so each case with a token tests it. |
| 9.9 | edge | A kept token is given only before its exp, and the edge bounds the number of kept tokens. | A case cannot wait for exp, and it cannot see the memory of the edge. |
| 9.9 | edge | An edge MAY keep an identity token that it made. | The sentence gives a permission, not a requirement. |

