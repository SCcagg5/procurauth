# Coverage of the conformance cases

This file lists each paragraph that a role must follow, and the cases that test it.
A role is a PEP (series U), a PDP (series D) or an edge (series E).
The paragraphs come from protocol 1.3 and 15 (item 2), and from binding 1.4.
The second table lists the rules that no case tests, with the reason.

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
| 3.5 | pdp | D03, D14, D15, D32, D33, D74 |
| 3.7 | pdp | D08, D09 |
| 3.8 | pdp | D11, D55, D70 |
| 3.9 | pdp | none |
| 4.1 | pdp | D17, D18, D19, D21, D22, D23, D24, D36 |
| 4.2 | pdp | D25 |
| 4.3 | pdp | D01, D02, D14, D25, D26, D27, D28, D29, D30 |
| 4.4 | pdp | D04, D31, D32, D33, D34, D35, D60 |
| 4.5 | pdp | none |
| 5.1 | pdp | none |
| 5.2 | pdp | D19, D20, D24 |
| 5.3 | pdp | none |
| 5.3a | pdp | none |
| 5.3b | pdp | none |
| 5.3c | pdp | D38 |
| 5.4 | pdp | none |
| 5.5 | pdp | D49, D64 |
| 5.5a | pdp | D72 |
| 6.1 | pdp | D46, D56 |
| 6.2 | pdp | D49, D68 |
| 6.3 | pdp | D41, D42, D43, D44, D47, D48 |
| 6.4 | pdp | D58 |
| 6.5 | pdp | D06, D49, D50, D55, D61 |
| 6.6 | pdp | D06, D51, D72 |
| 6.7 | pdp | D45, D53, D54, D55, D56 |
| 6.8 | pdp | none |
| 6.9 | pdp | none |
| 6.10 | pdp | D52, D57 |
| 6.11 | pdp | D59, D60, D61, D62 |
| 6.12 | pdp | D52, D54, D63 |
| 7.1 | pdp | D64 |
| 7.3 | pdp | D01, D05, D64, D65, D66, D67, D68, D72 |
| 7.4 | pdp | none |
| 7.5 | pdp | D68 |
| 7.6 | pdp | D73 |
| 8.1 | pdp | D05, D64, D70 |
| 8.2 | pdp | D57, D65, D71 |
| 8.3 | pdp | D22, D39, D69, D74 |
| 8.4 | pdp | D05, D53, D55, D70, D71 |
| 10.7 | pdp | none |
| 10.7a | pdp | none |
| 11.1 | pdp | D06, D07, D08, D09, D11, D12, D13, D17, D18, D19, D20, D21, D35, D36, D37, D39, D40, D41, D42, D43, D44, D45, D46, D48, D56 |
| 11.2 | pdp | D02, D30, D73 |
| 12 | pdp | D16, D40, D53, D55 |
| 3.3 | pep | U01, U07, U08 |
| 3.4 | pep | U09 |
| 4.1 | pep | U02, U11, U70, U87 |
| 4.4 | pep | U12 |
| 4.5 | pep | none |
| 5.1 | pep | U13, U14, U15 |
| 5.2 | pep | U16 |
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
| 10.1 | pep | U15, U21, U22, U57, U58, U59, U83, U84 |
| 10.1a | pep | U34, U35 |
| 10.1b | pep | none |
| 10.2 | pep | U36, U37 |
| 10.3 | pep | U04, U06, U23, U32, U36, U58, U60, U61, U62, U63, U64, U65, U66, U67, U74, U90 |
| 10.6 | pep | U68 |
| 10.7 | pep | U69 |
| 10.7a | pep | none |
| 11.1 | pep | U04, U08, U61, U62, U63, U67 |
| 11.2 | pep | U60 |
| 15 | pep | U84 |
| mcp:1.3 | pep | U25 |
| mcp:3.1 | pep | none |
| mcp:3.2 | pep | U87 |
| mcp:3.3 | pep | U27, U85 |
| mcp:3.3a | pep | U27, U86 |
| mcp:3.4 | pep | U18 |
| mcp:3.5 | pep | U18 |
| mcp:3.5a | pep | U30 |
| mcp:3.6 | pep | U18 |
| mcp:3.6a | pep | U29, U95 |
| mcp:3.7 | pep | U96, U97 |
| mcp:4.1 | pep | U26, U88 |
| mcp:4.2 | pep | U26, U89 |
| mcp:4.3 | pep | none |
| mcp:4.4 | pep | none |
| mcp:5.1 | pep | U23, U26, U28, U29, U89, U90, U91, U94, U97 |
| mcp:5.1a | pep | U92 |
| mcp:5.1b | pep | U29, U31 |
| mcp:5.2 | pep | U27, U86 |
| mcp:5.3 | pep | U23, U93 |
| mcp:5.3a | pep | U93 |
| mcp:5.4 | pep | U23 |
| mcp:5.5 | pep | U28, U91 |
| mcp:5.6 | pep | U94 |
| mcp:5.6a | pep | U27, U86 |
| mcp:7.1 | pep | none |
| mcp:7.2 | pep | none |
| mcp:7.3 | pep | U98, U99 |
| mcp:7.4 | pep | none |
| 1.4 | edge | E08 |
| 8.3 | edge | E10 |
| 9.1 | edge | E05, E06, E11 |
| 9.2 | edge | E12 |
| 9.3 | edge | E07, E14 |
| 9.4 | edge | E13 |
| 9.8 | edge | E01, E02, E03, E04, E09, E10, E11, E17 |
| 9.9 | edge | E15, E16 |
| mcp:6.1 | edge | E01, E17 |
| mcp:6.2 | edge | E01, E18 |
| mcp:6.3 | edge | E01, E17 |

## Not testable

| Paragraph | Role | Rule | Reason |
| --- | --- | --- | --- |
| 3.5 | pdp | The key loses a right at the first decision after its owner loses the right. | A case has no step that changes the directory between two questions. |
| 3.8 | pdp | The system that makes keys chooses the local part and the format of the text of a key. | The rule is for the system that makes keys. This version has no series for it (protocol 15, item 2). |
| 3.9 | pdp | A PDP that decides from a copy of its directory bounds the age of the copy, and it answers false for each key when the copy is older. | The runner cannot make a copy old, and a PDP can read its directory with no copy. |
| 4.5 | pdp | The PEP builds the chain from its own data. | The paragraph states a rule for the PEP only. |
| 5.1 | pdp | A service publishes its document at /.well-known/procurauth/actions, with no authentication. | The rule is for the service. A case cannot see the read of the document by the PDP. |
| 5.2 | pdp | The document has the members and the checks of 5.2. | The directory of a case holds good documents only. A case cannot send a bad document to the PDP. |
| 5.3 | pdp | A bad document, or a failed read, keeps the last good document. | A case cannot make a service publish a bad document or fail a read. |
| 5.3a | pdp | The reader gives its maximum time in its documentation. | The rule is about documentation, and a case cannot wait for a long time. |
| 5.3b | pdp | A reader that reads at a fixed period spreads the reads at equal intervals. | A case cannot see the time of the reads of the PDP. The level of the rule is SHOULD. |
| 5.3c | pdp | A reader MAY accept more than the numbers of the rule. | The sentence gives a permission, not a requirement. |
| 5.4 | pdp | The labels and the descriptions are in English. | A program cannot check the language of a text. The rule is for the service. |
| 5.5 | pdp | A service MUST NOT ask two actions with context.usage for one operation. | The sentence states a rule for the PEP. The PDP part of the paragraph has cases. |
| 6.8 | pdp | A PDP with several instances counts each counter one time for all of them. | A case needs several instances of the PDP, and the runner sees one endpoint. |
| 6.9 | pdp | When the PDP cannot read or change a counter, it answers HTTP 503. It publishes the longest time of an answer. | A case cannot make the store of the counters fail. The PDP can publish the time in its documentation. |
| 7.1 | pdp | A service MUST NOT declare a ceiling where a higher value is stricter. | The rule is for the document of the service. The lowest value of 8.1 depends on it, and its cases cover that part. |
| 7.4 | pdp | A ceiling applies to each use of the action, on each route of the service. | The sentence states a rule for the PEP. |
| 7.5 | pdp | A PEP that cannot apply a ceiling treats the answer as false. | The sentence states a rule for the PEP. The PDP part of the paragraph has cases. |
| 10.7 | pdp | The PDP publishes the longest time that it keeps an idle connection open. | The PDP can publish the time in its documentation. A case cannot read it. |
| 10.7a | pdp | The PDP publishes the largest body and the largest number of items of one Access Evaluations request. | The PDP can publish the values in its documentation. A case cannot read them. |
| 11.1 | pdp | A retry_after of 11.2 seconds gives 12. | The clock of a case has whole seconds, so the time to the end of a window has no fraction. |
| 12 | pdp | The credential of each service SHOULD have at least 128 random bits. The PDP SHOULD keep only its SHA-256 digest. | A case cannot see the credential or the way that the PDP stores it. |
| 12 | pdp | The PDP is a single point of failure, and the protocol accepts it. | The sentence is a remark. It states no rule for a case. |
| 12 | pdp | A client that sends a request again makes a new use, and the PDP counts it again. | The PDP cannot tell a request that a client sends again from a new request. |
| 4.1 | pep | The PEP does not encode an id. | The runner cannot choose the id of a node. The service decides its nodes. |
| 4.5 | pep | The PEP builds the chain from its own data and never takes it from a client. | A case cannot know where a service could read a chain from a client. The case U02 shows that the chain is equal to the data of the service. |
| 5.2 | pep | The service percent-encodes each id of a path. | The core reader checks this rule in the cases that give valid_as. The rule needs a node with a special character in its id. |
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
| mcp:3.1 | pep | The service does the MCP work: the endpoint, the map of the tools, the list of the tools and the approvals. | The sentence is a summary. Each rule has its own paragraph with cases. |
| mcp:3.2 | pep | The map of the tools is not in the MCP messages. | A case cannot read the map of the service. |
| mcp:4.1 | pep | The service sends the questions of a tools/list in one Access Evaluations request. | The model counts questions, not requests. |
| mcp:4.3 | pep | For one subject, two requests give the same list while the answers of the PDP do not change. | A case cannot compare the answers of two steps. |
| mcp:4.4 | pep | The paragraph gives an example of the load on the PDP. | The paragraph is informative. It states no rule. |
| mcp:7.1 | pep | For a request with a standalone key, the service asks the PDP no question. | The profile of the service under test has no standalone key in this version. |
| mcp:7.2 | pep | The text of a standalone key is mcp_ and 43 base64url characters. | The profile of the service under test has no standalone key in this version. |
| mcp:7.4 | pep | For a standalone key, the 401 and the 429 have an empty body, and the 429 has Retry-After. | The profile of the service under test has no standalone key in this version. |
| 1.4 | edge | This version defines no OAuth flow, and it has no hosted client. | The sentence says what the version does not define. A case cannot test an absent feature. |
| 9.2 | edge | The operator sets the life of the token (exp minus iat) to no more than the maximum age of each service. | The runner does not know the maximum age, and a matcher has no arithmetic. |
| 9.2 | edge | The edge uses its signing key only for the identity token. | A case cannot see the use of a key. |
| 9.4 | edge | The edge gives its public keys as a JWK Set. | The place of the key set is part of the configuration of the run. The runner reads it to check the tokens, so each case with a token tests it. |
| 9.9 | edge | A kept token is given only before its exp, and the edge bounds the number of kept tokens. | A case cannot wait for exp, and it cannot see the memory of the edge. |
| 9.9 | edge | An edge MAY keep an identity token that it made. | The sentence gives a permission, not a requirement. |

