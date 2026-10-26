# ProcurAuth MCP Binding

Version 1.0
This document holds the rules of the ProcurAuth protocol [PROTOCOL] that only MCP needs.

The changelog in `docs/` of the repository gives the changes of each version.

A paragraph keeps its number in later versions. A paragraph that leaves this document keeps its number, with the word "Unused" and a pointer. A new paragraph gets a new number, or a letter after the number of the paragraph that it continues.

This document is the MCP binding of the protocol. Its place is `bindings/mcp/` in the repository of this specification.
It names no product, and any product can use it.

In this document, "protocol N.M" is paragraph N.M of [PROTOCOL], and "protocol N" is section N of [PROTOCOL]. "protocol 2, Key" is the term Key in section 2. This binding cites the rules of the protocol and does not restate them.

The words MUST, MUST NOT, SHOULD and MAY have the meaning of [RFC 2119] and [RFC 8174].

## 1. Introduction
1.1 This binding applies to a service with an MCP endpoint that follows the protocol (protocol 1.3). It also applies to an edge in front of such a service. It gives:
- the work of the service for the MCP methods (section 3) and the list of the tools (section 4);
- the form of a refusal of a service (section 5) and of a refusal of an edge (section 6);
- the standalone keys of a service without an edge (section 7).

1.2 A service without an MCP endpoint does not need this binding. The protocol gives its refusals (protocol 10.3).

1.3 This binding is for the MCP revision 2026-07-28 [MCP 2026-07-28]. A request of this revision has `params._meta["io.modelcontextprotocol/protocolVersion"]` [CONTRACT, 2.5]. A service can also accept the legacy revisions of [CONTRACT, 2.4]. The rules of this binding apply to each revision, except where a paragraph names one revision.

1.4 A service with an MCP endpoint conforms to this binding when it follows 1.3, sections 3 to 5 and 7.3. An edge in front of an MCP endpoint conforms when it follows section 6. A service that checks standalone keys follows section 7. The cases of section 9 test a service and an edge.

1.5 This binding adds no member to the questions and the answers of the protocol (protocol 1.2). It adds no field to an MCP message [CONTRACT, 0.3]. It gives only the MCP form of the rules of the protocol.

## 2. Terms
The terms of protocol section 2 apply. This binding adds these terms:
- **MCP endpoint**: the route of a service that receives MCP requests, for example `POST /mcp` [CONTRACT, 2.1].
- **MCP request**: one JSON-RPC request that a client sends to the MCP endpoint.
- **Tool**: a tool of the service, which `tools/list` names and `tools/call` runs [MCP 2026-07-28].
- **Tool error**: a result of `tools/call` with `isError` true, which MCP calls a tool execution error [MCP 2026-07-28, tools]. It is not a JSON-RPC error.
- **Map of the tools**: the table of the service that gives each tool its action and the arguments that name its resource (3.2).
- **Standalone key**: a key that a service checks by itself, with no edge (section 7). It is not a key of the protocol (protocol 2, Key).

## 3. The work of the service
3.1 The service does the MCP work: the MCP endpoint, the map of the tools, the list of the tools and the approvals of the actions [CONTRACT, section 9]. The service is the PEP of each tool (protocol 1.3). The edge decides only the action `access` on the service (protocol 8.3). It answers no MCP method.

3.2 The map of the tools gives each tool one action of the action document (protocol 5.2). The arguments of a call name the resource of the call. The service builds the chain of this resource from its own data (protocol 4.1, 4.5). The map is not in the MCP messages (1.5).

3.3 The MCP endpoint accepts the identity token, as each other route does (protocol 10.0, step 2). The service checks the token on each MCP request, for each method (protocol 9.4). A request with no token, or with a token that is not valid, gets HTTP 401 with an empty body (3.3a).

3.3a The check of the token takes the place of the check of the key in the order of [CONTRACT, 2.8]. It comes after the checks of `Origin` and of the client address, and before the service reads the message. Thus the service sends the 401 of 3.3 before it reads the `id`, with an empty body (5.6a).

3.4 A `tools/call` is one operation (protocol 2). When the tool runs, the call is one use of the action of the tool. For an action that lists a budget, the service sends one question with `context.usage` for this use (protocol 6.4).

3.5 A call that only asks the client for input (MCP `InputRequiredResult`) is not a use. For this call, the service asks the action of the tool without `context.usage` (protocol 6.6, 10.1). The later call that gives the input and runs the tool is the use of 3.4. For an action that lists a budget, a kept `true` answer of the first call never starts this use (protocol 10.1).

3.5a A tool with an effect gives an action that waits for an approval [CONTRACT, 9.4]. At the call, the service asks this action without `context.usage` (protocol 6.6, 10.1). After the approval, at the run, the service sends the question of 3.4 with `context.usage`. A refused approval takes no unit.

3.6a A request for an MCP method with no tool asks the action `mcp.session` on the resource of type `service` with the id of the service (protocol 4.1). Such methods are `initialize`, `ping`, `server/discover` and the notifications. The service declares the action `mcp.session` in its action document (protocol 5.2). When this action lists a budget, each such request is one use (protocol 6.4).

3.6 A `tools/list` is not a use. Its questions are questions for a display (protocol 2, Use), and section 4 gives them.

3.7 A tool can need permissions on other actions or on other resources (protocol 5.5a). The service asks them as protocol 10.1a shows, with `context.usage` only for the action of the tool. When one answer is `false`, the service refuses the call as 5.1 says. Section 10 gives an example.

## 4. The list of the tools
4.1 For `tools/list`, the service names only the tools whose action the PDP lets the subject do in the service. For each tool, it asks the action of the tool on the service, with `context.match` = `subtree` (protocol 4.4). It asks these questions without `context.usage`, with one item for each action of its tools, not for each tool. It sends them in one Access Evaluations request, or in several requests when the items are above the maxima of the PDP (protocol 6.6, 6.11, 10.7a). It names a tool when the answer for the action of the tool is `true`.

4.2 A `true` answer of 4.1 is for the display only (protocol 4.4). Each `tools/call` asks its own question (3.4). A tool that `tools/list` does not name and a tool that the service does not have get the same refusal (5.1).

4.3 The service keeps the order of the tools of [CONTRACT, 4.2], without the tools that 4.1 removes. For one subject, two requests give the same list while the answers of the PDP do not change. The service MAY keep the answers of 4.1 for `cache_ttl` at most (protocol 10.1).

4.4 For one `tools/list`, tools with the same action share one item (4.1), so the items are not more than the actions of the action document (protocol 5.3c). Example: with 20 actions and one `tools/list` each minute on each service, the PDP gets approximately 17 requests (333 items) each second for 1,000 services. For 10,000 services, it gets approximately 167 requests (3,333 items) each second. The kept answers of 4.3 take one entry for each subject and action of one service. For 1,000 subjects and 20 actions, they take 20,000 entries, approximately 2 MB at 100 bytes each. This number is the same for 1,000 and for 10,000 services.

## 5. Refusals of a service
5.1 Protocol 10.3 applies to an MCP request: the service fails closed and sends no `context.reason` to the client. The one exception is the code `budget_exceeded` in the tool error of 5.3. The service maps each answer of the PDP as the list below shows:
- `false` with no reason, or with a reason other than `budget_exceeded`: on `tools/call`, HTTP 200 and the JSON-RPC error `-32602`, as for an unknown tool [CONTRACT, 3.6]. On another MCP request, HTTP 403 with the body of 5.1b.
- `false` with `budget_exceeded`: on `tools/call`, HTTP 200 and the tool error of 5.3. On another MCP request, HTTP 429 with `Retry-After`, and the JSON-RPC error of 5.4.
- No answer, an HTTP error, or an answer that is not valid: HTTP 503 and the JSON-RPC error of 5.5.

5.1a A `true` answer that the service treats as `false` (protocol 6.12, 7.5) gets the refusal of a `false` answer with no reason. A kept `false` answer (protocol 10.1) gets the refusal of the same answer. For a kept answer with `budget_exceeded`, `retry_after` has the value that protocol 10.1 gives.

5.1b On an MCP request other than `tools/call`, the HTTP 403 of 5.1 has the body of the JSON-RPC error `-32001` with the message `forbidden`. The error has no `data`. Example: `{"jsonrpc": "2.0", "id": 7, "error": {"code": -32001, "message": "forbidden"}}`. The code is the code that COAZ-MCP gives to each denial (section 11). The service sends this body only when it knows the `id` (5.6a).

5.2 The service sends each HTTP 401 before it reads the `id` of the MCP request (3.3a, 7.4). Thus the body of the 401 is empty (5.6a).

5.3 On `tools/call`, a `false` answer with `budget_exceeded` gives a tool error, not a JSON-RPC error. The tool error has the code `budget_exceeded`, `retryable` true, and `retry_after` with the seconds that protocol 10.3 gives to `Retry-After`. The service writes a fixed message and copies no value of the request. `content[0].text` holds `structuredContent` as compact JSON [CONTRACT, 5.1, 6.1]. For a request of revision 2026-07-28, the result also has `resultType` `complete` [CONTRACT, 2.5]. The result has this form:
```json
{ "resultType": "complete",
  "content": [ { "type": "text", "text": "{\"error\":{\"code\":\"budget_exceeded\",\"message\":\"The budget of this action is spent.\",\"retryable\":true,\"retry_after\":12}}" } ],
  "structuredContent": { "error": { "code": "budget_exceeded", "message": "The budget of this action is spent.", "retryable": true, "retry_after": 12 } },
  "isError": true }
```

5.3a This binding adds the code `budget_exceeded` to the common codes of a tool error of [CONTRACT, 6.2] (section 12, item 3). It tells that a budget of the action is spent, and it is retryable.

5.4 On an MCP request other than `tools/call`, a `false` answer with `budget_exceeded` gives HTTP 429 with `Retry-After` (protocol 10.3). The body is the JSON-RPC error `-31429` with the message `rate_limited`. Its `data.retry_after` has the value of `Retry-After`. Example: `{"jsonrpc": "2.0", "id": 7, "error": {"code": -31429, "message": "rate_limited", "data": {"retry_after": 12}}}`.

5.5 When the service gives HTTP 503 (protocol 10.3), the body is the JSON-RPC error `-32603`, with a fixed message. A request that the client sends again is a new use (protocol 12).

5.6 Each error of this section has a fixed message, and the service copies no value of the request into it [CONTRACT, 5.2].

5.6a When the service refuses an MCP request before it reads the `id`, the body of the answer is empty, as for an edge (6.1). The client reads the HTTP status and the headers. The service sends a JSON-RPC error only when it knows the `id` of the request.

## 6. Refusals of an edge
6.1 When an edge refuses an MCP request, the body of the answer is empty, for each status. The client reads the HTTP status and the headers: `WWW-Authenticate` on a 401 (protocol 9.8) and `Retry-After` on a 429. The edge sends no JSON-RPC error, so it needs no part of the body of the request. Only a service that answers by itself uses the JSON-RPC errors of section 5.

6.2 An edge never answers 400, 404 or 405 to an MCP request. A client of revision 2026-07-28 that gets one of these statuses uses the legacy transport [MCP 2026-07-28].

6.3 The 401 of an edge that refuses a key (protocol 9.8) has no parameter `resource_metadata` in `WWW-Authenticate`. The edge for the keys is not MCP authorization. This version of the protocol defines no OAuth flow (protocol 1.4).

## 7. Standalone keys
7.1 A service that has no edge can check its own keys: the standalone keys of [CONTRACT, section 3]. A standalone key is not a key of the protocol (protocol 2, Key). For a request with a standalone key, the service asks the PDP no question [CONTRACT, 11.1].

7.2 The text of a standalone key is `mcp_`, then 43 base64url characters, with no `=` at the end: 47 characters in total [CONTRACT, 3.1]. The 43 characters encode 32 random bytes.

7.3 A service behind an edge accepts requests only through the edge (protocol 9.4). It takes the subject only from the identity token, and it does not check a standalone key (7.1). The limits of a standalone key [CONTRACT, 3.8, 3.9] do not apply to a request with an identity token. The own limits of the service still apply (protocol 6.10).

7.4 For a standalone key, the service sends the 401 and the 429 of [CONTRACT, 2.7] before it reads the message [CONTRACT, 2.8]. Thus their body is empty (5.6a). The 429 has `Retry-After` [CONTRACT, 2.7].

7.5 Unused. The system that makes keys chooses the format of their text, because the protocol defines no format (protocol 3.8).

## 8. Security considerations
- An MCP client can send a request again after a broken stream. No rule of MCP 2026-07-28 prevents it. The service asks a new question with `context.usage`, and the PDP counts the use again (protocol 12). This over-count is safe.
- A refused tool and an unknown tool get the same answer (5.1), and `tools/list` does not name a refused tool (4.1). Thus a client does not learn a tool whose action it cannot do in the service.
- The errors of section 5 copy no value of the request (5.6), and a refusal of an edge has no body (6.1). Thus an agent reads no text of a third party in a refusal [CONTRACT, 5.2].
- The tool error of 5.3 tells that a budget is spent, and the seconds to wait. It shows no grant and no amount (protocol 7.3, 11.2).

## 9. Conformance cases
9.1 The conformance cases of the protocol are data in `conformance/` of the repository of this specification (protocol 15, item 2). The cases that only MCP needs are in this section, and each case cites the paragraphs that it tests. Earlier versions of the protocol gave them these ids for a later version of [CONTRACT]. [CONTRACT] does not hold them yet (section 12, item 1). These ids are in the series U, for a PEP, but the cases are in this binding. `conformance/` gives these ids to no case of its own.
- U18 (3.4, 3.5, 3.6; protocol 6.4): a use of an action that lists a budget sends one Access Evaluation with `context.usage` equal to `{"units": 1}`. A `tools/list`, a call that ends with `InputRequiredResult` and a call of a tool whose action lists no budget send no question with `context.usage`.
- U23 (5.1, 5.3, 5.4; protocol 10.3): the test PDP answers `false` with `budget_exceeded` and `retry_after` 12. A `tools/call` gets HTTP 200 and the tool error of 5.3, with `retryable` true and `retry_after` 12. An MCP request other than `tools/call` whose action lists a budget (3.6a) gets HTTP 429, `Retry-After: 12` and `-31429` with `data.retry_after` 12. `conformance/` tests the HTTP route of protocol 10.3 in a case with its own id.
- U25 (1.3; [CONTRACT, 2.5]): with a valid identity token, the header `MCP-Protocol-Version: 2026-07-28` and the `_meta` version `2025-11-25` give HTTP 400 and `-32020`.

9.2 These cases test the other rules of sections 3 to 6. The ids U26 to U31 continue the series U of `conformance/`. E01 is the first case of the series E, and the series E of `conformance/` starts at E02 (protocol 15, item 2). `conformance/` does not use these ids.
- U26 (4.1, 4.2, 5.1): the test PDP answers `false` for the action of one tool, and `true` for the other actions. `tools/list` does not name this tool. A `tools/call` of this tool gets HTTP 200 and `-32602`, as for an unknown tool.
- U27 (3.3, 3.3a, 5.2, 5.6a): an MCP request with no identity token gets HTTP 401 and an empty body.
- U28 (5.1, 5.5): when the test PDP does not answer, a `tools/call` gets HTTP 503 and `-32603`.
- U29 (3.6a): a `ping` asks the action `mcp.session` on the resource of type `service` with the id of the service. The test PDP answers `false`, and the `ping` gets HTTP 403 and `-32001`.
- U30 (3.5a): a tool whose action waits for an approval sends one question without `context.usage` at the call, and one question with `context.usage` equal to `{"units": 1}` after the approval. A refused approval sends no question with `context.usage`.
- U31 (5.1b): the test PDP answers `false` with no reason for a `server/discover`. The answer is HTTP 403 with the body `{"jsonrpc": "2.0", "id": 7, "error": {"code": -32001, "message": "forbidden"}}`.
- E01 (6.1, 6.2, 6.3; protocol 9.8): an MCP request with a key text that the edge does not know gets HTTP 401, `WWW-Authenticate: Bearer error="invalid_token"` with no `resource_metadata`, and an empty body. No refusal of the edge has the status 400, 404 or 405.

## 10. Examples
The examples use the service `datastore`, the person Alice and her key `key:9b1c04e2aa71f0c3`, with the grants of protocol section 13. The service has the tools `read_rows` (action `data.read`), `write_rows` (action `data.write`) and `copy_table` (action `data.write`).

**The list of the tools.** For `tools/list` with the identity token of the key, the service sends one Access Evaluations request (4.1). The top-level `subject`, `resource` and `context` give the values of each item [AUTHZEN 1.0, l.542].
```json
{ "subject":  { "type": "user", "id": "key:9b1c04e2aa71f0c3" },
  "resource": { "type": "service", "id": "datastore" },
  "context":  { "match": "subtree" },
  "evaluations": [ { "action": { "name": "data.read" } },
                   { "action": { "name": "data.write" } } ] }
```
The answer:
```json
{ "evaluations": [ { "decision": true }, { "decision": false } ] }
```
The key has a grant of `data.read` on the database `test2`, and no grant of `data.write`. Thus `tools/list` names only `read_rows`. A `tools/call` of `write_rows` or of `copy_table` gets `-32602`, as for an unknown tool (5.1).

**A call of a tool.** An agent with the key calls `read_rows` on the table `orders` of the database `test2`:
```json
{ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": { "name": "read_rows",
              "arguments": { "host": "prod", "database": "test2", "table": "orders" },
              "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } } }
```
The request also has the headers of [CONTRACT, 2.5]. The service builds the chain from its own data (3.2), and it sends one question with `context.usage` (3.4):
```json
{ "subject":  { "type": "user", "id": "key:9b1c04e2aa71f0c3" },
  "action":   { "name": "data.read" },
  "resource": { "type": "table", "id": "orders",
                "properties": { "ancestors": [ { "type": "service", "id": "datastore" },
                                               { "type": "host", "id": "prod" },
                                               { "type": "database", "id": "test2" } ] } },
  "context":  { "usage": { "units": 1 } } }
```
The answer, when the use can run:
```json
{ "decision": true, "context": { "limits": { "max_rows": 100, "max_duration": 30 }, "usage": { "units": 1 } } }
```
The grant of Alice on the table `orders` gives the lowest value of `max_rows`, 100 (protocol 8.1). The service gives 100 rows at most, and the read runs for 30 seconds at most (protocol 7.5).
The answer, when the budget is spent:
```json
{ "decision": false, "context": { "reason": "budget_exceeded", "retry_after": 12 } }
```
The service then answers HTTP 200, with the tool error of 5.3 as the `result` of the request with the `id` 7.

**Two permissions for one tool.** The tool `copy_table` copies the table `orders` of `test1` into `test2`, as in protocol 10.1a. For Alice, the service asks `data.read` on the table without `context.usage`, then `data.write` on `test2` with `context.usage`. Both answers are `true`, and the copy takes one unit from each counter of Alice (protocol 6.7). For the key, the first answer is `false`, because the key has no grant on `test1`. The service gives `-32602` and sends no question with `context.usage` (3.7).

**A refusal at the edge.** An agent sends a key text that the edge does not know. The edge answers with no body (6.1) and no `resource_metadata` (6.3):
```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
Content-Length: 0
```

## 11. Relation to other work (informative)
- COAZ-MCP gives the JSON-RPC code `-32001` to each denial. It says that an implementation MUST NOT use a code outside `-32000` to `-32099` [COAZ-MCP, l.859-863]. This binding uses `-31429` (5.4), so it does not claim COAZ-MCP conformance.
- MCP 2026-07-28 tells new implementations not to use the codes `-32000` to `-32019` [MCP 2026-07-28]. The AuthZEN repository does not hold this text.
- COAZ-MCP lets an implementation give a denial as a tool result with `isError` true [COAZ-MCP, l.880-883]. The tool error of 5.3 has this form, but only for `budget_exceeded`.
- COAZ-MCP gives `-32603` when the PEP cannot reach the PDP [COAZ-MCP, l.887-888]. Section 5 gives the same code, with HTTP 503 (protocol 10.3).
- COAZ-MCP puts the map of a tool, `x-authzen-mapping`, in the `inputSchema` of the tool in the `tools/list` response [COAZ-MCP, l.374-376]. Thus a gateway can be the PEP of the tools [COAZ-MCP, l.191-197]. In this binding, the service is the PEP of its tools (3.1), and an MCP message has no added field (1.5).

## 12. Open points
1. The contract of the MCP servers [CONTRACT] moves into this binding in a later version. Until then, this binding applies where the two texts differ. Items 2 to 6 give the differences.
2. Its 2.7 gives the JSON-RPC codes `-32001` for 401 and `-32002` for 429. Section 5 gives a 401 with an empty body (5.2). It replaces `-32002` with `-31429`, only when the service knows the `id`. Before the service reads the `id`, each refusal has an empty body (5.6a, 7.4). An example is the 400 that its 2.7 gives to a body that is not JSON. Its 2.7 also gives status 200 to each error of a method. Section 5 gives HTTP 429 with `-31429` and HTTP 503 with `-32603`.
3. Its 6.1 has `retry_after_ms` in place of `retry_after` in whole seconds (5.3). Its 6.2 has no code `budget_exceeded` (5.3a). Its 4.5 does not say that the `outputSchema` of a tool accepts the error object of its 6.1 and of 5.3.
4. Its section 11 restates rules of the protocol and does not cite the protocol. Its 11.3 to 11.5 and 11.8 become references to the protocol. Then three differences end. Its 11.3 has `EdDSA` (protocol 9.2), and its 11.4 has a path of the action document other than `/.well-known/procurauth/actions` (protocol 5.1). Its 11.5 accepts a network without TLS (protocol 10.0, step 4). Its 11.1 says that AuthZEN does not apply to the MCP endpoint, but 3.3 accepts the identity token there.
5. Its 11.5 gives `false` when the PDP fails, and its case U08 then expects 403: the protocol gives HTTP 503 (protocol 10.3). Its case D14 expects `false` with `invalid_request` for a bad `context.match` in one evaluation: the protocol gives HTTP 400 (protocol 11.1). Its 11.6 gives 403 to each `false`, also for `budget_exceeded` (protocol 10.3).
6. Its file `IMPLEMENTATIONS.md` names products. It does not move into the repository of this specification.

## References
- [PROTOCOL] ProcurAuth Protocol, version 1.0: `spec/` in the repository of this specification.
- [AUTHZEN] (also cited as [AUTHZEN 1.0]) AuthZEN Authorization API 1.0, Final Specification, OpenID Foundation. A citation l.N is a line of `api/authorization-api-1_0.md` in the repository `openid/authzen` at commit `4deba63`.
- [COAZ-MCP] COAZ Binding for the Model Context Protocol, Draft 1: `profiles/authzen-coaz-mcp-binding-1_0.md` at the same commit. A citation l.N is a line of this file.
- [CONTRACT] The contract of the MCP servers, version 1 (draft): `SPEC.md` and `conformance/CASES.md` of the repository `mcp-server-contract`. A citation N.M is a paragraph of `SPEC.md`. It moves into this binding later (section 12, item 1).
- [MCP 2026-07-28] Model Context Protocol, revision 2026-07-28.
- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels. [RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
