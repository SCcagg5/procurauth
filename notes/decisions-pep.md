# Technical decisions of procurauth-pep and reference-service

Each item gives one choice and the reason. The numbers are for this file only.

## Library

1. The library has no TLS client and no feature `tls`. A TLS crate such as `rustls` needs `ring` or `aws-lc-rs`, which need a C compiler. It also needs a root store and many more crates. The core avoids a C compiler on purpose (decision 9 of `decisions.md`). The trait `PdpTransport` lets an application plug in its own TLS client.
2. The configuration refuses an `http` URL unless the flag `allow_insecure_pdp_link` is set. Protocol 10.0 (step 4) says that the PEP MUST secure the link, so the safe value is the default.
3. `HttpTransport` is a synchronous client on `std::net`, with a small pool. It needs no runtime, no `unsafe` code and no dependency. The PDP link has few connections, so a thread for each caller is enough.
4. The transport tells the PEP how an exchange failed: `NotSent`, `Timeout`, `Lost`, `Malformed`, `TooLarge` or `Unsupported`. Protocol 10.6 lets the PEP send a question with `context.usage` again only when the request did not leave the PEP. Thus the PEP must know the kind.
5. A failure of the first write is `NotSent`, and a failure after the first byte is `Lost`. The client checks with a non-blocking `peek` that the PDP did not close an idle connection, before it reuses the connection. This keeps the case of a stale connection very rare.
6. The pool closes an idle connection at the next use of the pool, not in a thread of its own. The rule of 10.7 is that the PEP never uses a connection that the PDP can have closed. A thread that only closes sockets adds a lock and a clock for no gain.
7. The PEP asks a question without `context.usage` again after `NotSent` or `Lost`, `plain_retries` times. It never asks again after a timeout, because a timeout already took the whole wait. A question with `context.usage` goes again only after `NotSent`, one time.
8. The wait for a question with `context.usage` is the time that the PDP publishes plus a margin, and at least the normal timeout. Protocol 10.6 says that the PEP SHOULD wait longer than this published time.
9. The PEP reads the metadata at the first question, and again after `metadata_max_age`. It keeps the old metadata when a new read fails. A status 404, 405, 410 or 501 means no metadata, and the PEP uses the default paths of AuthZEN (10.0, step 4). After a failed new read, the PEP keeps the old metadata and tries again 5 seconds later.
10. The PEP refuses an endpoint of the metadata that has another origin than the PDP. A bad metadata document could send the credential of the service to another host.
11. The metadata must have `policy_decision_point` equal to the URL of the PDP, as AuthZEN 1.0 requires. A member of this protocol that is not a whole number of 1 or more makes the metadata not valid. The PEP then fails closed.
12. The PEP sends questions without `context.usage` in one Access Evaluations request when there are two or more. A request holds the subject and `context.match` one time, and each item holds the action and the resource. The binding shows this form in its example.
13. A PDP without an Access Evaluations endpoint gets one request for each question. AuthZEN 1.0 says that such a PDP omits the endpoint from its metadata.
14. The PEP derives "the action lists a budget" from the action document, and `Operation` has no flag for it. The document is the declaration of the service (6.2, 7.5), so a flag could only contradict it.
15. An operation has one use and other permissions (5.5a). The other permissions come first, without `context.usage` (10.1a). An other permission that equals the use is not asked twice, because 10.1 forbids the same question without usage before the question with usage.
16. For several actions for the use, the PEP asks them one at a time with `context.usage`, in the order of preference. This is the last item of 10.1. It stops at the first `true` or at the first `budget_exceeded`. A `false` answer without `budget_exceeded` counted nothing, and the PEP keeps it as an answer without usage.
17. The PEP keeps answers in two sets: with usage and without usage. A kept `true` answer without usage never starts a use of an action that lists a budget. The PEP keeps a `true` answer with usage only when `units` is 0.
18. A kept `budget_exceeded` answer gives the time that remains to the end of the window. It does not give the time that remains to the end of the kept life. The value never grows (case U58). See question 1 of `spec-questions-pep.md`.
19. A ceiling that the action does not list, or that the document does not declare, makes the answer `false` (7.5). A name that the document declares as a budget gives HTTP 503, because a budget value never appears in an answer (7.3).
20. The PEP accepts a ceiling value outside the range `min` to `max` of its declaration. A lower value is stricter, and a value above `max` can be applied as it is.
21. A mistake of the service, for example an action that the document does not declare, gives `Refusal::Internal` with HTTP 500. The PEP sends no question. Protocol 10.3 has no status for it, and a client must not see it as a decision of the PDP.
22. A display question has no rule that the action lists the type of the node. The question `subtree` also looks below the node (4.4), and the list of the tools asks each action on the service (binding 4.1).
23. The PEP refuses a request that has the header of the token more than one time. The edge replaces this header (9.1), so a duplicate shows a fault of the proxy chain.
24. The library does not keep the result of a token check (9.7 says MAY). A check costs one signature check, and a kept result adds a table to bound (10.1b).
25. The `Pep` takes a `Clock`. The library reads the system clock only in `SystemClock`. A test moves a `ManualClock`, and the tests of windows and kept answers need no sleep.
26. The error of the configuration is a list of `ConfigError` with the key, the expected value and the value found. The credential is a `Secret`. A message never holds it, also when it is not valid.
27. The feature `mcp` is on by default, so that `scripts/ci.sh` builds and tests it. `scripts/ci.sh` also checks the build with no default features.
28. The MCP module has no state and no transport. It parses a request, maps a tool to an action, asks the PEP and maps a refusal. The service does the work of the tools.
29. The MCP module reads a request with the strict JSON reader of the core. A duplicate member is not a request.
30. A tool that the map does not have gets the refusal of a `false` answer, and the PEP sends no question for it (binding 4.2). Arguments that do not name a node give the code `-32602` with the message `Invalid params`. This reply does not depend on the rights of the subject.
31. The reply of the input request follows the draft of the MCP revision 2026-07-28: `resultType` `input_required`, `inputRequests` and `inputResponses`. The binding does not define the form. The helpers are small, and the service shows the use.

## Reference service

32. The service has its own HTTP/1.1 layer on `std::net`, as `fake-pdp` has. The layer is about 400 lines with tests. It refuses a folded header, a chunked body and a bad length. Its `Reject` replies close the connection. A framework would hide these rules.
33. The configuration file is JSON, as the other tools of the repository use. The reader is the strict reader of the core. A duplicate member is an error.
34. The table of keys is in the code. The README holds the same table, and a test compares them. The forms `_env` and `_file` exist for the keys that name a place: `listen`, `issuer`, `jwks`, `pdp.url` and `pdp.credential`.
35. A secret takes only `_env` and `_file`. A secret in clear text in the file stops the program, and the error does not show it.
36. The effective configuration shows `default`, `file`, `env:VAR` or `file:/path` as the source. The program also writes it to the standard error at start.
37. The program has no TLS client, so `pdp.url` takes an `http` URL and the flag `pdp.allow_insecure_pdp_link` is needed. The README says that a deployment builds its own service with a transport with TLS.
38. The default of `cache_ttl_seconds` is 0. The conformance cases use the same subject and the same resource in many cases. A kept answer from one case would change the next case.
39. The service asks the PDP before it looks for a node. A client that has no right gets 403 and learns nothing about the existence of the node.
40. The service builds the chain from the position of each id in the path. The type of the node comes from the route, never from the client (4.5).
41. A read lowers the value of `timeout_seconds` to the ceiling `max_duration`, and a write refuses a value above it. The two routes show both ways to apply a ceiling.
42. The service answers 401 with an empty body on each route. The MCP binding asks for this on the MCP endpoint (5.6a), and the other routes follow the same rule.
43. The log has the method, the path and the status for each request, and the cause of a refusal. It never has a header, a query, a body or a token.
