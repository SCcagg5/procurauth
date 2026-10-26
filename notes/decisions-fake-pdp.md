# Technical decisions of fake-pdp

Each item gives one choice and the reason. The numbers are for this file only.

## Dependencies

1. The crate has its own HTTP/1.1 layer on the standard library. It does not use `tiny_http`. The tool must close a connection with no byte. It must also hold a connection open with no answer. `tiny_http` sends HTTP 500 when a handler drops a request, and it gives no control of the read timeouts.
2. The HTTP layer has about 300 lines and unit tests. A test PDP needs a small and strict parser. It needs no feature of a full server.
3. The parser refuses a bare line feed, a folded header and a bad `Content-Length`. It also refuses two different values of `Content-Length` and each `Transfer-Encoding`. A strict parser removes the cases of request confusion.
4. The crate uses `clap` with the features `derive`, `help`, `usage` and `error-context`. The common rules ask for no colour, so the feature `color` is off.
5. The crate uses `ctrlc` with the feature `termination`. It handles SIGINT, SIGTERM and SIGHUP. It is well known, and it also works on Windows. The crate has no `unsafe` code.
6. The crate uses `sha2` for the digest of the credential. The core already depends on it.
7. The tests need no new dependency except `regex` and the schema checker. They use `std::net::TcpStream`.

## Server

8. The server has a fixed pool of worker threads. One open connection uses one worker. This is the simplest model with a bounded number of threads.
9. The accept loop polls a non-blocking listener every 10 ms. This stops the loop with no `unsafe` code and with no wake-up connection.
10. A worker checks the stop flag every 50 ms in each wait. A graceful stop must not wait for an idle connection.
11. One lock protects the counters, the failure rules and the log. A decision and its count must be one atomic step (6.5, 6.8).
12. The server writes the text log under the lock of the decision. The order of the blocks must be the order of the decisions.
13. The server sends no `Date` header. The clock of the tool can be fixed, and a real date would make the answers differ between runs.

## HTTP choices

14. A body above the maximum gets HTTP 413 before the body arrives. The size is known from the head, and RFC 9110 gives 413 to this case.
15. A request with more items than the maximum gets HTTP 400. The body is not too large, and AuthZEN gives 400 to a bad request.
16. The size maximum applies to the body of each POST request. A PEP must bound the body of the other endpoints too.
17. A body that is not `application/json` gets HTTP 415. The transport of AuthZEN requires this content type.
18. A bad request gets the fixed body `{"error":"Bad Request"}`. The body must not leak a value or a rule.
19. The server writes the JSON paths and the rule numbers of a bad request to the diagnostics. It never writes a value. A developer needs the path, and the response must stay silent.
20. The check of the credential comes before each other check of a request. A PEP that did not authenticate must learn nothing about the format.
21. The metadata needs no credential. AuthZEN publishes it at a well-known URL, and a PEP reads it first.
22. The admin endpoints need the credential of the PEP when the server has one. They change the clock and the counters.
23. The metadata takes `policy_decision_point` from the `Host` header when the header has only the characters of a host. The value must be the identifier that the PEP used (AuthZEN 1.0, metadata validation).

## Decisions

24. The decision logic is in the module `pdp`. It has no network code and no clock. Unit tests and other tools use it as a library.
25. The module `pdp` copies the logic of the reference PDP in the tests of the core. The original stays where it is, because another agent uses it.
26. A question for a service that the data does not hold gets `invalid_resource`. The PDP answers only for its own services (11.1, 12).
27. A caller whose credential belongs to one service gets `invalid_resource` for another service. Paragraph 12 says that the PDP answers each PEP only for its own service.
28. A service with no good document answers `false` with no reason, except for `access` on the service. Paragraph 11.1 says so.
29. A use of an action that the document does not declare takes no unit. A `true` answer then has `units` 0, because no budget applies to it.
30. The PDP takes the budget values from the first grant of `access` on the service, for each side. Paragraph 8.3 gives one value for each budget to a subject.
31. A counter has the service, the subject, the budget and the window in its name. Two services can declare a budget with the same name.
32. A counter keeps the start of its window. A counter of an older window counts as zero. The windows are fixed, and the clock can move (6.3).
33. When the clock moves back, a counter of a later window counts as zero. The PDP keeps one window for each counter.
34. A fixed clock starts at `clock.now` or at `--clock-start`. The two together stop the program, because two keys that contradict each other are an error.
35. A system clock becomes a fixed clock when a test moves it. The test then controls all the windows.

## Failures

36. The kinds `no_answer`, `close` and `invalid_json` decide and count before they act. The kind `no_units` also counts. Paragraph 10.6 says that the units of a lost answer stay counted.
37. The kind `error_503` counts nothing and gives no decision. Paragraph 6.9 says that the PDP answers HTTP 503 when it cannot use a counter.
38. The kind `delay` waits first and decides after. The PEP must see the time of the whole answer.
39. The kind `no_units` removes `context.usage.units` from a `true` answer only. The test is about 6.12, and a `false` answer has no units.
40. One rule applies to a request: the first rule that matches and that has uses left. Several failures on one request make a test hard to read.
41. A request with items matches a rule when one item matches. A failure is a property of the HTTP exchange.

## Configuration

42. The program has the flags `--admin`, `--credential-file` and `--failures`. It has no new member of the data file. The data schema is closed and belongs to the core.
43. The credential comes only from a file. The owner forbids a secret in an argument and in the environment.
44. The program checks the data file, the credential file and the failure file before it opens the port. It reports every problem. A configuration error must stop the program before it serves.
45. The program writes the effective configuration to the standard error at start. With `--print-config` it writes it to the standard output. The configuration rules ask for both.
46. The table of keys is in the code. A test checks that the README has the same table. The reference must agree with the code.

## Tests

47. The tests start the server in the same process on port 0. This needs no fixed port and no other process.
48. The binary tests send SIGTERM and SIGINT with the program `kill`. The standard library cannot send a signal, and the code has no `unsafe` block.
49. A local runner in the tests runs the cases of the series D through HTTP. The crate `procurauth-schema-check` has no API for the case model.
