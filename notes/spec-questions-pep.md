# Questions about the protocol text, from the PEP library

This file lists the places where the text of the protocol or of the MCP binding has two possible meanings. The library chose one of them. Each item gives the paragraph, the question, and the meaning that the library takes. The owner decides if the text needs a change. The files `spec-questions.md` and `spec-questions-cases.md` list other questions.

1. **10.1.** A kept `budget_exceeded` answer gives `retry_after` as "the seconds to the end of that time". Which time? The kept life is the lower of `retry_after` and `cache_ttl`. The end of the window can be later. The library gives the seconds to the end of the window, so that a client does not retry too early.
2. **10.1.** A PEP that chooses among several actions can ask them without usage in one request, or with usage one at a time. The library takes the second way. It also keeps a `false` answer without usage. The text does not say how a PEP mixes an action with a budget and an action with no budget.
3. **7.3, 7.5.** A name in `context.limits` that the document declares as a budget gives HTTP 503. A name that the action does not list gives HTTP 403. Question 6 of `spec-questions-cases.md` asks the same about a value that is not a whole number.
4. **7.5.** Can a ceiling value be outside the range `min` to `max` of its declaration? The library applies it as it is.
5. **5.5a, 10.1.** An operation lists a permission that equals the use. The library does not ask it a second time without usage.
6. **4.4, binding 4.1.** Must the action of a display question list the type of the node in `resource_types`? The binding asks each action of a tool on the service. An action that is valid only on a table has no `service` in its `resource_types`. The library does not check the type for a display question.
7. **10.0.** What does the PEP do when the metadata is absent, or when it has a bad member? The library uses the default paths for the statuses 404, 405, 410 and 501. It fails closed for any other failure.
8. **10.0, AuthZEN 1.0.** An endpoint of the metadata has another origin than the PDP. The library refuses it, so that the credential of the service stays with the PDP.
9. **10.6.** What is a connection that "failed before the PEP wrote the request"? The library says: no connection, no free connection, or a failure of the first write. A failure after the first byte is a lost answer.
10. **10.3.** A mistake of the service, for example an operation with an action that the document does not declare, has no status. The library gives HTTP 500.
11. **9.4.** A request has the header of the token more than one time. The library refuses it with 401. The text says that the edge replaces this header.
12. **Binding 3.5, 3.5a.** The binding does not define the form of the request for input and of the approval in the revision 2026-07-28. The reference service follows the draft: `resultType` `input_required`, `inputRequests` and `inputResponses`.
13. **Binding 1.3.** The code `-32020` has no message in the binding. The library gives the fixed message `Version mismatch`.
14. **Binding 3.6a.** The binding gives no result for `initialize`, `ping` and `server/discover`. The reference service gives the smallest result that is good for each.
15. **Binding 5.1.** A `tools/call` with arguments that name no node gets the code `-32602`, as an unknown tool does. The library uses the message `Invalid params` for it, and `Unknown tool` for a tool that is absent or refused. The two replies differ, but neither depends on the rights of the subject.
