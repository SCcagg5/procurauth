# Questions about the protocol text

This file lists the places where the text of the protocol or of the MCP binding has two possible meanings. Each item gives the paragraph, the question, and the meaning that the code uses. The code takes the most literal meaning. The owner decides if the text needs a change.

## Action document

1. **5.3, 5.2.** Does an unknown member outside a limit declaration make the document bad? Paragraph 5.3 names only the limit declarations. The code gives a warning and keeps the document good.
2. **5.2.** Is an action with an empty list `resource_types` valid? No grant can be valid for such an action. The code accepts it with no finding.
3. **5.2.** Must the id in `server` follow the rules of 4.1 (1 to 256 bytes, no control character)? The service is the root node. The code applies 4.1.
4. **5.2.** Can a `label` or a `description` be empty? The text gives a maximum, not a minimum. The code accepts an empty text.

   Status: Closed (lot PS1, decision 175): a label and a description have 1 character or more.

5. **5.2.** Must the `actions` of a `resources` item list the type of the node? The text says only that each name is declared. The code does not check the type.

   Status: Closed (lot PS1, decision 175): the document is bad when an action of a `resources` item does not list the type of the node.

6. **5.2, 5.7.** Is the percent-encoding of an id in `path` strict? Paragraph 5.2 says that the encoded text is the only text form. The code refuses a lower-case escape and a reserved character that is not encoded.
7. **7.1.** A ceiling name is `max_` and a noun. Does a ceiling name without `max_` make the document bad? The code gives a warning.

   Status: Closed (lot PS1, decision 175): a ceiling name that does not start with `max_` makes the document bad.

8. **6.1.** Does "whole number" include the JSON text `1.0`? The code refuses it for `min`, `max` and `amount`. A JSON Schema of type integer accepts it.
9. **6.1.** Is there a largest value for `max` and `amount`? The text gives none. The code reads a whole number up to 2^64 - 1.

   Status: Closed (lot PS1, decisions 175 and 176): the largest whole number of a limit is 2^53-1.

10. **4.1.** Which characters are control characters? The code uses the Unicode category Cc: U+0000 to U+001F and U+007F to U+009F.

## Identity token

11. **9.3, 9.4.** Can `iat` and `exp` have a fraction, as RFC 7519 permits for a NumericDate? The code accepts a whole number of seconds only.
12. **9.4.** What happens when `exp` is before `iat`? The text bounds the life by a maximum and gives no minimum. The code refuses such a token.
13. **9.4.** Is the check of `typ` case-sensitive? RFC 7515 treats the media type `JWT` without case. The code accepts only the text `JWT`.
14. **9.4.** What does the service do with a header `crit`? The protocol is silent. RFC 7515 says to refuse a token with an extension that the service does not know. The code refuses each `crit`.
15. **9.4.** The key set has one key with no `kid`, and the token has a `kid`. The text says to refuse a `kid` that the set does not hold. The code refuses the token.
16. **9.4.** Does the service check `nbf`? The protocol does not name it. The code ignores it as an unknown claim.

## Decisions and reasons

17. **11.1.** An id of the chain with an empty text, more than 256 bytes or a control character has no reason in the list. The code gives `false` with no reason (11.2).
18. **11.1.** A `false` answer with the reason `budget_exceeded` and no `retry_after`: is the answer valid? The text says that the context also has `retry_after`. The code treats the answer as not valid. A PEP then gives HTTP 503.
19. **3.5.** The protocol does not say how a PDP decides the current rights of the owner. The shared functions use the grants of the owner. A real PDP can use another source.
20. **8.3.** The text gives the budgets to the grant of `access` on the service. The code refuses a grant of `access` on another node. The text does not say if this is an error.
21. **8.3, 7.3.** A ceiling on a grant of `access` has no effect, but the text does not say it. The code gives a warning.

## Edge

22. **8.3, 9.8.** An edge refuses a subject that has no `true` decision for `access`. Paragraph 9.8 gives HTTP 401 for a refused key. Is 401 also right for a key with a valid text but without `access`? The example cases of the series E do not test this point.

## Conformance

23. **15, item 2.** The binding gives the ids U18, U23 and U25 to U31, and E01. The page `conformance.html` of the site lists U25 to U28 only. The data model reserves all the ids of the binding.

## Approval of an effect (section 17)

24. **5.2b.** The papers give the letter d to the new paragraph. The repository has no 5.2b and no 5.2c, so the text uses b. Do the other texts that cite 5.2d change, or does the owner want the gap?
25. **17.1, 17.7, 10.1.** The PEP asks a question without usage and then a question with usage. A single question with usage and the effect needs one call less, but the papers keep the first question. Which one does the owner want?
26. **17.1.** A void approval gives `approval_required` to a question without usage. The agent then gets a new request, and the tool call gives no `approval_expired`. Is this right? The reason `approval_expired` shows only when the approval ends between the two questions.
27. **17.6.** The deny time makes the same effect get `approval_denied`. After it, the agent can ask again. The agent learns the text of the refusal only at the PDP. Does the PEP need a count of refusals?
28. **10.3, 17.7.** The protocol gives no HTTP form for a request that waits. An HTTP route that follows section 17 submits the request and answers 403. Does the owner want an HTTP form, for example 202 with a body?
29. **17.1.** A question with no effect for a grant with `confirm` gets `approval_required`. This includes the questions of 5.5a that ask a second permission without usage. An operation that needs a second permission on an action with `confirm` cannot run. Does the owner accept this?
30. **17.4.** The names of the errors of the narrow API are new: `invalid_evaluation`, `lease_required`, `invalid_lease` and `cannot_supersede`. The papers also differ for the owner with no device: `no_phone` and `no_device`. The text takes `no_device`.
31. **Binding 5.7.** A call must give exactly one of `approval_ref`, `lease_s` and `until`. A service can give a default lease from its own configuration instead. The papers say that the PDP refuses a call with none.
32. **Binding 5.7a.** The papers list `approval_cancelled`, but the PEP learns only `void` (17.12). The text defines no such code. Does the owner want a ninth verdict, or does the code leave the list?
33. **Binding 5.7.** The result for a request that waits has a second item `NOT EXECUTED` and no `isError`. The paper asks to read this choice again after two weeks of use. Is the contract of the MCP servers changed to hold it?
34. **17.4.** Each read of a request has the parameter `subject`, also without `renew=true`. The papers show it only with `renew=true`. The text makes it mandatory, so that no verdict leaks to another subject.
35. **17.9.** The effect and the pointers are checked by the PDP only. A case cannot check that a pointer of the `view` names a value of the `op` that the PEP sent. A new matcher could do it.
36. **15, item 2.** The series A of the papers (API of the PDP) is not in the data. Does the owner want it as conformance cases for a PDP, with the endpoints `approval_requests` and `approval_status`?

37. **17.1, 17.2.** Does a question with no usable approval and a spent budget get `approval_required` or `budget_exceeded`? The text says that the PDP first decides as for a question without the effect. The code answers the approval reason, because the approval comes before the budget (decision 106).
38. **17.6.** Does the deny time end at `deny_until` or after it? Does the consume time end at `consume_before` or after it? The case D80 says that `consume_before` is the last good second. The code ends the deny time at `deny_until` (decision 109).
39. **17.4.** The text says that the PDP bounds `wait` and publishes the bound. It does not say what happens above the bound. The code waits the bound and answers the verdict, with no error (decision 113).
40. **17.4, 17.5.** The text does not say how a PDP publishes its bounds. The code uses twelve metadata members `procurauth_approval_*` (decision 112). The names are not in the protocol.

   Status: Closed (lot PS1, decision 170): paragraph 17.4a defines the twelve names.

41. **17.1, 17.4.** The submission has no subject, action or resource. The `evaluation_id` must give them back. A stateless id needs a long text, so the code keeps the binding in memory (decision 114).
42. **17.5.** Does a renewal after the end of a lease count as a revival? The code says yes, because the first call that sees the end also makes the request `abandoned` (decision 110).
43. **17.4.** A request for an effect that has an approval that can be used still gets a new request. Is this an error? The code makes the new request the latest approval (decision 108).
44. **17.8, 5.2b.** Does `confirm` apply to an action that has no member `approval`? The text says that the member "tells" that a grant can have it. The code applies `confirm` to each action except `access` (decision 105).

## The PEP for the approval of an effect (lot S4b)

45. **Binding 5.7.** A call with a bad control argument gets `invalid_argument` and no question goes to the PDP. A subject that has no right on the tool then sees a different reply from the reply for an unknown tool (4.2). Does the owner accept this, or must the service ask the PDP first?
46. **17.4, 17.5, binding 5.7.** A call with `wait_s` waits for the verdict and does not renew the lease, because the call does not name the request. The agent can still renew with `get_action_status`. Does the owner want the wait to renew?
47. **17.4, binding 5.7a.** A late `evaluation_id` gets 422 `invalid_evaluation`, and the PEP gives HTTP 503. The PEP could ask the question again one time and submit with the new id. Does the owner want this retry?
48. **Binding 5.7, protocol 15.** The operations `mcp_approve` and `mcp_refuse` of the data model stand for the old request for input. No case uses them now. Does the owner want to remove them from the schema and the README?
49. **MCP server contract 4.3, 4.5.** A tool with an effect has `readOnlyHint` false and `openWorldHint` true, and an `outputSchema` with the object `action`. The type `ToolSpec` of the library has no annotation and no `outputSchema`. Does the owner want them in the type?
50. **Binding 5.7a, 10.3.** The binding has no HTTP form for a refusal of the approval on a route that is not MCP. The library gives 403, 422, 503 and 429 (decision 125). Does the owner want a form in the protocol? This extends question 28.

## Approval for every action (lot S7)

51. **17.7a, 17.8.** A grant of a person can have `confirm`, and the approver is the owner only, so a person approves their own action. A person with an interactive session cannot wait, so the call gets HTTP 403 with `approval_cannot_wait`. We recommend that the PDP ignores `confirm` of a grant of a person for the questions of the person, because self-approval adds no check. It applies that `confirm` to the keys of the person only. Does the owner accept this rule?

   Status: Decided by the owner on 2026-11-12 (decision 177). The `confirm` of a grant of a person has no effect on the questions of the person. It applies to the keys of the person.

52. **17.7a, 15.** Only the MCP binding gives an interface that can wait (open point 7, spec questions 28 and 50). A service with an HTTP route only, or a web interface, can never wait, so no approval can run its actions. We recommend an HTTP form with the answer 202 and the body `{"action": {...}}` of the binding. The controls of 17.5 go in the query or in a header. Does the owner want to define it?

   Status: Decided by the owner on 2026-11-12 (decision 183): a route of a plain HTTP service keeps HTTP 403 with `approval_cannot_wait`. A standalone key stays outside the approval.

53. **17.7, 5.5a, spec question 29.** An operation that needs a second permission fails when the PDP asks for an approval for that permission. A `confirm` on `data.read` then stops each copy. We recommend that one approval covers the whole operation: the PEP sends the effect of the operation with each permission, and one submission lists them. Until then, the portal must not offer `confirm` for an action that an operation uses as an other permission. Does the owner want a design for it?

   Status: Still open: it needs a decision of the owner (decision 182). The text does not change.

54. **17.1, 17.7, 10.1, spec question 25.** The PEP asks first with no effect, and it computes the effect only on a reason of 17.1 (decision 150). A gated use then costs three questions: one with no effect, one with the effect, and one with usage. The other design sends the effect in each question and costs two for each use. Does the owner accept the lazy design?
55. **Binding 5.7, spec question 31.** A call with no control argument gets `invalid_argument` when the PDP asks for an approval (decision 156). A service could use a default lease from its own configuration instead. Then an agent never needs to know in advance. We recommend the error, because the lease is the choice of the agent. Does the owner agree?
56. **Binding 3.6a, 17.7a.** The action `mcp.session` is for the methods with no tool, for example `ping`. It must follow section 17, but such a method cannot wait. A grant with `confirm` on it makes `ping` and `initialize` fail. We recommend that the PDP ignores `confirm` for `mcp.session`, like it does for `access`. Does the owner agree?

   Status: Decided by the owner on 2026-11-12 (decision 179): `confirm` has no effect on `mcp.session`, and a PDP SHOULD refuse such a grant.

57. **17.3a.** A service must name the operation in `op` when an action serves more than one operation. The text gives the member `tool` only for the MCP binding. A service with no MCP endpoint has no name. Does the owner want a member name for other interfaces?
