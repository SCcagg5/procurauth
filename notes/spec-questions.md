# Questions about the protocol text

This file lists the places where the text of the protocol or of the MCP binding has two possible meanings. Each item gives the paragraph, the question, and the meaning that the code uses. The code takes the most literal meaning. The owner decides if the text needs a change.

## Action document

1. **5.3, 5.2.** Does an unknown member outside a limit declaration make the document bad? Paragraph 5.3 names only the limit declarations. The code gives a warning and keeps the document good.
2. **5.2.** Is an action with an empty list `resource_types` valid? No grant can be valid for such an action. The code accepts it with no finding.
3. **5.2.** Must the id in `server` follow the rules of 4.1 (1 to 256 bytes, no control character)? The service is the root node. The code applies 4.1.
4. **5.2.** Can a `label` or a `description` be empty? The text gives a maximum, not a minimum. The code accepts an empty text.
5. **5.2.** Must the `actions` of a `resources` item list the type of the node? The text says only that each name is declared. The code does not check the type.
6. **5.2, 5.7.** Is the percent-encoding of an id in `path` strict? Paragraph 5.2 says that the encoded text is the only text form. The code refuses a lower-case escape and a reserved character that is not encoded.
7. **7.1.** A ceiling name is `max_` and a noun. Does a ceiling name without `max_` make the document bad? The code gives a warning.
8. **6.1.** Does "whole number" include the JSON text `1.0`? The code refuses it for `min`, `max` and `amount`. A JSON Schema of type integer accepts it.
9. **6.1.** Is there a largest value for `max` and `amount`? The text gives none. The code reads a whole number up to 2^64 - 1.
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
