# ProcurAuth Protocol

Version 1.0

The changelog in `docs/` of the repository gives the changes of each version.

A paragraph keeps its number in later versions. A paragraph that leaves this document keeps its number, with the word "Unused" and a pointer. A new paragraph gets a new number, or a letter after the number of the paragraph that it continues. The numbers 7.2, 7.7, 8.5, 10.4 and 10.5 stay unused.

This document defines the ProcurAuth protocol, a profile of the AuthZEN Authorization API 1.0 [AUTHZEN].
It names no product, and any product can use it.

The words MUST, MUST NOT, SHOULD and MAY have the meaning of [RFC 2119] and [RFC 8174].

## 1. Introduction
1.1 This protocol adds four things to AuthZEN 1.0:
- a resource chain with a rule of coverage (section 4);
- keys: subjects that act for a person (section 3);
- limits: budgets, which a PDP counts (section 6), and ceilings, which a PEP applies (section 7);
- a route of a service that lists the children of a node for a form (5.6).

1.2 This protocol changes no member of the core. It uses `properties`, `context`, the action document (section 5) and the identity token (section 9).
A receiver of AuthZEN 1.0 ignores a member that it does not know [AUTHZEN 1.0, l.1418].
A PEP of this protocol MUST understand each member that this protocol marks as mandatory.
This protocol is the only normative text for the subject, chain, coverage, action document, list of the options, identity token, limits and reasons. Other documents refer to its paragraphs and do not restate them.

1.3 A PDP conforms to this protocol when it follows sections 3 and 4, 5.1 to 5.5, sections 6 to 8, 10.7, 10.7a, 11 and 12.
A service (its PEP) conforms when it follows these paragraphs:
- 3.3, 3.4, 4.1, 4.4 and 4.5;
- 5.1, 5.2, the last sentence of 5.3c, 5.4, 5.5 and 5.5a, and 5.6 to 5.8 when it publishes the list of the options;
- 6.1, 6.2, 6.4, 6.11 and 6.12;
- 7.1 and 7.3 to 7.6;
- the last sentence of 8.3;
- 9.3 to 9.7, 10 and 11, and item 6 of section 15.

An edge conforms when it follows 1.4, 8.3, 9.1 to 9.3, the second paragraph of 9.4, 9.8 and 9.9. The system that makes keys follows 3.2 and 3.8 for this job. A caller of the route of 5.6 follows 5.6 to 5.9. A service with an MCP endpoint, and an edge in front of such a service, also follow the MCP binding [MCP-BINDING].

1.4 In this version, an agent sends the text of its key to the edge in the header `Authorization: Bearer` [RFC 6750, 2.1]. This version is for local clients that can send this header.
A hosted client, which runs on the servers of a third party, is not in this version. This version defines no OAuth flow.
A later version can add an OAuth server at the edge. The identity token of section 9 then does not change.

## 2. Terms
The words PDP, PEP, subject, action, resource and evaluation have the meaning of [AUTHZEN]. Other words have the meaning of this list or of the section that defines them.
- **Person**: a human subject. Its id has no colon (3.1).
- **Key**: a subject that acts for a person, its owner (3.4). Its subject id (3.2) has a colon and is not secret. A key also has a secret text, the text of the key, which an agent sends to the edge (1.4). A question names a key by its subject id and never holds the text of the key (9.3). A key is not a token. A key that a service checks by itself (no edge) and the signing key of the edge (9.2, 9.4) are not keys of this protocol.
- **Owner**: the person for whom a key acts.
- **Agent**: a program that uses a key. An agent is not a subject: the PDP decides for the key.
- **Edge**: the part in front of a service that authenticates a client and gives the identity token to the service. It can be a proxy and its authentication server.
- **Service**: the application that holds a PEP. Its id is the id of the root node, of type `service`, and the member `server` of its document.
- **Node**: the service, or a resource below it in the tree of the types of the service (5.2).
- **Chain**: the ancestors of a node, from the service down, in `resource.properties.ancestors` (4.1).
- **Coverage**: the rule of 4.3: a grant on a node covers the node and each node below it.
- **Action document**: the document in which a service declares its types, its actions and its limits (section 5).
- **Options**: the children of a node that a service lists for a form (5.6).
- **Identity token**: the token that an edge gives a service for one subject (section 9).
- **Directory**: the subjects, the grants and the limit values on which a PDP decides. 3.9 bounds the age of a copy of it.
- **Question**: one evaluation that a PEP sends to the PDP.
- **Kept answer**: an answer that a PEP keeps for at most `cache_ttl` (10.1).
- **Grant**: a right to do an action on a resource. A grant can carry limit values.
- **Limit**: a number that bounds the uses of an action. Its kind is `ceiling` or `budget`.
- **Ceiling**: the maximum of one use, for example the most rows that one read gives. The PEP applies it.
- **Budget**: a limit that gives an amount of units for each of one or more windows (6.1). The PDP counts it.
- **Counter**: the units that one subject spent on one budget in the current window. Each window of a budget value has its own counter (6.7). Only the PDP knows the counters.
- **Window**: the fixed period in which a counter counts (6.3). The member `window` of an item of a budget value gives its length (6.1).
- **Amount**: the units that a grant gives to a budget for one window.
- **Units**: the quantity that one use takes from a budget, as a number in the unit of the budget, in `context.usage.units` (6.4).
- **Unit**: the unit of measure of a limit, which the member `unit` of its declaration names (6.1). Examples: `request` for the budget `requests`, `row` for the ceiling `max_rows`.
- **Operation**: one request that a client sends to a service. An operation can ask several questions.
- **Use**: one run of an action that a service does for one operation. A use takes units from budgets.
  A question to the PDP is not a use. A question for a display, for example to choose the options of 5.6, is not a use.
- **ttl**: the life of an item that the system makes and renews, for example an identity token or a kept answer (10.1).

## 3. Subjects
3.1 The id of a person has no colon. Thus the PDP can know if a subject is a person or a key (3.2, 3.7).
3.2 A key has the subject id `<prefix>:<local>`. This protocol defines the prefix `key`.
The local part has 1 to 64 characters from a to z, 0 to 9, underscore and hyphen. It is the id of the key in the system that makes the key. Example: the subject id `key:9b1c04e2aa71f0c3` has the local part `9b1c04e2aa71f0c3`.
3.3 The PEP sends the subject with the type `user`, for a person and for a key. The id is the `sub` of the identity token.
The PEP MUST treat the id as opaque text. The PEP MUST NOT read a meaning from its characters. A subject of another type is an unknown subject (11.1).
3.4 The PDP knows the owner of each key. The PEP does not send the owner (9.6).
3.5 The PDP answers `true` for a key only when two conditions are true at that moment. A grant of the key gives the action and covers the resource (4.3). The owner has the right to do that action on that resource. This protocol does not say how the PDP decides the current rights of the owner. A grant of the key that the rights of the owner do not cover gives nothing. The decision for a key follows this paragraph only.

When the owner loses a right, the key loses it at the first decision of the PDP after the PDP has the change. A kept answer of the PEP can delay this by `cache_ttl` at most (10.1). The PDP copies no right.
3.6 Unused.
3.7 An id with a colon and an unknown prefix, or a bad local part, is an unknown subject (11.1).
3.8 Each key is one subject. The grants and the limit values of a key are its own.
The system that makes a key chooses the local part of its subject id (3.2) and the format of its text. This protocol defines no format for the text of a key. When the system revokes or deletes a key, or when a key expires, the key is an unknown subject (11.1).
3.9 A PDP that decides from a copy of its directory MUST bound the age of that copy. It MUST answer `false` for each key when the copy is older than the bound. The PDP publishes the bound.

## 4. Resources and coverage
4.1 A resource has a type and an id. The PEP sends the most specific node that the operation uses. The service itself is the resource of type `service`, with the id of the service. It has no `ancestors`, or an empty array.

A resource below the service MUST carry the chain of its ancestors in `resource.properties.ancestors`. The chain is an array of objects with `type` and `id`, from the service to the parent of the resource, in this order. The first object is the service, and the chain does not hold the resource.

The types of the chain, then the type of the resource, follow the parents of the action document (5.2). The depth of a type is the number of steps from `service` to it: a type with the parent `service` has the depth 1. The maximum depth is 4.
An id is an exact string of 1 to 256 bytes in UTF-8, with no control character. The PEP does not encode it.
4.2 An id is unique only below its parent. Two parents can have a child with the same id.
4.3 A grant on a node covers the node and each node below it, also a node that the service adds later. A grant on a database does not cover its host.
Example, with the service and the notation of section 13: a grant of `data.read` on `service:datastore/host:prod` covers each database of this host, now and later. To give two databases only, give one grant on each of them. Alice in section 13 has no such grant, so her grants do not cover the host.
4.4 The request can carry `context.match`. The value `node` is the default: the answer is a decision about the node.
The value `subtree` asks if a grant applies on the node, above it or below it. A `true` answer for `subtree` is for the display only.
A PEP MUST NOT let an operation run because of it.

For a key, a `true` answer for `subtree` needs one node that a grant of the key and a right of the owner both cover (3.5). This node is the node of the question, a node above it or a node below it. The next example uses the databases `test1` and `test2` of section 13. A key with `data.read` on `test2`, and an owner with `data.read` only on `test1`, gets `false` for `data.read` with `subtree` on the service.
4.5 The PEP builds the chain from its own data. It never takes the chain from a client.

## 5. The action document and the list of the options
5.1 A service publishes its document at `/.well-known/procurauth/actions`, without authentication.
5.2 The document is a JSON object with these members:
- `server`: the id of the service. It is equal to the `aud` of the identity tokens of the service;
- `resource_types`: the tree of types below the service. Each item has `name`, `parent` and `description`. A type name has 1 to 32 characters: a to z first, then a to z, 0 to 9 or underscore. A type name is not `service` and occurs one time. The `parent` is `service` or another declared type, with no cycle and a depth of 4 at most (4.1). The type `service` is the root, and the document does not declare it;
- `actions`: each with `name`, `resource_types`, `description` and `limits`. A name has 1 to 64 characters: parts of a to z, 0 to 9 and underscore, with `.` between the parts. `resource_types` gives the types on which a grant of the action is valid: `service` or declared types, each one time. `limits` is optional: it gives the names of the limits of the action (6.2). A limit name that the document does not declare, or a name that occurs more than one time, makes the document bad (5.3). The list never has the action `access`, which opens the service to a subject (8.3). An action name occurs one time in the document;
- `resources`: optional, the nodes that the service names, each with `path`, and optionally `label` and `actions`. `path` is `<type>:<id>` segments with `/` between them, and the path does not hold the service. Each segment has a type whose parent is the type of the segment before it, or `service` for the first segment (4.1). The service percent-encodes each id: each byte outside A-Z, a-z, 0-9, `-`, `.`, `_` and `~` becomes `%XX`, with upper-case hexadecimal digits [RFC 3986]. This is the only text form of an id. Without `actions`, the item takes each action that lists its type. In `actions`, an action name that the document does not declare, or a name that occurs more than one time, makes the document bad (5.3);
- `limits`: optional, the limit declarations of the service (6.1). A limit name has 1 to 32 characters: a to z first, then a to z, 0 to 9 or underscore.

5.3 The reader checks the document. A bad member, or an unknown member of a limit declaration, makes the whole document bad.

A read fails when it gets a status other than 200, also 404, or no answer. After a bad document or a failed read, the reader keeps the last good document, for a maximum time (5.3a). Only a good document replaces it.

The reader bounds the size of the document that it reads, and it gives this bound in its documentation. A larger document is bad (5.3c).
5.3a The reader MUST give this maximum time in its documentation. The time starts at the last good read. After this time, the reader acts as with no good document of the service (11.1).
5.3b A reader that reads the document of each service at a fixed period SHOULD make these reads at equal intervals over the period. With a period of 5 minutes, it makes approximately 3.3 reads each second for 1,000 services and approximately 33 for 10,000. The reader keeps the last good document of each service. With a bound of 64 KiB for each document, they take approximately 66 MB at most for 1,000 services and 655 MB for 10,000.
5.3c A reader MUST accept a document of 64 KiB, with 64 actions, 16 types, 256 resources and 16 limit declarations. It MUST accept a label of 60 characters, a description of 300 characters and a unit of 20 characters. A reader MAY accept more. A service SHOULD stay within these numbers, because a reader MAY treat a larger document as bad (5.3).
5.4 The labels and the descriptions are in English.
5.5 Each use has one action. That action lists each budget that the use spends and each ceiling that applies to the action of the use. A ceiling of another permission of the operation applies only to the part that this permission lets run (5.5a).

A service MUST NOT ask two actions with `context.usage` for one operation, except to choose the action of the use as 10.1 says. Only the action of the use takes units (5.5a). A PEP can choose the action of a use among several actions for one operation (10.1). Other actions of the operation can list a budget.
5.5a An operation can also need permissions on other actions or on other resources. The PEP asks each of these permissions without `context.usage` (6.6). It asks only the action of the use with `context.usage`, when this action lists a budget (6.4). Thus one operation takes units for one action only. 10.1a gives an example. This is also true when another of its actions lists a budget.

A `true` answer for one of these other permissions can have `context.limits`. The PEP applies these ceilings to the part of the operation that this permission lets run (7.5).
5.6 A service MAY publish a route that lists the children of a node, page by page, with a search. A system that shows a form for grants, the caller, uses it to show the options of a node. The request is `GET /.well-known/procurauth/resources` with the query parameters of 5.7, and the answer is a JSON object (5.8).

The request carries an identity token that the edge makes for the person who fills the form (section 9). Only the edge signs identity tokens (9.1, 9.4), so the caller is a part of the edge. The caller sends the request to the origin of the action document (5.1). Thus the rule of 9.4 lets the caller reach the service.

The service checks the token as 9.4 says, and it lists only the children that the subject of the token can see. The member `resources` of the action document still names the nodes at the top (5.2).

For each child that it lists, the service MUST get a `true` answer with `context.match` = `subtree` (4.4). The question of this answer names an action whose `resource_types` holds the type of the child (5.2). The service can use a kept answer (10.1). The service MAY also apply its own rules that remove more children, and it gives these rules in its documentation. When the PDP gives no valid answer, the service follows 10.3.

The service SHOULD bound the number of questions to the PDP for one request. When it reaches this bound, it gives the items that it has and a `next` value (5.7, 5.8). Thus a node with many children that the subject cannot see does not make one request ask the PDP for each child.
5.7 The caller encodes the value of each query parameter as 5.2 encodes an id. Each byte outside A-Z, a-z, 0-9, `-`, `.`, `_` and `~` becomes `%XX`, with upper-case hexadecimal digits [RFC 3986]. The service decodes each `%XX` one time. It does not read `+` as a space. The parameters are:
- `parent`: optional, the path of the node, in the form of the member `path` of 5.2. Without it, the service lists the nodes whose type has the parent `service`;
- `type`: mandatory, the type of the children. Its parent in the action document is the type of the node of `parent`, or `service` when the request has no `parent`;
- `q`: optional, a search text. The service lists the children whose id or label holds this text, with rules that it chooses;
- `limit`: optional, the maximum number of items, a whole number from 1. The service MAY give fewer items;
- `after`: optional, the value of `next` in the previous answer.

The service decodes the value of `parent` one time. Then it reads the value as a path of 5.2: it splits it at each `/`, and then it decodes each id. Example: the database `a/b` of the host `prod` is `parent=host%3Aprod%2Fdatabase%3Aa%252Fb`.

A parameter is bad when it occurs more than one time, or when its value breaks the rules of 5.7. Thus a `type` is bad when its parent in the action document is not the type of the node of `parent`, or `service` without `parent`. A bad parameter gets HTTP 400. A request without `type` also gets HTTP 400. The service ignores a parameter that 5.7 does not name.

A request with no token, or with a token that is not valid, gets HTTP 401 (9.4). A node that does not exist, or that the subject of the token cannot see, gets an answer with no items.
5.8 Each item of `items` is one child of the node, with these members:
- `id`: the id of the child, as 4.1 says. The service does not encode it;
- `label`: a short text for the form, for example the id itself;
- `has_children`: `true` when the route can list children below this child.

`next` is the cursor of the next page, or `null` on the last page. The caller treats it as opaque text. The path of a child is the path of `parent`, then `/`, then `<type>:<id>`, with the id encoded as 5.2 says. Without `parent`, the path is only `<type>:<id>`.
Example: the databases of the host `prod` whose names hold `test`, two at a time (section 13).
```text
GET /.well-known/procurauth/resources?parent=host%3Aprod&type=database&q=test&limit=2
```
```json
{ "items": [ { "id": "test1", "label": "test1", "has_children": true },
             { "id": "test2", "label": "test2", "has_children": true } ],
  "next": null }
```
A caller MUST accept an answer of 64 KiB with 50 items, an id of 256 bytes and a label of 60 characters. The service SHOULD stay within these numbers. A caller MAY treat a larger answer as a failed call.
5.9 The caller MAY keep each answer for a short time that it chooses. An entry applies only to the same service, subject and query parameters. The caller never gives an entry to another subject. It bounds the number of entries. This bound does not grow with the number of services: it is the same for 1,000 and for 10,000 services.

The caller bounds the size of an answer and the number of its items. A larger answer is a failed call.

## 6. Limits and budgets
6.1 A limit declaration has `name`, `label`, `description`, `unit` and `kind`. The kind is `ceiling` or `budget`. A name is unique in the document.

A ceiling also has `min` and `max`. They are whole numbers, `min` is 0 or more, and `min` is not above `max`. Another value makes the document bad (5.3). A budget has neither: a budget declaration with `min` or `max` makes the document bad (5.3).

A budget name is the plural noun of the thing that it counts, with no unit and no window, for example `requests`. A qualifier can come before the noun, for example `write_requests` for a second budget of requests (6.2). A budget name never starts with `max_` (7.1).
A grant gives a value for a limit in one of two forms:
- for a ceiling, a whole number from `min` to `max`, for example `30`;
- for a budget, an array of 1 to 4 items, one item for each window. Each item has `amount` and `window`, for example `[{"amount": 10, "window": "second"}, {"amount": 300, "window": "minute"}]`. The amount is a whole number from 1. The window is `second`, `minute`, `hour` or `day`. Two items never have the same window.

Each window of a budget value has its own counter (6.7).

6.2 An action lists the limits that apply to it. One use of the action takes units from each budget that it lists. The PEP applies each ceiling that it lists (section 7). To count one action separately, the service declares a second budget and lists it only on that action.
6.3 The window is fixed. It starts at a multiple of its length since the Unix epoch, by one clock that all instances of the PDP use. A client can send at most two times the amount around the boundary of two windows. A shorter window on the same grant bounds this burst.
6.4 For each use of an action that lists a budget, the PEP sends one question with `context.usage` (6.11). The one exception is the kept answer of 10.1. For an action without a budget, it sends none.
`context.usage` is an object with one member, `units`. In this version, `units` is 1: `"context": {"usage": {"units": 1}}`. Another value gets HTTP 400.
6.5 The PDP first checks the subject, the resource and the grants. It takes units only when they give `true`. It takes the units from each counter of the use in one atomic step, or from none. These are the counters of each window, for the key and for its owner (6.7).
If one counter has fewer units left than the use asks, the PDP takes none. It answers `false` with the reason `budget_exceeded` and `retry_after` (section 11).
6.6 A question without `context.usage` counts nothing.
6.7 Each subject that a grant gives a budget has its own counter for each window of that budget value. A use by a key takes units from each of these counters that exists: the counters of the key and the counters of its owner. A use with no counter takes no unit (6.12).
The uses of the owner and the uses of all its keys share the counters of the owner. The PDP chooses the counters. The PEP never names a counter.
6.8 A PDP with several instances counts each counter one time for all of them. The units that all its instances take from a counter never exceed its amount in one window. No instance counts on its own.
6.9 When the PDP cannot read or change a counter that a question needs, it immediately answers HTTP 503, never a decision [RFC 9110, 15.6.4].
A PDP publishes the longest time that it takes to answer a question with `context.usage`. Within this time, it gives a decision or HTTP 503. The PDP can give this time in the metadata member `procurauth_usage_max_seconds` (section 14).
6.10 A limit that no grant gives is no limit from the PDP. A grant value for a limit that the current document of the service does not declare gives nothing.
The right of the grant and its other values still apply. The own limits of the PEP still apply.
6.11 Only a request with one evaluation can carry `context.usage`: an Access Evaluation API request, or an Access Evaluations API request without items [AUTHZEN 1.0, l.473].
Any other request that has `context.usage` at any level gets HTTP 400, and the PDP counts nothing. This applies to an Access Evaluations request with items and to each Search API request. A request with `context.usage` and `context.match` = `subtree` also gets HTTP 400.
A PEP that chooses among several actions for one operation follows 10.1.
6.12 A `true` answer to a question with `context.usage` has `context.usage.units`: the units that the PDP took from each counter of the use, 0 or 1. The value 0 tells that no budget applies to the subject for this action.
A PEP that gets `true` without this member MUST treat the answer as `false`.

## 7. Ceilings
7.1 A ceiling is the maximum of one use. A lower value is stricter: a service MUST NOT declare a ceiling where a higher value is stricter.
A ceiling name is `max_` and a noun, with no unit. A duration is in whole seconds. Examples: `max_rows`, the most rows that one read gives, and `max_duration`, the longest run of one use, in seconds.
7.3 For a `true` answer, `context.limits` gives each ceiling that the action lists and that a grant gives. It holds only ceilings. The PDP uses a ceiling value only on a grant of the action of the question, for a ceiling that this action lists. The PDP ignores a ceiling value on any other grant. The value is the combination of these grants that cover the resource, as section 8 says. A budget value never appears in an answer.

Example: `{"decision": true, "context": {"limits": {"max_duration": 30}}}`. For a use of an action that lists a budget, the PEP applies the `context.limits` of the answer to the question with `context.usage` (6.4).
7.4 A ceiling applies to each use of the action, on each route of the service.
7.5 A ceiling is mandatory to understand. A PEP that cannot apply a ceiling of `context.limits` MUST treat the answer as `false`.
The action document of the service is its adoption: the PDP gives only the ceilings that the action lists. The PEP sends no opt-in member.
7.6 The PDP does not add `context.limits` to a `false` answer. A PEP ignores it.

## 8. Combination of values
8.1 Limits narrow access. No limit widens it. A decision for a key has two sides, the key and its owner, and each limit value of both sides applies (3.5). For a ceiling, the lowest value applies: among the grants of the asked action that cover the resource (7.3), and between the two sides. For a budget, each side has its own counters (6.7). The PDP never compares two budgets.
8.2 A value that only one grant or only one side gives stays as it is.
8.3 A subject has one value for each budget of a service. It is on the grant of the action `access` on the service: the grant that opens the service to the subject. The PDP ignores a budget value on any other grant.
An edge gives an identity token for a service only to a subject with a `true` decision for the action `access` on that service (3.5). The PEP never asks for `access`.
8.4 For a ceiling, a value of a key above the value of its owner has no effect (8.1). For a budget, the counters of the owner still bound each use of the key (6.7). The budget of a key adds no units to its owner.

## 9. The identity token
9.1 An edge authenticates a client and gives a service an identity token. This section defines the token for a person and for a key. A service receives no other token.
When a client sends a header with the name of the token header, the edge MUST replace it. The edge MUST remove the text of the key from the request before it sends the request to the service.
9.2 The token is a JWT, signed with `Ed25519` or `ES256`, with the header type `JWT`. The operator MUST set the life of the token (`exp` minus `iat`) to no more than the maximum age that each service accepts. A service refuses a token with a longer life (9.4).
The edge MUST use its signing key only for the identity token.
[RFC 9864, 4.1.1] registers the JOSE name `Ed25519` for the header `alg`, and deprecates the name `EdDSA` [RFC 9864, 4.1.2].
9.3 Claims: `iss`, `sub`, `aud`, `iat` and `exp`. A token for a key also has `owner`.
- `sub` is the id of the subject (section 3). `aud` is the id of the service.
- For a key, `owner` is the id of its owner (3.1). The token and the questions never hold the text of the key. The token has no `act` claim, because `sub` is the key and not the person.

9.4 The configuration of the service names the token header, the value of `iss` and the public keys of the edge. It also names the id of the service, its maximum age for a token and its clock skew.

The edge gives its public keys as a JWK Set [RFC 7517, 5]. When the set holds more than one key, the edge puts `kid` in the header of each token [RFC 7515, 4.1.4]. The service then checks the token with the key that has this `kid`. The service refuses a token with a `kid` that the set does not hold.

For each request other than a read of its action document (5.1), the service MUST check that `alg` is one of the algorithms of 9.2 [RFC 8725, 3.1]. It MUST also check the signature, `typ` (`JWT`), `iss`, `aud` and `exp`. It refuses a token without `iss`, `sub`, `aud`, `iat` or `exp` (9.3). `aud` is the id of the service, or an array that holds it [RFC 7519, 4.1.3].

The service refuses a token whose `exp` minus `iat` is more than its maximum age. It also refuses a token whose `iat` is later than its clock plus the skew. The skew also applies to `exp`: the service refuses a token when its clock is later than `exp` plus the skew. It refuses any other `typ`, for example `at+jwt` [RFC 8725, 3.12].

The service takes the token only from the header that the edge sets, never from `Authorization`, a cookie or a query parameter. The service MUST accept requests only through the edge, for example with a network rule (section 12). The service answers a read of its action document (5.1) without a token, through the edge. A request with no token, or with a token that is not valid, gets HTTP 401. The service MUST ignore an unknown claim.

The read of the action document is the one exception to the rule on the edge. The service can also answer this read directly to the reader of 5.3 that the operator names.
9.5 `owner` is for logs and for approvals. A service MUST NOT use it in a decision.
9.6 The service sends no claim other than `sub` (3.3) to the PDP.
9.7 The token carries no grant, no limit and no decision. A decision comes only from the PDP.
A service MAY keep the result of a token check until the `exp` of the token, only for that exact token. It bounds the number of kept results.
9.8 An edge that refuses a key answers HTTP 401 with `WWW-Authenticate: Bearer`. When the request has the text of a key, the header also has `error="invalid_token"` [RFC 6750, 3.1]. The edge never redirects a request that has the text of a key.
The body of this answer is empty. Thus the edge needs no part of the body of the request.
9.9 An edge MAY keep an identity token that it made, and give it again to the same subject for the same service. It gives a kept token only after it authenticated the client and got a `true` decision for `access` (8.3) for this request. It gives a kept token only before its `exp`, and it bounds the number of kept tokens.

The number of kept tokens grows with the pairs of a subject and a service that this subject uses. Example: 1,000 subjects that each use 10 of 1,000 services need 10,000 tokens, approximately 10 MB at 1 KB each. If each subject uses 100 of 10,000 services, they need 100,000 tokens, approximately 100 MB. A bound keeps the memory fixed: when the table is full, the edge signs a new token.

## 10. Requirements for a PEP
10.0 Before it integrates, a PEP gets from the operator the URL of the PDP and the credential for the PDP (step 4). It also gets the values of 9.4, except the id of the service. It gives the operator the id of the service (5.2). It also gives the operator the origin of its action document (5.1).

Then the PEP integrates in seven steps:
1. Check the identity token as 9.4 says. Send `sub` as the subject id, with the type `user` (3.3).
2. Refuse each request without a valid identity token, on each route except the route of the action document (5.1). Accept requests only through the edge, for example with a network rule (9.4).
3. Give each use one action and one resource with its chain (5.5). Declare the actions and their limits in the action document (section 5).
4. Ask the PDP for each operation. Use the endpoints of its metadata `/.well-known/authzen-configuration`, or the default paths [AUTHZEN 1.0, l.1382]. Send the credential of the service for the PDP in `Authorization: Bearer`, a choice that AuthZEN 1.0 leaves free [AUTHZEN 1.0, l.1743-1749]. The PEP MUST secure the link to the PDP by adequate means, for example TLS [AUTHZEN 1.0, l.1739]. Keep answers for `cache_ttl` at most (10.1).
5. For a use of an action that lists a budget, send one Access Evaluation with `"context": {"usage": {"units": 1}}` (6.4, 6.11). Treat a `true` answer without `context.usage.units` as `false` (6.12). Reuse a kept answer only as 10.1 says. Do not send it again, except as 10.6 says.
6. Apply each ceiling of `context.limits` (7.5). For a use, take the ceilings of the action of the use from the answer to its question. For an action that lists a budget, this is the question with `context.usage` (6.4). Take the ceilings of each other permission from its own answer (5.5a).
7. Map each refusal with 10.3.

10.1 The PEP MUST ask the PDP for each operation, with two exceptions. For a read of the action document (5.1), the PEP asks no question. For a request to the route of 5.6, it asks only the questions of 5.6, without `context.usage`. For a use of an action that lists a budget, the question with `context.usage` is the question of the operation (6.4). The PEP MUST NOT send the same question without `context.usage` before it, except to choose among several actions (below). The PEP MAY keep an answer to a question without `context.usage` for at most `cache_ttl`, a time that its configuration sets.

A kept answer applies only to the same subject, action, resource with its chain (`resource.properties.ancestors`), and `context.match`. These rules apply to the kept answers:
- A kept `true` answer never starts a use of an action that lists a budget. The PEP keeps the answers to questions with `context.usage` separate from the other answers. It never keeps a `true` answer with `units` above 0. It MAY keep a `true` answer with `units` equal to 0 for at most `cache_ttl`. That kept answer is the one exception: it lets a use run with no question (6.12).
- A kept `false` answer MAY refuse a use with no question.
- The PEP MAY keep a `false` answer with `budget_exceeded` for the same subject, action, and resource with its chain. It keeps that answer for the lower of `retry_after` and `cache_ttl` at most. Until then, it refuses the use as 10.3 says. Its `retry_after` gives the seconds to the end of that time.
- A PEP that chooses among several actions for one operation MAY first ask them without `context.usage`, in one request. Then it sends one question with `context.usage` for the action of the use, when this action lists a budget (6.4).
- Or that PEP MAY ask them with `context.usage`, one at a time, in its order of preference. It stops at the first `true` or at the first `budget_exceeded`. A `false` answer without `budget_exceeded` counted nothing. The PEP MAY keep it as an answer to the same question without `context.usage`. If the PEP kept a `true` answer to that question, it deletes its kept answers for that subject and that resource.

10.1a An example of 5.5a: an operation copies the table `orders` of the database `test1` into the database `test2` of the service `datastore` (section 13). For Alice, the PEP first asks `data.read` on the table `orders` of `test1`, without `context.usage`. Her grant on `test1` gives `max_rows` 1000. Then the PEP asks `data.write` on the database `test2`, with `context.usage`. Only the second question takes a unit. When the first answer is `false`, the PEP refuses the operation and sends no question with `context.usage`.

The value `max_rows` 1000 applies to the read: thus the copy reads 1000 rows at most. The first question takes no unit, although `data.read` also lists the budget `requests`.
10.1b The PEP bounds the number of kept answers (10.1). The bound does not depend on the requests of the clients, because a client chooses the resources of the questions. When the table is full, the PEP keeps no new answer.
10.2 The PEP applies the ceilings as 7.3 and 7.5 say.
10.3 The PEP MUST fail closed. It MUST NOT send `context.reason` to the client. On an HTTP route, it maps each answer of the PDP as the list below shows. The MCP binding gives the map for an MCP request [MCP-BINDING]. Its tool error for `budget_exceeded` is the one exception to the rule on `context.reason`.
- `false` with no reason, or with a reason other than `budget_exceeded`: HTTP 403.
- `false` with `budget_exceeded`: HTTP 429, with `Retry-After` set to the seconds of `retry_after` (11.1).
- No answer, an HTTP error, or an answer that is not valid: HTTP 503.

10.6 The PEP MUST NOT send a question with `context.usage` again after a timeout, a lost answer or a connection error. The one exception: the connection failed before the PEP wrote the request.
The units of a lost answer stay counted. The PEP refuses that use as for a PDP that does not answer (10.3). The PEP SHOULD wait for each answer longer than the longest time that the PDP publishes (6.9).
10.7 The PEP SHOULD keep its connections to the PDP open between questions [RFC 9112, 9.3]. It SHOULD keep a small fixed number of connections. The PDP publishes the longest time that it keeps an idle connection open. The PEP closes an idle connection before the PDP does: after half of this time, or less. The PDP can give this time in the metadata member `procurauth_idle_max_seconds` (section 14).
10.7a A PDP publishes the largest body and the largest number of items of one Access Evaluations request that it reads. A PEP sends its questions in requests within these maxima. When necessary, it splits them into several requests. The PDP can give these maxima in the metadata members `procurauth_evaluations_max_bytes` and `procurauth_evaluations_max_items` (section 14).
10.8 Unused. The MCP binding holds the tool error of a refused budget [MCP-BINDING].

## 11. Answers and reasons
11.1 A `false` answer can carry `context.reason`. The values are:
- `unknown_subject`: the PDP does not know the subject. A revoked, expired or deleted key, a deleted person, and a key whose owner does not exist, get this reason. A subject of a type other than `user` (3.3), and an id with an unknown prefix or a bad local part (3.7), also get it;
- `invalid_resource`: the PDP checks the resource with the last good action document of the service of the PEP (5.3). It gives this reason when the first object of the chain is not that service, or when the resource is the service of another PEP. A resource below the service with no `ancestors`, or an empty array, has no first object of the chain, so it also gets this reason (4.1). It also gives it when the types of the chain and of the resource do not follow the parents of the document. It also gives it when the document does not declare a type, or when the depth is more than 4. With no good document of the service, the PDP answers `false` without a reason for each node, except a question for `access` on the service (8.3, 11.2);
- `invalid_request`: only in an item of an Access Evaluations answer. The item has a bad `context.match`, or a `resource.properties.ancestors` that is not an array of objects with `type` and `id`. In a request with one evaluation, a bad member of this protocol gives HTTP 400. This is a rule of this protocol: the core makes 400 mandatory only when the request does not have a mandatory attribute [AUTHZEN 1.0, l.1416]. Its error table gives 400 to a bad request in general [AUTHZEN 1.0, l.1425-1432];
- `budget_exceeded`: a counter of the use has too few units left. The PDP answers HTTP 200 with `false`, never 429. The context also has `retry_after`: the seconds to the latest end among the windows of the counters that refuse. It is a whole number, at least 1: a time of 11.2 seconds gives 12. It has the meaning of the HTTP field `Retry-After` [RFC 9110, 10.2.3].

11.2 Any other `false` answer has no reason, for example when no grant covers the resource. An answer never shows the grants.

## 12. Security considerations
- The PDP trusts the PEP [AUTHZEN 1.0, l.1766]. A PEP that is not safe can name any person as subject. The PDP answers each PEP only for its own service.
- The PDP counts only the uses that a PEP declares with `context.usage`. A budget limits the clients of a service, not the service. A PEP that does not send `context.usage` spends no unit.
- A key never has more than its owner has, because of 3.5.
- A new key is a new subject (3.8), so it has new counters and starts with a full budget of its own. When the owner has a budget, the counters of the owner still bound the uses of all its keys (6.7). Give the budget to the owner to bound the uses of all its keys together.
- A client never chooses the owner, the chain or the counter.
- A PEP that ignores a ceiling widens the access. This is why 7.5 makes it mandatory.
- The PDP is a single point of failure. The protocol accepts it: fail closed (6.9, 10.3).
- An old copy of the directory is not safe. This is why 3.9 bounds its age.
- A client that reaches a service without the edge can use an identity token that it gets until its `exp`. It then skips the checks of the edge, for example the decision for `access` (8.3). This is why 9.4 makes a service accept requests only through the edge.
- An edge that sends the text of a key to a service lets that service use the key on each other service of the owner. This is why 9.1 makes the edge remove it.
- A client that sends a request again makes a new use. The PDP counts it again. This over-count is safe.
- The credential of each service for the PDP (10.0, step 4) SHOULD have at least 128 random bits. The PDP SHOULD keep only its SHA-256 digest, so that a leak of the data of the PDP gives no credential. The digests take approximately 32 KB for 1,000 services and approximately 320 KB for 10,000.

## 13. Examples
The examples use the service `datastore`, with the types `host`, `database` and `table`. In the examples, `service:datastore` names the service, and `service:datastore/host:prod` names the node `host:prod` (5.2). This notation is only for the examples and the conformance data.

The action document of the service:
```json
{ "server": "datastore",
  "resource_types": [ { "name": "host", "parent": "service", "description": "One database server." },
                      { "name": "database", "parent": "host", "description": "One database." },
                      { "name": "table", "parent": "database", "description": "One table." } ],
  "actions": [ { "name": "data.read", "resource_types": ["service", "host", "database", "table"],
                 "description": "Read data.", "limits": ["requests", "max_rows", "max_duration"] },
               { "name": "data.write", "resource_types": ["service", "host", "database", "table"],
                 "description": "Change data.", "limits": ["requests", "max_duration"] } ],
  "resources": [ { "path": "host:prod", "label": "Production" } ],
  "limits": [ { "name": "requests", "label": "Requests", "description": "Requests that run.",
                "unit": "request", "kind": "budget" },
              { "name": "max_rows", "label": "Most rows", "description": "The most rows that one read gives.",
                "unit": "row", "kind": "ceiling", "min": 1, "max": 1000000 },
              { "name": "max_duration", "label": "Longest run", "description": "The longest run of one use, in seconds.",
                "unit": "second", "kind": "ceiling", "min": 1, "max": 600 } ] }
```
The list of the options gives the databases below `host:prod`, as the example of 5.8 shows.

**A person with two databases.** Alice reads the database `test1`, and she reads and writes the database `test2`. Both databases are on the host `prod`. Her grants are:
- `access` on `service:datastore`, with `{"requests": [{"amount": 10, "window": "second"}, {"amount": 300, "window": "minute"}]}`;
- `data.read` on `service:datastore/host:prod/database:test1`, with `{"max_rows": 1000}`;
- `data.read` on `service:datastore/host:prod/database:test2`, with `{"max_rows": 5000, "max_duration": 30}`;
- `data.read` on `service:datastore/host:prod/database:test2/table:orders`, with `{"max_rows": 100}`;
- `data.write` on `service:datastore/host:prod/database:test2`, with `{"max_duration": 10}`.

A read of the table `orders` of `test2`, for one use:
```json
{ "subject":  { "type": "user", "id": "alice" },
  "action":   { "name": "data.read" },
  "resource": { "type": "table", "id": "orders",
                "properties": { "ancestors": [ { "type": "service", "id": "datastore" },
                                               { "type": "host", "id": "prod" },
                                               { "type": "database", "id": "test2" } ] } },
  "context":  { "usage": { "units": 1 } } }
```
The answer:
```json
{ "decision": true, "context": { "limits": { "max_rows": 100, "max_duration": 30 }, "usage": { "units": 1 } } }
```
A ceiling takes the lowest value among the grants of the asked action that cover the resource (8.1). Two grants of `data.read` cover the table `orders`, so `max_rows` is 100, the lower of 5000 and 100. Only the grant on `test2` gives `max_duration`, so its value 30 stays (8.2). The grant of `data.write` on `test2` also covers the table, but it is not a grant of the asked action. Thus its value 10 does not apply to a read (7.3).

The answers to the other questions of Alice, each with `context.usage`:
- `data.write` on `database:test2`: `true`, with `max_duration` 10.
- `data.read` on `database:test1`: `true`, with `max_rows` 1000.
- `data.write` on `database:test1`: `false` without a reason. The PDP takes no unit.
- `data.read` on `host:prod`: `false` without a reason. A grant on a database does not cover its host (4.3).

Each use of Alice takes one unit from her counter of the second and one unit from her counter of the minute (6.7). The eleventh use in one second gets `false` with `budget_exceeded` (11.1). When the counter of the minute also refuses, `retry_after` gives the end of the minute, the later end.

**A key of Alice.** Alice has a key with the subject id `key:9b1c04e2aa71f0c3` and these grants:
- `access` on `service:datastore`, with `{"requests": [{"amount": 100, "window": "minute"}]}`;
- `data.read` on `service:datastore/host:prod/database:test2`, with `{"max_rows": 10000}`.

The identity token of the key. The header: `{"alg": "Ed25519", "typ": "JWT"}`. The claims:
```json
{ "iss": "https://edge.example", "sub": "key:9b1c04e2aa71f0c3", "aud": "datastore",
  "iat": 1792569600, "exp": 1792569900,
  "owner": "alice" }
```
The service sends only `sub` to the PDP (9.6). A token for a person has no `owner`, and its `sub` is the id of the person.

A use of the key, with one unit:
```json
{ "subject":  { "type": "user", "id": "key:9b1c04e2aa71f0c3" },
  "action":   { "name": "data.read" },
  "resource": { "type": "database", "id": "test2",
                "properties": { "ancestors": [ { "type": "service", "id": "datastore" },
                                               { "type": "host", "id": "prod" } ] } },
  "context":  { "usage": { "units": 1 } } }
```
The answer, when the use can run:
```json
{ "decision": true, "context": { "limits": { "max_rows": 5000, "max_duration": 30 }, "usage": { "units": 1 } } }
```
The value 10000 of the key is above the value 5000 of Alice, so it has no effect (8.4). The grant of Alice on the table `orders` does not cover the database `test2` (4.3). The use takes one unit from three counters: the minute of the key, and the second and the minute of Alice (6.7).
The answer, when the budget is spent:
```json
{ "decision": false, "context": { "reason": "budget_exceeded", "retry_after": 12 } }
```
A PEP that chooses between `data.write` and `data.read` asks `data.write` with `context.usage` (10.1). The key has no grant of `data.write`, so it gets `false` without a reason, and the PDP takes no unit.
The PEP keeps this answer and asks `data.read` with `context.usage`. The next run within `cache_ttl` costs one call.

## 14. Relation to AuthZEN work (informative)
- The chain and the coverage come from a proposal of the author, issue #760 of the AuthZEN repository. The tree of types of the action document (5.2) comes from issue #762. Issue #761 proposes a scoped Resource Search, which this protocol does not define. The three issues are open, and they are not part of AuthZEN. The list of the options (5.6) is a route of the service, not a search of the PDP.
- Issue #521 proposes `context.constraints`, a typed list of bounds. It is open. This protocol has the same idea: one list of limits with two kinds.
- This protocol adds the members `context.usage`, `context.limits` and `context.match`. A later value goes inside one of them. This protocol sends no `next_action`.
- `context.retry_after` has the unit and the meaning of the `retry_after` of the Access Request and Approval profile [ARAP, l.616], which gives it for a retry. The reasons of this protocol are not ARAP codes.
- The token issuance profile asks for a URN for an extension that adds response vocabulary [AUTHZEN-ISSUANCE, l.1189-1192]. This version has no URN member: see section 15, item 5.
- The token issuance profile has a close precedent: a ceiling from the PDP, mandatory-to-understand members, and values that a PEP ignores on a denial [AUTHZEN-ISSUANCE].
- The token issuance profile defines no rate-limit member. It sends such limits as advisory context and as limits on the token that it issues. A downstream enforcement point applies them [AUTHZEN-ISSUANCE, l.183-190, 1011-1049]. This protocol counts in the decision on purpose: one call for each use, and the count and the `true` answer are one atomic step.
- The Obligations profile defines no numeric-limit type. Its obligations are coarse declarative instructions, and the two sides make an agreement about the meaning of the type `custom` [AUTHZEN-OBLIGATIONS, l.110, 363-365]. A PEP treats an obligation that it does not know as a denial.
- A question with `context.usage` is not idempotent. Two equal questions can get `true`, then `false` with `budget_exceeded`. The idempotence case of the AuthZEN certification (c-2-6) applies only to questions without `context.usage`.
- `owner` is a private claim [RFC 7519, 4.3]. It is not in the IANA JWT Claims registry. In OAuth token exchange [RFC 8693], `sub` is the person and `act` is the actor. In this protocol, `sub` is the key. A service that reads only `sub` thus decides for the key, never for the person.
- The relation of the MCP refusals to the COAZ binding for MCP is in the MCP binding [MCP-BINDING, section 11].
- The metadata members of 6.9, 10.7 and 10.7a are not in the IANA registry "AuthZEN Policy Decision Point Metadata" [AUTHZEN 1.0, l.1821-1823]. A PEP that does not know them MUST ignore them [AUTHZEN 1.0, l.1342]. Register them before a publication outside the network of the author.

## 15. Open points
1. If AuthZEN adopts the extensibility model of pull request #697 as written, the adoption by the action document (7.5) is not adoption on the wire. A PEP then sends `supported_mandatory_extensions`, and the three members of section 14 get names that resist collision.
2. The conformance cases are data in `conformance/` of the repository of this specification, and each case cites a paragraph of this document. The series U is for a PEP, and the series D is for a PDP. The series E is for an edge (1.3), and its cases test 1.4, 8.3, 9.1 to 9.3, the second paragraph of 9.4, 9.8 or 9.9. The MCP binding holds the cases that only MCP needs: U18, U23, U25 to U31 and E01 [MCP-BINDING]. `conformance/` gives none of these ids to another case, so its series E starts at E02. No series tests the system that makes keys (3.2, 3.8) or the caller of the route of 5.6 (5.6 to 5.9) in this version.
3. A later version can add `remaining` to `context.usage`. A PEP can then copy it into the `RateLimit` field [RATELIMIT]. The seconds to the end of a window keep one name: `retry_after`.
4. Before a publication outside the network of the author, register the well-known name `procurauth` [RFC 8615]. The two documents of this protocol are below this name: `/.well-known/procurauth/actions` (5.1) and `/.well-known/procurauth/resources` (5.6).
5. The token issuance profile registers a capability URN for an extension that adds response vocabulary. `context.limits` is such a vocabulary. The project ProcurAuth defines a capability URN later, after a check of its format. No URN member exists in this version. Until then, `context.usage.units` in each counted answer shows that a PDP counts (6.12).
6. A PEP asks the PDP for each operation (10.1). A later version can give a rule for a request that runs no action of the action document, for example a static file. Until then, the service declares an action for such a request, on the type `service`, and asks it.

## 16. Implementations and tools (informative)
16.1 `IMPLEMENTATIONS.md` of the repository of this specification lists the known implementations. The repository also has a linter of action documents, a test PDP and a maker of test identity tokens. It also has a checker of key texts, a runner of the conformance cases (15, item 2) and a reference PEP library in Rust. The checker of key texts takes the format of the text as an input, because this protocol defines no format (3.8). `docs/` and the README of each crate describe them.

## References
- [AUTHZEN] (also cited as [AUTHZEN 1.0]) AuthZEN Authorization API 1.0, Final Specification, OpenID Foundation. A citation l.N is a line of `api/authorization-api-1_0.md` in the repository `openid/authzen` at commit `4deba63`.
- [AUTHZEN-ISSUANCE] AuthZEN Profile for OAuth 2.0 Token Issuance, Draft 1: `profiles/authzen-oauth/authzen-oauth-token-issuance-1_0.md` at the same commit.
- [AUTHZEN-OBLIGATIONS] AuthZEN Profile for Obligations, Draft 1: `profiles/authzen-obligations-profile-1_0.md` at the same commit.
- [ARAP] AuthZEN Access Request and Approval Profile, Draft 1: `profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md` at the same commit.
- [MCP-BINDING] The MCP binding of ProcurAuth, an internal binding of this protocol: `bindings/mcp/` in the repository of this specification. It is normative for a service with an MCP endpoint and for an edge in front of such a service (1.3).
- [RATELIMIT] IETF RateLimit header fields for HTTP, draft-ietf-httpapi-ratelimit-headers-11.
- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels. [RFC 8174] Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- [RFC 3986] Uniform Resource Identifier (URI): Generic Syntax.
- [RFC 6750] The OAuth 2.0 Authorization Framework: Bearer Token Usage.
- [RFC 7515] JSON Web Signature (JWS). [RFC 7517] JSON Web Key (JWK).
- [RFC 7519] JSON Web Token. [RFC 8693] OAuth 2.0 Token Exchange. [RFC 8725] JSON Web Token Best Current Practices.
- [RFC 8615] Well-Known Uniform Resource Identifiers.
- [RFC 9110] HTTP Semantics. [RFC 9112] HTTP/1.1.
- [RFC 9864] Fully-Specified Algorithms for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE).
