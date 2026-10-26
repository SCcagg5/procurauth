# Rules of access-lint

This file lists each rule that `access-lint` reports. Each rule has the paragraph of the protocol, a stable code, a severity and a short text. The text output shows the short text. The JSON output shows the code, the short text and a full message.

A test makes sure that this table and the table in `src/rules.rs` are the same. Each rule has a bad fixture and a good fixture in `tests/fixtures/<scope>/<rule>_<code>/`.

## Severity

An error means that the input breaks a rule of the protocol. At least one error gives the exit code 1. A warning means that a SHOULD or a limit of 5.3c is not met, or that a value has no effect. A warning does not change the exit code.

## Scopes

- `document`: the action document, the argument of the tool.
- `grants`: the file of `--grants`. Its format is `schemas/grants-file.schema.json`.
- `options`: the file of `--options`. Its format is `schemas/options-file.schema.json`.

The checks of `grants` and `options` that need the document run only when the document has no error. Otherwise the tool checks the form of the input only.

## Table

| Scope | Rule | Code | Severity | Short text | Meaning |
| --- | --- | --- | --- | --- | --- |
| document | 5.3 | `bad_json` | error | text is not valid JSON | The text is not JSON, or an object has the same member two times. |
| document | 5.2 | `wrong_type` | error | value of a wrong type | A member has a JSON type that 5.2 does not give it. |
| document | 5.2 | `missing_member` | error | member is absent | A mandatory member of 5.2 is absent. |
| document | 5.2 | `unknown_member` | warning | unknown member | A member that 5.2 does not name. A reader ignores it (1.2, 5.3). |
| document | 5.3 | `unknown_member` | error | unknown member in a limit declaration | A limit declaration has a member that 6.1 does not name. This makes the document bad. |
| document | 6.1 | `wrong_type` | error | value of a wrong type | A member of a limit declaration has a wrong JSON type. |
| document | 6.1 | `missing_member` | error | member is absent | A limit declaration lacks `name`, `label`, `description`, `unit` or `kind`. |
| document | 5.2 | `bad_server` | error | bad id of the service | The id in `server` breaks 4.1: 1 to 256 bytes, no control character. |
| document | 5.2 | `reserved_type_name` | error | type named service | A type has the name `service`, which the document does not declare. |
| document | 5.2 | `bad_type_name` | error | bad type name | A type name does not have 1 to 32 characters, a to z first, then a to z, 0 to 9 or underscore. |
| document | 5.2 | `duplicate_type_name` | error | duplicate type name | A type name occurs more than one time. |
| document | 5.2 | `undeclared_parent` | error | parent is not declared | The `parent` of a type is not `service` and is not a declared type. |
| document | 5.2 | `type_cycle` | error | parents make a cycle | The parents of a type make a cycle. |
| document | 4.1 | `type_too_deep` | error | type is deeper than 4 | A type is more than 4 steps below `service`. |
| document | 5.2 | `type_too_deep` | error | path is deeper than 4 | A `path` of `resources` has more than 4 segments. |
| document | 5.2 | `access_in_list` | error | action access is in the list | The list of actions has the action `access` (8.3). |
| document | 5.2 | `bad_action_name` | error | bad action name | An action name does not follow 5.2: 1 to 64 characters, parts with `.` between them. |
| document | 5.2 | `duplicate_action_name` | error | duplicate action name | An action name occurs more than one time. |
| document | 5.2 | `undeclared_type` | error | undeclared type | A type of an action, or of a path, is not `service` and is not declared. |
| document | 5.2 | `duplicate_type` | error | duplicate type | An action lists a type more than one time. |
| document | 5.2 | `undeclared_limit` | error | undeclared limit | An action lists a limit that the document does not declare. |
| document | 5.2 | `duplicate_limit` | error | duplicate limit | An action lists a limit more than one time. |
| document | 5.2 | `undeclared_action` | error | undeclared action | A resource lists an action that the document does not declare. |
| document | 5.2 | `duplicate_action` | error | duplicate action | A resource lists an action more than one time. |
| document | 5.2 | `bad_path` | error | bad path | A `path` is not `<type>:<id>` segments, or an id is not percent-encoded as 5.2 says. |
| document | 5.2 | `wrong_parent` | error | segment does not follow the types | The type of a segment does not have the type of the segment before it as its parent. |
| document | 5.2 | `bad_limit_name` | error | bad limit name | A limit name does not have 1 to 32 characters, a to z first, then a to z, 0 to 9 or underscore. |
| document | 6.1 | `bad_kind` | error | kind is not ceiling or budget | The `kind` is not `ceiling` or `budget`. |
| document | 6.1 | `duplicate_limit_name` | error | duplicate limit name | A limit name occurs more than one time in the document. |
| document | 6.1 | `budget_name_max` | error | budget name starts with max_ | A budget name starts with `max_` (6.1, 7.1). |
| document | 6.1 | `budget_with_min` | error | budget with "min" | A budget declaration has `min`. |
| document | 6.1 | `budget_with_max` | error | budget with "max" | A budget declaration has `max`. |
| document | 6.1 | `ceiling_without_bound` | error | ceiling without a bound | A ceiling declaration lacks `min` or `max`. |
| document | 6.1 | `bad_bound` | error | bound is not a whole number | `min` or `max` is not a whole number of 0 or more. |
| document | 6.1 | `min_above_max` | error | min is above max | `min` is above `max`. |
| document | 6.1 | `budget_name_window` | warning | budget name has a window or a unit | A budget name has a part that gives a window or a unit, for example `per` or `minute`. 6.1 says that a budget name has none. |
| document | 7.1 | `ceiling_name` | warning | ceiling name is not max_ and a noun | A ceiling name is not `max_` and a noun. |
| document | 5.3c | `above_reader_minimum` | warning | above the minimum of a reader | A size, a count or a length is above the minimum that a reader must accept: 64 KiB, 64 actions, 16 types, 256 resources, 16 limits, label 60, description 300, unit 20. A reader can treat the document as bad. |
| grants | 3.5 | `bad_json` | error | text is not valid JSON | The text is not JSON, or an object has the same member two times. |
| grants | 3.5 | `wrong_type` | error | value of a wrong type | The file, `grants` or a grant has a wrong JSON type. |
| grants | 3.5 | `missing_member` | error | member is absent | The file lacks `grants`, or a grant lacks `action` or `resource`. |
| grants | 3.5 | `unknown_member` | error | unknown member | The file or a grant has a member that the format does not name. The format is closed. |
| grants | 5.2 | `bad_action_name` | error | bad action name | The action name of a grant does not follow 5.2. |
| grants | 5.2 | `undeclared_action` | error | undeclared action | The action of a grant is not `access` and is not declared in the document. |
| grants | 5.2 | `action_not_valid_on_type` | error | action is not valid on the type | The action of a grant does not list the type of its resource. |
| grants | 5.2 | `bad_limit_name` | error | bad limit name | A limit name in `limits` does not follow 5.2. |
| grants | 4.1 | `bad_path` | error | bad resource path | The `resource` is not a full path of 4.1, from `service:<id>`. |
| grants | 4.1 | `unknown_service` | error | service is not the service of the document | The service of the `resource` is not the `server` of the document. |
| grants | 4.1 | `invalid_node` | error | node does not follow the types | A segment of the `resource` does not follow the types of the document. |
| grants | 6.1 | `wrong_type` | error | value of a wrong type | `limits` is not an object, or a budget item has a member of a wrong type. |
| grants | 6.1 | `missing_member` | error | member is absent | A budget item lacks `amount` or `window`. |
| grants | 6.1 | `unknown_member` | error | unknown member | A budget item has a member other than `amount` and `window`. |
| grants | 6.1 | `bad_limit_value` | error | value is not a number or an array | The value of a limit that the document does not declare is not a number or an array. |
| grants | 6.1 | `bad_ceiling_value` | error | value of a ceiling is not a whole number | The value of a ceiling is not a whole number, for example an array of a budget. |
| grants | 6.1 | `ceiling_out_of_range` | error | value of a ceiling is out of range | The value of a ceiling is below `min` or above `max` of its declaration. |
| grants | 6.1 | `bad_budget_value` | error | budget value is not 1 to 4 items | The value of a budget is not an array of 1 to 4 items. |
| grants | 6.1 | `bad_amount` | error | amount is not 1 or more | An `amount` is 0. It is a whole number from 1. |
| grants | 6.1 | `bad_window` | error | window does not exist | A `window` is not `second`, `minute`, `hour` or `day`. |
| grants | 6.1 | `duplicate_window` | error | duplicate window | Two items of one budget value have the same window. |
| grants | 6.10 | `undeclared_limit` | warning | limit is not declared, the value gives nothing | The document does not declare the limit. The value gives nothing. |
| grants | 7.3 | `ceiling_ignored` | warning | the PDP ignores this ceiling | The PDP ignores the ceiling: the grant is of `access`, or its action does not list the ceiling. |
| grants | 8.3 | `access_not_on_service` | error | access is valid only on the service | The action `access` has a resource other than the service. |
| grants | 8.3 | `budget_ignored` | warning | the PDP ignores this budget | A budget value is on a grant other than `access` on the service. The PDP ignores it. |
| grants | 8.3 | `duplicate_budget_value` | warning | second value for one budget | Two grants of `access` give a value for one budget. A subject has one value for each budget. |
| options | 5.8 | `bad_json` | error | text is not valid JSON | The text is not JSON, or an object has the same member two times. |
| options | 5.8 | `wrong_type` | error | value of a wrong type | The answer, `items`, `next`, an item or a member of an item has a wrong JSON type. |
| options | 5.8 | `missing_member` | error | member is absent | The answer lacks `items` or `next`, or an item lacks `id`, `label` or `has_children`. |
| options | 5.8 | `unknown_member` | warning | unknown member | The answer or an item has a member that 5.8 does not name. A caller ignores it. |
| options | 5.8 | `unknown_envelope_member` | error | unknown member of the options file | The options file has the member `answer`, and another member than `query` and `answer`. |
| options | 4.1 | `bad_id` | error | bad id | An id of an item breaks 4.1: 1 to 256 bytes, no control character. |
| options | 4.2 | `duplicate_id` | warning | duplicate id | Two items of one answer have the same id. An id is unique below its parent. |
| options | 5.8 | `above_caller_minimum` | warning | above the minimum of a caller | The answer is above the minimum that a caller must accept: 64 KiB, 50 items, a label of 60 characters. |
| options | 5.8 | `has_children_without_types` | warning | has_children, but the type has no child type | An item has `has_children` true, and the document has no type below the type of the items. |
| options | 5.7 | `duplicate_parameter` | error | parameter occurs more than one time | A parameter of the query occurs more than one time. |
| options | 5.7 | `bad_parameter_value` | error | bad value of a parameter | A value is not encoded as 5.2 says, `limit` is not a whole number from 1, or `parent` is not a path of the document. |
| options | 5.7 | `missing_type` | error | parameter type is absent | The query has no parameter `type`. |
| options | 5.7 | `undeclared_type` | error | type is not declared | The `type` is not a type of the document. |
| options | 5.7 | `wrong_parent_type` | error | type does not follow the parent | The type of the `type` does not have the type of the `parent` node as its parent. |
| options | 5.7 | `answer_above_limit` | error | more items than the limit | The answer has more items than the parameter `limit`. |

## Not checked

The tool does not check these points. The protocol gives no rule that a program can check, or the rule needs data that the file does not have.

- 5.4: the labels and the descriptions are in English.
- 7.1: a ceiling where a higher value is stricter. The tool checks the name only.
- 5.1: the document is at `/.well-known/procurauth/actions` and has no authentication.
- 5.3a, 5.3b: the keep time and the read period of a reader.
- 5.9: the cache of a caller.
- 5.6: that the options route lists only the children that the subject can see.
