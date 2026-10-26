# Fixes of conformance cases

This file lists each case that the tool `access-conformance` found wrong, and the change. A case is wrong when a correct implementation fails it.

1. **U98.** The case sends a `ping` and the PDP answers `true` with no `context.usage`. When the action `mcp.session` lists a budget, the `ping` is one use (binding 3.6a). A true answer with no `usage.units` then counts as false (protocol 6.12), and the service gives HTTP 403. The script of the case now answers `true` with `units` 1 to a question with usage, and `true` to each other question. A service with no budget for `mcp.session` sees no change.
