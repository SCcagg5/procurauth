# Requests from fake-pdp to procurauth-core and to the schemas

The tool changed no file of `procurauth-core`. This file lists the changes that would make the tool simpler. The owner decides.

1. **Schema `fake-pdp-data`: three members.** The tool takes the admin switch and the credential file from the command line, because the schema is closed. If the owner wants them in the data file, add the root members `admin` (boolean) and `credential_file` (string). Also add the failure kinds `close`, `invalid_json` and `no_units` to the `failure` definition, and to the reader in `directory.rs`.
2. **Schema `fake-pdp-data`: the description of `metadata`.** It says that a member that the file does not give is not in the metadata. The tool publishes the four members always, with defaults. Change the description, or the tool.
3. **Counter presets for several services.** A counter names no service. The tool applies it to each service that declares the budget. Add an optional member `service` to the `counter` definition if a file has several services with the same budget name.
4. **A reader of the case model.** The crate `procurauth-schema-check` has no typed API for the conformance cases and their matchers. The test `conformance_d.rs` of this crate has a local runner. The tool `access-conformance` needs a shared reader.
5. **Order of the members of a JSON object.** `serde_json` sorts the members of an object. The log of `fake-pdp` shows the limits in sorted order, and the page shows the order of the action document. Use the feature `preserve_order` of `serde_json` in the workspace, if the owner wants the page order.
