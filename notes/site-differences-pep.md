# Differences of the PEP library and the reference service from the published site

This file lists the places where `procurauth-pep` and `reference-service` differ from the page `docs/tools.html`. The code does not change the site. The owner updates the site later. The numbers are for this file only.

## Library

1. The site shows the dependency `procurauth-pep` from the repository with the tag `v1.0`. The crate has the name `procurauth-pep` and the version `1.0.0` of the workspace. The tag comes with the release.
2. The site says that the README of the crate and the `docs/` directory describe the library. The README of the crate describes it. This work adds no file to `docs/`.
3. The site lists the rules 9.4, 10.0, 10.1, 10.3 and 10.6. The library also follows 3.3, 4.1, 4.5, 5.1, 5.5a, 5.6 to 5.8, 6.4, 6.11, 6.12, 7.3 to 7.6, 9.5 to 9.7, 10.7 and 10.7a. It also follows the MCP binding.
4. The site says that the library gives the steps of 10.0. The library also gives the options route (5.6 to 5.8), the MCP helpers and the builder of the action document.
5. The library has no TLS client. A deployment must give its own `PdpTransport` with TLS. The site does not say that the PDP link needs one.
6. The library has one cargo feature, `mcp`. It is on by default.

## Reference service

7. The site lists five programs: `access-lint`, `fake-pdp`, `access-token`, `keycheck` and `access-conformance`. The repository has a sixth, `reference-service`. It is the test subject of the series U. It is not a tool for an operator.
8. The sentence "Build all the programs with cargo build --release" now builds six programs.
9. The site gives no profile of the service under test. `crates/reference-service/PROFILE.md` gives the request of each operation. The profile of `access-conformance` follows it.
10. The service has no TLS client, so it needs the flag `pdp.allow_insecure_pdp_link` and an `http` URL for the PDP.
11. The configuration of the service is a JSON file with a closed schema. The forms `_env` and `_file` give a value from a variable or a file. The effective configuration shows the source of each value.
