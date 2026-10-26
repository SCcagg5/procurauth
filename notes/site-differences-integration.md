# Differences of the reference edge and the scripts from the published site

This file lists the places where the reference edge, the profiles and the scripts differ from the pages `docs/tools.html` and `docs/conformance.html`. The code does not change the site. The owner updates the site later. The numbers are for this file only.

1. The site lists five programs, and the files `notes/site-differences-pep.md` add `reference-service`. The repository has a seventh program, `reference-edge`. It is the test subject of the series E. It is not a tool for an operator.
2. The sentence "Build all the programs with cargo build --release" now builds seven programs.
3. The site gives no profile of an edge. The file `crates/reference-edge/examples/conformance-profile.json` is one. It has `token_cache` true and the key set of two keys, so no case of the series E is skipped.
4. The edge has no TLS code. It needs a proxy that ends TLS, and the flag `pdp.allow_insecure_pdp_link` for an `http` link to the PDP.
5. The configuration of the edge is a JSON file with a closed schema. The forms `_env` and `_file` give a value from a variable or a file. The signing key and the credential of the PDP take only these two forms.
6. The edge reads the text of a key from `Authorization: Bearer` only. It finds the key by the SHA-256 digest in a keys file. The keys file and the key format are inputs of the program. The protocol defines neither (3.8).
7. `fake-pdp` has a new admin request, `PUT /__fake/load`. The site lists the admin requests that the tool had before. A PDP under test with the runner needs a load request, and this request is the one for `fake-pdp`.
8. `procurauth-pep` has a new module, `access`. It gives the question of an edge for the action `access`. The site says that a PEP never asks for `access`. This is still true. The module is for an edge.
9. The reference service has a new key, `mcp_session_budget`. With it, the action `mcp.session` lists a budget, and the case U95 runs.
10. The scripts `scripts/conformance.sh` and `scripts/ci.sh` are new in the description of the repository. The site does not describe them.
