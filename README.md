# ProcurAuth

ProcurAuth is an open specification for services that let AI agents act for people. A backend holds the users, their rights and the keys of their agents. A key never has more rights than the person who owns it.

ProcurAuth is a profile of the AuthZEN Authorization API 1.0. A service asks a decision point (PDP) with AuthZEN. The PDP gives the decision and the limits that apply.

Site: <https://sccagg5.github.io/procurauth/>

## Contents

- `protocol/procurauth-protocol.md`: the protocol. It is neutral and it covers the questions, the answers, the keys, the limits and the identity token.
- `bindings/mcp/procurauth-mcp-binding.md`: the binding for services with an MCP endpoint.
- `docs/`: the source of the site. GitHub Pages serves this directory.

## Licences

- The texts are under CC BY 4.0. See `LICENSE-TEXTS.txt`.
- The code is under Apache-2.0. See `LICENSE`.

## Contribute

Open an issue to ask a question or to report an error in the texts. Cite the number of the paragraph.
