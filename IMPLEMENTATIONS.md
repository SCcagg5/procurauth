# Implementations

This file lists the known implementations of ProcurAuth.

## In this repository

- `procurauth-pep`: a library in Rust for a PEP. It follows the requirements of the protocol for a service (section 10) and the approval flow of section 17 for each action.
- `reference-service`: a service that uses the library. It passes the series U of the conformance cases. Each of its actions goes through the approval flow of section 17.
- `reference-edge`: an edge. It passes the series E.
- `fake-pdp`: a test PDP. It passes the series D.

## Other implementations

No other implementation is known.

A service conforms only when it follows section 17 for each action of its action document. An action that cannot ask for an approval makes the service not conformant.

To add one, open an issue with its name, its role (PEP, PDP or edge), a link and the result of `access-conformance`.
