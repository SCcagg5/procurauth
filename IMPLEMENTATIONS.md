# Implementations

This file lists the known implementations of ProcurAuth.

## In this repository

- `procurauth-pep`: a library in Rust for a PEP. It follows the requirements of the protocol for a service (section 10).
- `reference-service`: a service that uses the library. It passes the series U of the conformance cases.
- `reference-edge`: an edge. It passes the series E.
- `fake-pdp`: a test PDP. It passes the series D.

## Other implementations

No other implementation is known.

To add one, open an issue with its name, its role (PEP, PDP or edge), a link and the result of `access-conformance`.
