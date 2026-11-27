# CHANGELOG

This node follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
version covers the HTTP API in [`openapi/node.openapi.yaml`](openapi/node.openapi.yaml),
the environment the binary reads and the submission sets it produces.

Entries are one line per change: `type:scope: what changed`, where `type` is
`feature`, `bugfix`, `breaking`, `deprecation`, `security` or `docs`.

## 1.0.0

* feature:HTTP API: `POST /v1/activate`, `POST /v1/issue`, `GET /v1/operations/{operation_id}`, `GET /v1/emissions/by-commitment/{independence_ref}`, `GET /v1/emissions/unresolved`, `GET /v1/outbox/dead` and `POST /v1/outbox/dead/{request_id}/redrive`, specified in `openapi/node.openapi.yaml`
* feature:Submission sets: commitments accumulated in a durable journal are closed into `submission-set/1` with its canonical Merkle construction, and submitted with retries and idempotency through a durable outbox
* feature:Contracts: one node serves one contract or several isolated contracts, with the same public semantics for equivalent inputs
* feature:Upgrades: two node processes can share one journal and outbox while one replaces the other; background delivery, domain binding and retention run in the one holding `<NODE_JOURNAL>.background.lock`
* security:Issuer authentication: every request carries an issuer proof bound to its challenge, host, method, path and body digest; a challenge is accepted once
* security:Foundation: the node starts only after verifying the signed system foundation of the configured system domain against the pinned root fingerprint
* docs:HTTP API: every operation in `openapi/node.openapi.yaml` carries request, parameter and response examples, checked against their schemas by the test suite
* feature:Protocol core: `crates/protocol-core/` carries the wire types, canonicalization, digests, Merkle rules, composite signatures and manifest resolution, held to the published conformance vectors
