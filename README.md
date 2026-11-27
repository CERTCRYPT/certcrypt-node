# CERTCRYPT Node

Official issuer-side node for CERTCRYPT submission-set lifecycle, capacity commitments, and submission.

CERTCRYPT is infrastructure that makes certification independently verifiable under public rules. Selected artifacts can reach `Independent` through `Proof of Independence`, a structural result, so later verification no longer depends on the issuer's live systems.

`certcrypt-node` is the local operational component that lets an issuer aggregate issuance activity into submission sets, close those sets, and submit them to CERTCRYPT infrastructure so selected artifacts can later reach `Independent`.

`certcrypt-node` does not decide whether certificate content is true, legally valid, or factually correct. Local node state is operational and subordinate: it is not a source of semantic truth, authoritative capacity state, or proof validity.

> [!NOTE]
> **CERTCRYPT runs a public node built from this repository.**
>
> Other operators can run the same code alongside it, as public, private,
> organization or sector nodes. Before a node can submit, its operator proves
> control of the node's operator key and links the node to an administrative
> contract, which yields its `operator.recognition/1` credential (see
> [Initial configuration](#initial-configuration)). That link identifies the
> operator; it is not an endorsement of the operator or of what it transports.
>
> The node plays no part in verification. A verifier evaluates the artifacts
> against the public specifications and reaches the same result whichever node
> assembled the submission set, so running a node grants no say over whether an
> artifact reaches `Independent`.

## Role

`certcrypt-node` encapsulates the local complexity of the path from issuer-side activity to `submission-set/1`.

It is intended to handle:

- local submission-set opening and closure
- submission-set journal persistence
- retry and idempotency around submission
- capacity commitment material loaded by the issuer
- canonical Merkle construction for submission-set contents
- preparation of the `submission-set/1`

The issuer remains responsible for its own issuance logic, custody of original material, and any business or legal claims made by the underlying certificate.

## Architecture Direction

`certcrypt-node` is Rust-first and intended to be distributed as a single operational binary.

The structure is:

- `crates/protocol-core/` for the protocol itself — the wire types,
  canonicalization, digests, Merkle rules, composite signatures and manifest
  resolution that every CERTCRYPT implementation reproduces byte-for-byte. Held
  to the published conformance vectors; see [Conformance](#conformance).
- `crates/core/` for what this node builds on top: the journal, the
  submission-set envelope, settlement packaging
- `crates/node/` for the HTTP server, dispatch, persistence, and upstream submission

The node is designed for both:

- `single-contract` operation, where one node instance serves one CERTCRYPT contract
- `multi-contract` operation, where one node instance serves multiple isolated contracts

Both modes must produce the same public semantics for equivalent inputs. Verification of `Independent` must not depend on the continued availability of the node.

## CERTCRYPT boundary

- not a claim of factual truth
- not a validator of correctness
- not a custodian of documents
- not blockchain notarization
- not a trust badge

## Boundary of this node

- not a verifier
- not a source of proof validity
- not a document custody system
- not a long-term archive for issuer data
- not a replacement for the issuer's own issuance system
- not an authority that validates semantic truth or legal validity
- not a way to convert local capacity estimates into authoritative consumption

## Initial configuration

Obtain and pin the chosen system domain's root fingerprint through an
independent channel. Then create the complete environment file in a secure
deployment-owned location, naming the API for this environment and the path
where the node will keep its verified foundation cache:

```sh
NODE_BIND_ADDR=127.0.0.1:8080 \
./scripts/install_node.sh \
  /secure/path/certcrypt-node.env \
  '<64-lowercase-hex-from-system-domain>' \
  '<api-url-for-this-environment>' \
  /secure/path/system-foundation.json
```

The optional `NODE_BIND_ADDR` selects this deployment's listener and is written
into the resulting environment (the public mold defaults to `127.0.0.1:8080`).
The installer creates missing deployment-owned directories with mode `0700`,
validates the independently supplied fingerprint, API URL and cache path,
generates the stable operator keypair locally, and writes the complete result
atomically with mode `0600`. It never prints the private key or
sends it to the console or to CERTCRYPT. On first start the node downloads the
signed `system-foundation/1` from the API, verifies the complete statement
against that fingerprint, and only then installs it atomically in the cache.
A later restart uses a valid local copy even if the API is unavailable.

The installer opens a possession-proven link request and prints a short
`XXXX-XXXX-XXXX-XXXX` locator. If you started from an integration creation page,
return to that already-open page so its fields remain intact and enter the code
there. For a standalone installation, open the alternative console URL printed
by the installer. Compare `operator_id` and the key fingerprint with this host,
choose the administrative contract, and select **Link node**. The locator cannot
obtain the credential. The installer
keeps a separate 256-bit claim secret locally, demonstrates the same key again,
and stores the returned `operator.recognition/1` credential in the protected
environment file. This is an administrative link, not a quality, reputation,
sector, or semantic-validity statement by CERTCRYPT.

After three incorrect request codes, run the same `install_node.sh` command
again. If the protected environment already exists, the installer preserves
the operator key instead of overwriting it and opens a fresh demonstrated link
request. Only a request created after the three-attempt lock can continue.

Start the node with the completed file:

```sh
CERTCRYPT_ENV_FILE=/secure/path/certcrypt-node.env ./scripts/run_node.sh
```

The node holds no shared bearer token: submissions carry operator recognition
and a fresh possession proof.

## System-domain pin

The node authenticates each issuer offline, by verifying a Level-1 binding signed
by the system domain. It learns the system domain's Level-1 public key from one
artifact only: the domain's signed `system-foundation/1` statement.

| Variable | Meaning |
| --- | --- |
| `CERTCRYPT_SYSTEM_ROOT_FINGERPRINT` | The pinned `system_root_fingerprint`: 64 lowercase hex characters, obtained independently |
| `CERTCRYPT_SYSTEM_FOUNDATION_PATH` | Path to the signed `system-foundation/1` statement of that system domain |

At startup the node verifies the statement in full and refuses to start if any
check fails: the embedded bootstrap manifest must recompute to the pinned
fingerprint, at least `k` of its members must have signed the statement — the
Level-1 key included — and any successor-binding observations supplied with it
must carry the bootstrap quorum and must not conflict. Only then does it accept
bindings, and only under that fingerprint and the Level-1 key the statement
publishes.

For local development, `cargo run -p certcrypt-node --example gen_dev_foundation`
produces an equivalent statement around your own Level-1 development key and
prints its fingerprint; see the example's header. A real deployment uses the
statement its key ceremony emitted.

The node's own administrative contract is linked separately through the
demonstrated request above. The short code only locates the request in an
authenticated console. Finalization requires both the locally retained claim
secret and a new signature by the same operator key; integration creation and
credential storage are atomic and idempotent. Typing an `operator_id`, copying
the locator, or controlling the console session alone is insufficient.

That administrative contract is not an issuer allow-list and does not pay for
transported issuers. Admission of public, private, organization, or sector
issuers is node-local policy; billing and capacity remain attributable to each
issuer's signed authorization.

## Retention

Because the node is not an archive, it forgets:

- A delivered submission set leaves the outbox as soon as the issuance service answers for it.
- A dead-lettered set is never removed automatically; it is the only copy, and it waits for an operator.
- An operation record is kept for the retention period after it becomes terminal. An `accepted` record the node never saw finish is kept for twice that period after it was written. An `accepted_for_retry` record whose set was never delivered is never removed.

The period is `NODE_JOURNAL_RETENTION_DAYS`: 30 days by default and **never less than 30**. A lower or unparseable value stops the node from starting instead of being silently replaced. Embedders get the same floor through `RetentionPolicy::with_retention_days`.

After the period, `GET /v1/operations/{id}` answers 404. The emission can still be read by `GET /v1/emissions/by-commitment/{digest}`, which does not depend on any node's records. The issuer is expected to keep its `independence_proof` once the operation is terminal; the node never holds it.

## Declared operator domain (optional)

An operator may associate its operator key with a host name it controls, following `operator.domain-binding/1`. A service that displays operations can then show that host name next to the operator. The association says who operates the node; it is not an endorsement, it is not part of any proof, and a node without it carries submissions exactly the same way.

Set `CERTCRYPT_NODE_OPERATOR_DOMAIN` to the host name (an internationalized name is accepted and converted to its ASCII form). The node then:

- signs a `bind` statement with the operator key, valid for 90 days, and writes the resource to publish into `NODE_WELL_KNOWN_FILE` (default `certcrypt-node.json`);
- registers the statement with the issuance service once the host serves it: before registering a new statement, the node fetches `https://<host>/.well-known/certcrypt-node.json` itself and waits (checking again every hour) until the file there carries it. A node that cannot reach its own host from its network registers without that check. The service fetches the host too, and only shows the host name after a successful fetch. If the host stops serving the file before that, the service keeps checking the newest statement while it is valid and shows the host name once the file is back, with nothing to do on the node;
- signs a new statement after 60 days and keeps the previous one in the file until it expires;
- presents its newest statement again at every start, which carries a renewed recognition credential.

When the node itself is reached through that host (its HTTPS front end passes every path to it), set `NODE_SERVE_WELL_KNOWN=1` and the node answers `GET /.well-known/certcrypt-node.json` with the file, so no separate web server is needed. Several nodes behind one host each sign their own statements, so only one of them may declare the host and serve the file: route that path to that node, and leave `CERTCRYPT_NODE_OPERATOR_DOMAIN` unset on the others.

Otherwise serving the file is the operator's part: the operator's own web server must answer `GET /.well-known/certcrypt-node.json` on that host over HTTPS with a valid certificate, directly (no redirect), with the file's exact content. The node never serves that origin and is never contacted through it, so a node on a private network can be associated with a public host name; a name that does not resolve publicly cannot be associated.

The node keeps its sequence numbers and published statements in `NODE_DOMAIN_BINDING_STATE` (default `node-domain-binding.json`). Keep that file with the operator key: a statement's sequence is never reused, and if the file is lost the issuance service answers with the highest sequence it accepted and the node continues above it.

Two commands use the same environment:

- `certcrypt-node unbind <host>` withdraws the association with a host. The `unbind` statement replaces that host's `bind` statements in the file and the node will not bind that host again on its own.
- `certcrypt-node rebind` signs a new `bind` for the configured host immediately. It also lifts an earlier `unbind` of that host.

A new operator key is a new operator: its statements start a new sequence, and the previous key's statements stay in the file until they expire.

## Restarts and outages

The node is built so that neither its own restart nor an outage of the issuance service loses a submission:

- **Durable before it answers.** A submission set is written to the node's outbox before it is sent on. If the outbox cannot take it, the node answers `503` with `Retry-After` and sends nothing: it only holds what it can keep.
- **An unanswered submit still gets its ids.** When the issuance service cannot be reached or is unavailable (a transport failure, `408`, `425`, `429` or `5xx`), `POST /v1/issue` answers `202` with one `accepted_for_retry` result per member. The delivery later writes each member's outcome onto that same operation id.
- **Outages are waited out.** The relay retries an unreachable or failing service for as long as it takes, with backoff. When the service asks for a pause (`503` or `429` with `Retry-After`, such as planned maintenance), the relay stops for that long and does not count it as an attempt.
- **A capacity shortfall is waited out while it can be.** An `insufficient_capacity` answer consumes nothing, so while the earliest commitment in the set expires more than five minutes later, the node keeps the set and answers `202` with one `accepted_for_retry` result per member, carrying the service's `required`, `available` and `missing` figures. It submits the same set again after 1, 2 and 5 minutes and then every 15 minutes, the last attempt five minutes before that expiry; waiting spends no delivery attempt and never dead-letters. If capacity arrives in time, each member's outcome lands on its operation id as usual; otherwise each member records the final `insufficient_capacity` with the latest figures. With less than five minutes left, `insufficient_capacity` is answered at once.
- **A refusal is answered, not retried.** When the issuance service refuses a submission outright (a `4xx` other than `408`, `425` or `429`), sending the same bytes again cannot change the answer, so the node sets it aside instead of queueing it. On `POST /v1/issue` the issuer gets `422` with a `submission_failed` state carrying the service's status, and nothing stays in the outbox. Request problems the node can see itself (no commitments, too many, a commitment TTL that does not match its `rules_version`, timestamps that are not RFC 3339, members that cannot form one set) are answered `422` before anything is sent.
- **Dead letters are for refusals, not outages.** A refusal met during background delivery dead-letters at once; a `500` from the service is retried a bounded number of times first. `GET /v1/outbox/dead` lists them and `POST /v1/outbox/dead/{request_id}/redrive` puts one back once the cause is fixed. Both are scoped to the issuer that owns the submission, and nothing is ever re-signed.
- **Restarts drain.** On `SIGTERM` the node keeps its port open for `NODE_SHUTDOWN_DRAIN_SECS` (default 3), answers writes with `503` and `Retry-After: NODE_RESTART_RETRY_AFTER_SECS` (default 10), keeps serving reads, finishes requests in flight and lets the relay record the delivery it has in hand. `/health` reports `draining` meanwhile.
- **Upgrades without a gap.** Two node processes can share one journal and one outbox, so a new process can start and serve before the old one stops. Both answer requests; the relay, the domain binding and the retention sweep run in one of them only: the process holding the lock on `<NODE_JOURNAL>.background.lock`. The new process takes them over as soon as the old one exits, and a crashed process never keeps the lock.
- **`GET /ops` for the operator.** With `NODE_OPS_TOKEN` set, `GET /ops` (Bearer that token) reports the commit the binary was built from, when the process started, its memory and, with `?logs=N` (up to 1000), its last log lines, kept in memory since the last start. Unset, it answers `404`. It shares the node's listener and sits outside the `/v1` limits like `/health`.

Clients should treat these answers the same way: honor `Retry-After` without counting it and bound their retrying by time.

## Conformance

`certcrypt-node-core` is held to the primitive byte-contract vectors of
[`certcrypt-conformance`](https://github.com/CERTCRYPT/certcrypt-conformance). It
is not a verifier and returns no `VerifierResult`, so the verdict fixtures do not
apply to it; what it must reproduce is the bytes — key derivation, holder key
sets, submission sets, subject canonicalization — identically to every other
implementation, in any language.

Five test files carry that: `crates/core/tests/primitive_vectors_parity.rs`,
`crates/core/tests/conformance_parity.rs`,
`crates/protocol-core/capacity-verify/tests/composite_conformance_parity.rs` —
which pins the composite signature framing and what verification refuses,
where two implementations diverge without either noticing —
`crates/protocol-core/capacity-verify/tests/ecdsa_p256_deterministic_parity.rs`,
which holds the ECDSA P-256 signer to the contract's deterministic bytes, and
`crates/protocol-core/capacity-verify/tests/foundation_conformance.rs`, which runs
every `system-foundation.json` vector through the statement verifier the node
boots from: the valid ones must expose exactly the key they publish, the
adversarial ones must be refused for the check the vector names.

**The contract is required to build green.** They expect `certcrypt-conformance`
as a sibling checkout, and when it is absent they FAIL rather than skip. A
skipped test reports no failure, so a run without the vectors would end green
having checked no parity at all — the one property these tests exist to prove.

```bash
git clone https://github.com/CERTCRYPT/certcrypt-conformance.git ../certcrypt-conformance
cargo test
```

These environment variables are deliberate and none is a default:

| Variable | Effect |
| --- | --- |
| `CERTCRYPT_CONFORMANCE_PRIMITIVES_DIR` | Point `primitive_vectors_parity.rs` at a `fixtures/primitives` that is not a sibling checkout — a vendored copy, a CI cache, a release tarball |
| `CERTCRYPT_CONFORMANCE_FIXTURES_DIR` | The same for the other test files, pointing at the contract's `fixtures/` |
| `CERTCRYPT_ALLOW_MISSING_CONFORMANCE=1` | Run without the contract. Warns on stderr in every affected test; a run under it backs no parity claim |

**The version is checked, not just the presence.** Requiring the contract to be
present would still let two implementations build green against different
versions of it and diverge anyway; what keeps them in step is agreeing on the
same `VERSION`. This crate is held to the version named in `EXPECTED_VERSION`
(both `crates/core` test files), and a checkout that is not that one fails. Adopting a new
contract means raising the constant and re-running — the run is what makes the
claim true. `CERTCRYPT_ALLOW_CONFORMANCE_VERSION_MISMATCH=1` explores a bump
without adopting it, and says loudly that the run backs no claim.

## Public Specifications

Public specifications and technical documentation:

https://docs.certcrypt.com

The public website is available at:

https://certcrypt.com

## License

Copyright 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.

## Contact

Website: https://certcrypt.com  
Docs: https://docs.certcrypt.com  
Blog: https://blog.certcrypt.com  
Open source: opensource@certcrypt.com

---

## Tests and CI

```bash
cargo test --workspace
bash scripts/ci.sh      # everything the pre-push hook runs
```

### The gate is a pre-push hook

`.githooks/pre-push` runs the checks and **refuses the push** when one fails.
Install it once per clone:

```bash
git config core.hooksPath .githooks
```

`core.hooksPath` is per-clone git config, not something the repository carries:
**a fresh clone has no hook until that command is run.**

What it checks:

1. **`cargo fmt --check`** — the tree is formatted, and this keeps it that way.
   Run `cargo fmt --all` before pushing.
2. **`cargo clippy -D warnings`**.
3. **`cargo test --workspace`**.
4. **no tracked secrets** — the push is refused if one is about to be committed.

It deliberately does not build a release binary: `clippy` catches the same
compile errors in a fraction of the time, and a hook slow enough to be annoying
is a hook that gets disabled.
