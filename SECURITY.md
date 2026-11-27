# Security Policy

## Supported Versions

No stable `certcrypt-node` release is published yet.

| Version | Supported |
| --- | --- |
| No public release yet | Not applicable |

Security updates will apply to public releases once versioned node artifacts are published.

## Reporting a Vulnerability

Please do not open public issues for security vulnerabilities.

Report security concerns by email to security@certcrypt.com.

Include:

- affected repository or component
- affected version or commit, if known
- a clear description of the issue
- reproduction steps, if available
- potential impact

Please avoid including customer data, production credentials, private keys, capacity material, node journals, or confidential third-party material in reports.

We will acknowledge valid reports as soon as practical and coordinate remediation before public disclosure.

## Coordinated Disclosure

Please give us a reasonable opportunity to investigate and remediate security issues before public disclosure.

Do not publish exploit details, proof-of-concept code, or operational indicators before we have completed triage and remediation planning.

## Scope

This repository is intended for public `certcrypt-node` code and related operational tooling.

Security-relevant areas include:

- local submission-set lifecycle handling
- journal persistence and recovery behavior
- capacity commitment handling
- retry and idempotency behavior
- upstream submission behavior
- isolation between contracts in multi-contract deployments

Do not submit secrets, production credentials, private keys, customer data, capacity commitments from real deployments, or node journals in issues, pull requests, or discussions.

## Out of Scope

The following are not handled through this repository's security process:

- general product questions
- documentation corrections without security impact
- requests for roadmap information
- reports about private CERTCRYPT systems not represented in this repository
- reports that depend on treating node-local state as authoritative proof or semantic truth
- claims about semantic truth, legal validity, or factual correctness of certificate content

For non-security questions, use the public open-source contact channel:

opensource@certcrypt.com
