# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |
| older   | No        |

Only the latest published release receives security updates.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/Sigilweaver/OpenSQLAnywhere/security/advisories/new).

Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof of concept (a small input file is
  ideal).
- The affected crate (`opensqlany` or `opensqlany-cli`).
- The OS, Rust toolchain, and crate version you were running.

Expect an initial acknowledgment within 7 days.

## Scope

In scope:

- **Parser correctness on malicious input.** Crashes (panics,
  out-of-bounds reads, infinite loops), arbitrary file writes, or
  memory corruption triggered by a crafted SA17 page-store file are
  in scope. `opensqlany` is `#![forbid(unsafe_code)]` so memory
  corruption in safe Rust would be unexpected.
- **Path-traversal or arbitrary-file-write bugs** in the
  `opensqlany` CLI.
- **Supply-chain integrity** of published artifacts on crates.io:
  tampered manifests, missing provenance, unsigned releases.

Out of scope:

- Denial of service via legitimately oversized database files.
- Vulnerabilities in third-party crates with no demonstrated exploit
  path through this stack. Forward those upstream.
- Bug reports about format-spec inaccuracy or unsupported page types
  - file those as regular GitHub issues.

## Disclosure

We follow coordinated disclosure. Reporters are credited in the
release notes unless they prefer to remain anonymous. We aim to ship
a fix within 30 days of confirming a high or critical issue.

## Note on reverse-engineered formats

OpenSQLAnywhere is clean-room: it is derived from observation of
on-disk bytes and from SAP's own public documentation. It ships with
no SAP code or binaries. Bug reports about parser inaccuracy are
welcome but are not security issues.
