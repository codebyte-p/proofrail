# ProofRail

ProofRail is an evidence-backed software assurance platform for GitHub pull requests. Its goal is to help teams verify security-sensitive code and dependency changes—including changes produced by coding agents—before they reach production.

## Status

ProofRail is in its architecture and threat-modeling phase. The first implementation milestone will deliver a local CLI and reusable GitHub Action. A hosted GitHub App will follow only after the core verification engine is reliable.

## Product principles

- Deterministic evidence, tests, and explicit policy decide whether a check blocks a merge.
- AI may explain and correlate findings, but it may not invent evidence or silently merge changes.
- Every finding must identify its source, affected artifact, severity, and remediation path.
- Security-sensitive changes require independent review.
- Provider safety rules and repository policy cannot be overridden by agent instructions.

## Planned progression

1. Approve the architecture and threat model.
2. Build a test-first verification CLI.
3. Publish results through GitHub Actions and SARIF.
4. Add high-signal analyzers and policy-as-code.
5. Add a production control plane and GitHub App.

See [GOVERNANCE.md](GOVERNANCE.md) for decision authority and [AI_MAINTAINERS.md](AI_MAINTAINERS.md) for the Codex–Claude collaboration protocol.

