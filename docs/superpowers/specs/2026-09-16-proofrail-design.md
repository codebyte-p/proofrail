# ProofRail Product and System Design

- **Status:** Approved for Gate 1 implementation
- **Date:** 2026-09-16
- **Implementation authorization:** Granted by the repository owner on 2026-09-16 after independent Claude review returned `APPROVE`

## Problem

Modern pull requests can change application code, dependency graphs, CI authority, deployment configuration, and security policy at once. Existing scanners often emit disconnected alerts without proving which revision, policy, evidence, and analyzer state produced the merge decision. Failure or missing coverage can be mistaken for safety.

ProofRail provides a deterministic verification layer between a proposed change and merge. It binds analysis to exact revisions, records coverage and failure, normalizes evidence from focused analyzers, evaluates restricted repository policy, and produces human- and machine-readable results.

## Product thesis

The portfolio and production value is not “AI detects every vulnerability.” It is trustworthy change assurance:

- evidence is traceable to immutable inputs;
- missing analysis is visible and cannot become a pass;
- high-risk changes are routed to the right review;
- policies are declarative and cannot execute arbitrary code;
- AI may explain evidence later but cannot originate or silently change enforcement;
- every override is scoped, attributable, expiring, and auditable.

ProofRail evaluates observable changes equally. It does not infer whether code was written by a human or AI system.

## Users and primary workflows

### Repository maintainer

Installs the GitHub Action, adopts or customizes a base-branch policy, reviews findings, and promotes selected high-confidence rules from shadow mode to blocking mode.

### Security reviewer

Receives evidence for security-sensitive changes, verifies analyzer limitations, approves or rejects scoped waivers, and audits changes to policies, workflows, dependencies, and releases.

### Contributor

Receives a concise pull-request result identifying the rule, location, evidence, impact, required response, and known limitations without exposing secrets.

### Local developer

Runs the same engine before pushing and receives the same canonical decision semantics as CI.

## Approved scope

### Version 1

- Offline CLI operating on immutable base/head revisions.
- Safe parsing and normalized change model.
- Three built-in analyzers specified in [analyzers.md](../../analyzers.md).
- Restricted policy evaluator specified in [ADR 0001](../../decisions/0001-restricted-policy-model.md).
- Console, canonical JSON, job-summary Markdown, and SARIF output.
- Reusable GitHub Action on the unprivileged `pull_request` event.
- Versioned fixture corpus, fault injection, fuzzing, deterministic golden tests, and pilot metrics.

### Conditional later scope

- Hosted GitHub App and tenant-aware control plane only after Gate 3 requirements are met.
- External metadata and third-party analyzer ingestion only through separately reviewed contracts.
- AI-assisted explanation only when deterministic evidence is preserved and the explanation is explicitly advisory.

### Non-goals

- Proving that a repository is vulnerability-free.
- Running builds, tests, installers, hooks, or arbitrary repository code.
- AI authorship detection.
- Automatic remediation, merging, deployment, or risk acceptance.
- General-purpose policy languages or runtime-downloaded plugins.
- Live reputation, registry, or advisory lookup in version 1.
- Regulatory compliance or certification claims.

## Architecture decision

Use a progressive hybrid architecture: one deterministic engine first exposed as a CLI, wrapped by a GitHub Action, and later scheduled by a hosted App. The engine and canonical result schema remain shared so hosting does not redefine security semantics.

Detailed components, data flow, permissions, result schema, exit codes, overrides, resource limits, and the future hosted boundary are defined in [architecture.md](../../architecture.md).

## Technology stack and repository shape

The CLI uses Go 1.27 or a newer supported Go 1.x release, with the exact patch version pinned in CI and release metadata. Go provides a portable single binary, bounded concurrency, strong standard-library support, and a smaller runtime dependency surface than a JavaScript Action. The module path is `github.com/codebyte-p/proofrail`; version 1 avoids cgo so official releases can be statically linked for supported platforms. Go's official policy supports a major release until two newer major releases exist ([release policy](https://go.dev/doc/devel/release)).

The planned source boundaries are:

```text
cmd/proofrail/                  CLI entry point only
internal/run/                   orchestration and terminal status
internal/gitdiff/               revision binding and normalized changes
internal/parser/workflow/       bounded GitHub Actions YAML parser
internal/parser/npm/            package.json and package-lock.json
internal/parser/python/         pyproject.toml and uv.lock
internal/analyzer/workflow/     PFR-WF rules
internal/analyzer/dependency/   PFR-DEP rules
internal/analyzer/diff/         PFR-DIFF rules
internal/finding/               canonical finding and fingerprinting
internal/policy/                restricted policy and waivers
internal/report/                console, JSON, Markdown, and SARIF
schemas/                        versioned policy, waiver, and result schemas
testdata/                       malicious, benign, malformed, and replay fixtures
action/action.yml               reusable Action wrapper
```

Files change together by responsibility rather than generic technical layers. Parsers cannot import reporters or policy. Analyzers consume normalized records and cannot access arbitrary paths. Reporters consume only the canonical result.

The canonical result schema identifier is `https://github.com/codebyte-p/proofrail/schemas/run-result/v1.json`. Initial dependency support is npm with `package-lock.json` and Python with `uv.lock`; other lockfiles are explicit unsupported coverage, not guessed parsing.

The primary command is:

```text
proofrail scan --repo <path> --base <sha> --head <sha> [--policy <path>] [--output <format>=<path>]...
```

`--policy` is intended for authorized local evaluation and its path and digest are recorded. In CI, the wrapper does not expose it to pull-request-controlled input and always resolves policy from the base revision.

## Core interfaces

The implementation plan must preserve these conceptual boundaries; exact language types will be fixed during implementation planning.

### `RunIdentity`

```text
repository identity
base commit SHA
head commit SHA
policy digest
waiver digest
engine version
evaluated_at UTC timestamp
```

### `AnalysisInput`

```text
RunIdentity
normalized changed files
base-revision policy
base-revision waivers
resource budgets
```

### `AnalyzerResult`

```text
analyzer identity and version
completion status
findings
coverage notes
duration and budget usage
failure detail without secrets
```

### `CanonicalRunResult`

```text
schema version
RunIdentity
terminal status
validated findings
analyzer completion ledger
policy matches
applied and rejected waivers
coverage limitations
integrity digest
```

Consumers must depend on these contracts rather than analyzer internals. Reporters may project information but cannot reinterpret the terminal decision.

## Security model

The reusable [threat model](../../threat-model.md) defines protected assets, attackers, trust boundaries, invariants, hypotheses, failure modes, and severity. Its core design requirements are:

- hostile repository data is never executed by version 1;
- effective policy comes from the base revision;
- required-analysis failure yields `incomplete`;
- credentials remain separate from hostile content;
- reports redact secret values and bind to immutable inputs;
- hosted processing, if built, uses per-job and per-tenant isolation.

## Analyzer design

Version 1 contains exactly three enforcement families:

1. **GitHub Actions workflow security:** detects privileged untrusted checkout, permission expansion, mutable Actions, expression injection, secret exposure, and unsafe self-hosted execution patterns.
2. **Dependency change and provenance:** validates manifest/lock consistency, immutable resolved identity, install-time execution changes, graph expansion, and suspicious but non-blocking name similarity.
3. **Security-sensitive diff classification:** routes authentication, authorization, process execution, cryptography, CI, deployment, and other security-boundary changes to specialized review without claiming a vulnerability.

Each rule documents evidence, default decision, false positives, false negatives, and unsupported conditions in [analyzers.md](../../analyzers.md).

## Policy and override model

Policy is restricted declarative YAML. It uses an allow-listed field registry, bounded operators, fixed nesting and operation limits, and most-restrictive-decision precedence. Unknown syntax fails closed as `incomplete`. It cannot read files, use environment variables, call functions, access a network, or load code.

Waivers are separate base-branch records restricted to one exact finding fingerprint and exact paths, with justification, approver attribution, issue, creation time, and a maximum 30-day lifetime. A pull request cannot create the waiver that approves itself. No waiver can suppress incomplete analysis. Scope changes require a new identifier and owner-reviewed base-branch change, as specified in ADR 0001.

## Error handling

Errors are security-relevant output, not logging details:

- malformed or ambiguous input: `incomplete`;
- unsupported optional surface: explicit coverage note;
- unsupported required surface: `incomplete`;
- analyzer timeout, crash, or budget exhaustion: preserve completed evidence and mark run `incomplete`;
- policy parse or evaluation error: `incomplete`;
- report schema or atomic-write failure: `incomplete`;
- SARIF publication failure: analysis status remains recorded, while overall CI reports publication failure separately;
- unexpected internal error: bounded diagnostic identifier, no stack trace or repository content in public output by default.

The system never catches an error and substitutes an empty finding list.

## Data handling and privacy

The CLI retains no data beyond requested output files. The Action uses ephemeral runner storage and uploads only configured artifacts. Evidence excerpts are bounded, Markdown- and terminal-escaped, and passed through secret redaction. Raw secret values are replaced by rule-specific descriptions and one-way digests only when a digest is needed for stable correlation.

The future App must define tenant-specific retention, deletion, region, encryption, logging, and support access before private beta. No production privacy claim is made in version 1.

## Validation strategy

Testing combines:

- unit tests for schemas, parsers, rules, policy operators, precedence, reporters, and exit codes;
- golden tests for canonical JSON, Markdown, and SARIF;
- property tests for decision monotonicity, deterministic ordering, fingerprint stability, and safe path normalization;
- fuzz tests for YAML, manifests, lockfiles, diffs, paths, and presentation escaping;
- fault injection at each parser, analyzer, policy, and reporter boundary;
- end-to-end Action fixtures for forks, permissions, exact SHAs, failures, and unavailable SARIF;
- shadow-mode pilots before any blocking rollout;
- security review focused on parser, path, policy, credential, publication, and tenant boundaries.

Quantitative stage requirements, pilot sizes, rollback, and incident targets are in [validation-gates.md](../../validation-gates.md).

## Release and operational progression

1. Specification approval.
2. CLI alpha with no network and no repository execution.
3. GitHub Action beta in shadow mode.
4. Selective blocking for high-confidence rules after measured pilots.
5. GitHub App private beta only after tenant isolation, credential, webhook, rollback, and incident controls are tested.
6. Production consideration only after external assessment and named operations ownership.

The CLI and Action remain independently usable if hosted service development stops.

## Repository and agent governance

[GOVERNANCE.md](../../../GOVERNANCE.md) defines owner authority, risk classes, and merge rules. [AI_MAINTAINERS.md](../../../AI_MAINTAINERS.md) defines the independent Codex–Claude review protocol. Neither document delegates legal ownership, provider-policy interpretation, secret access, or critical approval to an agent.

Security-sensitive implementation work must use a scoped branch and independent review. A reviewer must cite reproducible evidence and finish with one agreed verdict. An unresolved blocking finding prevents merge.

## Acceptance criteria for the specification

The package is ready for implementation planning only when:

- all linked documents exist and contain no unresolved placeholder;
- architecture, analyzer, policy, threat, and validation semantics do not conflict;
- every Claude concern from the initial review is answered or explicitly rejected with rationale;
- Claude returns `APPROVE` or `APPROVE_WITH_NONBLOCKING_NOTES`;
- the repository owner approves the written package.

## Resolution of initial independent-review concerns

| Concern | Resolution |
|---|---|
| Missing threat model and trust boundaries | Standalone source-backed design model in `docs/threat-model.md` |
| Undefined analyzers and false-confidence risk | Three bounded contracts with false-positive and false-negative profiles in `docs/analyzers.md` |
| No stage validation or rollback | Quantitative gates, pilots, rollback, and incident targets in `docs/validation-gates.md` |
| Unreliable AI-authorship distinction | Removed from product behavior; supplied provenance may be recorded but never inferred |
| Undefined policy-as-code mechanism | Restricted non-Turing-complete model, examples, SARIF projection, and tests in ADR 0001 |
| External metadata poisoning and outage | Network access excluded from MVP; future input must expose freshness, provenance, corroboration, and unavailable state |
| False-positive cost and overrides | Shadow mode, measured false-block gates, review decisions, and protected expiring waivers |
| Multi-tenant isolation | Hosted App remains blocked until explicit isolation controls and adversarial tests pass |
| Credentials and supply-chain risk | Least privilege, fork isolation, separated capabilities, immutable Action pinning, short-lived future App tokens, and release integrity gates |

## Implementation-plan requirements

The implementation plan must make function signatures and task-level file ownership exact, show test-first steps, pin dependencies and CI Actions, and preserve every invariant in this specification. Performance evidence must record the `ubuntu-latest` runner image, operating system, architecture, CPU, memory, Go patch version, engine commit, corpus digest, and command so later runs remain comparable even when hosted-runner hardware changes.
