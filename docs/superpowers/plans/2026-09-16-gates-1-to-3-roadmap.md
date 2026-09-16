# ProofRail Gates 1–3 Delivery Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved ProofRail design as an offline CLI, a safe GitHub Action, and a tenant-isolated GitHub App private beta without weakening the Gate 0 security model.

**Architecture:** One deterministic Go engine is shared by all stages. Gate 1 creates the offline engine and canonical result; Gate 2 wraps the released binary in an unprivileged GitHub Action; Gate 3 adds a separate hosted control plane whose networked ingestion and publication components never become dependencies of the offline analyzer.

**Tech Stack:** Go 1.27.1, JSON Schema Draft 2020-12, restricted YAML, canonical JSON, SARIF 2.1.0, GitHub Actions, GitHub App APIs, PostgreSQL 18, S3-compatible object storage, Docker/OCI, OpenTofu, AWS ECS Fargate for the reference private-beta deployment.

**Spec:** `docs/superpowers/specs/2026-09-16-proofrail-design.md`

## Global Constraints

- Module path is `github.com/codebyte-p/proofrail`; the CLI and workers build with `CGO_ENABLED=0`.
- Pin `toolchain go1.27.1`; record toolchain, operating system, architecture, CPU, memory, engine revision, corpus digest, and command in performance evidence.
- Analysis never executes repository content and performs no network request.
- Policy and waivers come from the immutable base revision; malformed or unavailable required input yields `incomplete`.
- Canonical JSON is authoritative; every reporter is a projection.
- Hard limits, error semantics, exit codes, waiver behavior, and decision precedence are exactly those in the approved architecture and ADR 0001.
- No task may claim promotion until every criterion in `docs/validation-gates.md` has fresh evidence and owner approval.
- All production changes use test-first red/green/refactor cycles and security-sensitive changes receive independent review.
- `Guardian` is the workspace directory only; product name, module path, schema IDs, and remote remain ProofRail until a separately approved rename.

---

## Delivery sequence

| Stage | Deliverable | Detailed plan | Promotion authority |
|---|---|---|---|
| Gate 1 | Offline CLI alpha with three analyzer families, bounded policy/waivers, canonical JSON, console, Markdown, and SARIF | `2026-09-16-gate-1-cli-alpha.md` | Owner after independent security review |
| Gate 2 | Reusable unprivileged `pull_request` Action, artifacts, summary, optional isolated SARIF publication, and shadow pilot | `2026-09-16-gate-2-action-beta.md` | Owner after pilot metrics and rollback check |
| Gate 3 | GitHub App private beta with verified webhooks, durable jobs, ephemeral workers, credential separation, tenant isolation, audit, retention, and deployment rollback | `2026-09-16-gate-3-hosted-app.md` | Owner after 30-day evidence and cross-tenant review |

The stages are sequential. Work that is merely preparatory for a later gate may be documented early, but its runtime must not be connected to a release before the preceding gate is promoted.

## Program dependency graph

```text
Gate 0 approved specification
        |
        v
Gate 1A contracts and deterministic result
        |
        +--> Git revision binding and bounded readers
        |          |
        |          +--> workflow parser --> workflow analyzer
        |          +--> npm/python parsers --> dependency analyzer
        |          +--> normalized diff --> diff classifier
        |
        +--> restricted policy and waivers
        +--> canonical reporters and CLI
                         |
                         v
                 Gate 1 evidence + approval
                         |
                         v
                 Gate 2 Action wrapper
                         |
                  shadow-mode pilot
                         |
                         v
                 Gate 2 evidence + approval
                         |
                         v
      Gate 3 webhook/API --> durable queue --> isolated worker
              |                  |                 |
              +--> tenant DB ----+----- artifact store
                                 |
                          separated publisher
                                 |
                          GitHub Checks/SARIF
                                 |
                    30-day private-beta evidence
```

## Final repository shape through Gate 3

```text
.github/
  workflows/ci.yml
  workflows/codeql.yml
  workflows/release.yml
  workflows/proofrail.yml
action/action.yml
cmd/proofrail/main.go
cmd/proofrail-api/main.go
cmd/proofrail-worker/main.go
cmd/proofrail-publisher/main.go
internal/analyzer/{workflow,dependency,diff}/
internal/finding/
internal/gitdiff/
internal/hosted/audit/
internal/hosted/authz/
internal/hosted/githubapp/
internal/hosted/jobs/
internal/hosted/publisher/
internal/hosted/store/
internal/hosted/tenant/
internal/hosted/webhook/
internal/hosted/worker/
internal/parser/{workflow,npm,python}/
internal/policy/
internal/report/
internal/run/
schemas/{policy,waiver,finding,run-result}/
deploy/compose/
deploy/opentofu/modules/{database,ecs,iam,network,objectstore,secrets}/
deploy/opentofu/environments/private-beta/
migrations/
testdata/{malicious,benign,malformed,replay,hosted}/
docs/evidence/gate-{1,2,3}/
```

## Planned dependency envelope

The offline engine begins with only:

- `go.yaml.in/yaml/v3 v3.0.5` for a syntax tree that ProofRail inspects before decoding;
- `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3` for embedded Draft 2020-12 schema conformance.

Gate 3 adds:

- `github.com/jackc/pgx/v5 v5.11.0` for PostgreSQL access.

GitHub API calls use `net/http` with typed local request/response contracts. Object storage uses a narrow internal interface and the AWS SDK module only in the reference deployment adapter; pin its version when Gate 3 begins after dependency review. OpenTelemetry is not admitted by default: structured logs and explicit metrics are sufficient for private beta, and telemetry libraries require a separate dependency review.

## CI and release pins

- `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`)
- `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` (`v7.0.0`)

These revisions were verified against the upstream tag refs on 2026-09-16. Every additional Action introduced later must be pinned to a full commit SHA and recorded in the dependency ledger.

## Review and branch program

1. Create one scoped branch per numbered task group; never accumulate an entire gate in one unreviewable branch.
2. Merge only after the task's focused tests, full suite, static checks, and document checks pass.
3. Use a release-candidate branch only to collect already-reviewed changes and evidence; do not develop directly on it.
4. Claude may implement a task but may not provide its decisive security approval. Codex or another approved independent reviewer must validate the diff and test evidence.
5. Promotion commits are documentation-only commits recording evidence links, immutable release digest, reviewer verdict, and owner approval.

## Evidence directory contract

Each gate directory contains:

```text
README.md                 criterion-to-evidence index
environment.json          toolchain and runner metadata
commands.txt              exact reproducible commands
tests/                    machine-readable test summaries
benchmarks/               raw benchmark output and corpus digest
security-review.md        independent verdict and findings
limitations.md            accepted limitations and non-findings
promotion.md              release digest, rollback target, owner approval
```

Evidence files must not contain credentials, raw webhook payloads from private repositories, source excerpts beyond the redaction limits, or tenant identifiers that are not synthetic.

## Effort and calendar expectations

These are planning ranges, not deadlines:

- Gate 1: 30–45 focused implementation/review days, plus corpus construction and independent review.
- Gate 2: 15–25 focused days, plus enough authorized pull requests to reach 100 shadow runs across at least three repositories.
- Gate 3: 40–65 focused days, plus a mandatory 30-calendar-day private-beta measurement window and at least 500 analyses across five invited installations.

Automation can reduce coding time, but it cannot compress the measured pilot windows, independent review, owner approvals, or incident/rollback exercises.

## Program-level stop conditions

Stop implementation and return to design review when any task would require:

- executing repository code;
- making missing analysis non-blocking;
- using head-revision policy to judge itself;
- granting broader GitHub permissions than the approved architecture;
- sharing workspaces, credentials, caches, logs, or object prefixes across tenants;
- adding an unbounded language or plugin mechanism;
- increasing an approved resource limit;
- retaining private repository data beyond the approved policy;
- claiming regulatory compliance or vulnerability absence.

## Completion definition

This roadmap is complete only when Gate 3 promotion evidence shows all private-beta criteria passing. It does not authorize public production. Gate 4 remains a separate future program requiring external assessment, named operations ownership, disaster-recovery and credential-compromise exercises, capacity tests, signed artifacts, SBOMs, and explicit owner approval.
