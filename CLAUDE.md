# Claude Code Execution Contract

This repository implements ProofRail, an evidence-backed assurance platform for GitHub pull requests. The local workspace may be named `Guardian`; that directory name does not rename the product, module, schemas, or GitHub repository.

## Start here

Read these files before changing application code:

1. `docs/superpowers/specs/2026-09-16-proofrail-design.md`
2. `docs/architecture.md`
3. `docs/threat-model.md`
4. `docs/analyzers.md`
5. `docs/decisions/0001-restricted-policy-model.md`
6. `docs/validation-gates.md`
7. `docs/superpowers/plans/2026-09-16-gates-1-to-3-roadmap.md`
8. The plan for the active gate under `docs/superpowers/plans/`

Gate 0 is approved. Do not reinterpret that approval as permission to weaken an invariant or skip a later promotion gate.

## Non-negotiable invariants

- Never execute repository-controlled code, hooks, builds, installers, Actions, or binaries during analysis.
- Load effective policy and waivers from the bound base revision. Head-revision changes never judge their own pull request.
- Any required-parser, analyzer, policy, reporter, budget, or integrity failure yields `incomplete` and exit code `2`; it can never become `pass`.
- Canonical JSON is the source of truth. Console, Markdown, checks, and SARIF are projections and may not reinterpret the decision.
- Keep analysis offline. Network clients belong only in explicit GitHub ingestion, checkout, publication, and hosted-control-plane packages.
- Never infer AI authorship.
- Never expose secrets or raw credentials in findings, logs, errors, snapshots, fixtures, or test output.
- Do not introduce `pull_request_target` execution of untrusted content.
- Do not add general-purpose policy evaluation, templates, regular expressions, callbacks, downloaded plugins, or runtime code loading.
- Do not broaden limits, fields, operators, waiver scope, permissions, retention, or egress without updating the threat model and obtaining owner review.

## Required development loop

For every behavior change:

1. Create or continue a scoped branch named `feat/gateN-<scope>`, `fix/<scope>`, or `docs/<scope>`.
2. Write one focused test against the desired public behavior.
3. Run it and record that it fails for the expected missing behavior.
4. Write the minimum production code required to pass.
5. Run the focused test, then `go test ./...`, `go vet ./...`, and the gate-specific verification commands.
6. Refactor only while the suite remains green.
7. Commit one independently reviewable unit. Do not combine unrelated cleanup.
8. Update the active plan checkboxes and evidence ledger in the same branch.

Production code written before its test must be removed and reimplemented test-first. Generated schema bindings and configuration files are exempt from test-first ordering, but the behavior that consumes them is not.

## Branch and review rules

- Never push application work directly to `main`.
- Never merge your own security-sensitive change without the independent review required by `AI_MAINTAINERS.md`.
- Preserve user and collaborator changes. Do not reset, force-push, rewrite shared history, or delete branches without explicit owner authorization.
- Use conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `ci:`, `build:`, `refactor:`, `security:`.
- A task is complete only when its tests and verification commands have fresh passing output.

## Technology and dependency policy

- Go toolchain: `go1.27.1`; module: `github.com/codebyte-p/proofrail`; `CGO_ENABLED=0` for CLI releases.
- Prefer the standard library. Every added module requires a stated purpose, exact version, license check, checksum in `go.sum`, vulnerability scan, and owner-visible review.
- Approved initial modules are `go.yaml.in/yaml/v3 v3.0.5`, `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3`, and, beginning at Gate 3, `github.com/jackc/pgx/v5 v5.11.0`.
- GitHub Actions must use immutable 40-character commit SHAs with the release tag in a comment.
- Current approved CI pins are `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`) and `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` (`v7.0.0`). Reverify upstream before changing them.

## Package boundaries

- `internal/gitdiff` owns Git invocation, revision binding, path normalization, and changed-file limits. It may not execute hooks, filters, submodules, LFS, or repository programs.
- `internal/parser/*` consumes bounded bytes and emits normalized records. Parsers have no filesystem or network authority.
- `internal/analyzer/*` consumes normalized records and emits candidate findings. Analyzers have no reporter, policy, filesystem, process, or network authority.
- `internal/finding` owns finding validation, ordering, fingerprints, and redaction-safe evidence types.
- `internal/policy` owns restricted policy, waiver validation, and decision precedence. It receives registered values only.
- `internal/report` consumes a validated canonical result. It cannot change status, decision, fingerprints, or analyzer completion.
- `internal/hosted/*` begins at Gate 3 and may not be imported by the offline analysis engine.

## Gate discipline

- Gate 1 closes only when every CLI-alpha criterion in `docs/validation-gates.md` has reproducible evidence.
- Gate 2 starts only after Gate 1 owner promotion approval and closes only after Action beta evidence and authorized shadow pilots.
- Gate 3 starts only after Gate 2 owner promotion approval. Private-beta deployment is prohibited until cross-tenant, credential, webhook, egress, retention, rollback, and incident exercises pass.
- Record evidence in `docs/evidence/gate-N/`; do not replace evidence with claims in prose.

When a plan and implementation disagree, stop and update the plan through review before continuing. When a security requirement is ambiguous, choose the fail-closed behavior and escalate the ambiguity to the repository owner.

## Build and verification commands

```bash
go test ./...                 # full suite
go vet ./...
gofmt -l .                    # must print nothing
go build ./...
```

Focused runs:

```bash
go test ./internal/parser/workflow -run TestParse -v
go test ./internal/analyzer/workflow -run 'TestRuleDetectsMaliciousFixture/PFR-WF-004' -v
```

Fuzzing. `-fuzz` takes a regex that must match exactly one target in exactly one package; `internal/parser/{workflow,npm,python}` all name their target `FuzzParse`, so a `./internal/parser/...` wildcard fails with "cannot use -fuzz flag with multiple packages". Without `-fuzz`, the seed corpus runs as ordinary unit tests, which is what `go test ./...` does.

```bash
go test ./internal/parser/npm -fuzz=FuzzParse -fuzztime=60s
```

A crasher is written to `internal/<pkg>/testdata/fuzz/FuzzParse/<hash>`. Commit it: it replays on every later `go test` and is the regression test.

Dependency policy requires a vulnerability scan, and the binary is not installed by default:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
"$(go env GOPATH)/bin/govulncheck" -show verbose ./...
```

`go test -race` does not build on the Windows workstation (no C toolchain). Race evidence comes from `.github/workflows/ci.yml` on `ubuntu-latest`. CI also runs `go test ./... -run TestCanonical -count=100` for determinism.

## Dependency direction

`internal/finding` and `internal/gitdiff` are leaves and import only the standard library. Everything else flows one way:

```
analyzer/* ──> parser/* ──> run ──> finding
     └──────────────────────> gitdiff <──┘
```

An import that reverses an arrow is an import cycle. Amendment 1 (enums in `finding`, aliased from `run`) and Amendment 3 (`gitdiff` owns its narrow `Limits`) exist because the plan's literal wording would have closed one.

## Parser and analyzer conventions

Every parser exposes `Parse*(path string, content []byte, maxBytes int64) (Model, []run.Diagnostic)` and returns **the zero model on any diagnostic** — never a partially populated one a caller might act on. Bounds are checked before the decoder sees the input.

Diagnostics and coverage notes are not interchangeable:

- **Diagnostic** — the input could not be read. Drives `failed` completion, `incomplete`, exit code `2`.
- **Coverage note** — the input was read but a field is not modeled. The run stays complete and states what it did not cover.

A `Scalar` carries `Value` plus source `Position`. `Present()` means *written*, which an **empty string satisfies** — guard on `Value != ""` when a name will key a map. A fuzz-found defect (`name = ""` in `uv.lock`) collided every empty name into one entry.

Analyzers return a result, never an `error`: a caller could ignore an error and read missing analysis as a pass. `failed` completion **retains** findings from inputs that were fully analyzed. `finding.Finalize` is the only way to obtain a canonical `Finding`. Sanitize repository-supplied strings to printable ASCII before they reach a message, locator, or excerpt.

Diagnostic locators are `<file>#<pointer>`, e.g. `.github/workflows/ci.yml#jobs.build.steps[0].run`.

## Current state

Tasks 1–5 complete; Task 6 (PFR-DIFF) is next. Amendments 1 and 3–7 are accepted; Amendment 2 is historical context only. Amendment 5 defines `Scanner.Scan` as returning `(CanonicalRunResult, Telemetry)`, keeps telemetry outside every canonical projection, and no longer blocks Task 10. PR #1 remains unmerged pending another independent non-authoring review.
