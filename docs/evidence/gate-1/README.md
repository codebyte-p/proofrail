# Gate 1 Evidence Index

This directory holds reproducible evidence for the CLI-alpha promotion criteria
in [`docs/validation-gates.md`](../../validation-gates.md). Every criterion links
to a concrete artifact. Prose claims do not substitute for evidence, and a
criterion is not satisfied until a fresh command in `commands.txt` reproduces the
linked output.

**Gate 1 is open.** No promotion has been requested and no owner approval has
been recorded. Criteria are marked `pending` until their evidence exists.

## Directory contract

| File | Contents | State |
|---|---|---|
| `README.md` | This criterion-to-evidence index | present |
| `environment.json` | Toolchain, runner, OS, architecture, CPU, memory, engine revision, corpus digest | pending (Task 13) |
| `commands.txt` | Exact reproducible commands for every recorded result | pending (Task 13) |
| `tests/summary.json` | Machine-readable test and corpus results | pending (Task 13) |
| `benchmarks/results.json` | Raw benchmark output, corpus digest, P95 | pending (Task 13) |
| `security-review.md` | Independent reviewer verdict and findings | pending (Task 13) |
| `limitations.md` | Accepted limitations and documented non-findings | pending (Task 13) |
| `promotion.md` | Release digest, rollback target, owner approval | pending (Task 13) |

Evidence files must not contain credentials, source excerpts beyond the
redaction limits, or non-synthetic repository identifiers.

## Criterion index

| # | Gate 1 criterion | Evidence | State |
|---|---|---|---|
| 1 | 100% pass on schema, parser, policy, reporter, and exit-code unit tests | `tests/summary.json` | pending |
| 2 | 100% detection of `must_detect` fixtures for `PFR-WF-001`, `PFR-WF-004`, `PFR-WF-005`, `PFR-DEP-001`, `PFR-DEP-004`, and required-analyzer failure | `tests/summary.json` | pending |
| 3 | Zero false `pass` across malformed, timeout, parser-failure, unsupported-required-input, and reporter-failure fixtures | `tests/summary.json` | pending |
| 4 | At least 500 adversarial parser fixtures execute without process escape, uncontrolled resource growth, or unhandled termination | `tests/summary.json` | pending |
| 5 | Deterministic canonical JSON in 100 repeated runs on every golden fixture across supported platforms | `tests/summary.json` | pending |
| 6 | False-block rate at or below 5% on the benign corpus, remaining cases documented | `tests/summary.json`, `limitations.md` | pending |
| 7 | P95 below 60 seconds for 5,000 changed lines and 100 changed supported files | `benchmarks/results.json` | pending |
| 8 | No network request during analysis, verified in an isolated environment | `tests/summary.json` | pending |
| 9 | Policy evaluation satisfies the ADR 0001 operator, termination, adversarial-policy, fixed-clock, waiver-containment, fuzz, and fault-injection obligations | `tests/summary.json` | pending |
| 10 | Independent security review of parser, path, policy, redaction, and atomic-output boundaries | `security-review.md` | pending |
| 11 | Shadow-mode pilot on ProofRail and at least two authorized public repositories | `promotion.md` | pending |

## Task ledger

Progress against [the Gate 1 plan](../../superpowers/plans/2026-09-16-gate-1-cli-alpha.md).
A task counts as done only when its focused tests, `go test ./...`, and
`go vet ./...` have fresh passing output on its branch.

| Task | Scope | Branch | State |
|---|---|---|---|
| 1 | Toolchain, module, CI, terminal contracts | `feat/gate1-contracts` | done |
| 2 | Safe paths and immutable Git revision binding | `feat/gate1-gitdiff` | done |
| 3 | Findings, redaction, ordering, fingerprints | — | not started |
| 4 | Bounded workflow parser and PFR-WF analyzer | — | not started |
| 5 | npm/Python parsing and PFR-DEP analyzer | — | not started |
| 6 | PFR-DIFF security-sensitive classifier | — | not started |
| 7 | Embedded schemas and restricted policy parsing | — | not started |
| 8 | Non-Turing-complete policy evaluator | — | not started |
| 9 | Exact waivers and audit outcomes | — | not started |
| 10 | Orchestration, budgets, fail-closed completion | — | not started |
| 11 | Canonical JSON, console, Markdown, SARIF, atomic output | — | not started |
| 12 | CLI command and end-to-end offline scan | — | not started |
| 13 | Corpus, adversarial campaign, benchmarks, promotion evidence | — | not started |

## Plan amendments awaiting review

Both amendments are recorded in full in the Gate 1 plan and are **proposed, not
accepted**. Gate 1 cannot close while either is unreviewed.

- **Amendment 1** — the ordered `Severity`, `Confidence`, and `Decision` enums are
  defined in `internal/finding` and re-exported from `internal/run` as type
  aliases, because defining them in `internal/run` produces an import cycle once
  Task 10 orchestrates `[]finding.Finding`.
- **Amendment 2** — `AnalyzerResult` gains its `Findings` field in Task 10 rather
  than Task 1, because `finding.Finding` does not exist until Task 3 and the
  development loop forbids production code ahead of its test.

## Known environment limitations

| Limitation | Effect | Compensating control |
|---|---|---|
| The development workstation has no C toolchain, so `go test -race` cannot build locally (`cgo: C compiler "gcc" not found`) | Race evidence cannot be produced on the workstation | `.github/workflows/ci.yml` runs `go test -race ./...` on `ubuntu-latest` with `CGO_ENABLED=1`. Race evidence for Gate 1 comes from CI, and the run link is recorded in `tests/summary.json`. Resolve before Task 10 introduces concurrency, or record CI as the sole source. |
| Determinism must hold "across supported platforms" | A Windows checkout could change golden bytes through line-ending translation | `.gitattributes` forces LF in the working tree and marks `*.golden`, `*.sarif`, and `testdata/**` as binary so Git never rewrites them. |
