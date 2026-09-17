# Gate 2 GitHub Action Beta Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the promoted Gate 1 engine as an unprivileged `pull_request` GitHub Action that binds exact event revisions, publishes canonical artifacts and a job summary, optionally uploads SARIF in a separate capability, and earns shadow-mode pilot evidence.

**Architecture:** The analysis job has only `contents: read`, no secrets, and no write token. It checks out immutable event SHAs, extracts policy and waivers from the base commit, executes a checksum-verified ProofRail release, and uploads canonical JSON/SARIF as artifacts; a separate job with `security-events: write` may publish the already-generated SARIF and reports publication failure independently.

**Tech Stack:** GitHub Actions, promoted ProofRail CLI, Go 1.27.1 test harness, SARIF 2.1.0, pinned official Actions.

**Spec:** `docs/superpowers/specs/2026-09-16-proofrail-design.md`

## Global Constraints

- Gate 1 must be promoted before this plan's runtime is released.
- Trigger only on `pull_request`; never use `pull_request_target` for analysis.
- Analysis permissions are exactly `contents: read`; set all other permissions to none by omission under an explicit permissions block.
- Fork pull requests receive no secrets and no write-capable token.
- Effective policy and waiver bytes come from the exact base SHA, never the checked-out head tree.
- Canonical JSON remains authoritative; SARIF publication success or failure cannot change the analysis decision.
- All external Actions use immutable full SHAs.

---

## Approved Action pins

```text
actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1       # v7.0.1
actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0 # v5.0.0
github/codeql-action/upload-sarif@4bd7200e1f146b1c937cae12d258b50f41a53cf8 # v4.38.0
```

The tags above were resolved from their upstream Git refs on 2026-09-16. Reverify before changing any pin.

## Task 1: Release manifest and verified binary acquisition

**Files:**
- Create: `internal/release/manifest.go`
- Create: `internal/release/manifest_test.go`
- Create: `cmd/proofrail-installer/main.go`
- Create: `internal/release/install.go`
- Create: `internal/release/install_test.go`
- Create: `release/checksums.schema.json`
- Create: `.github/workflows/release.yml`

**Interfaces:**
- `release.VerifyManifest(manifest, signature, trustedKey []byte) (Manifest, error)`.
- `release.Install(ctx context.Context, client *http.Client, manifest Manifest, os, arch, destination string) error`.

- [ ] **Step 1: Write failing manifest verification tests**

Test exact release version, commit, filename, OS, architecture, byte length, SHA-256, signing-key ID, duplicate entries, unknown fields, path traversal filenames, signature tampering, and manifest/release mismatch. Seed only synthetic Ed25519 keys in tests.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/release -run TestVerifyManifest -v`

Expected: compile failure because verification is absent.

- [ ] **Step 3: Implement signed manifest verification**

Use `crypto/ed25519`, canonical JSON, embedded trusted public keys with explicit key IDs, maximum 1 MiB manifest, and exact filename allow-list `proofrail_<version>_<os>_<arch>`. Reject unsigned, expired/revoked-key, duplicate, extra, or mismatched entries.

- [ ] **Step 4: Write failing installer tests**

Use `httptest.Server` to verify HTTPS-only URLs, redirect rejection to another host, 64 MiB response cap, status handling, checksum/length validation before atomic rename, executable mode, and cleanup on cancellation/failure. Tests must prove no bearer token is sent to the release host.

- [ ] **Step 5: Implement, verify, and commit**

The installer is a small prebuilt bootstrap published with the Action; it downloads only from `github.com/codebyte-p/proofrail/releases/download/<version>/`, verifies before installation, and refuses floating `latest` URLs.

Run: `go test ./internal/release -v && go test ./... && go vet ./...`.

Commit: `feat: verify immutable proofrail releases`

## Task 2: Composite Action contract

**Files:**
- Create: `action/action.yml`
- Create: `action/run.ps1`
- Create: `action/run.sh`
- Create: `action/action_contract_test.go`
- Create: `docs/action.md`

**Interfaces:**
- Inputs: `base-sha`, `head-sha`, `repository`, `proofrail-version`, `evaluated-at`, `fail-on`.
- Outputs: `status`, `decision`, `exit-code`, `canonical-json`, `sarif`, `summary`.
- No input exists for policy path, waiver path, arbitrary arguments, command, shell, URL, token, or executable.

- [ ] **Step 1: Write failing static contract tests**

Parse `action.yml` as data and assert no forbidden input, no `pull_request_target` string, no unpinned `uses`, no interpolation of user-controlled values into shell source, and exact output names. Assert shell scripts quote every positional value and reject non-40-hex SHAs/repository names before invoking Git.

- [ ] **Step 2: Verify RED**

Run: `go test ./action -run TestActionContract -v`

Expected: failure because the Action does not exist.

- [ ] **Step 3: Implement base-controlled input extraction**

The wrapper must use `git show "${BASE_SHA}:.proofrail/policy.yml"` and `git show "${BASE_SHA}:.proofrail/waivers.yml"` into `RUNNER_TEMP` files with restrictive permissions. A missing waiver file means an empty valid waiver set; a missing required policy uses the immutable built-in policy embedded in the release. Any malformed/extraction failure becomes incomplete. Never source or execute extracted files.

- [ ] **Step 4: Implement CLI execution and output capture**

Invoke the installed binary with an argument array, not evaluated shell text. Write outputs under `RUNNER_TEMP/proofrail/`; append escaped Markdown to `GITHUB_STEP_SUMMARY`; use `GITHUB_OUTPUT` delimiter syntax with generated delimiters; preserve CLI exit code while still making artifacts available.

- [ ] **Step 5: Verify and commit**

Run: `go test ./action -v && shellcheck action/run.sh` on Linux and PSScriptAnalyzer for `action/run.ps1` on Windows CI. Gate 2 initially supports `ubuntu-24.04`; PowerShell exists for local parity but is not advertised until its E2E gate passes.

Commit: `feat: add constrained proofrail action wrapper`

## Task 3: Reference pull-request workflow and capability separation

**Files:**
- Create: `.github/workflows/proofrail.yml`
- Create: `internal/actiontest/workflow_test.go`
- Create: `internal/actiontest/permissions_test.go`

**Interfaces:**
- Job `analyze`: `contents: read` only; produces `proofrail-results` artifact.
- Job `publish-sarif`: `security-events: write`, `actions: read`, `contents: read`; downloads only the named artifact and never checks out or executes pull-request content.

- [ ] **Step 1: Write failing workflow-policy tests**

Assert event is exactly `pull_request`, analysis job permissions are exact, checkout uses head SHA and `persist-credentials: false`, fetch depth makes base available, every Action is pinned, no secrets are referenced, artifact retention is 7 days, and SARIF job has no `run:` step or checkout.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/actiontest -v`

Expected: failure because the workflow is absent.

- [ ] **Step 3: Implement analysis workflow**

Checkout with `ref: ${{ github.event.pull_request.head.sha }}`, `fetch-depth: 0`, and disabled persisted credentials. Pass base/head/repository/evaluated-at from trusted event and runner expressions, not PR inputs. Upload canonical JSON, SARIF, summary, and bounded diagnostics even when scan exit is nonzero; then finish with the recorded ProofRail exit code.

- [ ] **Step 4: Implement isolated optional SARIF job**

Use `if: always() && needs.analyze.outputs.sarif-ready == 'true' && github.event.pull_request.head.repo.fork == false` initially. Download only `proofrail-results`, validate artifact digest and SARIF schema, upload via the pinned CodeQL Action, and expose `publication-status` separately. A SARIF failure must not overwrite `analysis-status`.

- [ ] **Step 5: Verify and commit**

Run workflow lint, `go test ./internal/actiontest -v`, and a permissions snapshot test.

Commit: `ci: add least-privilege proofrail workflow`

## Task 4: End-to-end event matrix

**Files:**
- Create: `testdata/action/events/{same-repo,fork,dependabot,renamed,deleted,malformed-policy,timeout,sarif-unavailable}.json`
- Create: `internal/actiontest/e2e_test.go`
- Create: `internal/actiontest/fakegithub/server.go`

**Interfaces:**
- Test harness executes the wrapper in a temporary runner-like directory and records filesystem, environment, process arguments, and HTTP attempts.

- [ ] **Step 1: Write failing scenario tests**

For every required Gate 2 scenario, assert exact base/head binding, base policy digest, waiver digest, canonical artifact identity, exit status, and absence of secrets. Renamed/deleted files must preserve old/new paths correctly; malformed policy and timeout must be incomplete.

- [ ] **Step 2: Add hostile input tests**

Use repository names, paths, branch titles, commit messages, and artifact filenames containing spaces, quotes, newlines, workflow expressions, shell metacharacters, ANSI bytes, and Unicode. Assert none becomes shell, YAML, Markdown, or command injection.

- [ ] **Step 3: Verify RED, implement harness fixes, and verify GREEN**

Run RED: `go test ./internal/actiontest -run TestEndToEnd -v`.

Make only wrapper/workflow changes needed for the scenarios. Run GREEN: `go test ./internal/actiontest -v -count=10 && go test ./...`.

- [ ] **Step 4: Commit**

Commit: `test: cover github action trust boundaries`

## Task 5: Shadow-mode pilot and Gate 2 evidence

**Files:**
- Create: `docs/evidence/gate-2/{README.md,environment.json,commands.txt,limitations.md,promotion.md}`
- Create: `docs/evidence/gate-2/tests/summary.json`
- Create: `docs/evidence/gate-2/pilot/runs.ndjson`
- Create: `docs/evidence/gate-2/pilot/metrics.json`

**Interfaces:**
- Pilot collector accepts only redacted run metadata and canonical decisions from repositories whose maintainers authorized analysis.

- [ ] **Step 1: Run local workflow simulation**

Exercise the full event matrix with no GitHub credentials, then run in a disposable authorized repository. Confirm canonical revision/policy digests match the event in every case and publication failure is separately visible.

- [ ] **Step 2: Complete authorized shadow pilot**

Collect at least 100 pull-request runs across at least three authorized repositories. Record engine version, repository pseudonym, event class, status, decision, duration, expected outcome, false-block classification, and publication status; store no source or secret.

- [ ] **Step 3: Calculate promotion metrics**

Require at least 99% completion, false-block at or below 2%, P95 below 120 seconds, all Gate 1 gates still passing, minimum permissions, immutable pins, no fork secrets/write token, and successful revision/digest checks.

- [ ] **Step 4: Exercise rollback**

Pin the last known-good Action and CLI digest, simulate a decision-integrity regression, disable the affected release, restore the pin, and record elapsed time and verification output.

- [ ] **Step 5: Independent review and promotion commit**

Obtain independent review of workflow expression injection, fork boundaries, artifact substitution, release verification, and separated SARIF capability. Resolve blockers. Owner approval is recorded only after all evidence passes.

Commit: `test: record gate 2 promotion evidence`

## Gate 2 completion checkpoint

Do not begin hosted runtime implementation until the owner approves Gate 2. The Action remains shadow-only until measured false-block and completion thresholds pass; selective blocking is a separate owner-approved rollout decision.
