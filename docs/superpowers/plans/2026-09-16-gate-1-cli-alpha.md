# Gate 1 Offline CLI Alpha Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, offline `proofrail scan` CLI that binds immutable revisions, runs the three approved analyzer families, evaluates bounded policy and waivers, and emits validated canonical JSON plus console, Markdown, and SARIF projections.

**Architecture:** Git access is isolated in `internal/gitdiff`; parsers consume bounded bytes; analyzers consume normalized records; policy receives validated finding fields; reporters consume only a validated canonical result. The orchestrator preserves completion ledgers and converts every required-stage failure into `incomplete` and exit code `2`.

**Tech Stack:** Go 1.27.1, standard library, `go.yaml.in/yaml/v3 v3.0.5`, `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3`, JSON Schema Draft 2020-12, SARIF 2.1.0.

**Spec:** `docs/superpowers/specs/2026-09-16-proofrail-design.md`

## Global Constraints

- Preserve every invariant and hard limit in `docs/architecture.md`, `docs/threat-model.md`, and ADR 0001.
- No repository code execution and no network access during scan.
- All paths are normalized forward-slash repository-relative paths; absolute paths, drive letters, NUL, backslashes in policy paths, and `..` segments are rejected.
- Fixed `evaluated_at` is injected for tests; identity includes repository, base/head SHA, policy/waiver digests, engine version, limits, and timestamp.
- Stable ordering is fingerprints ascending, analyzer IDs ascending, policy rule IDs ascending, and locations path/line ascending.
- Errors exposed to users are bounded codes and redacted messages; internal stack traces and raw hostile content are excluded.
- Maximums: 5,000 files, 50 MiB aggregate changed content, 2 MiB workflow, 10 MiB lockfile, 1 MiB manifest, 128 KiB policy/waiver, nesting 64, 30 seconds/analyzer, 120 seconds/run, 5,000 findings/SARIF results, 50 MiB canonical output.

---

## Exact package contracts

Implement these signatures and keep later tasks aligned with them:

```go
// internal/gitdiff/model.go
type ChangeKind string
const (Added ChangeKind = "added"; Modified ChangeKind = "modified"; Deleted ChangeKind = "deleted"; Renamed ChangeKind = "renamed")
type FileChange struct { Path, PreviousPath string; Kind ChangeKind; Patch []byte; BaseContent, HeadContent []byte }
type ChangeSet struct { Repository, BaseSHA, HeadSHA string; Files []FileChange; ChangedLines int; ContentBytes int64 }
type Loader interface { Load(context.Context, Request) (ChangeSet, error) }
type Request struct { RepoPath, Repository, BaseSHA, HeadSHA string; Limits Limits }
```

```go
// internal/finding/model.go
type Finding struct {
    RuleID, AnalyzerID string
    Severity Severity
    Confidence Confidence
    DecisionHint Decision
    Message string
    Locations []Location
    Evidence []Evidence
    Limitations []string
    Fingerprint string
}
func Finalize(Finding) (Finding, error)
```

```go
// internal/run/model.go
type Analyzer interface { ID() string; Analyze(context.Context, AnalysisInput) AnalyzerResult }
type AnalysisInput struct { Identity RunIdentity; Changes gitdiff.ChangeSet; Policy []byte; Waivers []byte; Limits Limits }
type Scanner interface { Scan(context.Context, ScanRequest) CanonicalRunResult }
func ExitCode(CanonicalRunResult) int
```

```go
// internal/policy/api.go
func ParsePolicy([]byte) (Policy, []Diagnostic)
func ParseWaivers([]byte) (WaiverSet, []Diagnostic)
func Evaluate(EvaluationInput) EvaluationResult
```

```go
// internal/report/api.go
type Renderer interface { Format() string; Render(run.CanonicalRunResult) ([]byte, error) }
func WriteAtomic(path string, content []byte, maxBytes int64) error
```

## Plan amendments

Amendments are recorded here when implementation proves a planned structure
unworkable. Each one states the conflict, the change, and the invariants it
preserves. An amendment is proposed by the implementer and is not settled until
the independent reviewer and the repository owner accept it.

### Amendment 1: ordered finding enums live in `internal/finding`

- **Status:** Proposed 2026-09-16 during Task 1. Awaiting independent review and owner acceptance.
- **Conflict.** Task 1 assigns `Decision` to `internal/run/model.go`, and the
  Task 3 signature `type Finding struct { ... DecisionHint Decision ... }` uses
  the same identifier unqualified inside package `finding`. Task 10 then requires
  `internal/run` to orchestrate `[]finding.Finding`. Defining the ordered enums in
  `internal/run` forces `finding` to import `run` while `run` must import
  `finding`, which Go rejects as an import cycle.
- **Change.** `Severity`, `Confidence`, and `Decision` are defined in
  `internal/finding`, which imports only the standard library and is the leaf of
  the Gate 1 dependency graph. `internal/run` re-exports each of them as a type
  alias with its constants, so `run.Decision`, `run.DecisionBlock`,
  `run.Severity`, and `run.Confidence` remain valid spellings for every later
  task and for `ExitCode(CanonicalRunResult{Status, Decision})`. The single
  dependency direction becomes `run -> finding`.
- **Files added to Task 1.** `internal/finding/enum.go`, `internal/finding/enum_test.go`.
- **Invariants preserved.** No symbol named in the plan is removed or renamed;
  aliases are identical types, not conversions. Severity order stays
  `note < low < medium < high < critical`, confidence stays `low < medium < high`,
  and decision restrictiveness stays `block > require_review > warn > observe > pass`.
  No limit, error semantic, exit code, or package-boundary rule in
  `CLAUDE.md`, `docs/architecture.md`, or ADR 0001 changes.

### Amendment 2: `AnalyzerResult` gains its findings field in Task 10

- **Status:** Proposed 2026-09-16 during Task 1. Awaiting independent review and owner acceptance.
- **Conflict.** The specification's `AnalyzerResult` carries findings, but
  `finding.Finding` does not exist until Task 3, and the required development
  loop forbids writing production code ahead of the test that demands it.
- **Change.** Task 1 defines `AnalyzerResult` with analyzer identity, version,
  completion status, coverage notes, duration, budget usage, and redacted failure
  diagnostics. The `Findings []finding.Finding` field is added in Task 10, driven
  by the orchestration test that first requires it.
- **Invariants preserved.** The completion ledger and the rule that a required
  analyzer returning `failed` yields `incomplete` are unchanged; only the moment
  the field appears moves.

### Amendment 3: `internal/gitdiff` owns its own narrow `Limits`

- **Status:** Proposed 2026-09-16 during Task 2. Awaiting independent review and owner acceptance.
- **Conflict.** The contract block writes `Limits Limits` unqualified inside
  `internal/gitdiff/model.go` while Task 2 also says the package "consumes
  `run.Limits`". Those cannot both be literal: `internal/run` must import
  `internal/gitdiff` for `AnalysisInput.Changes`, so `internal/gitdiff` importing
  `internal/run` would close a second cycle.
- **Change.** `internal/gitdiff` defines its own `Limits` holding only the two
  bounds it actually enforces, `MaxChangedFiles` and `MaxChangedContentBytes`.
  `run.Limits` gains a `ForGitDiff()` converter in Task 10, so the architecture
  limits stay the single source of truth and `internal/gitdiff` stays the owner of
  changed-file limits as `CLAUDE.md` requires. The dependency direction becomes
  `run -> gitdiff`.
- **Invariants preserved.** The enforced values are unchanged: 5,000 changed files
  and 50 MiB of aggregate changed content. Exceeding either still yields an
  `incomplete`-class failure.

---

## Task 1: Toolchain, module, CI, and terminal contracts

**Files:**
- Create: `go.mod`
- Create: `.gitattributes`
- Create: `.github/workflows/ci.yml`
- Create: `internal/finding/enum.go` (Amendment 1)
- Create: `internal/finding/enum_test.go` (Amendment 1)
- Create: `internal/run/model.go`
- Create: `internal/run/model_test.go`
- Create: `internal/run/exit.go`
- Create: `internal/run/exit_test.go`
- Create: `docs/evidence/gate-1/README.md`

**Interfaces:**
- Produces `RunIdentity`, `Status`, `Decision`, `Diagnostic`, `AnalyzerResult`, `CanonicalRunResult`, `Limits`, and `ExitCode` used by all later tasks.

- [x] **Step 1: Pin the module and toolchain configuration**

Create `go.mod` with:

```go
module github.com/codebyte-p/proofrail

go 1.27

toolchain go1.27.1
```

Create CI with `permissions: contents: read`, `persist-credentials: false`, checkout SHA `3d3c42e5aac5ba805825da76410c181273ba90b1`, setup-go SHA `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`, `go-version: 1.27.1`, and commands `go test ./...`, `go vet ./...`, `go test -race ./...`, and `go test ./... -run TestCanonical -count=100`.

- [x] **Step 2: Write failing terminal-contract tests**

```go
func TestExitCode(t *testing.T) {
    cases := []struct{ status Status; decision Decision; want int }{
        {StatusComplete, DecisionPass, 0}, {StatusComplete, DecisionWarn, 0},
        {StatusComplete, DecisionRequireReview, 1}, {StatusComplete, DecisionBlock, 1},
        {StatusIncomplete, DecisionBlock, 2},
    }
    for _, tc := range cases {
        got := ExitCode(CanonicalRunResult{Status: tc.status, Decision: tc.decision})
        if got != tc.want { t.Fatalf("got %d want %d", got, tc.want) }
    }
}
```

- [x] **Step 3: Run the focused tests and verify RED**

Run: `go test ./internal/run -run 'TestExitCode|TestRunIdentityValidation' -v`

Expected: compile failure because the types and `ExitCode` do not exist.

- [x] **Step 4: Implement minimal immutable contracts and exit mapping**

Use string-backed closed enums, JSON field tags in the canonical order, `time.Time` normalized with `UTC()`, and `Limits` values copied from the architecture. `ExitCode` must check `StatusIncomplete` before decision.

- [x] **Step 5: Verify GREEN and commit**

Run: `go test ./internal/run -v && go test ./... && go vet ./...`

Commit: `feat: establish gate 1 runtime contracts`

## Task 2: Safe paths and immutable Git revision binding

**Files:**
- Create: `internal/gitdiff/model.go`
- Create: `internal/gitdiff/path.go`
- Create: `internal/gitdiff/path_test.go`
- Create: `internal/gitdiff/git.go`
- Create: `internal/gitdiff/git_test.go`
- Create: `testdata/replay/revision-binding/README.md`

**Interfaces:**
- Consumes `run.Limits`.
- Produces `gitdiff.Loader`, `Request`, `ChangeSet`, and `FileChange`.

- [x] **Step 1: Write path-normalization table tests**

Test acceptance of `src/auth/login.go` and `a/b-c_1.yml`; test rejection of `/etc/passwd`, `C:\\secret`, `../secret`, `a/../../b`, `a\\b`, `.`, empty input, and a NUL-containing string. Assert stable diagnostic code `path.invalid` without echoing the rejected value.

- [x] **Step 2: Run and verify RED**

Run: `go test ./internal/gitdiff -run TestNormalizeRepoPath -v`

Expected: compile failure because `NormalizeRepoPath` is missing.

- [x] **Step 3: Implement lexical normalization**

Implement `NormalizeRepoPath(raw string) (string, error)` using `path.Clean`, explicit pre-checks for NUL/backslash/absolute/drive syntax, and post-checks for `.` and `..`. Do not call `filepath.Abs`, `EvalSymlinks`, or access the filesystem.

- [x] **Step 4: Write failing Git-loader integration tests**

Create a temporary repository with hooks disabled, two commits, added/modified/deleted/renamed files, and assert exact base/head hashes and sorted normalized changes. Add tests proving invalid SHAs, more than 5,000 files, more than 50 MiB content, symlink targets, submodule entries, and external filters produce `incomplete`-class errors rather than execution.

- [x] **Step 5: Implement constrained Git invocation**

Invoke Git with an explicit executable and arguments, `cmd.Dir` set to the supplied repository, a minimal environment, `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`, `-c core.hooksPath=<empty temp dir>`, `-c filter.lfs.smudge=`, `-c filter.lfs.required=false`, `-c diff.external=`, and `--no-ext-diff`. Resolve commits with `rev-parse --verify <sha>^{commit}` and reject if returned hashes differ from the requested immutable hashes. Never initialize submodules or run checkout hooks.

- [x] **Step 6: Verify and commit**

Run: `go test ./internal/gitdiff -v && go test ./... && go vet ./...`

Commit: `feat: bind scans to safe immutable git changes`

## Task 3: Findings, redaction, ordering, and stable fingerprints

**Files:**
- Create: `internal/finding/model.go`
- Create: `internal/finding/validate.go`
- Create: `internal/finding/redact.go`
- Create: `internal/finding/fingerprint.go`
- Create: `internal/finding/finding_test.go`
- Create: `internal/finding/redact_test.go`
- Create: `internal/finding/fuzz_test.go`

**Interfaces:**
- Consumes normalized repository paths.
- Produces validated, redacted, deterministically ordered `Finding` values.

- [x] **Step 1: Write failing validation and fingerprint tests**

Create one finding with unsorted locations and evidence. Assert `Finalize` sorts inputs, truncates excerpts to 512 UTF-8 bytes without breaking encoding, and returns the same `sha256:<64 lowercase hex>` fingerprint in 100 repetitions. Assert changes to rule ID, normalized location, or stable redacted evidence change the fingerprint; message wording and slice insertion order do not.

- [x] **Step 2: Write failing redaction tests**

Cover keys `token`, `secret`, `password`, `passwd`, `private_key`, and `api_key`; GitHub token prefixes; AWS access-key shapes; PEM headers; JWT shapes; terminal escape bytes; and Markdown control characters. Assert public evidence contains `[REDACTED:<kind>]`, never the matched value.

- [x] **Step 3: Run and verify RED**

Run: `go test ./internal/finding -run 'TestFinalize|TestRedact' -v`

Expected: compile failure because `Finalize` and `Redact` are missing.

- [x] **Step 4: Implement minimal validation, redaction, and hashing**

Fingerprint the length-prefixed UTF-8 sequence of rule ID, analyzer ID, each sorted path/start/end location, each evidence kind, and the SHA-256 digest of its redacted excerpt. Reject unknown enum values and findings without rule, analyzer, message, location, or evidence kind.

- [x] **Step 5: Add fuzz properties and commit**

Fuzz arbitrary UTF-8/bytes through redaction and finalization; assert no panic, valid UTF-8 output, 512-byte excerpt bound, and no reproduction of seeded secrets.

Run: `go test ./internal/finding -v && go test ./internal/finding -fuzz=FuzzRedact -fuzztime=30s && go test ./...`

Commit: `feat: add redaction-safe canonical findings`

## Task 4: Bounded workflow parser and PFR-WF analyzer

**Files:**
- Create: `internal/parser/workflow/model.go`
- Create: `internal/parser/workflow/parser.go`
- Create: `internal/parser/workflow/parser_test.go`
- Create: `internal/parser/workflow/fuzz_test.go`
- Create: `internal/analyzer/workflow/analyzer.go`
- Create: `internal/analyzer/workflow/analyzer_test.go`
- Create: `testdata/{malicious,benign,malformed}/workflow/`

**Interfaces:**
- Parser: `Parse(path string, content []byte, maxBytes int64) (workflow.Document, []run.Diagnostic)`.
- Analyzer: `New() run.Analyzer`, ID `github-workflow`, implementing PFR-WF-001 through PFR-WF-006 exactly as specified.

- [ ] **Step 1: Write parser rejection tests**

Assert rejection of documents above 2 MiB, more than one YAML document, aliases, anchors, merge keys, custom tags, duplicate keys, non-string keys, and nesting above 64. Assert source locations are retained for scalar nodes and input bytes are never executed or interpolated.

- [ ] **Step 2: Run parser tests and verify RED**

Run: `go test ./internal/parser/workflow -run TestParse -v`

Expected: compile failure because `Parse` is missing.

- [ ] **Step 3: Implement the restricted syntax-tree pass**

Pin `go.yaml.in/yaml/v3 v3.0.5`. Decode exactly one `yaml.Node`, walk it iteratively, reject forbidden node properties before typed decoding, count nesting and nodes, then decode only allow-listed workflow fields needed by the six rules. Unknown workflow fields are preserved as coverage notes, not executed.

- [ ] **Step 4: Write one failing rule test per PFR-WF rule**

For each PFR-WF-001 through PFR-WF-006, include one minimal malicious fixture, one compensating/benign fixture, expected severity/confidence/decision hint, exact source path, evidence kind, and limitation text. PFR-WF-001, 004, and 005 fixtures are labeled `must_detect`.

- [ ] **Step 5: Implement rules without cross-rule weakening**

Return candidate findings independently; do not let a later rule suppress an earlier one. When static reachability cannot be proven, preserve the specified confidence and limitation instead of claiming safety.

- [ ] **Step 6: Fuzz, verify, and commit**

Seed at least 100 workflow mutations, then run: `go test ./internal/parser/workflow ./internal/analyzer/workflow -v`, `go test ./internal/parser/workflow -fuzz=FuzzParse -fuzztime=60s`, and `go test ./...`.

Commit: `feat: detect unsafe github workflow changes`

## Task 5: npm/Python parsing and PFR-DEP analyzer

**Files:**
- Create: `internal/parser/npm/{model.go,parser.go,parser_test.go,fuzz_test.go}`
- Create: `internal/parser/python/{model.go,parser.go,parser_test.go,fuzz_test.go}`
- Create: `internal/analyzer/dependency/{analyzer.go,analyzer_test.go}`
- Create: `testdata/{malicious,benign,malformed}/dependency/`

**Interfaces:**
- npm parser accepts `package.json` up to 1 MiB and `package-lock.json` up to 10 MiB.
- Python parser accepts `pyproject.toml` up to 1 MiB and `uv.lock` up to 10 MiB.
- Analyzer ID is `dependency`; implements PFR-DEP-001 through PFR-DEP-006.

- [ ] **Step 1: Write failing bounded parser tests**

Test duplicate JSON keys with a token-stream pre-pass, JSON/TOML nesting above 64, invalid UTF-8, oversized files, manifest/lock mismatch, renamed/deleted pairs, and unsupported lockfiles. Unsupported optional managers produce explicit coverage notes; required npm/uv parse failures produce diagnostics that make the run incomplete.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/parser/npm ./internal/parser/python -v`

Expected: compile failure for missing parser functions.

- [ ] **Step 3: Implement normalized dependency records**

Emit package name, normalized version requirement, resolved version, source type, integrity identity, lifecycle/install behavior, direct/transitive role, and source file/line when available. Never invoke npm, Python, uv, package hooks, or registry clients.

- [ ] **Step 4: Write failing PFR-DEP rule tests**

Cover all six rules. Mark PFR-DEP-001 and PFR-DEP-004 malicious fixtures as `must_detect`. Prove suspicious-name similarity remains warn-only and cannot block without a separate rule.

- [ ] **Step 5: Implement, fuzz, verify, and commit**

Use bounded standard-library JSON parsing and a reviewed TOML parser only if the dependency ledger approves it; otherwise implement the narrow `pyproject.toml` and `uv.lock` field reader needed by the normalized contract. Fuzz at least 200 seeded manifest/lock mutations.

Run: `go test ./internal/parser/npm ./internal/parser/python ./internal/analyzer/dependency -v && go test ./...`

Commit: `feat: verify dependency graph changes`

## Task 6: PFR-DIFF security-sensitive classifier

**Files:**
- Create: `internal/analyzer/diff/analyzer.go`
- Create: `internal/analyzer/diff/analyzer_test.go`
- Create: `testdata/{malicious,benign}/diff/`

**Interfaces:**
- Analyzer ID is `security-diff`; consumes only `gitdiff.ChangeSet`; implements PFR-DIFF-001 through PFR-DIFF-006.

- [ ] **Step 1: Write failing table tests for all six rules**

Use exact added/deleted line fixtures for authentication/authorization, process execution, cryptography, CI/security policy, deployment/infrastructure, and secret-handling boundaries. Include generated code, test fixtures, file-name-only coincidences, and pure refactors as false-positive controls.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/analyzer/diff -v`

Expected: compile failure because `New` and `Analyze` are missing.

- [ ] **Step 3: Implement deterministic lexical classification**

Use bounded literal token sets and normalized paths, not regular expressions. Every finding defaults to `require_review` or weaker and carries the limitation that classification is not a vulnerability claim. This analyzer may not produce `block` by itself.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/analyzer/diff -v && go test ./... && go vet ./...`

Commit: `feat: classify security-sensitive diffs`

## Task 7: Embedded schemas and restricted policy parsing

**Files:**
- Create: `schemas/policy/v1.json`
- Create: `schemas/waiver/v1.json`
- Create: `schemas/finding/v1.json`
- Create: `schemas/run-result/v1.json`
- Create: `internal/policy/schema.go`
- Create: `internal/policy/parser.go`
- Create: `internal/policy/parser_test.go`
- Create: `internal/policy/fuzz_test.go`

**Interfaces:**
- Produces immutable `Policy`, `Rule`, `Expression`, `Predicate`, `WaiverSet`, and stable diagnostics from `ParsePolicy`/`ParseWaivers`.

- [ ] **Step 1: Write failing schema-conformance tests**

Load each embedded schema with Draft 2020-12 explicitly selected. Test the valid examples from ADR 0001 and every boundary: 0/128/129 rules, ID syntax, scalar byte bounds, unknown keys, enum values, one-of expression shape, 8/9 depth, 32/33 nodes, 128/129 set values, 256/257-byte globs, and all waiver bounds.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/policy -run 'TestPolicySchema|TestWaiverSchema' -v`

Expected: failure because schemas and parsers are absent.

- [ ] **Step 3: Implement syntax rejection before decoding**

Use YAML v3 nodes and the same iterative forbidden-feature checks as the workflow parser, with stricter depth 8 for expressions. Reject BOM, multiple documents, anchors, aliases, merge keys, tags, duplicate/non-string keys, interpolation-shaped scalars such as `${HOME}`, and unknown operators/fields. Then convert to JSON-compatible values and validate against the embedded schemas using jsonschema v6.0.3 with no HTTP/file URL loader.

- [ ] **Step 4: Fuzz and commit**

Seed every rejected ADR example plus Unicode, numeric, glob, duplicate-key, and nested-node cases. Assert stable bounded diagnostic codes and `incomplete` classification.

Run: `go test ./internal/policy -v && go test ./internal/policy -fuzz=FuzzParsePolicy -fuzztime=60s && go test ./...`

Commit: `feat: parse bounded proofrail policy documents`

## Task 8: Non-Turing-complete policy evaluator

**Files:**
- Create: `internal/policy/compile.go`
- Create: `internal/policy/evaluate.go`
- Create: `internal/policy/glob.go`
- Create: `internal/policy/evaluate_test.go`
- Create: `internal/policy/properties_test.go`

**Interfaces:**
- `Evaluate(EvaluationInput) EvaluationResult` with explicit operation budget, deadline, fixed timestamp, findings, policy, and run fields.

- [ ] **Step 1: Write failing operator and precedence tests**

Table-test `eq`, `not_eq`, `in`, `not_in`, `gte`, `lte`, `path_matches`, and `exists` for every allowed field type. Test severity order `note < low < medium < high < critical`, confidence `low < medium < high`, and decision `block > require_review > warn > observe > pass`.

- [ ] **Step 2: Write failing property tests**

Generate bounded policies and findings; assert rule-order independence, monotonicity when adding a more restrictive match, deterministic output, and termination before 25,000,001 operations. Assert budget or deadline exhaustion returns `incomplete` and never a partial pass.

- [ ] **Step 3: Verify RED**

Run: `go test ./internal/policy -run 'TestEvaluate|TestProperties' -v`

Expected: compile failure for evaluator symbols.

- [ ] **Step 4: Implement iterative compilation and evaluation**

Compile expressions to immutable indexed nodes with an explicit stack. Evaluate every finding/rule pair in stable order, decrementing the operation counter for each node visit and comparison. Collect all matches without decision short-circuiting. Implement restricted globs with segments and dynamic programming bounded by the 256-byte pattern and normalized path length; do not translate globs to regex.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/policy -v -count=10 && go test ./... && go vet ./...`

Commit: `feat: evaluate bounded declarative policy`

## Task 9: Exact waivers and audit outcomes

**Files:**
- Create: `internal/policy/waiver.go`
- Create: `internal/policy/waiver_test.go`
- Create: `testdata/{benign,malformed}/waiver/`

**Interfaces:**
- `ApplyWaivers(findings []finding.Finding, set WaiverSet, evaluatedAt time.Time) WaiverResult` returning remaining findings, applied records, rejected records, and diagnostics.

- [ ] **Step 1: Write failing containment and time tests**

Test exact fingerprint, all-location path containment, inclusive creation boundary, exclusive expiry boundary, UTC RFC3339, maximum 30-day lifetime, no wildcard/prefix/rule-only/global waiver, and inability to suppress `incomplete`.

- [ ] **Step 2: Write failing modification tests**

Compare base/head waiver sets and assert reused IDs with changed fingerprint, path set, creation time, approver, or issue emit `waiver.id_reused_with_changed_scope`; head additions never apply to the introducing run.

- [ ] **Step 3: Verify RED, implement, and verify GREEN**

Run RED: `go test ./internal/policy -run TestWaiver -v`.

Implement exact set comparisons and audit records containing ID, digest, attribution, issue, timestamps, paths, and outcome code. Run GREEN: `go test ./internal/policy -run TestWaiver -v`.

- [ ] **Step 4: Commit**

Run: `go test ./... && go vet ./...`

Commit: `feat: enforce exact expiring waivers`

## Task 10: Orchestration, budgets, and fail-closed completion

**Files:**
- Create: `internal/run/analyzer.go`
- Create: `internal/run/scanner.go`
- Create: `internal/run/scanner_test.go`
- Create: `internal/run/fault_test.go`

**Interfaces:**
- Implements `Scanner.Scan`; accepts injected loader, parsers/analyzers, policy evaluator, clock, and resource limits.

- [ ] **Step 1: Write failing orchestration tests**

Use simple fakes to prove analyzers run in stable ID order, each gets at most 30 seconds, the run gets at most 120 seconds, completed evidence survives a later failure, and the ledger records duration/budget/failure without secrets.

- [ ] **Step 2: Write failing fault matrix**

Inject loader failure, each parser failure, required analyzer panic, analyzer timeout, finding overflow, policy error, waiver error, schema error, and canonical-output overflow. Every case must produce status `incomplete`, decision `block`, exit code `2`, and a bounded diagnostic. Recover analyzer panics at the boundary; do not recover process-wide corruption such as runtime fatal errors.

- [ ] **Step 3: Verify RED**

Run: `go test ./internal/run -run 'TestScanner|TestFault' -v`

Expected: compile failure for `NewScanner`.

- [ ] **Step 4: Implement the minimum scanner**

Use context deadlines, explicit analyzer result validation, a 5,000-finding ceiling, stable finalization, policy evaluation only after required analyzers complete, exact waiver application, and canonical status selection. No empty finding slice may substitute for a failed component.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/run -v -race && go test ./... && go vet ./...`

Commit: `feat: orchestrate fail-closed offline scans`

## Task 11: Canonical JSON, console, Markdown, SARIF, and atomic output

**Files:**
- Create: `internal/report/{api.go,json.go,console.go,markdown.go,sarif.go,atomic.go}`
- Create: `internal/report/{json_test.go,console_test.go,markdown_test.go,sarif_test.go,atomic_test.go}`
- Create: `internal/report/testdata/*.golden`

**Interfaces:**
- Renderers consume `run.CanonicalRunResult`; `WriteAtomic` writes only schema-valid bounded output.

- [ ] **Step 1: Write failing canonical JSON golden tests**

Assert byte-identical output in 100 runs, schema ID `https://github.com/codebyte-p/proofrail/schemas/run-result/v1.json`, RFC3339 UTC timestamp, complete identity/limits/analyzer ledger/policy/waiver/coverage data, integrity digest, trailing newline, and no HTML escaping drift. Avoid maps in canonical structures; where maps are unavoidable, convert to sorted key/value arrays.

- [ ] **Step 2: Write failing projection tests**

Console and Markdown must escape hostile control sequences. SARIF must cap at 5,000 results, bind revision and fingerprints, expose limitations and ProofRail decision properties, and never become the authoritative result. Projection failure must not mutate the canonical decision.

- [ ] **Step 3: Write failing atomic-output tests**

Test temporary file in the destination directory, mode `0600` where supported, sync/close/rename ordering, cleanup after injected write/sync/rename failure, refusal above 50 MiB, and preservation of an existing destination when replacement fails.

- [ ] **Step 4: Implement and verify**

Run RED: `go test ./internal/report -v`.

Implement renderers and atomic writer, then run GREEN: `go test ./internal/report -v -count=10 && go test ./...`.

- [ ] **Step 5: Commit**

Commit: `feat: publish canonical and projected scan results`

## Task 12: CLI command and end-to-end offline scan

**Files:**
- Create: `cmd/proofrail/main.go`
- Create: `internal/run/cli.go`
- Create: `internal/run/cli_test.go`
- Create: `internal/run/e2e_test.go`
- Modify: `README.md`

**Interfaces:**
- Command: `proofrail scan --repo <path> --repository <owner/name> --base <40-hex> --head <40-hex> --evaluated-at <RFC3339> [--policy <path>] [--waivers <path>] [--output <format>=<path>]...`.

- [ ] **Step 1: Write failing argument tests**

Assert missing/duplicate/unknown flags, invalid SHA, invalid timestamp, duplicate output format/path, unsupported format, relative repository identity, and extra arguments return usage error without scanning. `--policy` and `--waivers` are local-only inputs whose SHA-256 digests are recorded.

- [ ] **Step 2: Write failing end-to-end tests**

Use temporary Git repositories and the versioned fixture corpus. Assert pass/warn exit `0`, review/block exit `1`, malformed/timeout/reporter-failure exit `2`, no network socket use, exact output files, and repeatable JSON with fixed time.

- [ ] **Step 3: Verify RED**

Run: `go test ./internal/run -run 'TestCLI|TestEndToEnd' -v`

Expected: failure because CLI execution is not wired.

- [ ] **Step 4: Implement CLI wiring**

Use `flag.FlagSet` with `ContinueOnError`, injected stdout/stderr/clock/scanner for tests, bounded one-line diagnostics, and no logging of raw arguments or environment. `main` calls `os.Exit(run.Main(...))` and contains no analysis logic.

- [ ] **Step 5: Verify and commit**

Run: `go test ./... -race && go vet ./... && go build -trimpath -ldflags='-s -w' ./cmd/proofrail` with `CGO_ENABLED=0`.

Commit: `feat: deliver offline proofrail scan command`

## Task 13: Gate 1 corpus, adversarial campaign, benchmarks, and promotion evidence

**Files:**
- Create/complete: `testdata/{malicious,benign,malformed,replay}/`
- Create: `internal/testsupport/corpus.go`
- Create: `internal/testsupport/networkdeny.go`
- Create: `docs/evidence/gate-1/{environment.json,commands.txt,limitations.md,promotion.md}`
- Create: `docs/evidence/gate-1/tests/summary.json`
- Create: `docs/evidence/gate-1/benchmarks/results.json`

**Interfaces:**
- Produces reproducible evidence mapped one-to-one to every Gate 1 criterion.

- [ ] **Step 1: Freeze and digest the corpus**

Label fixtures before tuning as `must_detect`, benign, malformed/adversarial, or replay. Store expected findings and intentional non-findings. Generate a sorted SHA-256 manifest and fail tests when bytes change without manifest review.

- [ ] **Step 2: Meet adversarial and detection gates**

Run at least 500 adversarial parser fixtures; require 100% detection for `PFR-WF-001`, `PFR-WF-004`, `PFR-WF-005`, `PFR-DEP-001`, `PFR-DEP-004`, and required-analyzer failure; require zero false pass on every failure class; calculate and record false-block rate at or below 5%.

- [ ] **Step 3: Prove determinism and no network**

Run every golden fixture 100 times with identical identity, limits, and `evaluated_at`; compare bytes. Run analysis in an isolated environment with loopback and outbound connects denied; fail on any attempted socket creation by production analysis packages.

- [ ] **Step 4: Benchmark the reference workload**

Use 5,000 changed lines across 100 supported files. Record runner image, OS, architecture, CPU, memory, Go 1.27.1, engine commit, corpus digest, command, raw durations, and P95; require below 60 seconds.

- [ ] **Step 5: Run security review and close evidence**

Commission independent review of parser, path, policy, redaction, and atomic-output boundaries. Resolve blocking findings; record non-findings and limitations. Do not mark `promotion.md` approved until the owner supplies the release digest and explicit Gate 1 approval.

- [ ] **Step 6: Final verification and commit**

Run: `go test ./... -count=1 -race`, `go vet ./...`, all fuzz targets for the recorded duration, schema conformance, corpus metrics, deterministic replay, offline enforcement, and benchmark command.

Commit: `test: record gate 1 promotion evidence`

## Gate 1 completion checkpoint

Before requesting promotion, confirm every Gate 1 criterion in `docs/validation-gates.md` links to a concrete evidence file, the release binary checksum is recorded, rollback points to the last passing release, the independent verdict is non-blocking, and the owner has not yet been asked to approve Gate 2 implementation in the same change as unresolved Gate 1 findings.
