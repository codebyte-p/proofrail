# Analyzer Contracts

## Common execution contract

Version 1 analyzers are compiled into the ProofRail CLI. They are not downloaded at runtime, do not execute repository code, and receive immutable normalized input rather than unrestricted filesystem access.

Each analyzer declares:

- a stable identifier and semantic version;
- supported file types and input schema;
- whether it is required by the active policy;
- file, byte, recursion, result-count, and wall-clock budgets;
- rules with default severity, confidence, and decision hint;
- evidence fields and redaction behavior;
- known false-positive and false-negative conditions;
- completion status: `complete`, `not_applicable`, `disabled`, or `failed`.

Analyzer output is untrusted until the aggregator validates its schema, confirms every path belongs to the analyzed revision, limits excerpts, recomputes fingerprints, and records completion. A required analyzer that returns `failed` makes the run `incomplete`.

## Analyzer 1: GitHub Actions workflow security

### Objective

Detect pull-request changes that create common GitHub Actions privilege and supply-chain hazards without running a workflow.

### Inputs and parsing

- Changed and base versions of `.github/workflows/*.yml` and `*.yaml`.
- Repository Action policy when available.
- A safe YAML parser with aliases, depth, scalar length, and document count bounded.
- A normalized workflow model containing triggers, permissions, jobs, steps, `uses` references, `run` scripts, environments, secrets references, and checkout configuration.

### Initial rules

| Rule | Evidence | Default decision |
|---|---|---|
| `PFR-WF-001` privileged untrusted checkout | `pull_request_target` or `workflow_run`, checkout of PR head/fork, followed by a command or executable Action | Block |
| `PFR-WF-002` excessive token permission | Newly introduced `write-all` or write scopes not justified by a recognized publishing job | Require review; block on untrusted trigger |
| `PFR-WF-003` mutable third-party Action | `uses: owner/repo@tag-or-branch` rather than a full commit SHA | Require review |
| `PFR-WF-004` expression injection into shell | Untrusted event property interpolated directly into `run`, such as PR title or branch name | Block when reachable from an untrusted event |
| `PFR-WF-005` secrets exposed to untrusted execution | Secret-bearing job or environment combined with PR-controlled code execution | Block |
| `PFR-WF-006` persistence on self-hosted runner | Untrusted PR job targets `self-hosted` without an approved ephemeral-runner policy | Require review |

### Default classification

Owner-approved on 2026-09-16. These are the defaults each rule emits; policy may
route them differently, but an analyzer may not exceed them.

| Rule | Severity | Confidence |
|---|---|---|
| `PFR-WF-001` | high | high |
| `PFR-WF-002` | high | medium |
| `PFR-WF-003` | medium | high |
| `PFR-WF-004` | high | high when directly reachable from an untrusted trigger, medium when reachability is uncertain |
| `PFR-WF-005` | high | high |
| `PFR-WF-006` | high | medium |

**Critical severity is reserved.** A rule may claim `critical` only on evidence
proving exposure of write-capable or equivalently critical authority. Observing
that a hazardous pattern is present is not such proof, so no version 1 PFR-WF
rule emits `critical`. Confidence never raises severity: per the threat model it
exists so policy can route weak evidence to review, not so strong evidence can
escalate impact.

### Example

```yaml
on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
```

Expected findings: `PFR-WF-001` and `PFR-WF-002`. Evidence identifies the trigger, checkout reference, command step, and effective permission; it does not evaluate or run `npm test`.

### False-positive profile

- A workflow may have compensating organization policy ProofRail cannot observe.
- A write scope can be necessary for a release job; version 1 therefore routes many permission expansions to review rather than blocking them.
- Full-SHA pinning can conflict with local update conventions, but mutable references remain a real supply-chain risk.
- Static reachability may conservatively treat a job as runnable when a complex expression prevents it.

### False-negative profile

- Reusable workflows and composite Actions can hide execution or permissions outside the changed repository.
- Dynamically generated workflow files are outside version 1.
- Organization and enterprise settings are unavailable in offline mode.
- Novel expression-injection sinks not represented in the initial taint rules can be missed.

## Analyzer 2: Dependency change and provenance

### Objective

Explain and classify dependency-introducing changes using repository-local evidence. Version 1 does not claim that a package is vulnerable or malicious without an authoritative offline evidence input.

### Initial ecosystems

- npm-compatible `package.json` plus `package-lock.json`.
- Python `pyproject.toml` plus `uv.lock`.

Adding an ecosystem requires parser fixtures, a lock-integrity model, and a separate rule contract. Unsupported files produce an explicit coverage note rather than silent success.

### Initial rules

| Rule | Evidence | Default severity | Default confidence | Default decision |
|---|---|---|---|---|
| `PFR-DEP-001` manifest-lock mismatch | Dependency declaration changes without corresponding lock resolution, or inconsistent resolved identity | High | High | Block |
| `PFR-DEP-002` non-registry dependency | New Git, URL, local path, workspace escape, or unpinned source dependency | Medium for an immutable in-repository source; high when mutable or outside the repository | High | Require review for an immutable in-repository source; block when mutable or outside the repository |
| `PFR-DEP-003` lifecycle execution introduced | New or changed package lifecycle script, install hook, build backend, or plugin with install-time execution potential | Medium | High | Require review |
| `PFR-DEP-004` resolved source changed unexpectedly | Name/version unchanged but lockfile source URL, integrity value, or commit identity changes | High | High | Block |
| `PFR-DEP-005` dependency graph expansion | New direct dependency and transitive-count delta with exact manifest and lock evidence | Note below the review threshold; low at or above it | High | Observe below the threshold; require review at or above it |
| `PFR-DEP-006` suspicious name similarity | New direct dependency closely resembles an existing or allow-listed package | Low | Low | Warn only in version 1 |

These values are normative for version 1 and for Task 13 golden fixtures. The
PFR-DEP-005 review threshold is three newly declared direct dependencies. A Git
or URL source is outside the repository even when pinned to an immutable commit,
so PFR-DEP-002 blocks it under the "mutable or outside" contract. Critical
severity remains reserved for evidence proving exposure of write-capable or
equivalently critical authority.

### Example

```json
{
  "dependencies": {
    "safe-client": "git+https://example.invalid/team/safe-client.git#main"
  }
}
```

Expected finding: `PFR-DEP-002`, because `main` is mutable. ProofRail does not label the source malicious; it reports that the build is not reproducibly bound to an immutable identity.

### False-positive profile

- Monorepos can intentionally use local or workspace dependencies.
- Private registries and mirrors can look unfamiliar without repository configuration.
- A lifecycle script may be benign but still expands install-time execution authority.
- Name-similarity heuristics are noisy and therefore cannot block in version 1.

### False-negative profile

- A correctly locked package can still be malicious or compromised.
- Offline analysis cannot know newly published advisories, account takeover, maintainer reputation, or registry yanks.
- Lockfile parser gaps or unsupported package-manager features can miss source indirection.
- Build tools can download code outside the dependency manager; version 1 does not execute or trace builds.

## Analyzer 3: Security-sensitive diff classifier

### Objective

Identify changes that require specialized review. This analyzer classifies review impact; it does not claim that a vulnerability exists.

### Inputs and method

- Renames, additions, deletions, modes, and changed-line ranges from Git.
- File-path and configuration-key rules.
- Language-aware syntax extraction for explicitly supported languages, without dependency resolution or code execution.
- Conservative lexical fallback when a language parser is unavailable.

Initial review domains are authentication, authorization, cryptography, credential handling, network egress, deserialization, command execution, filesystem boundaries, CI/CD permissions, infrastructure-as-code, audit logging, and security-control configuration.

### Initial rules

| Rule | Evidence | Default decision |
|---|---|---|
| `PFR-DIFF-001` authentication or authorization boundary changed | Supported symbols, route guards, permission maps, middleware, or security configuration changed | Require security review |
| `PFR-DIFF-002` command or process execution surface changed | New or modified process-spawn call, shell construction, or executable selection | Require security review |
| `PFR-DIFF-003` cryptographic behavior changed | Algorithm, mode, randomness, key-loading, certificate, or signature verification code changed | Require security review |
| `PFR-DIFF-004` security control removed or weakened | Deletion or value reduction in recognized protection configuration | Require review; policy may block explicit unsafe values |
| `PFR-DIFF-005` CI or deployment authority changed | Workflow permissions, environments, deployment configuration, or infrastructure role binding changed | Require owner review |
| `PFR-DIFF-006` analysis blind spot | Security-relevant file changed in an unsupported language or generated format | Require review rather than imply coverage |

### Example

```diff
- if (!user.hasRole("admin")) return forbidden();
+ if (!user) return forbidden();
```

Expected result: `PFR-DIFF-001` with `require_review`. ProofRail records that an authorization boundary changed; it does not assert privilege escalation without deeper semantic evidence.

### False-positive profile

- File names and APIs can resemble security controls without enforcing one.
- Refactors can move checks while preserving behavior.
- Test fixtures and examples can intentionally contain dangerous-looking code.
- Generated code may duplicate sensitive symbols.

The classifier therefore cannot produce a vulnerability-level block by itself. It escalates review unless another analyzer supplies rule-specific blocking evidence.

### False-negative profile

- Business-logic authorization may use project-specific abstractions.
- Vulnerabilities can emerge from interactions across unchanged files.
- Dynamic languages, reflection, macros, generated code, and unsupported syntax reduce coverage.
- A small harmless-looking constant or ordering change can have security impact beyond lexical classification.

## Reporting and SARIF mapping

The canonical JSON finding remains authoritative. SARIF maps:

- `rule_id` to `ruleId`;
- severity and decision to `level` plus namespaced properties;
- primary path and range to `locations`;
- stable fingerprint to `partialFingerprints`;
- explanation and limitations to Markdown-safe `message.text`;
- analyzer identity and version to `tool.driver`.

SARIF cannot fully represent the run-level `incomplete` status or ProofRail's review and waiver semantics. Those remain in canonical JSON and the job summary. ProofRail caps canonical findings and SARIF results at 5,000 per run; overflow makes the run incomplete instead of silently truncating high-priority findings.

## Deferred analyzers

Secret detection, vulnerability-advisory correlation, license compliance, IaC semantic analysis, container scanning, and third-party analyzer integration are intentionally deferred. ProofRail may later ingest established tools' SARIF, but external results must retain their producer identity and cannot be presented as native ProofRail evidence.
