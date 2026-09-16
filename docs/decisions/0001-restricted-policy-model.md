# ADR 0001: Restricted Declarative Policy and Waiver Model

- **Status:** Accepted for Gate 1 implementation
- **Date:** 2026-09-16
- **Decision owners:** Repository owner, with independent Codex and Claude review

## Context

ProofRail must convert normalized findings into predictable CI decisions. A general-purpose language, template engine, callback, shell command, downloaded plugin, or dynamically evaluated expression would create an unnecessary code-execution boundary. The policy evaluator must terminate predictably, avoid ambient authority, and produce the same result for the same complete input.

## Decision

Version 1 policy is schema-versioned YAML interpreted by a bounded, non-Turing-complete evaluator. Policy can inspect only registered immutable run and finding fields. It cannot read files, inspect environment variables, access a network, import modules, invoke functions, mutate state, interpolate templates, allocate unbounded collections, or execute repository content.

The effective policy and waivers are loaded from the base revision. Head-revision policy and waiver changes are analyzed as security-control changes but never govern the pull request that introduces them.

## Encoding and parser rules

- UTF-8 without a byte-order mark.
- One YAML document only.
- Maximum policy document size: 131,072 bytes.
- Maximum waiver document size: 131,072 bytes.
- YAML anchors, aliases, merge keys, custom tags, duplicate mapping keys, non-string mapping keys, and implicit executable/object tags are rejected.
- Scalars are limited to 1,024 UTF-8 bytes unless a stricter field limit applies.
- Unknown keys are rejected at every schema level.
- Schema validation follows JSON Schema Draft 2020-12 semantics after the YAML syntax tree has passed the restrictions above.
- Parsing or validation failure produces run status `incomplete`; the engine does not fall back to a weaker policy.

## Policy schema

### Top-level structure

```yaml
schema: proofrail.policy/v1
defaults:
  on_incomplete: block
  on_unmatched: pass
rules:
  - id: stable-rule-name
    description: Human-readable purpose
    match:
      all:
        - field: finding.analyzer_id
          op: eq
          value: github-workflow
        - field: finding.severity
          op: in
          value: [critical, high]
    decision: block
    message: Explain the required response
```

### Field constraints

| Path | Type | Required | Constraints |
|---|---|---:|---|
| `schema` | string | yes | Exactly `proofrail.policy/v1` |
| `defaults` | object | yes | Exactly `on_incomplete` and `on_unmatched` |
| `defaults.on_incomplete` | string | yes | Exactly `block`; version 1 cannot weaken this |
| `defaults.on_unmatched` | string | yes | `pass`, `warn`, or `require_review` |
| `rules` | array | yes | 0–128 entries |
| `rules[].id` | string | yes | 1–64 characters; `^[a-z][a-z0-9-]*$`; unique |
| `rules[].description` | string | yes | 1–512 UTF-8 bytes |
| `rules[].match` | expression object | yes | Exactly one of `all`, `any`, `not`, or a leaf predicate |
| `rules[].decision` | string | yes | `block`, `require_review`, `warn`, or `observe` |
| `rules[].message` | string | yes | 1–1,024 UTF-8 bytes; treated as plain text |

`pass` is deliberately unavailable as a rule decision. A rule can add restrictions but cannot explicitly cancel another rule.

## Registered policy fields

Version 1 exposes only these fields:

| Field | Type | Source |
|---|---|---|
| `run.repository` | string | Bound repository identity |
| `run.base_sha` | string | Bound base commit |
| `run.head_sha` | string | Bound head commit |
| `run.status` | enum | Terminal analysis status |
| `finding.rule_id` | string | Validated finding |
| `finding.analyzer_id` | string | Validated finding |
| `finding.severity` | ordered enum | Validated finding |
| `finding.confidence` | ordered enum | Validated finding |
| `finding.decision_hint` | enum | Validated finding |
| `finding.locations.path` | array of normalized paths | Validated finding locations |
| `finding.evidence.kind` | array of strings | Validated evidence metadata |
| `finding.limitations` | array of strings | Validated finding limitations |

Policy cannot inspect evidence excerpts, secret-bearing values, environment data, local paths outside the repository, current user identity, or wall-clock time. Adding a registered field requires a schema version change, threat-model review, and conformance tests.

## Expression grammar and limits

An expression is exactly one of:

```text
all: [expression, ...]
any: [expression, ...]
not: expression
field: registered-field
op: allowed-operator
value: operator-specific-value
```

Limits:

- Maximum expression depth: 8, counting the root as depth 1.
- Maximum expression nodes per rule: 32.
- Maximum leaf predicates per policy: 2,048.
- Maximum total evaluation operations per run: 25,000,000.
- Maximum values in an `in` or `not_in` set: 128.
- Maximum path-glob length: 256 UTF-8 bytes.
- Maximum policy findings evaluated: 5,000.
- Evaluation deadline: 2 seconds on the reference runner; exceeding the operation budget or deadline produces `incomplete`.

The operation budget, rather than the deadline, is the deterministic termination control. The deadline is a host-safety backstop and is always reported distinctly.

## Operator reference

| Operator | Allowed field type | Semantics |
|---|---|---|
| `eq` | scalar enum or string | Exact, case-sensitive equality after enum canonicalization |
| `not_eq` | scalar enum or string | Logical negation of `eq` |
| `in` | scalar or array field | Scalar equals any set member; array has at least one matching element |
| `not_in` | scalar or array field | Scalar equals no member; every array element is outside the set |
| `gte` | ordered enum | Field rank is greater than or equal to the supplied enum rank |
| `lte` | ordered enum | Field rank is less than or equal to the supplied enum rank |
| `path_matches` | normalized path array | At least one path matches the restricted glob |
| `exists` | any registered field | Field is present; `value` must be boolean |

Severity order is `note < low < medium < high < critical`. Confidence order is `low < medium < high`. No numeric coercion, Unicode case folding, regular expression, substring, arithmetic, date, script, or user-defined operator exists in version 1.

Version 1 globs operate on normalized forward-slash repository-relative paths. They support literal characters, `?` within one segment, `*` within one segment, and `**` across segments. Brace expansion, character classes, escapes, backslashes, absolute paths, drive letters, NUL bytes, and `..` segments are rejected.

## Evaluation algorithm

1. Parse YAML into a data-only syntax tree under the encoding restrictions.
2. Validate the complete document against the versioned schema and field registry.
3. Compile every expression into an immutable node array using an explicit stack; recursive evaluation is not used.
4. Reject a policy exceeding any static limit before findings are evaluated.
5. Sort validated findings by stable fingerprint and rules by rule identifier for reproducible diagnostics. Sorting does not affect the final decision.
6. For each finding and rule, evaluate the finite node array while decrementing the run-wide operation budget for every node visit and comparison.
7. Collect every matching rule. Do not short-circuit collection after the first decision.
8. Select the most restrictive decision under:

```text
block > require_review > warn > observe > pass
```

9. If analysis status is `incomplete`, force the terminal decision to `block` semantics and exit code 2 regardless of matched rules.
10. Validate and atomically serialize the canonical result before any secondary reporter runs.

There is no policy-controlled loop, recursion, dynamic dispatch, allocation proportional to attacker-selected numeric values, file/network operation, or executable expression. The finite schema bounds rule count, expression nodes, value-set size, finding count, and total operations. The maximum structural workload is 5,000 findings × 128 rules × 32 expression nodes, or 20,480,000 node visits, below the 25,000,000-operation ceiling. Evaluation therefore terminates within the finite operation bound unless the host deadline stops it earlier, which also fails closed as `incomplete`.

## Safe policy examples

### Example 1: block privileged untrusted workflow execution

```yaml
schema: proofrail.policy/v1
defaults:
  on_incomplete: block
  on_unmatched: pass
rules:
  - id: block-privileged-pr-execution
    description: Do not execute pull-request content with base-repository authority
    match:
      all:
        - field: finding.rule_id
          op: eq
          value: PFR-WF-001
        - field: finding.confidence
          op: in
          value: [high, medium]
    decision: block
    message: Replace the privileged checkout pattern with an unprivileged pull_request workflow.
```

Representative SARIF projection:

```json
{
  "ruleId": "PFR-WF-001",
  "level": "error",
  "message": {"text": "Privileged workflow can execute pull-request-controlled content."},
  "properties": {
    "proofrail.decision": "block",
    "proofrail.policyRule": "block-privileged-pr-execution"
  }
}
```

### Example 2: review new install-time execution

```yaml
schema: proofrail.policy/v1
defaults:
  on_incomplete: block
  on_unmatched: pass
rules:
  - id: review-install-execution
    description: Installation-time execution requires supply-chain review
    match:
      all:
        - field: finding.rule_id
          op: eq
          value: PFR-DEP-003
        - any:
            - field: finding.locations.path
              op: path_matches
              value: "**/package.json"
            - field: finding.locations.path
              op: path_matches
              value: "**/pyproject.toml"
    decision: require_review
    message: Obtain security approval for new or changed install-time execution.
```

Representative SARIF projection:

```json
{
  "ruleId": "PFR-DEP-003",
  "level": "warning",
  "message": {"text": "Dependency installation behavior changed."},
  "properties": {
    "proofrail.decision": "require_review",
    "proofrail.policyRule": "review-install-execution"
  }
}
```

### Example 3: route authentication changes to owners

```yaml
schema: proofrail.policy/v1
defaults:
  on_incomplete: block
  on_unmatched: pass
rules:
  - id: auth-owner-review
    description: Authentication and authorization changes require designated review
    match:
      all:
        - field: finding.rule_id
          op: eq
          value: PFR-DIFF-001
        - any:
            - field: finding.locations.path
              op: path_matches
              value: "src/**"
            - field: finding.locations.path
              op: path_matches
              value: "app/**"
            - field: finding.locations.path
              op: path_matches
              value: "packages/**"
    decision: require_review
    message: Obtain approval from the configured security owners.
```

Representative SARIF projection:

```json
{
  "ruleId": "PFR-DIFF-001",
  "level": "warning",
  "message": {"text": "Authentication or authorization boundary changed."},
  "properties": {
    "proofrail.decision": "require_review",
    "proofrail.policyRule": "auth-owner-review"
  }
}
```

## Rejected policy examples

Invalid policies do not produce SARIF findings because policy evaluation never became trustworthy. They produce terminal status `incomplete`, exit code 2, and a bounded canonical diagnostic.

| Attempt | Rejection code | Reason |
|---|---|---|
| Top-level `script: curl ...` | `policy.unknown_key` | `script` is not in the schema |
| `op: regex` with `value: ".*"` | `policy.unknown_operator` | Regular expressions are unavailable |
| `value: "${HOME}"` intended as interpolation | `policy.interpolation_forbidden` | Template and environment expansion are forbidden |
| Nine nested `not` expressions | `policy.max_depth` | Expression depth exceeds 8 |
| YAML `!!python/object` or another custom tag | `policy.yaml_tag_forbidden` | Custom tags are rejected before schema validation |

Representative canonical diagnostic:

```json
{
  "status": "incomplete",
  "decision": "block",
  "error": {
    "code": "policy.unknown_operator",
    "path": "rules[0].match.op",
    "message": "operator is not available in proofrail.policy/v1"
  }
}
```

## Waiver schema

Waivers are stored in `.proofrail/waivers.yml` on the protected base revision.

```yaml
schema: proofrail.waivers/v1
waivers:
  - id: accepted-risk-2026-0042
    fingerprint: "sha256:0123456789abcdef..."
    paths:
      - src/auth/login.go
    justification: Compensating control documented in issue 42.
    approved_by: security-team
    issue: "#42"
    created_at: "2026-09-16T00:00:00Z"
    expires_at: "2026-10-16T00:00:00Z"
```

| Path | Type | Required | Constraints |
|---|---|---:|---|
| `schema` | string | yes | Exactly `proofrail.waivers/v1` |
| `waivers` | array | yes | 0–256 entries |
| `waivers[].id` | string | yes | Same identifier syntax as policy rules; unique |
| `waivers[].fingerprint` | string | yes | Exact `sha256:` fingerprint; no wildcard or prefix match |
| `waivers[].paths` | array of strings | yes | 1–20 exact normalized repository-relative paths; no glob |
| `waivers[].justification` | string | yes | 20–1,024 UTF-8 bytes |
| `waivers[].approved_by` | string | yes | 1–128 bytes; attribution, not identity proof |
| `waivers[].issue` | string | yes | `#` followed by digits or an HTTPS URL, maximum 512 bytes |
| `waivers[].created_at` | RFC 3339 UTC string | yes | Included in canonical output |
| `waivers[].expires_at` | RFC 3339 UTC string | yes | Later than creation; maximum lifetime 30 days |

An active waiver matches only when:

1. its exact fingerprint equals the finding fingerprint;
2. every finding location to be suppressed is one of the waiver's exact paths;
3. the explicit run evaluation time is before `expires_at` and not before `created_at`;
4. the waiver document came from the bound base revision; and
5. all schema and integrity checks passed.

Wildcards, rule-only waivers, directory-prefix waivers, line-range waivers, and global waivers are excluded from version 1. A class-wide exception requires a reviewed base-branch policy change, not a waiver.

`approved_by` is audit attribution in the offline MVP; ProofRail cannot cryptographically prove the human identity. Authority comes from protected-branch review outside the engine. The future GitHub App may add verified approval metadata through a separately versioned schema.

## Waiver modification and broadening

The earlier phrase “broadened waivers are ignored” is replaced by precise behavior:

- Head-revision waiver changes never apply to the pull request introducing them.
- Any change to an existing waiver's fingerprint, path set, creation time, approver, or issue must use a new waiver identifier. Reusing an identifier with changed scope produces `waiver.id_reused_with_changed_scope` in the head-change analysis.
- Adding paths or replacing the fingerprint is classified as a security-control expansion and requires owner review before merge.
- Once a separately reviewed waiver reaches the base branch, its exact fingerprint and path set are authoritative until expiry.
- The runtime does not claim to reconstruct historical human intent. It enforces exact scope containment against the current protected base revision.

This makes broadening detection syntactic and auditable rather than attempting an unreliable semantic comparison of glob languages.

## Evaluation time and determinism

Waiver expiry requires an explicit `evaluated_at` UTC timestamp supplied by the trusted CLI host or GitHub wrapper. The timestamp is included in the canonical run envelope and integrity digest. Tests inject a fixed timestamp. Two runs are deterministic only when repository identity, revisions, policy and waiver digests, engine version, resource limits, and `evaluated_at` are identical.

## Gate 1 test obligations

Gate 0 approves this specification. Executable proof belongs to Gate 1 after the evaluator exists; no pre-code test result is claimed.

Required Gate 1 evidence:

- JSON Schema Draft 2020-12 conformance tests for policy, waiver, finding, and run-result documents.
- Table-driven tests for every registered field, operator, enum, array rule, and precedence combination.
- Property tests for termination within the operation bound, rule-order independence, monotonicity, and deterministic output with a fixed clock.
- Fuzzing of YAML syntax, aliases, tags, duplicate keys, globs, nesting, set sizes, Unicode, and numeric boundaries.
- Adversarial policies attempting file access, network access, environment interpolation, recursion, loops, object construction, and executable tags; all must be rejected.
- Waiver tests for exact fingerprint/path containment, expiry boundaries, identifier reuse, base-versus-head behavior, and maximum lifetime.
- Golden tests for canonical JSON, bounded diagnostics, job-summary Markdown, and SARIF projection.
- Fault injection proving budget or deadline exhaustion yields `incomplete`, never `pass`.
- Independent code review of evaluator implementation and test evidence before Gate 1 closes.

## Consequences

The model is intentionally less expressive than OPA/Rego or a general language. It is finite, reviewable, portable, and safe to evaluate against attacker-controlled repository data. New fields, operators, waiver scope forms, or increased limits require a schema version change, threat-model update, conformance tests, and independent review.

## Rejected alternatives

- **OPA/Rego in version 1:** powerful and established, but expands the language and runtime surface before ProofRail semantics stabilize.
- **JavaScript, Python, shell, or template policies:** permit arbitrary execution or ambient authority.
- **Regular-expression operators:** increase complexity and denial-of-service risk; bounded globs cover version 1 path routing.
- **First-match-wins:** rule ordering can accidentally weaken a later security decision.
- **Head-revision policies or waivers:** let a pull request alter its own judge.
- **Glob-scoped waivers:** make containment and broadening difficult to reason about; exact fingerprints and paths are safer.
