# ADR 0001: Restricted Declarative Policy Model

- **Status:** Proposed for independent review
- **Date:** 2026-09-16
- **Decision owners:** Repository owner, with independent Codex and Claude review

## Context

ProofRail must convert normalized findings into predictable CI decisions. Executing a general-purpose language, template engine, user function, shell command, or downloaded plugin would turn policy into a code-execution boundary and make termination and review difficult.

## Decision

Version 1 policy is a schema-versioned YAML document evaluated by a bounded, non-Turing-complete interpreter. It can inspect only normalized run and finding fields. It cannot read arbitrary files, access environment variables, perform network calls, import modules, call functions, mutate state, or recurse.

The effective policy is loaded from the base revision. A policy changed in a pull request is analyzed but does not govern that pull request.

## Schema

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

Allowed fields are an explicit registry drawn from immutable run metadata and normalized findings. Initial operators are:

- `eq` and `not_eq` for scalar equality;
- `in` and `not_in` for bounded scalar sets;
- `gte` and `lte` for defined numeric fields;
- `path_matches` for a restricted Git-style glob with a fixed pattern-length limit;
- `exists` for field presence;
- `all`, `any`, and `not` for boolean composition with fixed depth and term limits.

Unknown fields, operators, enum values, or duplicate rule identifiers reject the policy. Rule evaluation order cannot change security outcome: the final decision is the most restrictive matched decision under this order:

```text
block > require_review > warn > observe > pass
```

No rule may map a run-level `incomplete` state to `pass`. Limits include maximum document bytes, rule count, terms per rule, composition depth, glob length, and total evaluation operations.

When a registered field contains multiple values, a positive predicate matches when any element matches and a negative predicate matches only when every element satisfies the negative condition. Version 1 globs support `*`, `?`, and `**` over normalized forward-slash repository paths; brace expansion, character classes, backslashes, absolute paths, and parent traversal are rejected.

## Example 1: block privileged untrusted workflow execution

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
  "message": {
    "text": "Privileged workflow can execute pull-request-controlled content. Policy block-privileged-pr-execution blocks this change."
  },
  "properties": {
    "proofrail.decision": "block",
    "proofrail.policyRule": "block-privileged-pr-execution"
  }
}
```

## Example 2: require review for new install-time execution

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
    message: A security reviewer must approve new or changed install-time execution.
```

Representative SARIF projection:

```json
{
  "ruleId": "PFR-DEP-003",
  "level": "warning",
  "message": {
    "text": "Dependency installation behavior changed. Policy review-install-execution requires security review."
  },
  "properties": {
    "proofrail.decision": "require_review",
    "proofrail.policyRule": "review-install-execution"
  }
}
```

## Example 3: route authentication changes to owners

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
    message: Obtain approval from the repository's configured security owners.
```

Representative SARIF projection:

```json
{
  "ruleId": "PFR-DIFF-001",
  "level": "warning",
  "message": {
    "text": "Authentication or authorization boundary changed. Policy auth-owner-review requires designated review."
  },
  "properties": {
    "proofrail.decision": "require_review",
    "proofrail.policyRule": "auth-owner-review"
  }
}
```

## Waiver model

Waivers use a separate schema and are read from the protected base revision. Each waiver contains an identifier, finding fingerprint or bounded rule/path scope, justification, approving actor or team, issue reference, creation time, and mandatory expiry time.

Waiver evaluation is deny-by-default:

- a malformed, expired, overbroad, or unauthenticated waiver does not apply;
- a waiver cannot suppress a run-level `incomplete` status;
- a waiver cannot disable an analyzer;
- all applied and rejected waivers appear in canonical output;
- a waiver introduced by the current pull request cannot approve that pull request.

## Testing requirements

- JSON Schema Draft 2020-12 structural conformance tests for policy, waiver, finding, and run-result documents.
- Table-driven tests for every field, operator, enum, and precedence combination.
- Property tests proving order independence and monotonicity: adding a more restrictive matching rule cannot weaken a decision.
- Fuzz tests for YAML parsing, glob matching, nesting, aliases, and numeric boundaries.
- Golden tests for canonical JSON and SARIF projection.
- Negative tests for unknown fields, excessive complexity, recursion attempts, object injection, environment interpolation, and executable tags.
- Base-versus-head tests proving a pull request cannot govern itself.

## Consequences

The model is explainable, deterministic, testable, and safe to evaluate against attacker-controlled repository data. It intentionally cannot express arbitrary organization logic. New fields and operators require a schema version change, threat-model update, conformance tests, and independent review.

## Rejected alternatives

- **OPA/Rego in version 1:** powerful and established, but expands the language and runtime surface before ProofRail's core semantics stabilize.
- **JavaScript, Python, or shell policies:** arbitrary code execution and non-termination are incompatible with hostile pull-request evaluation.
- **First-match-wins rules:** ordering can accidentally weaken a later security rule.
- **Policies from the head revision:** lets a pull request alter its own judge.
