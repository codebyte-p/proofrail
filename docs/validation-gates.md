# Validation and Promotion Gates

ProofRail advances only when the current stage has reproducible evidence for every required gate. Calendar dates, feature pressure, and agent confidence cannot waive a gate. The repository owner records promotion approval; failure returns the project to the previous safe stage.

## Global measurements

The test corpus is versioned and divided before tuning into malicious or policy-violating fixtures, benign fixtures, malformed/adversarial inputs, and real-project replay fixtures. Test fixtures record expected findings and intentional non-findings. A rule is not evaluated on examples used only to design that rule without labeling the potential bias.

Metrics:

- **Must-detect rate:** proportion of curated blocking scenarios producing the expected rule and decision.
- **False-block rate:** benign cases incorrectly receiving `block` or `require_review` beyond the documented policy expectation.
- **Completion rate:** runs that produce a schema-valid terminal result without internal error.
- **Determinism:** byte-equivalent canonical results for the same bound inputs and engine version.
- **P95 duration:** wall-clock duration at the defined corpus size.
- **Publication integrity:** GitHub presentation matches canonical decision, revision, and fingerprints.

## Gate 0: specification approval

Required before application code:

- Product design, architecture, threat model, analyzer contracts, policy ADR, and validation gates are committed.
- No unresolved contradiction or placeholder exists across the package.
- Codex self-review reports no blocking inconsistency.
- Claude independently returns `APPROVE` or `APPROVE_WITH_NONBLOCKING_NOTES` under `AI_MAINTAINERS.md`.
- The repository owner approves the specification and any accepted limitations.

Rollback: revise documentation only. No runtime artifact exists.

## Gate 1: CLI alpha

Deliverable: an offline CLI supporting immutable diff binding, three built-in analyzers, restricted policy evaluation, canonical JSON, console output, and SARIF generation.

Promotion criteria:

- 100% pass on schema, parser, policy, reporter, and exit-code unit tests.
- 100% detection of versioned `must_detect` fixtures for `PFR-WF-001`, `PFR-WF-004`, `PFR-WF-005`, `PFR-DEP-001`, `PFR-DEP-004`, and required-analyzer failure.
- Zero false `pass` results across malformed, timeout, parser-failure, unsupported-required-input, and reporter-failure fixtures.
- At least 500 adversarial parser fixtures execute without process escape, uncontrolled resource growth, or unhandled termination.
- Deterministic canonical JSON in 100 repeated runs on every golden fixture across supported platforms.
- False-block rate at or below 5% on the initial benign corpus, with every remaining case documented.
- P95 duration below 60 seconds for 5,000 changed lines and 100 changed supported files on the reference GitHub-hosted runner.
- No network request during analysis, verified by an isolated test environment.
- Independent security review of parser, path, policy, redaction, and atomic-output boundaries.

Pilot: local shadow-mode use on ProofRail and at least two public repositories whose maintainers authorize analysis. Findings are not merge-blocking.

Rollback: pin the last passing CLI release; revoke the affected release checksum and publish a visible advisory when decision integrity is affected.

## Gate 2: GitHub Action beta

Deliverable: a reusable Action that invokes the released CLI on `pull_request`, publishes a job summary and artifacts, and optionally uploads SARIF.

Promotion criteria:

- All CLI alpha gates continue to pass for the embedded version.
- End-to-end fixtures cover same-repository PRs, public forks, Dependabot-like restrictions, renamed files, deleted files, malformed policy, analyzer timeout, and SARIF unavailability.
- Workflow declares minimum explicit permissions and never uses privileged untrusted checkout.
- All third-party Actions are pinned to immutable full commit SHAs for a release.
- No forked-PR secret access and no write-capable token in the analysis job.
- Canonical artifact revision and policy digests match the GitHub event in every end-to-end fixture.
- At least 100 shadow-mode pull-request runs across at least three authorized repositories.
- Completion rate at least 99% excluding confirmed GitHub platform incidents.
- False-block rate at or below 2% during the pilot; no unexplained blocking decision.
- P95 Action duration below two minutes for the reference corpus.
- Publication failure is distinguishable from analysis failure and never converts `incomplete` to `pass`.

Pilot progression:

1. ProofRail repository in shadow mode.
2. Two authorized repositories in shadow mode.
3. Selected high-confidence workflow rules in blocking mode.
4. Broader blocking only after owner review of pilot metrics.

Rollback: repository owners can pin the previous Action SHA or disable the workflow. ProofRail maintains a release revocation list in release notes and provides a one-command version rollback. A decision-integrity incident disables blocking recommendations until fixed.

## Gate 3: GitHub App private beta

Deliverable: a hosted control plane, isolated workers, tenant-scoped result storage, and GitHub Check publication for invited installations.

Promotion criteria:

- Threat model revised against implemented infrastructure with source evidence.
- Webhook signature, replay, installation authorization, and immutable-revision tests pass.
- Automated cross-tenant tests demonstrate denial for repository content, policies, results, logs, caches, tokens, and identifiers outside the active tenant.
- Workers are ephemeral, do not execute repository code, and have default-deny egress with documented allow-list entries.
- Clone and publication use separate short-lived credentials with audited scopes.
- Secrets are stored in an approved secret manager, encrypted at rest and in transit, rotated, and excluded from logs.
- Per-tenant quotas prevent one installation from exhausting shared capacity.
- Backup, deletion, retention, disaster recovery, and regional assumptions are documented and tested.
- A staged deployment, kill switch, worker-version pin, and rollback complete successfully in an exercise.
- Incident notification can identify affected installations without disclosing another tenant's data.
- At least five invited installations complete 500 total analyses with no confirmed cross-tenant leak or incorrect revision binding.
- Service completion rate at least 99.5% over a 30-day beta window, excluding announced maintenance and upstream GitHub incidents.

Rollback: stop webhook intake, stop new jobs, disable publication, revoke installation tokens, restore the prior worker/control-plane release, and notify affected owners according to the incident runbook. The CLI and Action remain usable independently.

## Gate 4: production readiness

This gate is deliberately not a promise of general availability. It requires:

- An external security assessment of the hosted boundary.
- Defined service objectives, on-call ownership, monitoring, abuse controls, data-processing terms, privacy review, support process, and vulnerability response targets.
- At least one successful disaster-recovery exercise and one credential-compromise exercise.
- Capacity tests at twice the planned launch load.
- Signed artifacts, build provenance, software bill of materials, release rollback, and dependency response procedures.
- Repository-owner approval of residual risks and operating cost.

## Incident classification and response targets

| Class | Example | Initial containment target | Required action |
|---|---|---:|---|
| Decision integrity | A required analyzer failure produced pass | 1 hour | Disable affected blocking path, revoke release, notify affected users, preserve evidence |
| Credential exposure | Token or secret appears in output or logs | 1 hour | Stop affected jobs, revoke credential, restrict logs, identify recipients |
| Cross-tenant isolation | One tenant can access another tenant's data or authority | Immediate | Shut down hosted analysis and publication, revoke tokens, owner-led incident response |
| Availability or false blocking | Rule or service prevents legitimate merges at scale | 4 hours | Disable or roll back rule/version; preserve non-blocking evidence |
| Presentation defect | Markdown or SARIF display is misleading but canonical result is correct | 1 business day | Fix publisher and identify affected reports |

Targets are design objectives until an operated service has named responders and monitoring. They do not create a contractual service-level agreement.
