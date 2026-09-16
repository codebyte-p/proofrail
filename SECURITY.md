# Security Policy

## Supported versions

ProofRail is under initial development and has no supported release. Do not use the current repository to make production merge decisions.

## Security model

The complete product threat model—including protected assets, attacker capabilities, trust boundaries, adversarial scenarios, failure modes, severity, deployment assumptions, exclusions, and the absence of compliance claims—is maintained in [docs/threat-model.md](docs/threat-model.md). The implemented system must preserve these invariants:

- repository-controlled content is treated as hostile data and is not executed by version 1;
- a pull request cannot weaken the policy or waiver set used to evaluate itself;
- missing or failed required analysis cannot produce a pass;
- reports are bound to immutable revisions, engine version, and policy digest;
- secrets are not reproduced in findings, logs, or interoperability output;
- credentials are least-privileged and separated from untrusted pull-request execution;
- overrides are scoped, attributable, expiring, and auditable;
- future hosted processing must enforce tenant isolation before handling real customer repositories.

## Reportable security issues

Examples include:

- code execution, path escape, or uncontrolled resource consumption caused by analyzed repository data;
- a policy, waiver, analyzer, or error-handling path that turns incomplete or blocked analysis into pass;
- analysis or publication of the wrong commit, repository, installation, policy, or tenant;
- credential, secret, private source, or cross-tenant data disclosure;
- arbitrary code execution through policy or analyzer extension mechanisms;
- forged, substituted, or non-auditable findings and release artifacts;
- bypass of owner approval, protected-branch policy, or independent-review requirements.

A noisy rule, documented unsupported language, or disagreement with an explicitly advisory classification is ordinarily a quality issue rather than a vulnerability unless it creates a security-boundary bypass or repeatable denial of service.

## Reporting

Do not include credentials, personal data, private repository content, or weaponized exploit material in public issues. Until GitHub private vulnerability reporting is enabled, report suspected vulnerabilities directly to the repository owner and avoid publishing details that would increase harm.

Provide the affected revision and version, deployment type, minimal reproduction using synthetic data, expected invariant, observed behavior, and impact. Do not test against repositories, accounts, systems, or data without explicit authorization.

## Compliance

ProofRail does not currently claim compliance with or certification under any regulatory or assurance framework. Such claims require separately approved scope, legal review, control mapping, and operating evidence.
