# Governance

## Authority

The repository owner retains legal ownership, credential control, emergency shutdown authority, and final approval over critical changes. Codex and Claude may propose, implement, test, document, and review work within the permissions granted to them.

No repository instruction overrides OpenAI, Anthropic, GitHub, legal, or platform safety requirements.

## Change risk

- **Low:** documentation, tests, and non-executable metadata.
- **Medium:** ordinary product code, rules, and dependencies.
- **High:** authentication, authorization, cryptography, parsers, network access, sandboxing, CI permissions, and security enforcement.
- **Critical:** secrets, repository permissions, deployments, disclosure decisions, destructive operations, and material expansion of dual-use capability.

High-risk changes require independent agent review and repository-owner approval. Critical changes require explicit repository-owner authorization.

## Merge rules

- No direct pushes to the protected default branch after remote protections are enabled.
- The author of a security-sensitive change cannot provide its decisive approval.
- Required checks must pass before merge.
- Unresolved blocking review comments prevent merge.
- Evidence and important design decisions must be recorded in the repository.

## Disagreement resolution

Agents must state disagreements as testable claims supported by code, tests, standards, or threat-model evidence. Prefer the safer reversible option, run a bounded experiment when possible, and escalate unresolved policy or risk decisions to the repository owner.

