# Gate 1 Security Review Log

Gate 1 requires an independent security review of the parser, path, policy,
redaction, and atomic-output boundaries before it can close. That review is not
complete: most of those boundaries do not exist yet.

This file is the running log. Each entry records what was reviewed, by whom, what
was found, and how it was resolved. **No entry here constitutes the Gate 1
independent verdict.** Under `AI_MAINTAINERS.md`, Claude may implement a task but
may not supply its own decisive security approval; the reviews below were
performed by a Claude reviewer agent within the implementing session and are
therefore *self-review*. Codex or another approved independent reviewer must
still validate these diffs and this evidence.

## Boundary coverage

| Boundary | Reviewed | Outcome |
|---|---|---|
| Git invocation and revision binding | 2026-09-16 | 2 confirmed defects, both fixed; see R1 |
| Path normalization | 2026-09-16 | No findings |
| Redaction | 2026-09-16 (by fuzzing) | 1 confirmed defect, fixed; see R2 |
| Bounded parsers | not yet written | pending |
| Policy evaluator | not yet written | pending |
| Atomic output | not yet written | pending |
| Independent (non-Claude) review | not started | pending |

---

## R1 — `internal/gitdiff` resource limits enforced after allocation

- **Reviewed:** `internal/gitdiff/{model,path,git}.go` at `f6afaf6`
- **Reviewer:** Claude reviewer agent (self-review, not the independent verdict)
- **Resolved in:** `15e3173`

### R1.1 Content limit enforced after the full object was buffered — confirmed, high

Every Git invocation buffered the whole of stdout into a `bytes.Buffer` before
parsing. `readBlobs` checked object sizes against the budget only while walking
that already-materialized buffer. A hostile pull request containing one very
large file would therefore have the entire object resident in memory before the
50 MiB aggregate cap was consulted, producing an out-of-memory kill.

This defeated the architecture invariant that limit exhaustion yields
`incomplete` and exit code 2. An OOM is neither `incomplete` nor controlled, and
it is directly reachable from repository-controlled content.

**Fix:** Git output is consumed as a stream. The per-object check runs before the
body is allocated, written as `total > maxBytes-size` so an absurd reported size
cannot overflow past it. A consumer that stops early kills the child process and
drains its pipe.

**Regression test:** `TestLoadNeverReadsMoreObjectBytesThanTheLimitAllows`
measures allocation rather than only the returned error code, because the
returned code was already correct — the defect was upstream of the per-object
check. Verified RED against the previous implementation, which allocated
134,638,392 bytes for a 32 MiB file under a 64 KiB limit.

### R1.2 Changed-file limit reached only after full raw-diff output was buffered — confirmed, medium

The same buffer-then-check shape applied to `git diff --raw` and `--numstat`. A
commit with very many entries materialized its complete output before the
5,000-file cap was consulted. Lower magnitude than R1.1, bounded by path length
rather than arbitrary object size, but the same architectural gap.

**Fix:** both are parsed incrementally with the limit enforced per record, so
peak cost is proportional to the limit rather than to the commit presented.

### R1.3 Aggregate budget charged per unique object, not per file — confirmed, medium

Git content-addresses identical files to one object. Charging the budget per
unique object let a pull request adding many copies of one large file pass a
budget those files should have exhausted, since analyzers receive the content
once per file.

**Fix:** the aggregate is charged per file, which is the surface analyzers
actually receive. `TestLoadCountsDuplicateContentOncePerFile` covers it.

### Reviewed and found sound

- Git hardening: rebuilt environment, disabled system and global config,
  `core.hooksPath` redirected to a loader-owned empty directory, `--no-ext-diff`,
  `--no-textconv`, neutralized `diff.external` and LFS/clean/smudge filters, and
  content read through `cat-file`, which never applies a smudge filter. No
  additional config key was identified for the read-only subcommands invoked.
- Revision binding: full-hash validation plus
  `rev-parse --verify --end-of-options <sha>^{commit}` with exact self-resolution
  correctly rejects abbreviated hashes, symbolic refs, and non-commit objects.
- `-z` parsing cannot be desynchronized by adversarial path content, because Git
  disables C-style quoting under `-z` and a tree entry path cannot contain NUL.
- `NormalizeRepoPath` rejects NUL, control bytes, backslashes, drive letters,
  UNC forms, absolute paths, root-escaping traversal, trailing separators,
  oversized paths, and invalid UTF-8, and performs no filesystem access.
- The changed-file limit boundary is exact: `>=` before append admits the
  configured maximum and rejects the next record.
- Symlink and submodule entries never have their objects fetched.

---

## R2 — Redaction ordering allowed a credential to bypass every detector

- **Found by:** `FuzzRedact`, 3 seconds into a 30-second run
- **Resolved in:** `893864d`

Control bytes were stripped *after* shape detection. A value such as
`AKIA00000000\x030000000` therefore matched no detector as a contiguous run, and
the control byte was then removed on the way out, reassembling the real access
key inside the evidence excerpt.

This is a credential-exposure path, not a formatting nit: evidence is redacted
once before it reaches findings, logs, and SARIF.

**Fix:** control bytes are stripped before any detector runs, so detectors see
exactly the text a reader will see. Shape detection then runs before the
key-name rule so a recognizable credential keeps its precise kind.

**Regression:** the failing input is retained as a fuzz corpus seed at
`internal/finding/testdata/fuzz/FuzzRedact/a887510a52598d35`. `FuzzRedact` ran a
further 60 seconds after the fix with no new failures.

---

## Outstanding

- An independent, non-Claude reviewer must validate every diff and this evidence
  before Gate 1 closes.
- Plan amendments 1, 2, and 3 are proposed and unaccepted; see the Gate 1 plan.
- `go test -race` has not run on the development workstation (no C toolchain).
  CI runs it on `ubuntu-latest`; a run link must be recorded before promotion.

## PR #1 independent review — 2026-09-16

Verdict: **REQUEST_CHANGES**. Six high and eight medium findings, all fixed on
`feat/gate1-workflow` with a named regression test per finding. Every fix was
red-green verified: the test failed against the reviewed commit for the reason
the finding states, then passed.

### High

| # | Finding | Resolution |
|---|---|---|
| H1 | Mode 100755 caused active workflows and dependency files to be skipped | `EntryMode.ReadableAsContent` accepts file and executable; symlink and submodule still skipped |
| H2 | Python `build-system.requires` parsed but excluded from every rule | Ingested as `build-system.requires` declarations, subject to the source rules |
| H3 | Mixed-case `Actions/Checkout` bypassed PFR-WF-001 and PFR-WF-005 | Case-insensitive comparison, matching how GitHub resolves `uses:` |
| H4 | npm `owner/repo` Git shorthand misclassified as a registry dependency | Classified as Git; PFR-DEP-002 had been skipping registry sources outright |
| H5 | Manifest-only changes and lock deletion evaded PFR-DEP-001 | Lock presence and deletion recorded per ecosystem rather than inferred from resolution count |
| H6 | PFR-DEP-001 checked name presence but not version consistency | Exact pins compared against the resolved version; range satisfaction remains out of scope and is recorded as a limitation |

### Medium

| # | Finding | Resolution |
|---|---|---|
| M1a | Coverage notes bypassed redaction | Notes pass through `finding.Redact` |
| M1b | Diagnostic paths and messages bypassed redaction | Diagnostics pass through `finding.Redact` |
| M2 | TOML dotted key paths had no depth or node bound | Bounded by `MaxDepth` and the node budget |
| M3 | `Limits.MaxFindings` was never enforced | Exceeding it is a budget failure yielding `failed` completion |
| M4 | Records keyed by name collided across ecosystems | Keys namespaced by ecosystem; name similarity compares within one registry |
| M5 | PFR-DEP-002 tested only Git and URL for "outside repository" | Local paths that escape the tree, or are absolute, now block |
| M6 | Base-revision parse failure fell back to an empty baseline | Treated as a required-input failure in both analyzers |
| M7 | Only the first uv artifact hash formed the resolved identity | Identity spans the sdist and every wheel, bounded at 2 KiB |

### Notes for the re-review

- M6 tightens behavior: a repository whose base revision holds an unparseable
  manifest or lock now yields `incomplete` rather than analyzing against an
  empty baseline. This is the fail-closed reading `CLAUDE.md` requires, and it
  reverses a Task 4 decision that had recorded the same condition as coverage.
- H5's manifest-only case fires whenever a change adds or alters a dependency
  with no lockfile in the change set. Offline analysis cannot distinguish a
  project that keeps no lockfile from one whose lockfile was not updated, so
  the finding records both readings in its limitations.
- Severity and confidence for PFR-DEP-001..006 remain the implementer's choice
  and still want an owner ruling, as the PFR-WF table received in Amendment 6.

## PR #1 independent re-review of `e8f0670` — 2026-09-17

Verdict: **REQUEST_CHANGES**. H1-H6 accepted as materially fixed. Six findings
remained, all now closed with named regression tests.

| # | Finding | Resolution |
|---|---|---|
| 1 | `MaxFindings` enforced after generation, Finalize, and Sort | A `budget` is consulted *during* generation: rules check it inside their loops and `evaluate` stops between rules. `TestBudgetBoundsGenerationNotJustOutput` asserts candidates generated, not returned length: 20,000 hostile declarations under a 5-finding ceiling generate at most a handful. |
| 2 | `recordKey` collapsed same-ecosystem workspaces and duplicate resolved instances | Keys split three ways: `declaredKey` adds the manifest path, `resolvedKey` adds the lockfile path and a per-install `Instance`, and `nameKey` stays coarse for "does this lock resolve this name at all". `resolutionsByName` preserves every instance and its version. |
| 3 | PFR-DEP-002 used mutable AND outside; containment ignored the manifest | Now mutable **or** outside, per `docs/analyzers.md`. `pathEscapesRepository` takes the declaring manifest and resolves from `path.Dir`, so `../b` from `packages/a/package.json` stays inside while the same text from a root manifest does not. |
| 4 | uv `artifactIdentity` silently dropped hashes past 2 KiB | Every digest is length-framed and streamed into a SHA-256, so the identity is fixed-size without omitting a tail. Framing keeps `["ab","c"]` and `["a","bc"]` distinct. |
| 5 | Opaque `Authorization` values not recognized as secret-bearing | `authorization` and `credential` added to the secret key names; `proxy_authorization` normalizes to a superstring of the former. |
| 6 | Only the first assignment separator per line was examined | Every separator is considered; a redacted value extends to the next `,` or `;` so surrounding fields survive. `valueAlreadyClassified` preserves a precise shape classification such as `[REDACTED:jwt]` rather than overwriting it with the generic marker. |

### Consequence the re-review should note

Finding 3's OR reading means **every Git or URL dependency now blocks, including
one pinned to a full commit SHA**, because such a source is outside the
repository whichever way it is pinned. Only a source that is both immutable and
inside the tree — a contained workspace or local path — reaches review. This
changed an existing expectation in `TestNPMGitShorthandIsNotTreatedAsRegistry`,
which previously asserted review for a SHA-pinned shorthand.

### Still awaiting owner input

- **Amendment 5.** The re-review approves it "with the normative wording
  supplied by the reviewer", but that wording did not accompany the verdict. It
  is not recorded, so Task 10 stays blocked.
- **PFR-DEP severity and confidence.** Ruled "as supplied by the reviewer"; the
  table did not accompany the verdict and is not recorded. Required before
  Task 13 freezes golden fixtures.
