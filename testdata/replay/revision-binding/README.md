# Revision-binding replay fixtures

These fixtures exercise `internal/gitdiff` against real Git repositories rather
than recorded output, because the security property under test is how ProofRail
*invokes* Git, not how it parses a string.

Repositories are built at test time by `internal/gitdiff/git_test.go` under
`t.TempDir()`. Nothing is committed here, which keeps the corpus free of any
checked-in `.git` directory that could itself carry hooks, attributes, or
configuration.

## Scenarios covered

| Scenario | Property asserted |
|---|---|
| Added, modified, deleted, and renamed files in one head commit | Every `ChangeKind` is classified and a rename keeps its previous path |
| Abbreviated, symbolic, uppercase, and unknown revisions | Only a full 40-character lowercase commit hash can bind a run |
| A tree object supplied as a revision | A non-commit object cannot bind a run |
| A revision that resolves to a different hash | `git.revision_mismatch`; a run never judges a revision other than the one it reports |
| Paths differing in case and in segment depth | Ordering is byte order, not locale order, on every platform |
| Changed-file and changed-content limits | Exceeding either yields an `incomplete`-class failure, never a truncated success |
| A zero limit value | An unset limit fails closed rather than meaning unbounded |
| `120000` symlink entries | Recorded with a coverage note, content left unread, target never followed |
| `160000` gitlink entries | Recorded with a coverage note, referenced repository never entered |
| Repository-configured `diff.external`, `textconv`, clean/smudge/LFS filters, and `core.hooksPath` | No repository-controlled program executes; a marker file is asserted absent |
| `.gitattributes` requesting a required filter | Content is the raw stored blob, not a filtered projection |
| A cancelled context | The load stops instead of running Git |
| Any load failure | The error carries a stable code and never echoes a repository path or file content |

## Known platform limitations

- Symlink and submodule entries are staged through `git update-index
  --cacheinfo` rather than created on disk, so the tests do not depend on the
  host supporting symlink creation or on network access for a real submodule.
- Paths differing only in case are avoided; a case-insensitive filesystem would
  collapse them into one entry and the fixture would not mean what it says.
