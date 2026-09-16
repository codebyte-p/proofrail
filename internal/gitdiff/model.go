// Package gitdiff owns Git invocation, revision binding, path normalization,
// and changed-file limits.
//
// It is the only package permitted to run Git, and it may not execute hooks,
// filters, submodules, LFS, or any other repository-controlled program. It reads
// two immutable commits and produces a bounded, normalized, deterministically
// ordered change set. Everything downstream consumes that value and never
// reaches the filesystem again.
//
// The package imports only the standard library. internal/run depends on it, so
// it defines its own narrow Limits rather than importing run.Limits; see
// Amendment 3 in the Gate 1 plan.
package gitdiff

import "strings"

// ChangeKind classifies a file's change between the base and head revisions.
type ChangeKind string

const (
	Added    ChangeKind = "added"
	Modified ChangeKind = "modified"
	Deleted  ChangeKind = "deleted"
	Renamed  ChangeKind = "renamed"
)

// Valid reports whether k is a registered change kind.
func (k ChangeKind) Valid() bool {
	switch k {
	case Added, Modified, Deleted, Renamed:
		return true
	default:
		return false
	}
}

// EntryMode records what kind of tree entry a path is, so analysis can tell a
// regular file from something it must not read through.
type EntryMode string

const (
	ModeFile       EntryMode = "file"
	ModeExecutable EntryMode = "executable"
	ModeSymlink    EntryMode = "symlink"
	ModeSubmodule  EntryMode = "submodule"
)

// FileChange is one normalized changed path.
//
// Path and PreviousPath are normalized repository-relative paths. BaseContent
// and HeadContent hold raw blob bytes exactly as stored, never a filtered or
// smudged projection, and are empty for a mode that must not be read as content.
// CoverageNote is set when the entry is recorded but deliberately not analyzed,
// so a skipped entry appears in the coverage ledger instead of vanishing.
type FileChange struct {
	Path         string
	PreviousPath string
	Kind         ChangeKind
	Mode         EntryMode
	Patch        []byte
	BaseContent  []byte
	HeadContent  []byte
	CoverageNote string

	// Blob hashes of each side, used only while the loader fills content in a
	// single batched read. They are unexported so no consumer can mistake them
	// for part of the normalized contract.
	baseBlob string
	headBlob string
}

// ChangeSet is the complete bounded result of loading one base/head pair.
// Files are sorted by Path in byte order.
type ChangeSet struct {
	Repository   string
	BaseSHA      string
	HeadSHA      string
	Files        []FileChange
	ChangedLines int
	ContentBytes int64
}

// Limits are the bounds this package enforces. They mirror the approved
// architecture values; internal/run converts its full Limits into this narrow
// pair. A zero value is rejected rather than treated as unbounded.
type Limits struct {
	MaxChangedFiles        int
	MaxChangedContentBytes int64
}

// DefaultLimits returns the approved version 1 changed-file bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxChangedFiles:        5000,
		MaxChangedContentBytes: 50 << 20,
	}
}

// Request binds one load to an exact repository and revision pair.
type Request struct {
	RepoPath   string
	Repository string
	BaseSHA    string
	HeadSHA    string
	Limits     Limits
}

// LoadError reports a failed load with a stable diagnostic code.
//
// Every load failure is an incomplete-class failure: the engine could not bind
// or read the revisions, so it has no basis for a decision. Reason is bounded
// prose from a fixed set and never contains a repository path, a file name, or
// file content.
type LoadError struct {
	Code   string
	Reason string
}

func (e *LoadError) Error() string { return e.Code + ": " + e.Reason }

func loadFailure(code, reason string) *LoadError {
	return &LoadError{Code: code, Reason: reason}
}

// validFullSHA requires a full, unabbreviated, lowercase 40-character hash.
// Abbreviated hashes, branch names, and symbolic refs are all mutable and
// therefore cannot bind a run.
func validFullSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

// validRepositoryIdentity accepts exactly `owner/name`, matching the identity
// the canonical result is bound to.
func validRepositoryIdentity(s string) bool {
	if s == "" || len(s) > 140 {
		return false
	}
	owner, name, found := strings.Cut(s, "/")
	if !found || owner == "" || name == "" || strings.Contains(name, "/") {
		return false
	}
	for _, seg := range []string{owner, name} {
		if seg == "." || seg == ".." || seg[0] == '.' {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
				c == '-', c == '_', c == '.':
			default:
				return false
			}
		}
	}
	return true
}
