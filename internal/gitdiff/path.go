package gitdiff

import (
	"path"
	"strings"
	"unicode/utf8"
)

// MaxRepoPathBytes bounds a normalized repository-relative path. It sits far
// above any realistic source path while keeping every downstream buffer,
// fingerprint input, and report field bounded.
const MaxRepoPathBytes = 4096

// PathError reports a rejected repository path.
//
// Code is the stable diagnostic identifier callers and tests match on. Reason is
// bounded prose chosen from a fixed set. Neither ever contains the rejected
// value: a path is attacker-controlled text, and the error string reaches
// diagnostics, console output, and published reports.
type PathError struct {
	Code   string
	Reason string
}

func (e *PathError) Error() string { return e.Code + ": " + e.Reason }

func rejectPath(reason string) (string, error) {
	return "", &PathError{Code: "path.invalid", Reason: reason}
}

// NormalizeRepoPath converts a repository path into its canonical
// forward-slash, repository-relative form.
//
// Normalization is purely lexical. It never calls filepath.Abs, EvalSymlinks, or
// any other filesystem operation, so a symlink, a mount, a case-insensitive
// volume, or a concurrent change in the worktree cannot influence the result.
// The answer depends only on the bytes supplied, which is what makes
// fingerprints and waiver path containment reproducible.
//
// Accepted input may contain redundant `./` prefixes, doubled separators, and
// interior `..` segments that stay inside the repository; those are collapsed.
// Anything that could denote a location outside the bound revision, or that
// could corrupt a report, is rejected.
func NormalizeRepoPath(raw string) (string, error) {
	if raw == "" {
		return rejectPath("path is empty")
	}
	if len(raw) > MaxRepoPathBytes {
		return rejectPath("path exceeds the maximum length")
	}
	if !utf8.ValidString(raw) {
		return rejectPath("path is not valid UTF-8")
	}

	// Reject dangerous bytes before any interpretation. A NUL truncates the path
	// for a C API, and a control byte can rewrite a terminal or a Markdown table
	// once the path reaches a report.
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == 0x00 {
			return rejectPath("path contains a NUL byte")
		}
		if c < 0x20 || c == 0x7f {
			return rejectPath("path contains a control character")
		}
		if c == '\\' {
			// Backslash is a legal character in a POSIX filename and a separator
			// on Windows. Allowing it would make one path mean two things, so a
			// normalized path never contains it.
			return rejectPath("path contains a backslash")
		}
	}

	// Reject absolute and volume-qualified forms before cleaning, because
	// path.Clean preserves a leading separator and knows nothing about drives.
	if raw[0] == '/' {
		return rejectPath("path is absolute")
	}
	if hasDriveLetter(raw) {
		return rejectPath("path carries a drive letter")
	}
	// A trailing separator denotes a directory. Repository paths name files, and
	// treating "src" and "src/" as the same entry would confuse containment.
	if strings.HasSuffix(raw, "/") {
		return rejectPath("path has a trailing separator")
	}

	cleaned := path.Clean(raw)

	// path.Clean resolves interior traversal but leaves any prefix that escapes
	// the root, and collapses a path with no content to ".".
	switch {
	case cleaned == "." || cleaned == "":
		return rejectPath("path does not name a file")
	case cleaned == "..", strings.HasPrefix(cleaned, "../"):
		return rejectPath("path escapes the repository root")
	case strings.HasPrefix(cleaned, "/"):
		return rejectPath("path is absolute")
	}

	return cleaned, nil
}

// hasDriveLetter reports whether s begins with a Windows volume specifier such
// as `C:` or `c:`, with or without a following separator.
func hasDriveLetter(s string) bool {
	if len(s) < 2 || s[1] != ':' {
		return false
	}
	c := s[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
