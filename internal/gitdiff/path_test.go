package gitdiff

import (
	"errors"
	"strings"
	"testing"
)

// Every path that reaches a parser, an analyzer, a finding location, a waiver
// containment check, or a report is a normalized forward-slash
// repository-relative path. Normalization is lexical only: it never touches the
// filesystem, so a symlink or a race cannot change the answer.

func TestNormalizeRepoPathAccepts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"a nested source path", "src/auth/login.go", "src/auth/login.go"},
		{"punctuation Git permits", "a/b-c_1.yml", "a/b-c_1.yml"},
		{"a single segment", "README.md", "README.md"},
		{"a dotted directory", ".github/workflows/ci.yml", ".github/workflows/ci.yml"},
		{"a redundant current-directory prefix", "./src/main.go", "src/main.go"},
		{"a doubled separator", "src//main.go", "src/main.go"},
		{"an interior traversal that stays in the repository", "src/vendor/../main.go", "src/main.go"},
		{"a space inside a segment", "docs/design notes.md", "docs/design notes.md"},
		{"a non-ASCII segment", "docs/ドキュメント.md", "docs/ドキュメント.md"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeRepoPath(tc.in)
			if err != nil {
				t.Fatalf("NormalizeRepoPath(%q) returned %v, want it accepted", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeRepoPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeRepoPathRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"an absolute POSIX path", "/etc/passwd"},
		{"a Windows path with a drive and backslashes", `C:\secret`},
		{"a drive letter with forward slashes", "C:/secret"},
		{"a UNC share", `\\server\share\file`},
		{"a parent traversal", "../secret"},
		{"a traversal that escapes the root", "a/../../b"},
		{"a bare parent reference", ".."},
		{"a backslash separator", `a\b`},
		{"the current directory", "."},
		{"an empty path", ""},
		{"only separators", "///"},
		{"a NUL byte", "src/ma\x00in.go"},
		{"a newline", "src/ma\nin.go"},
		{"a terminal escape", "src/\x1b[2Jmain.go"},
		{"a trailing separator", "src/"},
		{"invalid UTF-8", "src/\xff\xfe.go"},
		{"a path above the length bound", strings.Repeat("a/", 3000) + "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeRepoPath(tc.in)
			if err == nil {
				t.Fatalf("NormalizeRepoPath(%q) = %q, want it rejected", tc.in, got)
			}
			if got != "" {
				t.Fatalf("a rejected path must return the empty string, got %q", got)
			}
			var pathErr *PathError
			if !errors.As(err, &pathErr) {
				t.Fatalf("error %v is not a *PathError", err)
			}
			if pathErr.Code != "path.invalid" {
				t.Fatalf("diagnostic code = %q, want %q", pathErr.Code, "path.invalid")
			}
			if pathErr.Reason == "" {
				t.Fatal("a rejection must state a bounded reason")
			}
		})
	}
}

func TestNormalizeRepoPathRejectionNeverEchoesTheValue(t *testing.T) {
	// A rejected path is attacker-controlled. Its bytes must not reach the error
	// string, which flows into diagnostics, console output, and reports.
	hostile := []string{
		"/pr00frail-canary/passwd",
		"../pr00frail-canary",
		"src/\x1b[2Jpr00frail-canary.go",
		"src/pr00frail-canary\x00.go",
		`C:\pr00frail-canary`,
	}
	for _, in := range hostile {
		_, err := NormalizeRepoPath(in)
		if err == nil {
			t.Fatalf("NormalizeRepoPath(%q) must reject", in)
		}
		msg := err.Error()
		for _, canary := range []string{"pr00frail-canary", "\x1b", "\x00"} {
			if strings.Contains(msg, canary) {
				t.Fatalf("error %q leaked the rejected path", msg)
			}
		}
	}
}

func TestNormalizeRepoPathIsIdempotent(t *testing.T) {
	// Fingerprints and waiver containment compare normalized paths, so
	// normalizing twice must not move the value.
	for _, in := range []string{"src/auth/login.go", "./a//b/../c.go", ".github/workflows/ci.yml"} {
		once, err := NormalizeRepoPath(in)
		if err != nil {
			t.Fatalf("NormalizeRepoPath(%q): %v", in, err)
		}
		twice, err := NormalizeRepoPath(once)
		if err != nil {
			t.Fatalf("NormalizeRepoPath(%q): %v", once, err)
		}
		if once != twice {
			t.Fatalf("normalization is not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}

func TestNormalizeRepoPathDoesNotTouchTheFilesystem(t *testing.T) {
	// A path for a file that does not exist normalizes exactly like one that
	// does. Resolving symlinks here would let repository content redirect
	// analysis to a path outside the bound revision.
	got, err := NormalizeRepoPath("does/not/exist/anywhere.go")
	if err != nil {
		t.Fatalf("normalization must be lexical, got %v", err)
	}
	if got != "does/not/exist/anywhere.go" {
		t.Fatalf("got %q", got)
	}
}
