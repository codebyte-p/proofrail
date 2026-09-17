package gitdiff

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test repository helpers
// ---------------------------------------------------------------------------

// git runs a Git command in dir with an isolated configuration so the
// developer's own global config cannot change a test outcome.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	base := []string{
		"-c", "user.name=ProofRail Test",
		"-c", "user.email=test@example.invalid",
		"-c", "commit.gpgsign=false",
		"-c", "init.defaultBranch=main",
		"-c", "core.autocrlf=false",
	}
	cmd := exec.Command("git", append(base, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// addedFileContent is deliberately unlike every base file so Git's rename
// detection does not pair the added and deleted fixtures.
const addedFileContent = `package totally

import "fmt"

func Unrelated() { fmt.Println("nothing in common") }
`

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, message string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", message, "--allow-empty")
	return git(t, dir, "rev-parse", "HEAD")
}

// newRepo returns an initialized repository directory.
func newRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	return dir
}

// twoCommitRepo builds a repository whose head commit exercises every change
// kind: one added, one modified, one deleted, and one renamed file.
func twoCommitRepo(t *testing.T) (dir, base, head string) {
	t.Helper()
	dir = newRepo(t)

	// The deleted and added files are deliberately dissimilar. Git's rename
	// detection is on, and near-identical boilerplate would legitimately pair
	// them into a single rename, which is not what this fixture is testing.
	writeFile(t, dir, "src/modified.go", "package src\n\nconst A = 1\n")
	writeFile(t, dir, "src/deleted.go", "package src\n\nconst B = 2\n")
	writeFile(t, dir, "src/old-name.go", "package src\n\nconst C = 3\n")
	writeFile(t, dir, "src/untouched.go", "package src\n\nconst D = 4\n")
	base = commit(t, dir, "base")

	writeFile(t, dir, "src/modified.go", "package src\n\nconst A = 99\n")
	if err := os.Remove(filepath.Join(dir, "src", "deleted.go")); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "mv", "src/old-name.go", "src/new-name.go")
	writeFile(t, dir, "src/added.go", addedFileContent)
	head = commit(t, dir, "head")

	return dir, base, head
}

func loadOK(t *testing.T, dir, base, head string, limits Limits) ChangeSet {
	t.Helper()
	loader, err := NewGitLoader()
	if err != nil {
		t.Skipf("git loader unavailable: %v", err)
	}
	cs, err := loader.Load(context.Background(), Request{
		RepoPath:   dir,
		Repository: "acme/demo",
		BaseSHA:    base,
		HeadSHA:    head,
		Limits:     limits,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cs
}

func loadErr(t *testing.T, req Request) *LoadError {
	t.Helper()
	loader, err := NewGitLoader()
	if err != nil {
		t.Skipf("git loader unavailable: %v", err)
	}
	_, err = loader.Load(context.Background(), req)
	if err == nil {
		t.Fatal("expected Load to fail")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("error %v is not a *LoadError", err)
	}
	return le
}

// ---------------------------------------------------------------------------
// Revision binding
// ---------------------------------------------------------------------------

func TestLoadBindsTheRequestedRevisionsExactly(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	cs := loadOK(t, dir, base, head, DefaultLimits())

	if cs.Repository != "acme/demo" {
		t.Errorf("Repository = %q", cs.Repository)
	}
	if cs.BaseSHA != base {
		t.Errorf("BaseSHA = %q, want %q", cs.BaseSHA, base)
	}
	if cs.HeadSHA != head {
		t.Errorf("HeadSHA = %q, want %q", cs.HeadSHA, head)
	}
}

func TestLoadRejectsRevisionsThatAreNotImmutableFullHashes(t *testing.T) {
	dir, base, head := twoCommitRepo(t)

	cases := []struct {
		name     string
		base     string
		head     string
		wantCode string
	}{
		{"abbreviated base", base[:7], head, "git.revision_invalid"},
		{"symbolic base", "HEAD~1", head, "git.revision_invalid"},
		{"branch name as head", base, "main", "git.revision_invalid"},
		{"uppercase hex", strings.ToUpper(base), head, "git.revision_invalid"},
		{"empty head", base, "", "git.revision_invalid"},
		{"well-formed but unknown commit", base, strings.Repeat("0", 39) + "1", "git.revision_unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			le := loadErr(t, Request{
				RepoPath: dir, Repository: "acme/demo",
				BaseSHA: tc.base, HeadSHA: tc.head, Limits: DefaultLimits(),
			})
			if le.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", le.Code, tc.wantCode)
			}
		})
	}
}

func TestLoadRejectsARevisionThatIsNotACommit(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	// A tree object is a valid object but is not a commit, so it cannot bind a run.
	tree := git(t, dir, "rev-parse", head+"^{tree}")

	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: tree, Limits: DefaultLimits(),
	})
	if le.Code != "git.revision_unknown" {
		t.Fatalf("code = %q, want git.revision_unknown", le.Code)
	}
}

func TestLoadRejectsAnInvalidRepositoryIdentity(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	le := loadErr(t, Request{
		RepoPath: dir, Repository: "not-a-repo-identity",
		BaseSHA: base, HeadSHA: head, Limits: DefaultLimits(),
	})
	if le.Code != "git.repository_invalid" {
		t.Fatalf("code = %q, want git.repository_invalid", le.Code)
	}
}

// ---------------------------------------------------------------------------
// Change classification
// ---------------------------------------------------------------------------

func TestLoadClassifiesEveryChangeKind(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	cs := loadOK(t, dir, base, head, DefaultLimits())

	byPath := map[string]FileChange{}
	for _, f := range cs.Files {
		byPath[f.Path] = f
	}

	if len(cs.Files) != 4 {
		t.Fatalf("got %d changed files, want 4: %+v", len(cs.Files), byPath)
	}
	if _, ok := byPath["src/untouched.go"]; ok {
		t.Error("an unchanged file must not appear in the change set")
	}

	if got := byPath["src/added.go"].Kind; got != Added {
		t.Errorf("src/added.go kind = %q, want %q", got, Added)
	}
	if got := byPath["src/modified.go"].Kind; got != Modified {
		t.Errorf("src/modified.go kind = %q, want %q", got, Modified)
	}
	if got := byPath["src/deleted.go"].Kind; got != Deleted {
		t.Errorf("src/deleted.go kind = %q, want %q", got, Deleted)
	}

	renamed, ok := byPath["src/new-name.go"]
	if !ok {
		t.Fatal("the renamed file must be recorded under its head path")
	}
	if renamed.Kind != Renamed {
		t.Errorf("rename kind = %q, want %q", renamed.Kind, Renamed)
	}
	if renamed.PreviousPath != "src/old-name.go" {
		t.Errorf("PreviousPath = %q, want src/old-name.go", renamed.PreviousPath)
	}
}

func TestLoadSortsChangesByPath(t *testing.T) {
	// Deterministic ordering is a promotion criterion: the same inputs must
	// produce byte-identical canonical output.
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")

	// "Zulu.go" sorts before "alpha.go" in byte order ('Z' is 0x5A, 'a' is 0x61)
	// but after it under a case-insensitive or locale-aware collation. That
	// distinction is what this test pins down.
	//
	// Names differing only in case are avoided on purpose: this test must pass on
	// a case-insensitive filesystem too, where they would collapse into one file.
	for _, p := range []string{"zeta.go", "alpha.go", "mid/beta.go", "Zulu.go"} {
		writeFile(t, dir, p, "package p // "+p+"\n")
	}
	head := commit(t, dir, "head")

	cs := loadOK(t, dir, base, head, DefaultLimits())
	var got []string
	for _, f := range cs.Files {
		got = append(got, f.Path)
	}
	want := []string{"Zulu.go", "alpha.go", "mid/beta.go", "zeta.go"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (byte order, not locale order)", got, want)
		}
	}
}

func TestLoadIsDeterministic(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	first := loadOK(t, dir, base, head, DefaultLimits())
	for i := 0; i < 5; i++ {
		again := loadOK(t, dir, base, head, DefaultLimits())
		if len(again.Files) != len(first.Files) {
			t.Fatalf("run %d changed the file count", i)
		}
		for j := range first.Files {
			if again.Files[j].Path != first.Files[j].Path || again.Files[j].Kind != first.Files[j].Kind {
				t.Fatalf("run %d changed entry %d", i, j)
			}
			if string(again.Files[j].HeadContent) != string(first.Files[j].HeadContent) {
				t.Fatalf("run %d changed head content of %s", i, first.Files[j].Path)
			}
		}
	}
}

func TestLoadCarriesBaseAndHeadContent(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	cs := loadOK(t, dir, base, head, DefaultLimits())

	for _, f := range cs.Files {
		switch f.Path {
		case "src/modified.go":
			if string(f.BaseContent) != "package src\n\nconst A = 1\n" {
				t.Errorf("modified base content = %q", f.BaseContent)
			}
			if string(f.HeadContent) != "package src\n\nconst A = 99\n" {
				t.Errorf("modified head content = %q", f.HeadContent)
			}
		case "src/added.go":
			if len(f.BaseContent) != 0 {
				t.Errorf("an added file has no base content, got %q", f.BaseContent)
			}
			if string(f.HeadContent) != addedFileContent {
				t.Errorf("added head content = %q", f.HeadContent)
			}
		case "src/deleted.go":
			if string(f.BaseContent) != "package src\n\nconst B = 2\n" {
				t.Errorf("deleted base content = %q", f.BaseContent)
			}
			if len(f.HeadContent) != 0 {
				t.Errorf("a deleted file has no head content, got %q", f.HeadContent)
			}
		}
	}
}

func TestLoadCountsChangedLinesAndBytes(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	cs := loadOK(t, dir, base, head, DefaultLimits())

	if cs.ChangedLines <= 0 {
		t.Errorf("ChangedLines = %d, want a positive count", cs.ChangedLines)
	}
	if cs.ContentBytes <= 0 {
		t.Errorf("ContentBytes = %d, want a positive count", cs.ContentBytes)
	}
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

func TestLoadRejectsTooManyChangedFiles(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")
	for i := 0; i < 5; i++ {
		writeFile(t, dir, "f"+string(rune('a'+i))+".txt", "x\n")
	}
	head := commit(t, dir, "head")

	limits := DefaultLimits()
	limits.MaxChangedFiles = 3

	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: limits,
	})
	if le.Code != "limit.changed_files_exceeded" {
		t.Fatalf("code = %q, want limit.changed_files_exceeded", le.Code)
	}
}

func TestLoadRejectsTooMuchChangedContent(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")
	writeFile(t, dir, "big.txt", strings.Repeat("abcdefgh", 4096)) // 32 KiB
	head := commit(t, dir, "head")

	limits := DefaultLimits()
	limits.MaxChangedContentBytes = 1024

	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: limits,
	})
	if le.Code != "limit.changed_content_exceeded" {
		t.Fatalf("code = %q, want limit.changed_content_exceeded", le.Code)
	}
}

func TestLoadRejectsAZeroLimit(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: Limits{},
	})
	// An unset limit must fail closed rather than mean "unbounded".
	if le.Code != "limit.invalid" {
		t.Fatalf("code = %q, want limit.invalid", le.Code)
	}
}

// ---------------------------------------------------------------------------
// Entries that must be recorded but never followed
// ---------------------------------------------------------------------------

func TestLoadRecordsASymlinkWithoutFollowingIt(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")

	// Stage a symlink through the index so the test does not depend on the host
	// supporting symlink creation. The blob content is the link target.
	target := gitStdin(t, dir, "/etc/passwd", "hash-object", "-w", "--stdin")
	git(t, dir, "update-index", "--add", "--cacheinfo", "120000,"+target+",link-to-passwd")
	head := commitIndex(t, dir, "add symlink")

	cs := loadOK(t, dir, base, head, DefaultLimits())

	var found bool
	for _, f := range cs.Files {
		if f.Path == "link-to-passwd" {
			found = true
			if f.Mode != ModeSymlink {
				t.Errorf("mode = %q, want %q", f.Mode, ModeSymlink)
			}
			if len(f.HeadContent) != 0 {
				t.Errorf("a symlink must carry no content, got %q", f.HeadContent)
			}
			if f.CoverageNote == "" {
				t.Error("a symlink must carry an explicit coverage note")
			}
		}
	}
	if !found {
		t.Fatal("the symlink entry must be recorded, not silently dropped")
	}
}

func TestLoadRecordsASubmoduleWithoutRecursingIntoIt(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")

	git(t, dir, "update-index", "--add", "--cacheinfo",
		"160000,"+strings.Repeat("a", 40)+",vendor/sub")
	head := commitIndex(t, dir, "add gitlink")

	cs := loadOK(t, dir, base, head, DefaultLimits())

	var found bool
	for _, f := range cs.Files {
		if f.Path == "vendor/sub" {
			found = true
			if f.Mode != ModeSubmodule {
				t.Errorf("mode = %q, want %q", f.Mode, ModeSubmodule)
			}
			if len(f.HeadContent) != 0 {
				t.Errorf("a submodule must carry no content, got %q", f.HeadContent)
			}
			if f.CoverageNote == "" {
				t.Error("a submodule must carry an explicit coverage note")
			}
		}
	}
	if !found {
		t.Fatal("the submodule entry must be recorded, not silently dropped")
	}
}

// ---------------------------------------------------------------------------
// No repository-controlled execution
// ---------------------------------------------------------------------------

func TestLoadNeverExecutesRepositoryControlledPrograms(t *testing.T) {
	dir, base, head := twoCommitRepo(t)

	marker := filepath.Join(t.TempDir(), "executed.marker")
	script := markerScript(t, marker)

	// Everything a repository can point at that Git would otherwise execute.
	git(t, dir, "config", "diff.external", script)
	git(t, dir, "config", "filter.hostile.smudge", script)
	git(t, dir, "config", "filter.hostile.clean", script)
	git(t, dir, "config", "filter.hostile.required", "true")
	git(t, dir, "config", "filter.lfs.smudge", script)
	git(t, dir, "config", "filter.lfs.required", "true")
	git(t, dir, "config", "diff.hostile.textconv", script)

	hooks := filepath.Join(dir, "hostile-hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"post-checkout", "post-index-change", "pre-auto-gc"} {
		installHook(t, hooks, hook, marker)
	}
	git(t, dir, "config", "core.hooksPath", hooks)

	cs := loadOK(t, dir, base, head, DefaultLimits())
	if len(cs.Files) == 0 {
		t.Fatal("the load must still succeed and produce changes")
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("repository-controlled program executed: marker %s exists (stat err %v)", marker, err)
	}
}

func TestLoadIgnoresRepositoryAttributesThatRequestFiltering(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")

	// Commit the attributes and the file first, then arm the filter. Staging with
	// a required clean filter already configured would fail inside the fixture
	// itself and never reach the loader, which is the thing under test.
	writeFile(t, dir, ".gitattributes", "*.go filter=hostile diff=hostile\n")
	writeFile(t, dir, "src/main.go", "package main\n")
	head := commit(t, dir, "head")

	marker := filepath.Join(t.TempDir(), "filtered.marker")
	script := markerScript(t, marker)
	git(t, dir, "config", "filter.hostile.smudge", script)
	git(t, dir, "config", "filter.hostile.clean", script)
	git(t, dir, "config", "filter.hostile.required", "true")
	git(t, dir, "config", "diff.hostile.textconv", script)

	cs := loadOK(t, dir, base, head, DefaultLimits())
	if len(cs.Files) != 2 {
		t.Fatalf("got %d files, want 2", len(cs.Files))
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a repository attribute caused filter execution: %s exists", marker)
	}
	// Content must be the raw blob, not a filtered projection.
	for _, f := range cs.Files {
		if f.Path == "src/main.go" && string(f.HeadContent) != "package main\n" {
			t.Fatalf("head content = %q, want the raw blob", f.HeadContent)
		}
	}
}

func TestLoadRejectsARepositoryPathThatIsNotAGitWorkTree(t *testing.T) {
	le := loadErr(t, Request{
		RepoPath:   t.TempDir(),
		Repository: "acme/demo",
		BaseSHA:    strings.Repeat("a", 40),
		HeadSHA:    strings.Repeat("b", 40),
		Limits:     DefaultLimits(),
	})
	if le.Code != "git.repository_unavailable" && le.Code != "git.revision_unknown" {
		t.Fatalf("code = %q, want a repository or revision failure", le.Code)
	}
}

func TestLoadErrorsNeverLeakRepositoryContentOrPaths(t *testing.T) {
	dir, base, _ := twoCommitRepo(t)
	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: strings.Repeat("0", 39) + "1", Limits: DefaultLimits(),
	})
	msg := le.Error()
	if strings.Contains(msg, dir) {
		t.Fatalf("error leaked the repository path: %q", msg)
	}
	if strings.Contains(msg, "package src") {
		t.Fatalf("error leaked repository content: %q", msg)
	}
}

func TestLoadHonoursContextCancellation(t *testing.T) {
	dir, base, head := twoCommitRepo(t)
	loader, err := NewGitLoader()
	if err != nil {
		t.Skipf("git loader unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := loader.Load(ctx, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: DefaultLimits(),
	}); err == nil {
		t.Fatal("a cancelled context must stop the load")
	}
}

// ---------------------------------------------------------------------------
// Helpers that need stdin or an OS-specific script
// ---------------------------------------------------------------------------

func gitStdin(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// commitIndex commits whatever is staged without running `git add`, so index
// entries written with update-index survive.
func commitIndex(t *testing.T, dir, message string) string {
	t.Helper()
	git(t, dir, "commit", "-q", "-m", message)
	return git(t, dir, "rev-parse", "HEAD")
}

// markerScript writes a small executable that creates marker when run, and
// returns a Git-safe command string pointing at it.
func markerScript(t *testing.T, marker string) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		p := filepath.Join(dir, "marker.bat")
		body := "@echo off\r\necho executed> \"" + marker + "\"\r\n"
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(p)
	}
	p := filepath.Join(dir, "marker.sh")
	body := "#!/bin/sh\necho executed > '" + marker + "'\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func installHook(t *testing.T, hooksDir, name, marker string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Git for Windows runs hooks through its bundled shell.
		body := "#!/bin/sh\necho executed > '" + filepath.ToSlash(marker) + "'\n"
		if err := os.WriteFile(filepath.Join(hooksDir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return
	}
	body := "#!/bin/sh\necho executed > '" + marker + "'\n"
	if err := os.WriteFile(filepath.Join(hooksDir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Resource bounds must hold before memory is allocated, not after
// ---------------------------------------------------------------------------

func TestLoadRejectsASingleObjectLargerThanTheContentLimit(t *testing.T) {
	// A hostile pull request needs only one very large file. If the limit is
	// checked while parsing output that has already been buffered in full, the
	// whole object is resident in memory before the limit is ever consulted, and
	// the process dies by OOM instead of returning a controlled incomplete.
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")
	writeFile(t, dir, "huge.bin", strings.Repeat("A", 4<<20)) // 4 MiB
	head := commit(t, dir, "head")

	limits := DefaultLimits()
	limits.MaxChangedContentBytes = 64 << 10 // 64 KiB

	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: limits,
	})
	if le.Code != "limit.changed_content_exceeded" {
		t.Fatalf("code = %q, want limit.changed_content_exceeded", le.Code)
	}
}

func TestLoadStopsReadingOnceTheContentLimitIsReached(t *testing.T) {
	// The bound must be enforced against bytes actually read, so the peak memory
	// of a load stays proportional to the limit rather than to whatever the
	// repository contains.
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")
	for i := 0; i < 8; i++ {
		writeFile(t, dir, "blob"+strconv.Itoa(i)+".bin", strings.Repeat(string(rune('a'+i)), 512<<10))
	}
	head := commit(t, dir, "head")

	limits := DefaultLimits()
	limits.MaxChangedContentBytes = 256 << 10

	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: limits,
	})
	if le.Code != "limit.changed_content_exceeded" {
		t.Fatalf("code = %q, want limit.changed_content_exceeded", le.Code)
	}
}

func TestLoadRejectsAChangedFileCountFarAboveTheLimit(t *testing.T) {
	// The file-count limit must also be reached without first materializing the
	// complete raw-diff output for an arbitrarily large commit.
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")
	for i := 0; i < 400; i++ {
		writeFile(t, dir, "gen/f"+strconv.Itoa(i)+".txt", "x\n")
	}
	head := commit(t, dir, "head")

	limits := DefaultLimits()
	limits.MaxChangedFiles = 10

	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: limits,
	})
	if le.Code != "limit.changed_files_exceeded" {
		t.Fatalf("code = %q, want limit.changed_files_exceeded", le.Code)
	}
}

func TestLoadCountsDuplicateContentOncePerFile(t *testing.T) {
	// Git content-addresses identical files to one blob. Counting that blob once
	// against the aggregate budget while handing every file a copy would let a
	// pull request present far more analysis surface than the limit allows.
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")

	identical := strings.Repeat("d", 64<<10)
	for i := 0; i < 6; i++ {
		writeFile(t, dir, "dup"+strconv.Itoa(i)+".txt", identical)
	}
	head := commit(t, dir, "head")

	limits := DefaultLimits()
	limits.MaxChangedContentBytes = 200 << 10 // below 6 x 64 KiB

	le := loadErr(t, Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: limits,
	})
	if le.Code != "limit.changed_content_exceeded" {
		t.Fatalf("code = %q, want limit.changed_content_exceeded", le.Code)
	}
}

func TestLoadNeverReadsMoreObjectBytesThanTheLimitAllows(t *testing.T) {
	// The limit must bound what the loader READS, not merely what it reports.
	// A repository chooses how much output Git produces, so buffering the whole
	// stream and checking the total afterwards means a single very large file is
	// already resident in memory before any limit is consulted -- an OOM kill
	// instead of the controlled incomplete the architecture requires.
	dir := newRepo(t)
	writeFile(t, dir, "seed.txt", "seed\n")
	base := commit(t, dir, "base")
	const huge = 32 << 20 // far above the limit used below
	writeFile(t, dir, "huge.bin", strings.Repeat("A", huge))
	head := commit(t, dir, "head")

	limits := DefaultLimits()
	limits.MaxChangedContentBytes = 64 << 10

	loader, err := NewGitLoader()
	if err != nil {
		t.Skipf("git loader unavailable: %v", err)
	}

	// A generous budget: well above what streaming needs, far below the file.
	const allocationBudget = huge / 4

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err = loader.Load(context.Background(), Request{
		RepoPath: dir, Repository: "acme/demo",
		BaseSHA: base, HeadSHA: head, Limits: limits,
	})

	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("the load must fail")
	}
	var le *LoadError
	if !errors.As(err, &le) || le.Code != "limit.changed_content_exceeded" {
		t.Fatalf("error = %v, want limit.changed_content_exceeded", err)
	}

	if got := loader.BlobBytesRead(); got > limits.MaxChangedContentBytes {
		t.Fatalf("loader retained %d object bytes with a %d byte limit; "+
			"the limit must be enforced before the object is read", got, limits.MaxChangedContentBytes)
	}

	// Retained bytes alone would not catch this: the defect was upstream of the
	// per-object check, in buffering the whole of git's stdout before parsing
	// any of it. Total allocation is what distinguishes streaming from
	// buffer-then-check.
	allocated := int64(after.TotalAlloc - before.TotalAlloc)
	if allocated > allocationBudget {
		t.Fatalf("the load allocated %d bytes for an %d byte file under a %d byte limit; "+
			"git output must be consumed as a bounded stream, not buffered whole",
			allocated, huge, limits.MaxChangedContentBytes)
	}
}
