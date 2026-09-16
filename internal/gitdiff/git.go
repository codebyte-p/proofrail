package gitdiff

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Loader binds a base/head pair to a normalized change set.
type Loader interface {
	Load(ctx context.Context, req Request) (ChangeSet, error)
}

// GitLoader is the only component that runs Git.
//
// Every invocation is hardened the same way, because the repository being
// analyzed is hostile input and Git is a program that will happily run other
// programs on that repository's instruction:
//
//   - the executable is resolved once, up front, from the operator's PATH;
//   - the environment is rebuilt from scratch rather than inherited, so a
//     GIT_* variable in the ambient environment cannot redirect the run;
//   - system and global configuration are disabled, so only repository-local
//     configuration is visible, and the dangerous parts of that are overridden;
//   - `core.hooksPath` points at an empty directory the loader owns;
//   - external diff, textconv, and LFS/clean/smudge filters are neutralized;
//   - content is read with `cat-file`, which returns the raw stored blob and
//     never applies a smudge filter;
//   - the working tree is never checked out, updated, or written to.
//
// The loader reads. It does not materialize repository content anywhere.
type GitLoader struct {
	// GitPath is the resolved Git executable.
	GitPath string
}

// NewGitLoader resolves the Git executable once so that every later invocation
// uses an explicit absolute path rather than re-searching a mutable PATH.
func NewGitLoader() (*GitLoader, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return nil, loadFailure("git.unavailable", "the git executable could not be located")
	}
	return &GitLoader{GitPath: path}, nil
}

var _ Loader = (*GitLoader)(nil)

// hardenedConfig is prepended to every invocation. These override any value the
// repository's own .git/config supplies.
var hardenedConfig = []string{
	"-c", "core.hooksPath=",
	"-c", "core.fsmonitor=",
	"-c", "core.askpass=",
	"-c", "core.editor=true",
	"-c", "core.symlinks=false",
	"-c", "diff.external=",
	"-c", "diff.noprefix=false",
	"-c", "filter.lfs.smudge=",
	"-c", "filter.lfs.clean=",
	"-c", "filter.lfs.process=",
	"-c", "filter.lfs.required=false",
	"-c", "protocol.version=2",
	"-c", "uploadpack.allowFilter=false",
	"-c", "gc.auto=0",
	"-c", "maintenance.auto=false",
	"-c", "advice.detachedHead=false",
}

// Load binds the requested revisions and returns the normalized change set.
func (g *GitLoader) Load(ctx context.Context, req Request) (ChangeSet, error) {
	if err := ctx.Err(); err != nil {
		return ChangeSet{}, loadFailure("git.cancelled", "the run was cancelled before git was invoked")
	}
	if !validRepositoryIdentity(req.Repository) {
		return ChangeSet{}, loadFailure("git.repository_invalid", "repository identity must be exactly owner/name")
	}
	if req.Limits.MaxChangedFiles <= 0 || req.Limits.MaxChangedContentBytes <= 0 {
		return ChangeSet{}, loadFailure("limit.invalid", "changed-file limits must be positive; an unset limit is not unbounded")
	}
	if !validFullSHA(req.BaseSHA) {
		return ChangeSet{}, loadFailure("git.revision_invalid", "base revision must be a full 40-character lowercase commit hash")
	}
	if !validFullSHA(req.HeadSHA) {
		return ChangeSet{}, loadFailure("git.revision_invalid", "head revision must be a full 40-character lowercase commit hash")
	}
	if req.RepoPath == "" {
		return ChangeSet{}, loadFailure("git.repository_unavailable", "no repository path was supplied")
	}

	// An empty directory the loader owns, so that `core.hooksPath` cannot
	// resolve to anything the repository controls.
	hooks, err := os.MkdirTemp("", "proofrail-nohooks-")
	if err != nil {
		return ChangeSet{}, loadFailure("git.repository_unavailable", "a temporary directory could not be created")
	}
	defer os.RemoveAll(hooks)

	run := func(stdin []byte, args ...string) ([]byte, error) {
		return g.exec(ctx, req.RepoPath, hooks, stdin, args...)
	}

	// Bind both revisions. rev-parse must return exactly the hash that was
	// requested: if it resolves to anything else, the run would be judging a
	// different revision than the one it reports.
	for _, want := range []string{req.BaseSHA, req.HeadSHA} {
		out, err := run(nil, "rev-parse", "--verify", "--quiet", "--end-of-options", want+"^{commit}")
		if err != nil {
			return ChangeSet{}, loadFailure("git.revision_unknown", "a requested revision is not a commit in this repository")
		}
		got := strings.TrimSpace(string(out))
		if got != want {
			return ChangeSet{}, loadFailure("git.revision_mismatch", "a requested revision did not resolve to itself")
		}
	}

	files, err := g.rawDiff(run, req)
	if err != nil {
		return ChangeSet{}, err
	}
	changedLines, err := g.changedLines(run, req)
	if err != nil {
		return ChangeSet{}, err
	}

	// Sorting by byte order, not locale order, keeps the ledger identical on
	// every platform.
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	var contentBytes int64
	for i := range files {
		contentBytes += int64(len(files[i].BaseContent)) + int64(len(files[i].HeadContent))
	}

	return ChangeSet{
		Repository:   req.Repository,
		BaseSHA:      req.BaseSHA,
		HeadSHA:      req.HeadSHA,
		Files:        files,
		ChangedLines: changedLines,
		ContentBytes: contentBytes,
	}, nil
}

// exec runs one hardened Git invocation.
func (g *GitLoader) exec(ctx context.Context, repoPath, hooksDir string, stdin []byte, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, loadFailure("git.cancelled", "the run was cancelled")
	}

	full := make([]string, 0, len(hardenedConfig)+len(args)+2)
	full = append(full, "-c", "core.hooksPath="+hooksDir)
	full = append(full, hardenedConfig[2:]...) // skip the placeholder hooksPath
	full = append(full, args...)

	cmd := exec.CommandContext(ctx, g.GitPath, full...)
	cmd.Dir = repoPath

	// The environment is built from nothing rather than inherited. An ambient
	// GIT_DIR, GIT_ALTERNATE_OBJECT_DIRECTORIES, GIT_EXTERNAL_DIFF, or
	// GIT_SSH_COMMAND would otherwise redirect or execute.
	cmd.Env = []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_ASKPASS=",
		"GIT_EXTERNAL_DIFF=",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_NOGLOB_PATHSPECS=1",
		"GIT_FLUSH=1",
		"LC_ALL=C",
		"TZ=UTC",
	}
	if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
		// Windows needs SystemRoot for basic process and socket startup.
		cmd.Env = append(cmd.Env, "SystemRoot="+systemRoot)
	}

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Git's own stderr can echo repository paths and content, so it is
		// deliberately discarded rather than wrapped into the error.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, loadFailure("git.command_failed", "a git command exited with a failure status")
		}
		if ctx.Err() != nil {
			return nil, loadFailure("git.cancelled", "the run was cancelled")
		}
		return nil, loadFailure("git.command_failed", "a git command could not be run")
	}
	return stdout.Bytes(), nil
}

// rawDiff reads `git diff --raw`, which reports the mode and blob hash of both
// sides without ever producing file content. Modes let the loader recognize a
// symlink or a submodule before deciding whether to read anything.
func (g *GitLoader) rawDiff(run func([]byte, ...string) ([]byte, error), req Request) ([]FileChange, error) {
	out, err := run(nil,
		// --no-abbrev is required: --raw abbreviates object hashes by default,
		// and an abbreviated hash cannot be fed back to cat-file reliably.
		"diff", "--raw", "-z", "--no-abbrev", "--find-renames", "--no-color",
		"--no-ext-diff", "--no-textconv", "--ignore-submodules=none",
		"--end-of-options", req.BaseSHA, req.HeadSHA,
	)
	if err != nil {
		return nil, err
	}

	fields := splitNUL(out)
	var (
		files       []FileChange
		blobsWanted []string
	)

	for i := 0; i < len(fields); {
		header := fields[i]
		if header == "" {
			i++
			continue
		}
		if !strings.HasPrefix(header, ":") {
			return nil, loadFailure("git.output_invalid", "git raw diff output was not in the expected form")
		}
		// ":<srcmode> <dstmode> <srcsha> <dstsha> <status>"
		parts := strings.Fields(header[1:])
		if len(parts) != 5 {
			return nil, loadFailure("git.output_invalid", "git raw diff header had an unexpected field count")
		}
		srcMode, dstMode, srcSHA, dstSHA, status := parts[0], parts[1], parts[2], parts[3], parts[4]

		statusLetter := status[0]
		wantPaths := 1
		if statusLetter == 'R' || statusLetter == 'C' {
			wantPaths = 2
		}
		if i+wantPaths >= len(fields) {
			return nil, loadFailure("git.output_invalid", "git raw diff output ended mid-record")
		}

		var oldRaw, newRaw string
		if wantPaths == 2 {
			oldRaw, newRaw = fields[i+1], fields[i+2]
		} else {
			newRaw = fields[i+1]
		}
		i += 1 + wantPaths

		fc, err := buildChange(statusLetter, srcMode, dstMode, srcSHA, dstSHA, oldRaw, newRaw)
		if err != nil {
			return nil, err
		}

		if len(files) >= req.Limits.MaxChangedFiles {
			return nil, loadFailure("limit.changed_files_exceeded", "the change set exceeds the maximum number of changed files")
		}
		files = append(files, fc)

		if fc.Mode == ModeFile || fc.Mode == ModeExecutable {
			if isReadableBlob(srcSHA) {
				blobsWanted = append(blobsWanted, srcSHA)
			}
			if isReadableBlob(dstSHA) {
				blobsWanted = append(blobsWanted, dstSHA)
			}
		}
	}

	if len(blobsWanted) > 0 {
		blobs, err := g.readBlobs(run, blobsWanted, req.Limits.MaxChangedContentBytes)
		if err != nil {
			return nil, err
		}
		for idx := range files {
			f := &files[idx]
			if f.Mode != ModeFile && f.Mode != ModeExecutable {
				continue
			}
			if b, ok := blobs[f.baseBlob]; ok {
				f.BaseContent = b
			}
			if b, ok := blobs[f.headBlob]; ok {
				f.HeadContent = b
			}
		}
	}

	return files, nil
}

// buildChange normalizes one raw-diff record.
func buildChange(status byte, srcMode, dstMode, srcSHA, dstSHA, oldRaw, newRaw string) (FileChange, error) {
	var fc FileChange

	newPath, err := NormalizeRepoPath(unquoteGitPath(newRaw))
	if err != nil {
		return fc, loadFailure("path.invalid", "a changed path could not be normalized")
	}
	fc.Path = newPath

	switch status {
	case 'A':
		fc.Kind = Added
	case 'M', 'T':
		fc.Kind = Modified
	case 'D':
		fc.Kind = Deleted
	case 'R', 'C':
		fc.Kind = Renamed
		prev, err := NormalizeRepoPath(unquoteGitPath(oldRaw))
		if err != nil {
			return fc, loadFailure("path.invalid", "a previous path could not be normalized")
		}
		fc.PreviousPath = prev
	default:
		return fc, loadFailure("git.output_invalid", "git reported an unsupported change status")
	}

	// The head mode decides how the entry may be read; a deleted entry is
	// described by its base mode.
	mode := dstMode
	if fc.Kind == Deleted || mode == "000000" {
		mode = srcMode
	}
	fc.Mode = classifyMode(mode)

	switch fc.Mode {
	case ModeSymlink:
		// The blob holds a path, not content. Following it would read a file
		// outside the bound revision, so it is recorded and left unread.
		fc.CoverageNote = "symlink recorded without following its target"
	case ModeSubmodule:
		// A gitlink names a commit in another repository that is not part of
		// this revision and must not be fetched or entered.
		fc.CoverageNote = "submodule recorded without entering the referenced repository"
	default:
		fc.baseBlob = srcSHA
		fc.headBlob = dstSHA
	}

	return fc, nil
}

func classifyMode(mode string) EntryMode {
	switch mode {
	case "120000":
		return ModeSymlink
	case "160000":
		return ModeSubmodule
	case "100755":
		return ModeExecutable
	default:
		return ModeFile
	}
}

// isReadableBlob reports whether a raw-diff hash names an object that exists.
// Git writes an all-zero hash for the absent side of an add or a delete.
func isReadableBlob(sha string) bool {
	if len(sha) < 40 {
		return false
	}
	return strings.Trim(sha, "0") != ""
}

// readBlobs streams the requested blobs through a single `cat-file --batch`.
//
// cat-file returns the object exactly as stored. Smudge and clean filters apply
// only to worktree materialization, which this package never performs, so a
// repository cannot interpose a program on the bytes ProofRail analyzes.
func (g *GitLoader) readBlobs(run func([]byte, ...string) ([]byte, error), want []string, maxBytes int64) (map[string][]byte, error) {
	unique := make([]string, 0, len(want))
	seen := make(map[string]bool, len(want))
	for _, sha := range want {
		if !seen[sha] {
			seen[sha] = true
			unique = append(unique, sha)
		}
	}
	sort.Strings(unique)

	var stdin bytes.Buffer
	for _, sha := range unique {
		stdin.WriteString(sha)
		stdin.WriteByte('\n')
	}

	out, err := run(stdin.Bytes(), "cat-file", "--batch")
	if err != nil {
		return nil, err
	}

	blobs := make(map[string][]byte, len(unique))
	reader := bufio.NewReader(bytes.NewReader(out))
	var total int64

	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		header = strings.TrimSuffix(header, "\n")
		if header == "" {
			continue
		}
		parts := strings.Fields(header)
		if len(parts) == 2 && parts[1] == "missing" {
			continue
		}
		if len(parts) != 3 {
			return nil, loadFailure("git.output_invalid", "git cat-file output was not in the expected form")
		}
		sha, kind, sizeText := parts[0], parts[1], parts[2]
		size, convErr := strconv.ParseInt(sizeText, 10, 64)
		if convErr != nil || size < 0 {
			return nil, loadFailure("git.output_invalid", "git reported an unparsable object size")
		}

		total += size
		if total > maxBytes {
			return nil, loadFailure("limit.changed_content_exceeded", "the change set exceeds the maximum aggregate changed content")
		}

		body := make([]byte, size)
		if _, readErr := readFull(reader, body); readErr != nil {
			return nil, loadFailure("git.output_invalid", "git cat-file output ended mid-object")
		}
		// Consume the newline Git appends after each object body.
		_, _ = reader.ReadByte()

		if kind == "blob" {
			blobs[sha] = body
		}
	}

	return blobs, nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// changedLines totals added and deleted lines via --numstat. Binary files report
// "-" and contribute no line count.
func (g *GitLoader) changedLines(run func([]byte, ...string) ([]byte, error), req Request) (int, error) {
	out, err := run(nil,
		"diff", "--numstat", "-z", "--find-renames", "--no-color",
		"--no-ext-diff", "--no-textconv",
		"--end-of-options", req.BaseSHA, req.HeadSHA,
	)
	if err != nil {
		return 0, err
	}

	total := 0
	for _, field := range splitNUL(out) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		parts := strings.Fields(field)
		if len(parts) < 2 {
			continue
		}
		for _, count := range parts[:2] {
			if count == "-" {
				continue
			}
			n, convErr := strconv.Atoi(count)
			if convErr != nil {
				continue
			}
			total += n
		}
	}
	return total, nil
}

// splitNUL splits Git's -z output, dropping the trailing empty field.
func splitNUL(b []byte) []string {
	s := string(b)
	s = strings.TrimSuffix(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// unquoteGitPath removes the C-style quoting Git applies to unusual path names.
// With -z output Git does not quote, but a defensive strip keeps a quoted value
// from reaching normalization with stray quotes attached.
func unquoteGitPath(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		if unquoted, err := strconv.Unquote(p); err == nil {
			return unquoted
		}
	}
	return p
}
