package gitdiff

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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
// Git's output is consumed as a stream and every read is bounded by the
// caller's limits. Nothing is buffered whole: the repository decides how much
// output Git produces, so buffering first and checking limits afterwards would
// let a single large file exhaust memory before any limit was consulted.
//
// The loader reads. It does not materialize repository content anywhere.
type GitLoader struct {
	// GitPath is the resolved Git executable.
	GitPath string

	// blobBytesRead counts raw object bytes retained from cat-file. It exists so
	// tests can assert that a load stops reading once a limit is reached rather
	// than merely reporting the right error afterwards.
	blobBytesRead atomic.Int64
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

// BlobBytesRead reports how many object bytes this loader has retained.
func (g *GitLoader) BlobBytesRead() int64 { return g.blobBytesRead.Load() }

// maxFieldBytes bounds one NUL-delimited field from Git's -z output. Paths are
// already capped at MaxRepoPathBytes; this stops a malformed or hostile stream
// from growing a single field without bound before that check can run.
const maxFieldBytes = 3 * MaxRepoPathBytes

// hardenedConfig is prepended to every invocation. These override any value the
// repository's own .git/config supplies.
var hardenedConfig = []string{
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

	// Bind both revisions. rev-parse must return exactly the hash that was
	// requested: if it resolves to anything else, the run would be judging a
	// different revision than the one it reports.
	for _, want := range []string{req.BaseSHA, req.HeadSHA} {
		out, err := g.output(ctx, req.RepoPath, hooks, 256,
			"rev-parse", "--verify", "--quiet", "--end-of-options", want+"^{commit}")
		if err != nil {
			return ChangeSet{}, loadFailure("git.revision_unknown", "a requested revision is not a commit in this repository")
		}
		if strings.TrimSpace(string(out)) != want {
			return ChangeSet{}, loadFailure("git.revision_mismatch", "a requested revision did not resolve to itself")
		}
	}

	files, err := g.rawDiff(ctx, req, hooks)
	if err != nil {
		return ChangeSet{}, err
	}
	if err := g.readBlobs(ctx, req, hooks, files); err != nil {
		return ChangeSet{}, err
	}
	changedLines, err := g.changedLines(ctx, req, hooks)
	if err != nil {
		return ChangeSet{}, err
	}

	// Sorting by byte order, not locale order, keeps the ledger identical on
	// every platform.
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	// Charge the budget per file rather than per unique object.
	//
	// Git content-addresses identical files to a single blob, so a pull request
	// that adds many copies of one large file costs almost nothing to fetch. The
	// limit exists to bound the analysis surface handed to analyzers, and that
	// surface is per file. Counting unique objects only would let thousands of
	// copies of a 49 MiB blob pass a 50 MiB budget.
	var contentBytes int64
	for i := range files {
		contentBytes += int64(len(files[i].BaseContent)) + int64(len(files[i].HeadContent))
		if contentBytes > req.Limits.MaxChangedContentBytes {
			return ChangeSet{}, loadFailure("limit.changed_content_exceeded",
				"the change set exceeds the maximum aggregate changed content")
		}
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

// ---------------------------------------------------------------------------
// Hardened invocation
// ---------------------------------------------------------------------------

// build assembles one hardened Git command.
func (g *GitLoader) build(ctx context.Context, repoPath, hooksDir string, args []string) *exec.Cmd {
	full := make([]string, 0, len(hardenedConfig)+len(args)+2)
	full = append(full, "-c", "core.hooksPath="+hooksDir)
	full = append(full, hardenedConfig...)
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

	// Git's stderr echoes repository paths and file content, so it is discarded
	// rather than captured; a diagnostic must never carry it to a report.
	cmd.Stderr = io.Discard
	return cmd
}

// output runs Git and returns at most maxBytes of stdout. It is for the short,
// fixed-size replies such as rev-parse, never for repository content.
func (g *GitLoader) output(ctx context.Context, repoPath, hooksDir string, maxBytes int64, args ...string) ([]byte, error) {
	var buf bytes.Buffer
	err := g.stream(ctx, repoPath, hooksDir, nil, args, func(r *bufio.Reader) error {
		if _, err := io.Copy(&buf, io.LimitReader(r, maxBytes)); err != nil {
			return loadFailure("git.output_invalid", "a git reply could not be read")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// stream runs Git and hands stdout to consume as a bounded stream.
//
// consume may stop early -- that is the point. When it does, the child process
// is killed and its pipe drained, so a repository cannot make ProofRail hold
// output it has already decided to reject.
func (g *GitLoader) stream(ctx context.Context, repoPath, hooksDir string, stdin []byte, args []string, consume func(*bufio.Reader) error) error {
	if err := ctx.Err(); err != nil {
		return loadFailure("git.cancelled", "the run was cancelled")
	}

	cmd := g.build(ctx, repoPath, hooksDir, args)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return loadFailure("git.command_failed", "a git command could not be started")
	}
	if err := cmd.Start(); err != nil {
		return loadFailure("git.command_failed", "a git command could not be started")
	}

	consumeErr := consume(bufio.NewReaderSize(pipe, 64<<10))

	// Stop Git before draining when the consumer bailed out, so an enormous
	// remaining stream is discarded rather than read to completion.
	if consumeErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	// Drain so Git is never blocked writing into a full pipe while we wait.
	_, _ = io.Copy(io.Discard, pipe)
	waitErr := cmd.Wait()

	if consumeErr != nil {
		// A deliberate early stop makes Wait report a kill; the consumer's
		// reason is the one that matters.
		return consumeErr
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return loadFailure("git.cancelled", "the run was cancelled")
		}
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return loadFailure("git.command_failed", "a git command exited with a failure status")
		}
		return loadFailure("git.command_failed", "a git command could not be run")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Raw diff
// ---------------------------------------------------------------------------

// rawDiff streams `git diff --raw`, which reports the mode and blob hash of both
// sides without ever producing file content. Modes let the loader recognize a
// symlink or a submodule before deciding whether to read anything.
//
// Records are parsed as they arrive and the file-count limit is enforced per
// record, so the peak cost is proportional to the limit rather than to the size
// of the commit the repository chose to present.
func (g *GitLoader) rawDiff(ctx context.Context, req Request, hooksDir string) ([]FileChange, error) {
	var files []FileChange

	err := g.stream(ctx, req.RepoPath, hooksDir, nil, []string{
		// --no-abbrev is required: --raw abbreviates object hashes by default,
		// and an abbreviated hash cannot be fed back to cat-file reliably.
		"diff", "--raw", "-z", "--no-abbrev", "--find-renames", "--no-color",
		"--no-ext-diff", "--no-textconv", "--ignore-submodules=none",
		"--end-of-options", req.BaseSHA, req.HeadSHA,
	}, func(r *bufio.Reader) error {
		for {
			header, err := readNULField(r)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if header == "" {
				continue
			}
			if !strings.HasPrefix(header, ":") {
				return loadFailure("git.output_invalid", "git raw diff output was not in the expected form")
			}

			// ":<srcmode> <dstmode> <srcsha> <dstsha> <status>"
			parts := strings.Fields(header[1:])
			if len(parts) != 5 {
				return loadFailure("git.output_invalid", "git raw diff header had an unexpected field count")
			}
			srcMode, dstMode, srcSHA, dstSHA, status := parts[0], parts[1], parts[2], parts[3], parts[4]

			newRaw, err := readNULField(r)
			if err != nil {
				return loadFailure("git.output_invalid", "git raw diff output ended mid-record")
			}
			var oldRaw string
			if status[0] == 'R' || status[0] == 'C' {
				oldRaw = newRaw
				if newRaw, err = readNULField(r); err != nil {
					return loadFailure("git.output_invalid", "git raw diff output ended mid-record")
				}
			}

			// Enforced before append, so the slice never grows past the limit
			// however many records the repository presents.
			if len(files) >= req.Limits.MaxChangedFiles {
				return loadFailure("limit.changed_files_exceeded",
					"the change set exceeds the maximum number of changed files")
			}

			fc, err := buildChange(status[0], srcMode, dstMode, srcSHA, dstSHA, oldRaw, newRaw)
			if err != nil {
				return err
			}
			files = append(files, fc)
		}
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// readNULField reads one NUL-delimited field, refusing an unbounded one.
func readNULField(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		chunk, err := r.ReadString(0x00)
		if len(chunk) > 0 {
			if b.Len()+len(chunk) > maxFieldBytes {
				return "", loadFailure("git.output_invalid", "a git output field exceeded the maximum length")
			}
			b.WriteString(chunk)
		}
		if err == nil {
			return strings.TrimSuffix(b.String(), "\x00"), nil
		}
		if err == io.EOF {
			if b.Len() == 0 {
				return "", io.EOF
			}
			// A trailing record with no terminator is still a complete field.
			return b.String(), nil
		}
		return "", loadFailure("git.output_invalid", "git output could not be read")
	}
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
		if isReadableBlob(srcSHA) {
			fc.baseBlob = srcSHA
		}
		if isReadableBlob(dstSHA) {
			fc.headBlob = dstSHA
		}
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
	if len(sha) != 40 {
		return false
	}
	return strings.Trim(sha, "0") != ""
}

// ---------------------------------------------------------------------------
// Object content
// ---------------------------------------------------------------------------

// readBlobs streams the requested objects through a single `cat-file --batch`
// and fills in each file's base and head content.
//
// cat-file returns the object exactly as stored. Smudge and clean filters apply
// only to worktree materialization, which this package never performs, so a
// repository cannot interpose a program on the bytes ProofRail analyzes.
//
// The size limit is checked against the running total BEFORE the object body is
// allocated. That ordering is the whole point: a single multi-gigabyte file in a
// hostile pull request must produce a clean incomplete result, not an
// out-of-memory kill, and an OOM is neither incomplete nor controlled.
func (g *GitLoader) readBlobs(ctx context.Context, req Request, hooksDir string, files []FileChange) error {
	wanted := make(map[string]bool)
	for i := range files {
		if files[i].baseBlob != "" {
			wanted[files[i].baseBlob] = true
		}
		if files[i].headBlob != "" {
			wanted[files[i].headBlob] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	unique := make([]string, 0, len(wanted))
	for sha := range wanted {
		unique = append(unique, sha)
	}
	sort.Strings(unique)

	var stdin bytes.Buffer
	for _, sha := range unique {
		stdin.WriteString(sha)
		stdin.WriteByte('\n')
	}

	maxBytes := req.Limits.MaxChangedContentBytes
	blobs := make(map[string][]byte, len(unique))

	err := g.stream(ctx, req.RepoPath, hooksDir, stdin.Bytes(), []string{"cat-file", "--batch"}, func(r *bufio.Reader) error {
		var total int64
		for {
			header, err := readHeaderLine(r)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if header == "" {
				continue
			}

			parts := strings.Fields(header)
			if len(parts) == 2 && parts[1] == "missing" {
				continue
			}
			if len(parts) != 3 {
				return loadFailure("git.output_invalid", "git cat-file output was not in the expected form")
			}
			sha, kind, sizeText := parts[0], parts[1], parts[2]

			size, convErr := strconv.ParseInt(sizeText, 10, 64)
			if convErr != nil || size < 0 {
				return loadFailure("git.output_invalid", "git reported an unparsable object size")
			}

			// Refuse before allocating. Reading this object would push the run
			// past its budget, so the run ends here rather than after the
			// allocation that would have exhausted memory. The subtraction form
			// avoids overflowing on an absurd reported size.
			if size > maxBytes || total > maxBytes-size {
				return loadFailure("limit.changed_content_exceeded",
					"the change set exceeds the maximum aggregate changed content")
			}
			total += size

			body := make([]byte, size)
			if _, readErr := io.ReadFull(r, body); readErr != nil {
				return loadFailure("git.output_invalid", "git cat-file output ended mid-object")
			}
			// Consume the newline Git appends after each object body.
			_, _ = r.ReadByte()

			g.blobBytesRead.Add(size)
			if kind == "blob" {
				blobs[sha] = body
			}
		}
	})
	if err != nil {
		return err
	}

	for i := range files {
		if b, ok := blobs[files[i].baseBlob]; ok {
			files[i].BaseContent = b
		}
		if b, ok := blobs[files[i].headBlob]; ok {
			files[i].HeadContent = b
		}
	}
	return nil
}

// readHeaderLine reads one bounded newline-terminated header.
func readHeaderLine(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		chunk, err := r.ReadString('\n')
		if len(chunk) > 0 {
			if b.Len()+len(chunk) > maxFieldBytes {
				return "", loadFailure("git.output_invalid", "a git output header exceeded the maximum length")
			}
			b.WriteString(chunk)
		}
		if err == nil {
			return strings.TrimSuffix(b.String(), "\n"), nil
		}
		if err == io.EOF {
			if b.Len() == 0 {
				return "", io.EOF
			}
			return b.String(), nil
		}
		return "", loadFailure("git.output_invalid", "git output could not be read")
	}
}

// ---------------------------------------------------------------------------
// Line counts
// ---------------------------------------------------------------------------

// changedLines totals added and deleted lines via --numstat. Binary files report
// "-" and contribute no line count. Records are consumed as a stream and capped
// at the changed-file limit for the same reason rawDiff is.
func (g *GitLoader) changedLines(ctx context.Context, req Request, hooksDir string) (int, error) {
	total := 0

	err := g.stream(ctx, req.RepoPath, hooksDir, nil, []string{
		"diff", "--numstat", "-z", "--find-renames", "--no-color",
		"--no-ext-diff", "--no-textconv",
		"--end-of-options", req.BaseSHA, req.HeadSHA,
	}, func(r *bufio.Reader) error {
		records := 0
		for {
			field, err := readNULField(r)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}

			parts := strings.Fields(field)
			if len(parts) < 2 {
				// A rename emits its paths as separate fields; they carry no counts.
				continue
			}
			records++
			if records > req.Limits.MaxChangedFiles {
				return loadFailure("limit.changed_files_exceeded",
					"the change set exceeds the maximum number of changed files")
			}
			for _, count := range parts[:2] {
				if count == "-" {
					continue
				}
				n, convErr := strconv.Atoi(count)
				if convErr != nil || n < 0 {
					continue
				}
				total += n
			}
		}
	})
	if err != nil {
		return 0, err
	}
	return total, nil
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
