package python_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/codebyte-p/proofrail/internal/parser/python"
	"github.com/codebyte-p/proofrail/internal/run"
)

const minimalProject = `[project]
name = "example"
version = "1.0.0"
dependencies = ["requests>=2.31.0"]
`

func codes(diags []run.Diagnostic) []string {
	out := make([]string, 0, len(diags))
	for _, d := range diags {
		out = append(out, d.Code)
	}
	return out
}

func hasCode(diags []run.Diagnostic, want string) bool {
	for _, d := range diags {
		if d.Code == want {
			return true
		}
	}
	return false
}

// TestParseProjectRejects covers every input class the narrow TOML reader
// refuses.
//
// The reader supports only the subset `pyproject.toml` and `uv.lock` actually
// use. Anything outside that subset is rejected rather than guessed at, because
// a construct this reader misunderstands would silently misstate the dependency
// set.
func TestParseProjectRejects(t *testing.T) {
	cases := []struct {
		name    string
		content string
		code    string
	}{
		{
			name:    "duplicate key in a table",
			content: "[project]\nname = \"a\"\nname = \"b\"\n",
			code:    "python.duplicate_key",
		},
		{
			name:    "duplicate table header",
			content: "[project]\nname = \"a\"\n\n[project]\nversion = \"1\"\n",
			code:    "python.duplicate_table",
		},
		{
			name:    "invalid utf-8",
			content: "[project]\nname = \"\xff\xfe\"\n",
			code:    "python.invalid_utf8",
		},
		{
			name:    "unterminated string",
			content: "[project]\nname = \"unterminated\n",
			code:    "python.malformed",
		},
		{
			// Root-level keys are legal TOML and `uv.lock` needs them for its
			// `version` field, so the rejection here is the unterminated array,
			// not the placement of the key.
			name:    "unterminated array",
			content: "[project]\ndependencies = [\"requests\",\n",
			code:    "python.malformed",
		},
		{
			name:    "unsupported construct",
			content: "[project]\nname = \"\"\"multi\nline\"\"\"\n",
			code:    "python.unsupported_construct",
		},
		{
			name:    "malformed table header",
			content: "[project\nname = \"a\"\n",
			code:    "python.malformed",
		},
		{
			name:    "value without a key",
			content: "[project]\n= \"a\"\n",
			code:    "python.malformed",
		},
		{
			name:    "empty document",
			content: "",
			code:    "python.empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project, diags := python.ParseProject("pyproject.toml", []byte(tc.content), 1<<20)
			if !hasCode(diags, tc.code) {
				t.Fatalf("expected diagnostic %q, got %v", tc.code, codes(diags))
			}
			if len(project.Requirements) != 0 {
				t.Errorf("a rejected project must not yield requirements, got %d", len(project.Requirements))
			}
			if tc.content != "" {
				for _, d := range diags {
					if strings.Contains(d.Message, tc.content) {
						t.Errorf("diagnostic echoed the rejected input: %q", d.Message)
					}
				}
			}
		})
	}
}

// TestParseProjectRejectsOversizedInput proves the 1 MiB bound is enforced
// before any scanning happens.
func TestParseProjectRejectsOversizedInput(t *testing.T) {
	const maxBytes = 1 << 20
	oversized := minimalProject + "# " + strings.Repeat("a", maxBytes)

	project, diags := python.ParseProject("pyproject.toml", []byte(oversized), maxBytes)
	if !hasCode(diags, "python.too_large") {
		t.Fatalf("expected python.too_large, got %v", codes(diags))
	}
	if len(project.Requirements) != 0 {
		t.Error("an oversized project must not be parsed")
	}
}

// TestParseProjectReadsRequirements proves each declared dependency is captured
// with its source line and its declaring section.
func TestParseProjectReadsRequirements(t *testing.T) {
	const content = `[project]
name = "example"
version = "2.1.0"
dependencies = [
    "requests>=2.31.0",
    "internal-tool @ git+https://example.invalid/team/tool.git@main",
]

[project.optional-dependencies]
dev = ["pytest==8.0.0"]

[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[tool.uv.sources]
internal-tool = { git = "https://example.invalid/team/tool.git", branch = "main" }
`

	project, diags := python.ParseProject("pyproject.toml", []byte(content), 1<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	if project.Path != "pyproject.toml" {
		t.Errorf("path = %q, want pyproject.toml", project.Path)
	}
	if project.Name.Value != "example" {
		t.Errorf("name = %q, want example", project.Name.Value)
	}

	want := map[string]struct {
		kind string
		line int
	}{
		"requests>=2.31.0": {"dependencies", 5},
		"internal-tool @ git+https://example.invalid/team/tool.git@main": {"dependencies", 6},
		"pytest==8.0.0": {"optional-dependencies", 10},
	}
	if len(project.Requirements) != len(want) {
		t.Fatalf("got %d requirements, want %d: %+v", len(project.Requirements), len(want), project.Requirements)
	}
	for _, req := range project.Requirements {
		expected, ok := want[req.Spec.Value]
		if !ok {
			t.Errorf("unexpected requirement %q", req.Spec.Value)
			continue
		}
		if req.Kind != expected.kind {
			t.Errorf("%s kind = %q, want %q", req.Spec.Value, req.Kind, expected.kind)
		}
		if req.Spec.Pos.Line != expected.line {
			t.Errorf("%s line = %d, want %d", req.Spec.Value, req.Spec.Pos.Line, expected.line)
		}
	}

	if project.BuildBackend.Value != "setuptools.build_meta" {
		t.Errorf("build-backend = %q", project.BuildBackend.Value)
	}
	if len(project.BuildRequires) != 1 || project.BuildRequires[0].Value != "setuptools>=69" {
		t.Errorf("build requires = %+v", project.BuildRequires)
	}

	source, ok := project.Source("internal-tool")
	if !ok {
		t.Fatalf("tool.uv.sources entry missing: %+v", project.Sources)
	}
	if source.Git.Value != "https://example.invalid/team/tool.git" {
		t.Errorf("git = %q", source.Git.Value)
	}
	if source.Branch.Value != "main" {
		t.Errorf("branch = %q", source.Branch.Value)
	}
}

// TestParseLockReadsResolvedIdentity proves uv.lock array-of-tables entries
// yield the resolved identity the provenance rules compare.
func TestParseLockReadsResolvedIdentity(t *testing.T) {
	const content = `version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package.wheels]]
hash = "sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"

[[package]]
name = "internal-tool"
version = "0.1.0"
source = { git = "https://example.invalid/team/tool.git?rev=main#abc123" }
`

	lock, diags := python.ParseLock("uv.lock", []byte(content), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	if len(lock.Packages) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(lock.Packages), lock.Packages)
	}

	requests, ok := lock.Package("requests")
	if !ok {
		t.Fatal("requests missing from lock")
	}
	if requests.Version.Value != "2.31.0" {
		t.Errorf("version = %q, want 2.31.0", requests.Version.Value)
	}
	if requests.Registry.Value != "https://pypi.org/simple" {
		t.Errorf("registry = %q", requests.Registry.Value)
	}
	if !strings.HasPrefix(requests.Hash.Value, "sha256:") {
		t.Errorf("hash = %q, want a sha256 digest from the wheel entry", requests.Hash.Value)
	}
	if requests.Name.Pos.Line < 1 {
		t.Error("locked package has no source line")
	}

	tool, ok := lock.Package("internal-tool")
	if !ok {
		t.Fatal("internal-tool missing from lock")
	}
	if !strings.HasPrefix(tool.Git.Value, "https://example.invalid/") {
		t.Errorf("git = %q", tool.Git.Value)
	}
	if tool.Registry.Present() {
		t.Errorf("a git-sourced package must not report a registry: %q", tool.Registry.Value)
	}
}

// TestParseLockSkipsPackageWithEmptyName proves a package whose name is written
// but empty is not modeled.
//
// Scalar.Present reports that a value was written, which an empty string
// satisfies. The analyzer keys packages by name, so an empty name would collide
// with every other empty name and make unrelated entries compare as the same
// package. Found by FuzzParse.
func TestParseLockSkipsPackageWithEmptyName(t *testing.T) {
	const content = "version = 1\n\n[[package]]\nname = \"\"\nversion = \"1.0.0\"\n"

	lock, diags := python.ParseLock("uv.lock", []byte(content), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	for _, pkg := range lock.Packages {
		if pkg.Name.Value == "" {
			t.Fatalf("a package with an empty name was modeled: %+v", pkg)
		}
	}
}

// TestParseRejectsEmptyKey proves a quoted empty key is refused. Neither file
// this package reads has a use for one, and it is the same collision hazard as
// an empty package name.
func TestParseRejectsEmptyKey(t *testing.T) {
	const content = "[tool.uv.sources]\n\"\" = { git = \"https://example.invalid/t.git\" }\n"

	project, diags := python.ParseProject("pyproject.toml", []byte(content), 1<<20)
	if !hasCode(diags, "python.malformed") {
		t.Fatalf("expected python.malformed, got %v", codes(diags))
	}
	if len(project.Sources) != 0 {
		t.Errorf("a rejected document must not yield sources")
	}
}

// TestParseRejectsUnboundedDottedKeyPath proves a dotted key path is bounded.
//
// The value depth bound did not cover key paths, so `[a.a.a...]` with thousands
// of segments allocated a nested table per segment with nothing stopping it.
// Review medium M2.
func TestParseRejectsUnboundedDottedKeyPath(t *testing.T) {
	segments := make([]string, 4000)
	for i := range segments {
		segments[i] = "a"
	}
	content := "[" + strings.Join(segments, ".") + "]\nkey = \"value\"\n"

	project, diags := python.ParseProject("pyproject.toml", []byte(content), 1<<20)
	if !hasCode(diags, "python.depth_exceeded") {
		t.Fatalf("expected python.depth_exceeded, got %v", codes(diags))
	}
	if len(project.Requirements) != 0 {
		t.Error("a rejected document must not yield requirements")
	}
}

// TestParseLockCoversEveryArtifactHash proves the resolved identity spans every
// declared artifact, not just the first.
//
// uv.lock lists one wheel per platform. Taking only the first meant swapping any
// later wheel left the identity unchanged, so PFR-DEP-004 could not see the
// substitution. Review medium M7.
func TestParseLockCoversEveryArtifactHash(t *testing.T) {
	build := func(secondHash string) string {
		return "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n" +
			"source = { registry = \"https://pypi.org/simple\" }\n\n" +
			"[[package.wheels]]\nhash = \"sha256:aaaa\"\n\n" +
			"[[package.wheels]]\nhash = \"" + secondHash + "\"\n"
	}

	first, diags := python.ParseLock("uv.lock", []byte(build("sha256:bbbb")), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	second, diags := python.ParseLock("uv.lock", []byte(build("sha256:cccc")), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	a, ok := first.Package("requests")
	if !ok {
		t.Fatal("requests missing from the first lock")
	}
	b, _ := second.Package("requests")

	if a.Hash.Value == b.Hash.Value {
		t.Fatalf("substituting the second wheel left the identity unchanged: %q", a.Hash.Value)
	}
	if !strings.HasPrefix(a.Hash.Value, "sha256:") {
		t.Errorf("identity is not a digest: %q", a.Hash.Value)
	}
}

// TestParseLockIdentityNeverDropsATail proves no artifact is omitted however
// many a package declares.
//
// Joining the digests and truncating at a byte budget left everything past the
// cut out of the identity, so a substitution in a late wheel was invisible in
// exactly the way taking only the first one had been. Independent re-review
// finding.
func TestParseLockIdentityNeverDropsATail(t *testing.T) {
	const wheelCount = 400

	build := func(lastHash string) string {
		var b strings.Builder
		b.WriteString("version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n")
		b.WriteString("source = { registry = \"https://pypi.org/simple\" }\n")
		for i := 0; i < wheelCount-1; i++ {
			b.WriteString("\n[[package.wheels]]\nhash = \"sha256:" + strconv.Itoa(i) + "\"\n")
		}
		b.WriteString("\n[[package.wheels]]\nhash = \"" + lastHash + "\"\n")
		return b.String()
	}

	first, diags := python.ParseLock("uv.lock", []byte(build("sha256:original")), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	second, diags := python.ParseLock("uv.lock", []byte(build("sha256:substituted")), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	a, _ := first.Package("requests")
	b, _ := second.Package("requests")

	if a.Hash.Value == b.Hash.Value {
		t.Fatalf("substituting wheel %d of %d left the identity unchanged", wheelCount, wheelCount)
	}
	// The identity is a fixed-size digest, so covering every artifact costs
	// nothing in record size.
	if len(a.Hash.Value) != len("sha256:")+64 {
		t.Errorf("identity is not a fixed-size digest: %q", a.Hash.Value)
	}
}

// TestParseLockIdentityIsFramed proves two different digest lists cannot fold to
// the same identity, which length framing is what prevents.
func TestParseLockIdentityIsFramed(t *testing.T) {
	build := func(a, b string) string {
		return "version = 1\n\n[[package]]\nname = \"p\"\nversion = \"1.0.0\"\n" +
			"\n[[package.wheels]]\nhash = \"" + a + "\"\n" +
			"\n[[package.wheels]]\nhash = \"" + b + "\"\n"
	}

	left, _ := python.ParseLock("uv.lock", []byte(build("ab", "c")), 10<<20)
	right, _ := python.ParseLock("uv.lock", []byte(build("a", "bc")), 10<<20)

	l, okL := left.Package("p")
	r, okR := right.Package("p")
	if !okL || !okR {
		t.Fatal("package missing from one of the locks")
	}
	if l.Hash.Value == r.Hash.Value {
		t.Fatalf("two different digest lists folded to the same identity: %q", l.Hash.Value)
	}
}

// TestParseLockRecordsUnsupportedVersion proves an unreadable lock format is a
// diagnostic rather than a silently empty dependency set, which would look
// identical to a project with no dependencies.
func TestParseLockRecordsUnsupportedVersion(t *testing.T) {
	const content = "version = 99\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n"

	lock, diags := python.ParseLock("uv.lock", []byte(content), 10<<20)
	if !hasCode(diags, "python.unsupported_lockfile_version") {
		t.Fatalf("expected python.unsupported_lockfile_version, got %v", codes(diags))
	}
	if len(lock.Packages) != 0 {
		t.Error("an unsupported lock must not yield packages")
	}
}

// TestDepthBoundMatchesArchitectureLimit keeps the parser constant tied to the
// approved run limit.
func TestDepthBoundMatchesArchitectureLimit(t *testing.T) {
	if python.MaxDepth != run.DefaultLimits().MaxParserDepth {
		t.Fatalf("parser depth bound %d does not match the architecture limit %d",
			python.MaxDepth, run.DefaultLimits().MaxParserDepth)
	}
}

// TestParseRecordsUnknownTablesAsCoverageNotes proves an unmodeled table is
// stated rather than silently dropped.
func TestParseRecordsUnknownTablesAsCoverageNotes(t *testing.T) {
	const content = `[project]
name = "example"

[tool.black]
line-length = 100
`

	project, diags := python.ParseProject("pyproject.toml", []byte(content), 1<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	joined := strings.Join(project.CoverageNotes, "\n")
	if !strings.Contains(joined, "tool.black") {
		t.Errorf("coverage notes %q do not mention tool.black", joined)
	}
}

// TestParseNeverEvaluatesValues proves the reader is a reader: a dependency
// specifier that looks like a command survives byte for byte.
func TestParseNeverEvaluatesValues(t *testing.T) {
	const spec = "evil @ git+https://example.invalid/x.git@$(whoami)"
	content := "[project]\nname = \"x\"\ndependencies = [\"" + spec + "\"]\n"

	project, diags := python.ParseProject("pyproject.toml", []byte(content), 1<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	if len(project.Requirements) != 1 {
		t.Fatalf("got %d requirements, want 1", len(project.Requirements))
	}
	if got := project.Requirements[0].Spec.Value; got != spec {
		t.Fatalf("specifier was rewritten.\n got: %q\nwant: %q", got, spec)
	}
}
