package python_test

import (
	"strings"
	"testing"

	"github.com/codebyte-p/proofrail/internal/parser/python"
	"github.com/codebyte-p/proofrail/internal/run"
)

// The seed corpus is the product of these fragments, which covers every shape
// the PFR-DEP rules read from a project file or a lock.
var (
	fuzzHeaders = []string{
		"[project]\nname = \"example\"\n",
		"[project]\nname = 'example'\n",
		"version = 1\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
		"version = 1\n",
	}

	fuzzDeps = []string{
		"dependencies = [\"requests>=2.31.0\"]\n",
		"dependencies = [\"requests==2.31.0\"]\n",
		"dependencies = [\"requests\"]\n",
		"dependencies = [\"tool @ git+https://example.invalid/t.git@main\"]\n",
		"dependencies = [\"tool @ git+https://example.invalid/t.git@0123456789abcdef0123456789abcdef01234567\"]\n",
		"dependencies = [\"tool @ file:///local\"]\n",
		"dependencies = []\n",
		"",
	}

	fuzzTables = []string{
		"\n[build-system]\nrequires = [\"setuptools>=69\"]\nbuild-backend = \"setuptools.build_meta\"\n",
		"\n[tool.uv.sources]\ntool = { git = \"https://example.invalid/t.git\", branch = \"main\" }\n",
		"\n[tool.uv.sources]\ntool = { path = \"../local\" }\n",
		"\n[project.optional-dependencies]\ndev = [\"pytest==8.0.0\"]\n",
		"\n[tool.black]\nline-length = 100\n",
		"",
	}

	fuzzTrailers = []string{
		"\n[[package.wheels]]\nhash = \"sha256:abc\"\n",
		"\n# a trailing comment\n",
		"\nsource = { registry = \"https://pypi.org/simple\" }\n",
		"",
	}
)

var pathologicalSeeds = []string{
	"",
	"   ",
	"#only a comment\n",
	"[project]\n",
	"[project\n",
	"[[project]\n",
	"= \"value\"\n",
	"key =\n",
	"[project]\nname = \"a\"\nname = \"b\"\n",
	"[project]\nname = \"a\"\n\n[project]\nname = \"b\"\n",
	"[project]\nname = \"\"\"multi\nline\"\"\"\n",
	"[project]\nname = '''multi\nline'''\n",
	"[project]\nname = \"unterminated\n",
	"[project]\nname = \"bad \\q escape\"\n",
	"[project]\nname = \"\\u00\"\n",
	"[project]\nname = \"\xff\xfe\"\n",
	"[project]\nd = [\"a\",\n",
	"[project]\nd = { a = 1\n",
	"[project]\nd = 1979-05-27T07:32:00Z\n",
	"[project]\nd = " + strings.Repeat("[", 80) + strings.Repeat("]", 80) + "\n",
	"version = 99\n[[package]]\nname = \"a\"\n",
	"version = 1\n[[package]]\n",
	"[a.b.c.d]\nkey = \"value\"\n",
	"a.b.c = \"dotted\"\n",
	"[project]\nname = " + strconvRepeat(5000) + "\n",
}

func strconvRepeat(n int) string { return "\"" + strings.Repeat("a", n) + "\"" }

// FuzzParse asserts the properties that must hold for every input, valid or
// hostile: both entry points terminate, stay deterministic, never let a
// rejected document escape, never grow their input, and never emit a
// diagnostic carrying a byte outside printable ASCII.
func FuzzParse(f *testing.F) {
	for _, header := range fuzzHeaders {
		for _, deps := range fuzzDeps {
			for _, tbl := range fuzzTables {
				for _, trailer := range fuzzTrailers {
					f.Add(header + deps + tbl + trailer)
				}
			}
		}
	}
	for _, seed := range pathologicalSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		assertProjectProperties(t, content)
		assertLockProperties(t, content)
	})
}

func assertProjectProperties(t *testing.T, content string) {
	t.Helper()
	const path = "pyproject.toml"

	project, diags := python.ParseProject(path, []byte(content), 1<<20)
	again, againDiags := python.ParseProject(path, []byte(content), 1<<20)

	assertDeterministicDiagnostics(t, diags, againDiags)

	if len(diags) > 0 {
		if project.Path != "" || len(project.Requirements) != 0 || len(project.Sources) != 0 {
			t.Fatalf("a rejected project leaked content: %+v", project)
		}
		assertDiagnosticsAreSafe(t, diags)
		return
	}

	if project.Path != path {
		t.Fatalf("project path = %q, want %q", project.Path, path)
	}
	if len(project.Requirements) != len(again.Requirements) {
		t.Fatal("two parses of the same bytes produced different projects")
	}

	// A literal string is taken verbatim and an escape only ever shrinks, so
	// the modeled scalars can never outweigh the bytes they came from.
	total := len(project.Name.Value) + len(project.Version.Value) + len(project.BuildBackend.Value)
	for _, r := range project.Requirements {
		total += len(r.Spec.Value)
		assertLine(t, r.Spec.Pos.Line, "requirement spec")
	}
	for _, s := range project.BuildRequires {
		total += len(s.Value)
	}
	for _, s := range project.Sources {
		total += len(s.Name.Value) + len(s.Git.Value) + len(s.URL.Value) + len(s.Path.Value)
		assertLine(t, s.Name.Pos.Line, "source name")
	}
	if total > len(content) {
		t.Fatalf("parsed scalars (%d bytes) exceed the input (%d bytes)", total, len(content))
	}
}

func assertLockProperties(t *testing.T, content string) {
	t.Helper()
	const path = "uv.lock"

	lock, diags := python.ParseLock(path, []byte(content), 10<<20)
	_, againDiags := python.ParseLock(path, []byte(content), 10<<20)

	assertDeterministicDiagnostics(t, diags, againDiags)

	if len(diags) > 0 {
		if lock.Path != "" || len(lock.Packages) != 0 {
			t.Fatalf("a rejected lock leaked content: %+v", lock)
		}
		assertDiagnosticsAreSafe(t, diags)
		return
	}

	for _, p := range lock.Packages {
		if p.Name.Value == "" {
			t.Fatal("a locked package escaped with no name")
		}
		assertLine(t, p.Name.Pos.Line, "locked package name")
	}
}

func assertDeterministicDiagnostics(t *testing.T, first, second []run.Diagnostic) {
	t.Helper()
	if len(first) != len(second) {
		t.Fatalf("diagnostic count is not deterministic: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("diagnostic %d is not deterministic: %+v vs %+v", i, first[i], second[i])
		}
	}
}

func assertDiagnosticsAreSafe(t *testing.T, diags []run.Diagnostic) {
	t.Helper()
	for _, d := range diags {
		if d.Code == "" {
			t.Fatal("a diagnostic has no stable code")
		}
		if d.Message == "" {
			t.Fatalf("diagnostic %q has no message", d.Code)
		}
		for _, field := range []string{d.Code, d.Path, d.Message} {
			for i := 0; i < len(field); i++ {
				if c := field[i]; c < 0x20 || c > 0x7e {
					t.Fatalf("diagnostic %q carries byte %#x outside printable ASCII", d.Code, c)
				}
			}
		}
	}
}

func assertLine(t *testing.T, line int, what string) {
	t.Helper()
	if line < 1 {
		t.Fatalf("%s has no source line", what)
	}
}
