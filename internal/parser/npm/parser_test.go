package npm_test

import (
	"strings"
	"testing"

	"github.com/codebyte-p/proofrail/internal/parser/npm"
	"github.com/codebyte-p/proofrail/internal/run"
)

const minimalManifest = `{
  "name": "example",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "^1.3.0"
  }
}
`

const minimalLock = `{
  "name": "example",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "example",
      "version": "1.0.0"
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
    }
  }
}
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

// TestParseManifestRejects covers every input class the bounded JSON reader
// refuses. Each case must fail closed with no dependency escaping.
func TestParseManifestRejects(t *testing.T) {
	deep := strings.Repeat("[", 70) + strings.Repeat("]", 70)

	cases := []struct {
		name    string
		content string
		code    string
	}{
		{
			name:    "duplicate key at root",
			content: `{"name": "a", "name": "b"}`,
			code:    "npm.duplicate_key",
		},
		{
			name:    "duplicate dependency name",
			content: `{"dependencies": {"left-pad": "^1.0.0", "left-pad": "^2.0.0"}}`,
			code:    "npm.duplicate_key",
		},
		{
			name:    "nesting above the depth bound",
			content: `{"a": ` + deep + `}`,
			code:    "npm.depth_exceeded",
		},
		{
			name:    "invalid utf-8",
			content: "{\"name\": \"\xff\xfe\"}",
			code:    "npm.invalid_utf8",
		},
		{
			name:    "malformed json",
			content: `{"name": }`,
			code:    "npm.malformed",
		},
		{
			name:    "trailing content after the document",
			content: `{"name": "a"} {"name": "b"}`,
			code:    "npm.trailing_content",
		},
		{
			name:    "root is not an object",
			content: `["left-pad"]`,
			code:    "npm.root_not_object",
		},
		{
			name:    "empty document",
			content: "",
			code:    "npm.empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, diags := npm.ParseManifest("package.json", []byte(tc.content), 1<<20)
			if !hasCode(diags, tc.code) {
				t.Fatalf("expected diagnostic %q, got %v", tc.code, codes(diags))
			}
			if len(manifest.Requirements) != 0 {
				t.Errorf("a rejected manifest must not yield requirements, got %d", len(manifest.Requirements))
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

// TestParseManifestRejectsOversizedInput proves the 1 MiB manifest bound is
// enforced before the JSON machinery sees the content.
func TestParseManifestRejectsOversizedInput(t *testing.T) {
	const maxBytes = 1 << 20
	oversized := `{"description": "` + strings.Repeat("a", maxBytes) + `"}`

	manifest, diags := npm.ParseManifest("package.json", []byte(oversized), maxBytes)
	if !hasCode(diags, "npm.too_large") {
		t.Fatalf("expected npm.too_large, got %v", codes(diags))
	}
	if len(manifest.Requirements) != 0 {
		t.Errorf("an oversized manifest must not be parsed")
	}
}

// TestParseLockRejectsOversizedInput proves the lock bound is the larger 10 MiB
// limit and is enforced independently of the manifest bound.
func TestParseLockRejectsOversizedInput(t *testing.T) {
	const maxBytes = 10 << 20
	oversized := `{"description": "` + strings.Repeat("a", maxBytes) + `"}`

	lock, diags := npm.ParseLock("package-lock.json", []byte(oversized), maxBytes)
	if !hasCode(diags, "npm.too_large") {
		t.Fatalf("expected npm.too_large, got %v", codes(diags))
	}
	if len(lock.Packages) != 0 {
		t.Errorf("an oversized lock must not be parsed")
	}
}

// TestDepthBoundMatchesArchitectureLimit keeps the parser constant tied to the
// approved run limit so the two cannot drift apart silently.
func TestDepthBoundMatchesArchitectureLimit(t *testing.T) {
	if npm.MaxDepth != run.DefaultLimits().MaxParserDepth {
		t.Fatalf("parser depth bound %d does not match the architecture limit %d",
			npm.MaxDepth, run.DefaultLimits().MaxParserDepth)
	}
}

// TestParseManifestReadsRequirements proves every dependency class is captured
// with its declaring section and its source line.
func TestParseManifestReadsRequirements(t *testing.T) {
	const content = `{
  "name": "example",
  "version": "2.1.0",
  "dependencies": {
    "left-pad": "^1.3.0",
    "internal-tool": "git+https://example.invalid/team/tool.git#main"
  },
  "devDependencies": {
    "test-runner": "~4.0.1"
  },
  "optionalDependencies": {
    "fast-native": "1.0.0"
  },
  "scripts": {
    "postinstall": "node ./scripts/setup.js",
    "test": "test-runner"
  }
}
`

	manifest, diags := npm.ParseManifest("package.json", []byte(content), 1<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	if manifest.Path != "package.json" {
		t.Errorf("path = %q, want package.json", manifest.Path)
	}
	if manifest.Name.Value != "example" {
		t.Errorf("name = %q, want example", manifest.Name.Value)
	}
	if manifest.Version.Value != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", manifest.Version.Value)
	}

	want := map[string]struct {
		spec string
		kind string
		line int
	}{
		"left-pad":      {"^1.3.0", "dependencies", 5},
		"internal-tool": {"git+https://example.invalid/team/tool.git#main", "dependencies", 6},
		"test-runner":   {"~4.0.1", "devDependencies", 9},
		"fast-native":   {"1.0.0", "optionalDependencies", 12},
	}
	if len(manifest.Requirements) != len(want) {
		t.Fatalf("got %d requirements, want %d: %+v", len(manifest.Requirements), len(want), manifest.Requirements)
	}
	for _, req := range manifest.Requirements {
		expected, ok := want[req.Name.Value]
		if !ok {
			t.Errorf("unexpected requirement %q", req.Name.Value)
			continue
		}
		if req.Spec.Value != expected.spec {
			t.Errorf("%s spec = %q, want %q", req.Name.Value, req.Spec.Value, expected.spec)
		}
		if req.Kind != expected.kind {
			t.Errorf("%s kind = %q, want %q", req.Name.Value, req.Kind, expected.kind)
		}
		if req.Name.Pos.Line != expected.line {
			t.Errorf("%s line = %d, want %d", req.Name.Value, req.Name.Pos.Line, expected.line)
		}
	}

	if len(manifest.Scripts) != 2 {
		t.Fatalf("got %d scripts, want 2", len(manifest.Scripts))
	}
	postinstall := manifest.Script("postinstall")
	if postinstall.Value != "node ./scripts/setup.js" {
		t.Errorf("postinstall = %q", postinstall.Value)
	}
	if postinstall.Pos.Line != 15 {
		t.Errorf("postinstall line = %d, want 15", postinstall.Pos.Line)
	}
}

// TestParseLockReadsResolvedIdentity proves the lock yields the resolved
// identity the provenance rules compare: version, source URL, and integrity.
func TestParseLockReadsResolvedIdentity(t *testing.T) {
	lock, diags := npm.ParseLock("package-lock.json", []byte(minimalLock), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	if lock.LockfileVersion != 3 {
		t.Errorf("lockfileVersion = %d, want 3", lock.LockfileVersion)
	}

	// The root entry, keyed by the empty string, is the project itself and is
	// not a dependency of it.
	pkg, ok := lock.Package("left-pad")
	if !ok {
		t.Fatalf("left-pad missing from lock: %+v", lock.Packages)
	}
	if pkg.Version.Value != "1.3.0" {
		t.Errorf("version = %q, want 1.3.0", pkg.Version.Value)
	}
	if !strings.HasPrefix(pkg.Resolved.Value, "https://registry.npmjs.org/") {
		t.Errorf("resolved = %q", pkg.Resolved.Value)
	}
	if !strings.HasPrefix(pkg.Integrity.Value, "sha512-") {
		t.Errorf("integrity = %q", pkg.Integrity.Value)
	}
	if pkg.Version.Pos.Line < 1 {
		t.Errorf("locked package has no source line")
	}
}

// TestParseLockReadsInstallScriptFlag proves the lock's install-behavior signal
// survives, because it is what PFR-DEP-003 reads for a transitive package.
func TestParseLockReadsInstallScriptFlag(t *testing.T) {
	const content = `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/native-ext": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/native-ext/-/native-ext-2.0.0.tgz",
      "integrity": "sha512-AAAA",
      "hasInstallScript": true
    }
  }
}
`

	lock, diags := npm.ParseLock("package-lock.json", []byte(content), 10<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	pkg, ok := lock.Package("native-ext")
	if !ok {
		t.Fatalf("native-ext missing from lock")
	}
	if !pkg.HasInstallScript {
		t.Error("hasInstallScript was not captured")
	}
}

// TestParseLockRecordsUnsupportedLockfileVersion proves an unreadable lock
// format is a diagnostic rather than a silently empty dependency set. An empty
// result would look identical to a project with no dependencies.
func TestParseLockRecordsUnsupportedLockfileVersion(t *testing.T) {
	const content = `{"lockfileVersion": 1, "dependencies": {"left-pad": {"version": "1.3.0"}}}`

	lock, diags := npm.ParseLock("package-lock.json", []byte(content), 10<<20)
	if !hasCode(diags, "npm.unsupported_lockfile_version") {
		t.Fatalf("expected npm.unsupported_lockfile_version, got %v", codes(diags))
	}
	if len(lock.Packages) != 0 {
		t.Errorf("an unsupported lock must not yield packages")
	}
}

// TestParseRecordsUnknownFieldsAsCoverageNotes proves an unmodeled field is
// stated rather than silently dropped.
func TestParseRecordsUnknownFieldsAsCoverageNotes(t *testing.T) {
	const content = `{
  "name": "example",
  "workspaces": ["packages/*"],
  "peerDependencies": {"react": "^18.0.0"}
}
`

	manifest, diags := npm.ParseManifest("package.json", []byte(content), 1<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	joined := strings.Join(manifest.CoverageNotes, "\n")
	if !strings.Contains(joined, "workspaces") {
		t.Errorf("coverage notes %q do not mention workspaces", joined)
	}
}

// TestParseNeverExecutesScriptContent proves a lifecycle script is captured as
// inert text. Anything else would mean repository content had been run.
func TestParseNeverExecutesScriptContent(t *testing.T) {
	const script = "node -e \\\"require('child_process').exec('id')\\\" && $(whoami)"
	content := `{"scripts": {"preinstall": "` + script + `"}}`

	manifest, diags := npm.ParseManifest("package.json", []byte(content), 1<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	got := manifest.Script("preinstall").Value
	want := strings.ReplaceAll(script, `\"`, `"`)
	if got != want {
		t.Fatalf("script was rewritten.\n got: %q\nwant: %q", got, want)
	}
}
