package workflow_test

import (
	"strings"
	"testing"

	"github.com/codebyte-p/proofrail/internal/parser/workflow"
	"github.com/codebyte-p/proofrail/internal/run"
)

// fuzzTriggers, fuzzPermissions, and fuzzSteps are combined into a seed corpus
// covering every shape the PFR-WF rules read. The product is 175 workflows,
// which is the mutation corpus the Gate 1 plan requires.
var (
	fuzzTriggers = []string{
		"push",
		"pull_request",
		"pull_request_target",
		"workflow_run",
		"issue_comment",
		"[push, pull_request]",
		"{pull_request_target: {types: [opened]}}",
	}

	fuzzPermissions = []string{
		"",
		"permissions: write-all\n",
		"permissions: read-all\n",
		"permissions:\n  contents: write\n  id-token: write\n",
		"permissions: {}\n",
	}

	fuzzSteps = []string{
		"      - run: make test\n",
		"      - run: echo ${{ github.event.pull_request.title }}\n",
		"      - uses: actions/checkout@v4\n",
		"      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		"      - run: ./publish.sh\n        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
	}
)

// pathologicalSeeds are the inputs that must be refused rather than parsed, plus
// the encoding edge cases a hostile repository can commit.
var pathologicalSeeds = []string{
	"",
	"---\n",
	"null\n",
	"- just: a sequence\n",
	"on: [unclosed\n",
	"a: &x 1\nb: *x\n",
	"base: &b {x: 1}\nuse:\n  <<: *b\n",
	"name: !Custom ci\n",
	"name: !!binary aGVsbG8=\n",
	"on: push\non: pull_request\n",
	"2: int key\n",
	"? [complex, key]\n: value\n",
	"on: push\ndeep: " + strings.Repeat("[", 80) + strings.Repeat("]", 80) + "\n",
	"name: ci\n---\nname: second\n",
	"\xef\xbb\xbfname: ci\non: push\n",
	"name: \"\\u0000\\u0007\"\non: push\n",
	"name: \xff\xfe\xfd\n",
	"\tname: tab-indented\n",
	"name: " + strings.Repeat("a", 5000) + "\n",
	strings.Repeat("k: v\n", 5000),
	"jobs:\n  a:\n    steps:\n      - run: |\n          line one\n          line two\n",
}

// FuzzParse asserts the properties that must hold for every input, valid or
// hostile: the parser terminates, stays deterministic, never lets a rejected
// document escape, never grows its input, and never emits a diagnostic carrying
// a control byte.
func FuzzParse(f *testing.F) {
	for _, trigger := range fuzzTriggers {
		for _, permissions := range fuzzPermissions {
			for _, step := range fuzzSteps {
				f.Add("name: ci\non: " + trigger + "\n" + permissions +
					"jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + step)
			}
		}
	}
	for _, seed := range pathologicalSeeds {
		f.Add(seed)
	}

	const path = ".github/workflows/fuzz.yml"

	f.Fuzz(func(t *testing.T, content string) {
		doc, diags := workflow.Parse(path, []byte(content), 2<<20)

		// Determinism: canonical output depends on the same bytes always
		// producing the same document.
		again, againDiags := workflow.Parse(path, []byte(content), 2<<20)
		if len(diags) != len(againDiags) {
			t.Fatalf("diagnostic count is not deterministic: %d vs %d", len(diags), len(againDiags))
		}
		for i := range diags {
			if diags[i] != againDiags[i] {
				t.Fatalf("diagnostic %d is not deterministic: %+v vs %+v", i, diags[i], againDiags[i])
			}
		}

		if len(diags) > 0 {
			// A rejected document must escape as the zero value, never as a
			// partially populated one a caller might act on.
			if doc.Path != "" || len(doc.Jobs) != 0 || len(doc.Triggers) != 0 || doc.Name.Present() {
				t.Fatalf("a rejected document leaked content: %+v", doc)
			}
			assertDiagnosticsAreSafe(t, diags)
			return
		}

		if doc.Path != path {
			t.Fatalf("document path = %q, want %q", doc.Path, path)
		}
		if !equalDocuments(doc, again) {
			t.Fatal("two parses of the same bytes produced different documents")
		}

		// No construct in the restricted grammar can duplicate content, so the
		// modeled scalars can never outweigh the bytes they came from. A
		// violation would mean the parser expanded or synthesized a value.
		if total := scalarBytes(doc); total > len(content) {
			t.Fatalf("parsed scalars (%d bytes) exceed the input (%d bytes)", total, len(content))
		}

		for _, pos := range scalarPositions(doc) {
			if pos.Line < 1 {
				t.Fatalf("a modeled scalar has no source line: %+v", pos)
			}
		}
	})
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

// scalarsOf walks every modeled scalar in the document.
func allScalars(doc workflow.Document) []workflow.Scalar {
	var out []workflow.Scalar
	add := func(s workflow.Scalar) {
		if s.Present() {
			out = append(out, s)
		}
	}
	addMap := func(m workflow.Map) {
		for _, e := range m {
			add(e.Key)
			add(e.Value)
		}
	}

	add(doc.Name)
	for _, t := range doc.Triggers {
		add(t.Name)
		out = append(out, presentOnly(t.Types)...)
		out = append(out, presentOnly(t.Branches)...)
	}
	add(doc.Permissions.Mode)
	addMap(doc.Permissions.Scopes)
	addMap(doc.Env)

	for _, job := range doc.Jobs {
		add(job.ID)
		add(job.If)
		add(job.Uses)
		out = append(out, presentOnly(job.RunsOn)...)
		out = append(out, presentOnly(job.Environment)...)
		add(job.Permissions.Mode)
		addMap(job.Permissions.Scopes)
		addMap(job.Secrets)
		addMap(job.Env)

		for _, step := range job.Steps {
			add(step.Name)
			add(step.Uses)
			add(step.Run)
			add(step.Shell)
			add(step.If)
			addMap(step.With)
			addMap(step.Env)
		}
	}
	return out
}

func presentOnly(scalars []workflow.Scalar) []workflow.Scalar {
	var out []workflow.Scalar
	for _, s := range scalars {
		if s.Present() {
			out = append(out, s)
		}
	}
	return out
}

func scalarBytes(doc workflow.Document) int {
	total := 0
	for _, s := range allScalars(doc) {
		total += len(s.Value)
	}
	return total
}

func scalarPositions(doc workflow.Document) []workflow.Position {
	scalars := allScalars(doc)
	out := make([]workflow.Position, 0, len(scalars))
	for _, s := range scalars {
		out = append(out, s.Pos)
	}
	return out
}

func equalDocuments(a, b workflow.Document) bool {
	if a.Path != b.Path || len(a.Jobs) != len(b.Jobs) || len(a.Triggers) != len(b.Triggers) {
		return false
	}
	left, right := allScalars(a), allScalars(b)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
