package workflow_test

import (
	"strings"
	"testing"

	"github.com/codebyte-p/proofrail/internal/parser/workflow"
	"github.com/codebyte-p/proofrail/internal/run"
)

// minimalWorkflow is the smallest document the parser accepts. Rejection cases
// embed it so a test proves the rejection it names, not an unrelated structural
// problem in the fixture.
const minimalWorkflow = `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
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

// TestParseRejects covers every syntax class the restricted parser refuses.
// Each case must fail closed: a diagnostic is raised and no job escapes.
func TestParseRejects(t *testing.T) {
	deepFlow := strings.Repeat("[", 70) + strings.Repeat("]", 70)

	cases := []struct {
		name    string
		content string
		code    string
	}{
		{
			name:    "multiple documents",
			content: minimalWorkflow + "---\nname: second\n",
			code:    "workflow.multiple_documents",
		},
		{
			name:    "anchor",
			content: "name: ci\non: push\ndefaults: &base\n  run:\n    shell: bash\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n",
			code:    "workflow.anchor_forbidden",
		},
		{
			name:    "alias",
			content: "name: &n ci\nalso: *n\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n",
			code:    "workflow.alias_forbidden",
		},
		{
			name:    "merge key",
			content: "base: &base\n  runs-on: ubuntu-latest\non: push\njobs:\n  build:\n    <<: *base\n    steps:\n      - run: make test\n",
			code:    "workflow.merge_key_forbidden",
		},
		{
			name:    "custom tag",
			content: "name: !Secret ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n",
			code:    "workflow.tag_forbidden",
		},
		{
			name:    "binary tag",
			content: "name: !!binary aGVsbG8=\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n",
			code:    "workflow.tag_forbidden",
		},
		{
			name:    "duplicate key at root",
			content: minimalWorkflow + "on: pull_request\n",
			code:    "workflow.duplicate_key",
		},
		{
			name:    "duplicate job id",
			content: "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make lint\n",
			code:    "workflow.duplicate_key",
		},
		{
			name:    "integer key",
			content: minimalWorkflow + "2: schedule\n",
			code:    "workflow.key_not_string",
		},
		{
			name:    "sequence key",
			content: minimalWorkflow + "? [a, b]\n: c\n",
			code:    "workflow.key_not_string",
		},
		{
			name:    "nesting above the depth bound",
			content: "on: push\ndeep: " + deepFlow + "\n",
			code:    "workflow.depth_exceeded",
		},
		{
			name:    "malformed yaml",
			content: "on: [unclosed\n",
			code:    "workflow.malformed",
		},
		{
			name:    "empty document",
			content: "",
			code:    "workflow.empty",
		},
		{
			name:    "root is not a mapping",
			content: "- run: make test\n",
			code:    "workflow.root_not_mapping",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, diags := workflow.Parse(".github/workflows/ci.yml", []byte(tc.content), 2<<20)
			if !hasCode(diags, tc.code) {
				t.Fatalf("expected diagnostic %q, got %v", tc.code, codes(diags))
			}
			if len(doc.Jobs) != 0 {
				t.Errorf("a rejected document must not yield jobs, got %d", len(doc.Jobs))
			}
			// A diagnostic reaches the console and published reports, so it may
			// never carry the rejected repository content back out.
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

// TestParseRejectsOversizedInput proves the byte bound is enforced before the
// YAML machinery ever sees the content.
func TestParseRejectsOversizedInput(t *testing.T) {
	const maxBytes = 2 << 20
	oversized := append([]byte(minimalWorkflow), []byte("# "+strings.Repeat("a", maxBytes))...)

	doc, diags := workflow.Parse(".github/workflows/ci.yml", oversized, maxBytes)
	if !hasCode(diags, "workflow.too_large") {
		t.Fatalf("expected workflow.too_large, got %v", codes(diags))
	}
	if len(doc.Jobs) != 0 {
		t.Errorf("an oversized document must not be parsed, got %d jobs", len(doc.Jobs))
	}
}

// TestParseDepthBoundMatchesArchitectureLimit keeps the parser's own constant
// tied to the approved run limit so the two cannot drift apart silently.
func TestParseDepthBoundMatchesArchitectureLimit(t *testing.T) {
	if workflow.MaxDepth != run.DefaultLimits().MaxParserDepth {
		t.Fatalf("parser depth bound %d does not match the architecture limit %d",
			workflow.MaxDepth, run.DefaultLimits().MaxParserDepth)
	}
}

// TestParseRetainsScalarLocations proves every scalar the rules consume keeps
// the source line it came from, because a finding must point at a real line.
func TestParseRetainsScalarLocations(t *testing.T) {
	const content = `name: ci
on:
  pull_request_target:
    types: [opened]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: refs/pull/1/head
      - run: make test
`

	doc, diags := workflow.Parse(".github/workflows/ci.yml", []byte(content), 2<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	if doc.Path != ".github/workflows/ci.yml" {
		t.Errorf("document path = %q, want the path passed to Parse", doc.Path)
	}
	if got := doc.Name.Value; got != "ci" {
		t.Errorf("name = %q, want ci", got)
	}
	if got := doc.Name.Pos.Line; got != 1 {
		t.Errorf("name line = %d, want 1", got)
	}

	if len(doc.Triggers) != 1 {
		t.Fatalf("expected one trigger, got %d", len(doc.Triggers))
	}
	if got := doc.Triggers[0].Name.Value; got != "pull_request_target" {
		t.Errorf("trigger = %q, want pull_request_target", got)
	}
	if got := doc.Triggers[0].Name.Pos.Line; got != 3 {
		t.Errorf("trigger line = %d, want 3", got)
	}

	if got := doc.Permissions.Mode.Value; got != "write-all" {
		t.Errorf("permissions mode = %q, want write-all", got)
	}
	if got := doc.Permissions.Mode.Pos.Line; got != 5 {
		t.Errorf("permissions line = %d, want 5", got)
	}

	if len(doc.Jobs) != 1 {
		t.Fatalf("expected one job, got %d", len(doc.Jobs))
	}
	job := doc.Jobs[0]
	if job.ID.Value != "build" {
		t.Errorf("job id = %q, want build", job.ID.Value)
	}
	if got := job.ID.Pos.Line; got != 7 {
		t.Errorf("job id line = %d, want 7", got)
	}
	if len(job.RunsOn) != 1 || job.RunsOn[0].Value != "ubuntu-latest" {
		t.Errorf("runs-on = %+v, want [ubuntu-latest]", job.RunsOn)
	}

	if len(job.Steps) != 2 {
		t.Fatalf("expected two steps, got %d", len(job.Steps))
	}
	if got := job.Steps[0].Uses.Value; got != "actions/checkout@v6" {
		t.Errorf("uses = %q, want actions/checkout@v6", got)
	}
	if got := job.Steps[0].Uses.Pos.Line; got != 10 {
		t.Errorf("uses line = %d, want 10", got)
	}
	if got := job.Steps[0].With.Get("ref").Value; got != "refs/pull/1/head" {
		t.Errorf("with.ref = %q, want refs/pull/1/head", got)
	}
	if got := job.Steps[1].Run.Value; got != "make test" {
		t.Errorf("run = %q, want make test", got)
	}
	if got := job.Steps[1].Run.Pos.Line; got != 13 {
		t.Errorf("run line = %d, want 13", got)
	}
}

// TestParseNeverInterpolates proves the parser is a reader, not an evaluator:
// expression, command-substitution, and environment syntax all survive byte for
// byte. Anything else would mean repository content had been evaluated.
func TestParseNeverInterpolates(t *testing.T) {
	const injected = "echo ${{ github.event.pull_request.title }} $(whoami) `id` ${HOME} %PATH%"
	content := "name: ci\non: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: '" + injected + "'\n"

	doc, diags := workflow.Parse(".github/workflows/ci.yml", []byte(content), 2<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}
	if len(doc.Jobs) != 1 || len(doc.Jobs[0].Steps) != 1 {
		t.Fatalf("expected one job with one step, got %+v", doc.Jobs)
	}
	if got := doc.Jobs[0].Steps[0].Run.Value; got != injected {
		t.Fatalf("run script was rewritten.\n got: %q\nwant: %q", got, injected)
	}
}

// TestParseRecordsUnknownFieldsAsCoverageNotes proves an unrecognized workflow
// field neither fails the parse nor silently disappears: version 1 states what
// it did not model instead of implying full coverage.
func TestParseRecordsUnknownFieldsAsCoverageNotes(t *testing.T) {
	const content = `name: ci
on: push
concurrency: build-group
jobs:
  build:
    runs-on: ubuntu-latest
    container: node:20
    steps:
      - run: make test
`

	doc, diags := workflow.Parse(".github/workflows/ci.yml", []byte(content), 2<<20)
	if len(diags) != 0 {
		t.Fatalf("expected a clean parse, got %v", codes(diags))
	}

	joined := strings.Join(doc.CoverageNotes, "\n")
	for _, want := range []string{"concurrency", "container"} {
		if !strings.Contains(joined, want) {
			t.Errorf("coverage notes %q do not mention unmodeled field %q", joined, want)
		}
	}
	if len(doc.Jobs) != 1 || len(doc.Jobs[0].Steps) != 1 {
		t.Errorf("unknown fields must not drop modeled content, got %+v", doc.Jobs)
	}
}
