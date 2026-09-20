package dependency_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codebyte-p/proofrail/internal/finding"
	"github.com/codebyte-p/proofrail/internal/gitdiff"
	"github.com/codebyte-p/proofrail/internal/run"
)

// The PFR-DEP severity, confidence, and decision values are normative in
// docs/analyzers.md. Nothing pinned them, so lowering a severity or a decision
// hint passed the suite in silence while quietly changing what a run does with
// the evidence. These tests assert the table, not the code: a value that
// disagrees with docs/analyzers.md is a defect in the analyzer.

// classificationCase pins one rule, in one branch, to the classification the
// contract specifies for it.
type classificationCase struct {
	name       string
	rule       string
	files      func(t *testing.T) []gitdiff.FileChange
	severity   finding.Severity
	confidence finding.Confidence
	decision   finding.Decision
}

// manifest is the single-file change every source-classification case uses.
func manifest(path, content string) func(t *testing.T) []gitdiff.FileChange {
	return func(t *testing.T) []gitdiff.FileChange {
		t.Helper()
		return []gitdiff.FileChange{changed(path, nil, []byte(content))}
	}
}

// fixtures builds a change set from named fixtures, so a case reads as the
// scenario it is rather than as file plumbing.
func fixtures(path, baseClass, base, headClass, head string) func(t *testing.T) []gitdiff.FileChange {
	return func(t *testing.T) []gitdiff.FileChange {
		t.Helper()
		var baseContent []byte
		if base != "" {
			baseContent = fixture(t, baseClass, base)
		}
		return []gitdiff.FileChange{changed(path, baseContent, fixture(t, headClass, head))}
	}
}

func classificationCases() []classificationCase {
	return []classificationCase{
		{
			name: "PFR-DEP-001 manifest-lock mismatch",
			rule: "PFR-DEP-001",
			files: fixtures("package.json",
				"malicious", "pfr-dep-001-manifest-lock-mismatch.base.json",
				"malicious", "pfr-dep-001-manifest-lock-mismatch.head.json"),
			severity:   finding.SeverityHigh,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionBlock,
		},
		{
			// The only PFR-DEP-002 branch that does not block: the source is
			// bound to this revision and cannot change without a change here.
			name:       "PFR-DEP-002 immutable in-repository source",
			rule:       "PFR-DEP-002",
			files:      manifest("package.json", `{"name":"example","dependencies":{"local-lib":"file:./packages/lib"}}`),
			severity:   finding.SeverityMedium,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionRequireReview,
		},
		{
			name:       "PFR-DEP-002 mutable source",
			rule:       "PFR-DEP-002",
			files:      fixtures("package.json", "", "", "malicious", "pfr-dep-002-git-dependency.json"),
			severity:   finding.SeverityHigh,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionBlock,
		},
		{
			// Pinned to a full commit hash, so immutable, and still outside the
			// repository: the contract blocks on either condition alone.
			name: "PFR-DEP-002 immutable source outside the repository",
			rule: "PFR-DEP-002",
			files: manifest("package.json",
				`{"name":"example","dependencies":{"tool":"git+https://example.invalid/team/tool.git#0123456789abcdef0123456789abcdef01234567"}}`),
			severity:   finding.SeverityHigh,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionBlock,
		},
		{
			name: "PFR-DEP-003 lifecycle execution introduced",
			rule: "PFR-DEP-003",
			files: fixtures("package.json",
				"malicious", "pfr-dep-003-lifecycle-script.base.json",
				"malicious", "pfr-dep-003-lifecycle-script.head.json"),
			severity:   finding.SeverityMedium,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionRequireReview,
		},
		{
			name: "PFR-DEP-004 resolved source changed",
			rule: "PFR-DEP-004",
			files: fixtures("package-lock.json",
				"malicious", "pfr-dep-004-source-changed.base.json",
				"malicious", "pfr-dep-004-source-changed.head.json"),
			severity:   finding.SeverityHigh,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionBlock,
		},
		{
			name: "PFR-DEP-005 below the review threshold",
			rule: "PFR-DEP-005",
			files: fixtures("package.json",
				"malicious", "pfr-dep-005-graph-expansion.base.json",
				"benign", "pfr-dep-005-single-addition.head.json"),
			severity:   finding.SeverityNote,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionObserve,
		},
		{
			name: "PFR-DEP-005 at or above the review threshold",
			rule: "PFR-DEP-005",
			files: fixtures("package.json",
				"malicious", "pfr-dep-005-graph-expansion.base.json",
				"malicious", "pfr-dep-005-graph-expansion.head.json"),
			severity:   finding.SeverityLow,
			confidence: finding.ConfidenceHigh,
			decision:   finding.DecisionRequireReview,
		},
		{
			name: "PFR-DEP-006 suspicious name similarity",
			rule: "PFR-DEP-006",
			files: fixtures("package.json",
				"malicious", "pfr-dep-006-name-similarity.base.json",
				"malicious", "pfr-dep-006-name-similarity.head.json"),
			severity:   finding.SeverityLow,
			confidence: finding.ConfidenceLow,
			decision:   finding.DecisionWarn,
		},
	}
}

// TestRuleClassification asserts the normative severity, confidence, and
// decision hint of every PFR-DEP rule, in both branches of the two rules that
// have one.
func TestRuleClassification(t *testing.T) {
	for _, tc := range classificationCases() {
		t.Run(tc.name, func(t *testing.T) {
			result := analyze(t, tc.files(t)...)

			matches := findingsFor(result, tc.rule)
			if len(matches) != 1 {
				t.Fatalf("expected exactly one %s finding, got %d (all rules: %v)", tc.rule, len(matches), ruleIDs(result))
			}
			f := matches[0]

			if f.Severity != tc.severity {
				t.Errorf("severity = %q, want %q", f.Severity, tc.severity)
			}
			if f.Confidence != tc.confidence {
				t.Errorf("confidence = %q, want %q", f.Confidence, tc.confidence)
			}
			if f.DecisionHint != tc.decision {
				t.Errorf("decision hint = %q, want %q", f.DecisionHint, tc.decision)
			}
		})
	}
}

// TestNoRuleClaimsCriticalSeverity holds the reservation line: critical is for
// evidence proving exposure of write-capable or equivalently critical
// authority, and no version 1 PFR-DEP rule proves that on its own.
func TestNoRuleClaimsCriticalSeverity(t *testing.T) {
	for _, tc := range classificationCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range analyze(t, tc.files(t)...).Findings {
				if f.Severity == finding.SeverityCritical {
					t.Errorf("%s claims critical severity without evidence of write-capable authority", f.RuleID)
				}
			}
		})
	}
}

// TestNonRegistrySourceMessageMatchesItsClassification proves the canonical
// message states the reason the classification actually rests on.
//
// One unconditional sentence claimed every reported source was "not bound to an
// immutable identity", which is false in both branches it is reachable from: a
// Git source pinned to a full commit hash is immutable and still blocks for
// being outside the repository, and the review branch is reachable only when the
// source is immutable and inside it.
func TestNonRegistrySourceMessageMatchesItsClassification(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"

	cases := []struct {
		name    string
		spec    string
		want    string
		notWant string
	}{
		{
			name: "mutable source",
			spec: "git+https://example.invalid/team/tool.git#main",
			want: "not bound to an immutable identity",
		},
		{
			name:    "immutable source outside the repository",
			spec:    "git+https://example.invalid/team/tool.git#" + commit,
			want:    "outside this repository",
			notWant: "not bound to an immutable identity",
		},
		{
			name:    "immutable source inside the repository",
			spec:    "file:./packages/lib",
			want:    "repository layout",
			notWant: "not bound to an immutable identity",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := `{"name":"example","dependencies":{"tool":"` + tc.spec + `"}}`
			result := analyze(t, changed("package.json", nil, []byte(content)))

			matches := findingsFor(result, "PFR-DEP-002")
			if len(matches) != 1 {
				t.Fatalf("expected one PFR-DEP-002 for %q, got %v", tc.spec, ruleIDs(result))
			}
			if !strings.Contains(matches[0].Message, tc.want) {
				t.Errorf("message does not explain the classification (%q): %q", tc.want, matches[0].Message)
			}
			if tc.notWant != "" && strings.Contains(matches[0].Message, tc.notWant) {
				t.Errorf("message claims %q, which contradicts its own classification: %q", tc.notWant, matches[0].Message)
			}
		})
	}
}

// TestBarePythonNameIsCoveredByLockResolution proves an unconstrained Python
// requirement is treated like an npm range.
//
// Both float to whatever the index serves today, so both belong to PFR-DEP-001
// through lock resolution. Routing only the Python spelling to PFR-DEP-002
// blocked ordinary practice in one ecosystem and exempted it in the other.
func TestBarePythonNameIsCoveredByLockResolution(t *testing.T) {
	const content = `[project]
name = "example"
version = "1.0.0"
dependencies = [
    "requests",
]
`
	result := analyze(t, changed("pyproject.toml", nil, []byte(content)))

	if matches := findingsFor(result, "PFR-DEP-002"); len(matches) != 0 {
		t.Errorf("PFR-DEP-002 fired on a bare registry requirement: %+v", matches)
	}
	matches := findingsFor(result, "PFR-DEP-001")
	if len(matches) != 1 {
		t.Fatalf("no PFR-DEP-001 covers the unresolved requirement; rules present: %v", ruleIDs(result))
	}
	if !strings.Contains(matches[0].Message, "requests") {
		t.Errorf("message does not name the requirement: %q", matches[0].Message)
	}
}

// ----------------------------------------------------------------------------
// Equivalent-syntax variants
// ----------------------------------------------------------------------------

// variantCase is one fixture that writes a scenario in an equivalent syntax.
// It is an independent case: an analyzer that matches one spelling and misses
// the other detects nothing, so the variant carries its own expectation and
// names the canonical fixture it varies.
type variantCase struct {
	class     string
	rule      string
	fixture   string
	canonical string
	path      string
}

// sourceVariantCases covers the URI-scheme spellings npm resolves identically.
// A scheme is case-insensitive, so `HTTPS://` and `https://` name the same
// source; matching them case-sensitively dropped the uppercase spelling into
// the registry branch, which PFR-DEP-002 skips outright.
func sourceVariantCases() []variantCase {
	return []variantCase{
		{class: "malicious", rule: "PFR-DEP-002", fixture: "pfr-dep-002-uppercase-git-dependency.json",
			canonical: "pfr-dep-002-git-dependency.json", path: "package.json"},
		{class: "malicious", rule: "PFR-DEP-002", fixture: "pfr-dep-002-uppercase-url-dependency.json",
			canonical: "pfr-dep-002-url-dependency.json", path: "package.json"},
		{class: "malicious", rule: "PFR-DEP-002", fixture: "pfr-dep-002-uppercase-path-escape.json",
			canonical: "pfr-dep-002-path-escape.json", path: "package.json"},
		{class: "benign", rule: "PFR-DEP-002", fixture: "pfr-dep-002-uppercase-registry-alias.json",
			canonical: "pfr-dep-002-registry-dependency.json", path: "package.json"},
		{class: "benign", rule: "PFR-DEP-002", fixture: "pfr-dep-002-uppercase-contained-path.json",
			canonical: "pfr-dep-002-contained-path.json", path: "package.json"},
	}
}

// TestMustDetectSourceVariantsBlock proves every malicious spelling reaches the
// same blocking classification as the canonical fixture it varies.
func TestMustDetectSourceVariantsBlock(t *testing.T) {
	for _, tc := range sourceVariantCases() {
		if tc.class != "malicious" {
			continue
		}
		for _, name := range []string{tc.canonical, tc.fixture} {
			t.Run(name, func(t *testing.T) {
				result := analyze(t, changed(tc.path, nil, fixture(t, "malicious", name)))

				matches := findingsFor(result, tc.rule)
				if len(matches) != 1 {
					t.Fatalf("%s produced no %s; rules present: %v", name, tc.rule, ruleIDs(result))
				}
				if matches[0].DecisionHint != finding.DecisionBlock {
					t.Errorf("decision = %q, want block", matches[0].DecisionHint)
				}
				if matches[0].Severity != finding.SeverityHigh {
					t.Errorf("severity = %q, want high", matches[0].Severity)
				}
			})
		}
	}
}

// TestExpectedCleanFixturesDoNotBlock is the false-block side of the corpus:
// the same syntaxes used safely may be reported, but may never block.
func TestExpectedCleanFixturesDoNotBlock(t *testing.T) {
	for _, label := range fixtureLabels(t, "benign", "EXPECTED_CLEAN.txt") {
		t.Run(label.fixture, func(t *testing.T) {
			path := "package.json"
			if strings.HasSuffix(label.fixture, ".toml") {
				path = "pyproject.toml"
			}
			result := analyze(t, changed(path, nil, fixture(t, "benign", label.fixture)))

			for _, f := range findingsFor(result, label.rule) {
				if f.DecisionHint == finding.DecisionBlock {
					t.Errorf("%s blocks on a benign fixture: %q", label.rule, f.Message)
				}
			}
		})
	}
}

// fixtureLabel is one sidecar line: `<RULE> <fixture> [variant_of=<canonical>]`.
type fixtureLabel struct {
	rule      string
	fixture   string
	variantOf string
}

const variantMarker = "variant_of="

// fixtureLabels reads a corpus sidecar. JSON has no comment syntax, so the
// labels live beside the fixtures rather than inside the parsed content.
func fixtureLabels(t *testing.T, class, name string) []fixtureLabel {
	t.Helper()

	var labels []fixtureLabel
	for _, line := range strings.Split(string(fixture(t, class, name)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("%s: malformed label %q", name, line)
		}
		label := fixtureLabel{rule: fields[0], fixture: fields[1]}
		for _, field := range fields[2:] {
			if rest, found := strings.CutPrefix(field, variantMarker); found {
				label.variantOf = rest
			}
		}
		labels = append(labels, label)
	}
	return labels
}

// TestFixtureVariantsNameTheirCanonicalFixture keeps the corpus labels honest.
// A variant that does not say what it varies reads as an unrelated fixture, and
// a canonical name that is not on disk is a label nobody can follow.
func TestFixtureVariantsNameTheirCanonicalFixture(t *testing.T) {
	sidecars := map[string]string{
		"malicious": "MUST_DETECT.txt",
		"benign":    "EXPECTED_CLEAN.txt",
	}

	for _, tc := range sourceVariantCases() {
		t.Run(tc.fixture, func(t *testing.T) {
			var declared string
			for _, label := range fixtureLabels(t, tc.class, sidecars[tc.class]) {
				if label.fixture == tc.fixture {
					declared = label.variantOf
				}
			}
			if declared == "" {
				t.Fatalf("%s does not declare %s%s", sidecars[tc.class], variantMarker, tc.canonical)
			}
			if declared != tc.canonical {
				t.Errorf("declared %s%s, want %s", variantMarker, declared, tc.canonical)
			}
			path := filepath.Join("..", "..", "..", "testdata", tc.class, "dependency", declared)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("canonical fixture %s is not on disk: %v", declared, err)
			}
		})
	}
}

// TestFindingCeilingReachedIsNotABudgetFailure proves the ceiling fires on
// overflow rather than on arrival.
//
// A run that produced exactly MaxFindings findings with nothing dropped was
// reported as a budget failure, which CLAUDE.md turns into incomplete and exit
// code 2. Every finding was present and correct; the run was rejected for
// fitting the budget exactly.
func TestFindingCeilingReachedIsNotABudgetFailure(t *testing.T) {
	change := changed("package.json", nil, fixture(t, "malicious", "pfr-dep-002-git-dependency.json"))

	unbounded := analyze(t, change)
	if len(unbounded.Findings) == 0 {
		t.Fatalf("the fixture produced no findings to bound; rules present: %v", ruleIDs(unbounded))
	}

	limits := run.DefaultLimits()
	limits.MaxFindings = len(unbounded.Findings)
	result := analyzeWithLimits(t, limits, change)

	if len(result.Findings) != len(unbounded.Findings) {
		t.Errorf("returned %d of %d findings at a ceiling that fits them all",
			len(result.Findings), len(unbounded.Findings))
	}
	for _, d := range result.Diagnostics {
		if strings.Contains(d.Code, "budget") {
			t.Errorf("a run that dropped nothing reported a budget failure: %+v", d)
		}
	}
	if result.Completion != run.CompletionComplete {
		t.Fatalf("completion = %q, want complete when nothing was dropped (diagnostics: %+v)",
			result.Completion, result.Diagnostics)
	}
}
