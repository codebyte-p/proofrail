package dependency_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dependency "github.com/codebyte-p/proofrail/internal/analyzer/dependency"
	"github.com/codebyte-p/proofrail/internal/finding"
	"github.com/codebyte-p/proofrail/internal/gitdiff"
	"github.com/codebyte-p/proofrail/internal/run"
)

func fixture(t *testing.T, class, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", class, "dependency", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return content
}

func testIdentity() run.RunIdentity {
	return run.RunIdentity{
		Repository:    "codebyte-p/proofrail",
		BaseSHA:       strings.Repeat("a", 40),
		HeadSHA:       strings.Repeat("b", 40),
		PolicyDigest:  "sha256:" + strings.Repeat("c", 64),
		WaiverDigest:  "sha256:" + strings.Repeat("d", 64),
		EngineVersion: "0.1.0-alpha",
		EvaluatedAt:   time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
	}
}

func analyze(t *testing.T, files ...gitdiff.FileChange) run.AnalyzerResult {
	t.Helper()
	return dependency.New().Analyze(context.Background(), run.AnalysisInput{
		Identity: testIdentity(),
		Changes: gitdiff.ChangeSet{
			Repository: "codebyte-p/proofrail",
			BaseSHA:    strings.Repeat("a", 40),
			HeadSHA:    strings.Repeat("b", 40),
			Files:      files,
		},
		Limits: run.DefaultLimits(),
	})
}

// changed models a modified file with distinct base and head content.
func changed(path string, base, head []byte) gitdiff.FileChange {
	kind := gitdiff.Modified
	if len(base) == 0 {
		kind = gitdiff.Added
	}
	return gitdiff.FileChange{
		Path:        path,
		Kind:        kind,
		Mode:        gitdiff.ModeFile,
		BaseContent: base,
		HeadContent: head,
	}
}

// unchanged models a file present in the change set whose content is identical
// on both sides, which is how a lock appears when only the manifest moved.
func unchanged(path string, content []byte) gitdiff.FileChange {
	return changed(path, content, content)
}

func findingsFor(result run.AnalyzerResult, ruleID string) []finding.Finding {
	var out []finding.Finding
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func ruleIDs(result run.AnalyzerResult) []string {
	out := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func hasEvidenceKind(f finding.Finding, kind string) bool {
	for _, e := range f.Evidence {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestAnalyzerIdentity(t *testing.T) {
	if got := dependency.New().ID(); got != "dependency" {
		t.Fatalf("analyzer id = %q, want dependency", got)
	}
}

// TestManifestLockMismatch covers PFR-DEP-001: a dependency is declared in the
// manifest with no corresponding lock resolution, so the build is not bound.
func TestManifestLockMismatch(t *testing.T) {
	result := analyze(t,
		changed("package.json",
			fixture(t, "malicious", "pfr-dep-001-manifest-lock-mismatch.base.json"),
			fixture(t, "malicious", "pfr-dep-001-manifest-lock-mismatch.head.json")),
		unchanged("package-lock.json", fixture(t, "malicious", "pfr-dep-001-lock.json")),
	)

	if result.Completion != run.CompletionComplete {
		t.Fatalf("completion = %q, want complete (diagnostics: %+v)", result.Completion, result.Diagnostics)
	}
	matches := findingsFor(result, "PFR-DEP-001")
	if len(matches) != 1 {
		t.Fatalf("expected one PFR-DEP-001, got %d (all: %v)", len(matches), ruleIDs(result))
	}
	f := matches[0]
	if f.DecisionHint != finding.DecisionBlock {
		t.Errorf("decision = %q, want block", f.DecisionHint)
	}
	if !hasEvidenceKind(f, "dependency_declaration") {
		t.Errorf("missing dependency_declaration evidence: %+v", f.Evidence)
	}
	if !strings.Contains(f.Message, "new-helper") {
		t.Errorf("message does not name the unresolved dependency: %q", f.Message)
	}
}

func TestManifestLockInSyncIsClean(t *testing.T) {
	result := analyze(t,
		changed("package.json", nil, fixture(t, "benign", "pfr-dep-001-in-sync.head.json")),
		unchanged("package-lock.json", fixture(t, "benign", "pfr-dep-001-lock.json")),
	)
	if matches := findingsFor(result, "PFR-DEP-001"); len(matches) != 0 {
		t.Fatalf("PFR-DEP-001 fired on a manifest in sync with its lock: %+v", matches)
	}
}

// TestNonRegistryDependency covers PFR-DEP-002 across both ecosystems, proving
// one rule serves npm and Python rather than each ecosystem carrying its own.
func TestNonRegistryDependency(t *testing.T) {
	cases := []struct {
		name    string
		file    gitdiff.FileChange
		wantDec finding.Decision
	}{
		{
			name:    "npm git dependency on a mutable branch",
			file:    changed("package.json", nil, fixture(t, "malicious", "pfr-dep-002-git-dependency.json")),
			wantDec: finding.DecisionBlock,
		},
		{
			name:    "python git source on a mutable branch",
			file:    changed("pyproject.toml", nil, fixture(t, "malicious", "pfr-dep-002-python-git-source.toml")),
			wantDec: finding.DecisionBlock,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyze(t, tc.file)
			matches := findingsFor(result, "PFR-DEP-002")
			if len(matches) != 1 {
				t.Fatalf("expected one PFR-DEP-002, got %d (all: %v)", len(matches), ruleIDs(result))
			}
			if matches[0].DecisionHint != tc.wantDec {
				t.Errorf("decision = %q, want %q", matches[0].DecisionHint, tc.wantDec)
			}
			if !hasEvidenceKind(matches[0], "dependency_source") {
				t.Errorf("missing dependency_source evidence: %+v", matches[0].Evidence)
			}
		})
	}
}

func TestRegistryDependencyIsClean(t *testing.T) {
	for _, tc := range []struct{ path, fixture string }{
		{"package.json", "pfr-dep-002-registry-dependency.json"},
		{"pyproject.toml", "pfr-dep-002-python-registry.toml"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			result := analyze(t, changed(tc.path, nil, fixture(t, "benign", tc.fixture)))
			if matches := findingsFor(result, "PFR-DEP-002"); len(matches) != 0 {
				t.Fatalf("PFR-DEP-002 fired on a pinned registry dependency: %+v", matches)
			}
		})
	}
}

// TestLifecycleExecutionIntroduced covers PFR-DEP-003: a new install-time hook
// expands what runs on a developer or CI machine.
func TestLifecycleExecutionIntroduced(t *testing.T) {
	result := analyze(t, changed("package.json",
		fixture(t, "malicious", "pfr-dep-003-lifecycle-script.base.json"),
		fixture(t, "malicious", "pfr-dep-003-lifecycle-script.head.json")))

	matches := findingsFor(result, "PFR-DEP-003")
	if len(matches) != 1 {
		t.Fatalf("expected one PFR-DEP-003, got %d (all: %v)", len(matches), ruleIDs(result))
	}
	if matches[0].DecisionHint != finding.DecisionRequireReview {
		t.Errorf("decision = %q, want require_review", matches[0].DecisionHint)
	}
	if !hasEvidenceKind(matches[0], "lifecycle_script") {
		t.Errorf("missing lifecycle_script evidence: %+v", matches[0].Evidence)
	}
	if !strings.Contains(matches[0].Message, "postinstall") {
		t.Errorf("message does not name the hook: %q", matches[0].Message)
	}
}

func TestUnchangedLifecycleScriptIsClean(t *testing.T) {
	content := fixture(t, "benign", "pfr-dep-003-no-lifecycle-change.json")
	result := analyze(t, unchanged("package.json", content))
	if matches := findingsFor(result, "PFR-DEP-003"); len(matches) != 0 {
		t.Fatalf("PFR-DEP-003 fired on an unchanged script set: %+v", matches)
	}
}

// TestResolvedSourceChanged covers PFR-DEP-004: the name and version are
// untouched but the artifact the lock points at is different.
func TestResolvedSourceChanged(t *testing.T) {
	result := analyze(t, changed("package-lock.json",
		fixture(t, "malicious", "pfr-dep-004-source-changed.base.json"),
		fixture(t, "malicious", "pfr-dep-004-source-changed.head.json")))

	matches := findingsFor(result, "PFR-DEP-004")
	if len(matches) != 1 {
		t.Fatalf("expected one PFR-DEP-004, got %d (all: %v)", len(matches), ruleIDs(result))
	}
	f := matches[0]
	if f.DecisionHint != finding.DecisionBlock {
		t.Errorf("decision = %q, want block", f.DecisionHint)
	}
	if !hasEvidenceKind(f, "resolved_identity") {
		t.Errorf("missing resolved_identity evidence: %+v", f.Evidence)
	}
	if !strings.Contains(f.Message, "left-pad") {
		t.Errorf("message does not name the package: %q", f.Message)
	}
}

func TestResolvedSourceUnchangedIsClean(t *testing.T) {
	content := fixture(t, "benign", "pfr-dep-004-source-unchanged.json")
	result := analyze(t, unchanged("package-lock.json", content))
	if matches := findingsFor(result, "PFR-DEP-004"); len(matches) != 0 {
		t.Fatalf("PFR-DEP-004 fired on an unchanged resolved identity: %+v", matches)
	}
}

// TestGraphExpansion covers PFR-DEP-005, whose decision rises with the size of
// the delta rather than firing at the same level for every addition.
func TestGraphExpansion(t *testing.T) {
	result := analyze(t, changed("package.json",
		fixture(t, "malicious", "pfr-dep-005-graph-expansion.base.json"),
		fixture(t, "malicious", "pfr-dep-005-graph-expansion.head.json")))

	matches := findingsFor(result, "PFR-DEP-005")
	if len(matches) != 1 {
		t.Fatalf("expected one PFR-DEP-005, got %d (all: %v)", len(matches), ruleIDs(result))
	}
	if matches[0].DecisionHint != finding.DecisionRequireReview {
		t.Errorf("decision = %q, want require_review for a five-dependency delta", matches[0].DecisionHint)
	}
	if !hasEvidenceKind(matches[0], "dependency_delta") {
		t.Errorf("missing dependency_delta evidence: %+v", matches[0].Evidence)
	}
}

func TestSmallGraphExpansionOnlyObserves(t *testing.T) {
	result := analyze(t, changed("package.json",
		fixture(t, "malicious", "pfr-dep-005-graph-expansion.base.json"),
		fixture(t, "benign", "pfr-dep-005-single-addition.head.json")))

	matches := findingsFor(result, "PFR-DEP-005")
	if len(matches) != 1 {
		t.Fatalf("expected one PFR-DEP-005, got %d (all: %v)", len(matches), ruleIDs(result))
	}
	if matches[0].DecisionHint != finding.DecisionObserve {
		t.Errorf("decision = %q, want observe for a one-dependency delta", matches[0].DecisionHint)
	}
}

// TestSuspiciousNameSimilarity covers PFR-DEP-006.
func TestSuspiciousNameSimilarity(t *testing.T) {
	result := analyze(t, changed("package.json",
		fixture(t, "malicious", "pfr-dep-006-name-similarity.base.json"),
		fixture(t, "malicious", "pfr-dep-006-name-similarity.head.json")))

	matches := findingsFor(result, "PFR-DEP-006")
	if len(matches) != 1 {
		t.Fatalf("expected one PFR-DEP-006, got %d (all: %v)", len(matches), ruleIDs(result))
	}
	if !hasEvidenceKind(matches[0], "name_similarity") {
		t.Errorf("missing name_similarity evidence: %+v", matches[0].Evidence)
	}
}

func TestDistinctNameIsClean(t *testing.T) {
	result := analyze(t, changed("package.json",
		fixture(t, "malicious", "pfr-dep-006-name-similarity.base.json"),
		fixture(t, "benign", "pfr-dep-006-distinct-name.head.json")))

	if matches := findingsFor(result, "PFR-DEP-006"); len(matches) != 0 {
		t.Fatalf("PFR-DEP-006 fired on a clearly distinct name: %+v", matches)
	}
}

// TestNameSimilarityCanNeverBlock is the version 1 guarantee from
// docs/analyzers.md: the heuristic is noisy, so it warns and nothing about it
// can escalate on its own.
func TestNameSimilarityCanNeverBlock(t *testing.T) {
	suspicious := [][2]string{
		{"pfr-dep-006-name-similarity.base.json", "pfr-dep-006-name-similarity.head.json"},
		{"pfr-dep-005-graph-expansion.base.json", "pfr-dep-005-graph-expansion.head.json"},
	}

	for _, pair := range suspicious {
		result := analyze(t, changed("package.json",
			fixture(t, "malicious", pair[0]),
			fixture(t, "malicious", pair[1])))

		for _, f := range findingsFor(result, "PFR-DEP-006") {
			if f.DecisionHint != finding.DecisionWarn {
				t.Errorf("PFR-DEP-006 decision = %q, want warn: version 1 may never block on name similarity", f.DecisionHint)
			}
			if f.Severity.Rank() > finding.SeverityLow.Rank() {
				t.Errorf("PFR-DEP-006 severity = %q, want low or below", f.Severity)
			}
		}
	}
}

// TestMustDetectFixturesAreLabeled keeps the corpus label honest. JSON has no
// comment syntax, so the label lives in a sidecar a reviewer can read.
func TestMustDetectFixturesAreLabeled(t *testing.T) {
	labels := string(fixture(t, "malicious", "MUST_DETECT.txt"))
	for _, want := range []string{
		"PFR-DEP-001 pfr-dep-001-manifest-lock-mismatch.head.json",
		"PFR-DEP-004 pfr-dep-004-source-changed.head.json",
	} {
		if !strings.Contains(labels, want) {
			t.Errorf("MUST_DETECT.txt does not label %q", want)
		}
	}
}

// TestAnalyzerIsNotApplicableWithoutDependencyFiles proves an unrelated change
// set reports not_applicable rather than a hollow complete.
func TestAnalyzerIsNotApplicableWithoutDependencyFiles(t *testing.T) {
	result := analyze(t, changed("README.md", nil, []byte("# docs\n")))
	if result.Completion != run.CompletionNotApplicable {
		t.Fatalf("completion = %q, want not_applicable", result.Completion)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %v", ruleIDs(result))
	}
}

// TestUnsupportedManagerProducesCoverageNote proves an ecosystem version 1 does
// not model is stated explicitly instead of passing silently.
func TestUnsupportedManagerProducesCoverageNote(t *testing.T) {
	result := analyze(t, changed("Cargo.toml", nil, []byte("[package]\nname = \"x\"\n")))

	if result.Completion != run.CompletionNotApplicable {
		t.Fatalf("completion = %q, want not_applicable", result.Completion)
	}
	joined := strings.Join(result.CoverageNotes, "\n")
	if !strings.Contains(joined, "Cargo.toml") {
		t.Errorf("coverage notes %q do not mention the unsupported manifest", joined)
	}
}

// TestAnalyzerFailsClosedOnRejectedFile proves an unparseable required input
// makes the analyzer fail rather than report a clean result.
func TestAnalyzerFailsClosedOnRejectedFile(t *testing.T) {
	for _, tc := range []struct{ path, fixture string }{
		{"package.json", "duplicate-key.json"},
		{"pyproject.toml", "unsupported-construct.toml"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			result := analyze(t, changed(tc.path, nil, fixture(t, "malformed", tc.fixture)))
			if result.Completion != run.CompletionFailed {
				t.Fatalf("completion = %q, want failed", result.Completion)
			}
			if len(result.Diagnostics) == 0 {
				t.Error("a failed analyzer must explain itself with diagnostics")
			}
		})
	}
}

// TestFindingsSurviveAnotherFileFailingToParse mirrors the PFR-WF guarantee:
// completed evidence is retained when a different file is rejected.
func TestFindingsSurviveAnotherFileFailingToParse(t *testing.T) {
	result := analyze(t,
		changed("package.json", nil, fixture(t, "malicious", "pfr-dep-002-git-dependency.json")),
		changed("pyproject.toml", nil, fixture(t, "malformed", "unsupported-construct.toml")),
	)

	if result.Completion != run.CompletionFailed {
		t.Fatalf("completion = %q, want failed", result.Completion)
	}
	if len(findingsFor(result, "PFR-DEP-002")) != 1 {
		t.Fatalf("evidence from the file that parsed was discarded; rules present: %v", ruleIDs(result))
	}
}

// TestAnalyzerIsDeterministic proves repeated runs produce identical findings
// in identical order, which canonical output requires.
func TestAnalyzerIsDeterministic(t *testing.T) {
	files := []gitdiff.FileChange{
		changed("package.json",
			fixture(t, "malicious", "pfr-dep-005-graph-expansion.base.json"),
			fixture(t, "malicious", "pfr-dep-005-graph-expansion.head.json")),
		changed("package-lock.json",
			fixture(t, "malicious", "pfr-dep-004-source-changed.base.json"),
			fixture(t, "malicious", "pfr-dep-004-source-changed.head.json")),
	}

	first := analyze(t, files...)
	second := analyze(t, files...)

	if len(first.Findings) == 0 {
		t.Fatal("expected findings across the malicious corpus")
	}
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("finding count differs: %d vs %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].Fingerprint != second.Findings[i].Fingerprint {
			t.Fatalf("finding %d differs between runs", i)
		}
		if i > 0 && first.Findings[i-1].Fingerprint > first.Findings[i].Fingerprint {
			t.Fatalf("findings are not ordered by fingerprint at index %d", i)
		}
	}
}

// TestAnalyzerNeverEmitsRawSecretValues proves a credential embedded in a
// dependency specifier is redacted before it leaves the analyzer.
func TestAnalyzerNeverEmitsRawSecretValues(t *testing.T) {
	const leaked = "ghp_0123456789abcdef0123456789abcdef0123"
	content := `{"name":"x","dependencies":{"private-lib":"git+https://` + leaked + `@example.invalid/team/lib.git#main"}}`

	result := analyze(t, changed("package.json", nil, []byte(content)))

	if len(findingsFor(result, "PFR-DEP-002")) == 0 {
		t.Fatalf("expected PFR-DEP-002 to carry the specifier as evidence, got %v", ruleIDs(result))
	}
	for _, f := range result.Findings {
		if strings.Contains(f.Message, leaked) {
			t.Errorf("finding message leaked a credential: %q", f.Message)
		}
		for _, e := range f.Evidence {
			if strings.Contains(e.Excerpt, leaked) || strings.Contains(e.Source, leaked) {
				t.Errorf("evidence leaked a credential: %+v", e)
			}
		}
	}
}
