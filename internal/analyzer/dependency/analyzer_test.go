package dependency_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
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

// analyzeWithLimits runs the analyzer under caller-chosen bounds, so a budget
// can be exercised without building a corpus large enough to hit the real one.
func analyzeWithLimits(t *testing.T, limits run.Limits, files ...gitdiff.FileChange) run.AnalyzerResult {
	t.Helper()
	return dependency.New().Analyze(context.Background(), run.AnalysisInput{
		Identity: testIdentity(),
		Changes: gitdiff.ChangeSet{
			Repository: "codebyte-p/proofrail",
			BaseSHA:    strings.Repeat("a", 40),
			HeadSHA:    strings.Repeat("b", 40),
			Files:      files,
		},
		Limits: limits,
	})
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
		// A mutable or outside source is a Gate 1 must-detect scenario in its
		// own right, so each canonical spelling of one is labeled here.
		"PFR-DEP-002 pfr-dep-002-git-dependency.json",
		"PFR-DEP-002 pfr-dep-002-url-dependency.json",
		"PFR-DEP-002 pfr-dep-002-path-escape.json",
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

// ----------------------------------------------------------------------------
// Independent-review regression tests
// ----------------------------------------------------------------------------

// TestExecutableDependencyFileIsStillAnalyzed proves the executable bit does not
// exempt a dependency file from analysis. A package manager reads package.json
// regardless of its mode, so skipping 100755 would let `chmod +x` evade every
// PFR-DEP rule. Review finding H1.
func TestExecutableDependencyFileIsStillAnalyzed(t *testing.T) {
	change := changed("package.json", nil, fixture(t, "malicious", "pfr-dep-002-git-dependency.json"))
	change.Mode = gitdiff.ModeExecutable

	result := analyze(t, change)

	if result.Completion != run.CompletionComplete {
		t.Fatalf("completion = %q, want complete (notes: %v)", result.Completion, result.CoverageNotes)
	}
	if len(findingsFor(result, "PFR-DEP-002")) != 1 {
		t.Fatalf("an executable manifest evaded analysis; rules present: %v", ruleIDs(result))
	}
}

// TestBuildRequirementsAreAnalyzed proves a build backend requirement is subject
// to the same source rules as a runtime dependency.
//
// `build-system.requires` installs and executes at build time, so a mutable Git
// requirement there is at least as dangerous as one in `dependencies`. The
// parser read the field but the analyzer never ingested it, leaving it invisible
// to every rule. Review finding H2.
func TestBuildRequirementsAreAnalyzed(t *testing.T) {
	const content = `[project]
name = "example"
version = "1.0.0"

[build-system]
requires = ["setuptools @ git+https://example.invalid/team/setuptools.git@main"]
build-backend = "setuptools.build_meta"
`

	result := analyze(t, changed("pyproject.toml", nil, []byte(content)))

	matches := findingsFor(result, "PFR-DEP-002")
	if len(matches) != 1 {
		t.Fatalf("a mutable build requirement was not reported; rules present: %v", ruleIDs(result))
	}
	if matches[0].DecisionHint != finding.DecisionBlock {
		t.Errorf("decision = %q, want block", matches[0].DecisionHint)
	}
	if !strings.Contains(matches[0].Message, "setuptools") {
		t.Errorf("message does not name the build requirement: %q", matches[0].Message)
	}
}

// TestNPMGitShorthandIsNotTreatedAsRegistry proves npm's `owner/repo` shorthand
// is classified as the Git dependency it is.
//
// npm resolves a bare `owner/repo` to GitHub. Falling through to the registry
// branch classified it as a registry dependency, and PFR-DEP-002 skips registry
// sources outright, so the shorthand produced no finding at all. Review finding
// H4.
func TestNPMGitShorthandIsNotTreatedAsRegistry(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"bare shorthand", "example-org/internal-tool"},
		{"shorthand with branch", "example-org/internal-tool#main"},
		{"shorthand with commit", "example-org/internal-tool#0123456789abcdef0123456789abcdef01234567"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := `{"name":"example","dependencies":{"internal-tool":"` + tc.spec + `"}}`
			result := analyze(t, changed("package.json", nil, []byte(content)))

			matches := findingsFor(result, "PFR-DEP-002")
			if len(matches) != 1 {
				t.Fatalf("%q produced no PFR-DEP-002; rules present: %v", tc.spec, ruleIDs(result))
			}
			// docs/analyzers.md blocks when a source is mutable *or* outside
			// the repository, and a Git dependency is outside it whether or not
			// the reference is pinned. Only a source that is both immutable and
			// inside the tree, such as a contained workspace path, reaches
			// review.
			if matches[0].DecisionHint != finding.DecisionBlock {
				t.Errorf("decision = %q, want block", matches[0].DecisionHint)
			}
		})
	}
}

// TestManifestOnlyChangeIsAMismatch proves a dependency added without any
// lockfile update is reported.
//
// The rule returned early whenever the change set carried no resolved packages,
// which is exactly the shape of the most common mismatch: edit the manifest and
// leave the lock alone. Review finding H5.
func TestManifestOnlyChangeIsAMismatch(t *testing.T) {
	result := analyze(t, changed("package.json",
		fixture(t, "malicious", "pfr-dep-001-manifest-lock-mismatch.base.json"),
		fixture(t, "malicious", "pfr-dep-001-manifest-lock-mismatch.head.json")))

	matches := findingsFor(result, "PFR-DEP-001")
	if len(matches) != 1 {
		t.Fatalf("a manifest-only dependency addition evaded PFR-DEP-001; rules present: %v", ruleIDs(result))
	}
	if matches[0].DecisionHint != finding.DecisionBlock {
		t.Errorf("decision = %q, want block", matches[0].DecisionHint)
	}
	if !strings.Contains(matches[0].Message, "new-helper") {
		t.Errorf("message does not name the unresolved dependency: %q", matches[0].Message)
	}
}

// TestDeletedLockIsAMismatch proves removing the lockfile is reported rather
// than silently skipped as an unreadable file. Deleting the lock unbinds every
// dependency at once. Review finding H5.
func TestDeletedLockIsAMismatch(t *testing.T) {
	result := analyze(t,
		unchanged("package.json", fixture(t, "benign", "pfr-dep-001-in-sync.head.json")),
		gitdiff.FileChange{
			Path:        "package-lock.json",
			Kind:        gitdiff.Deleted,
			Mode:        gitdiff.ModeFile,
			BaseContent: fixture(t, "benign", "pfr-dep-001-lock.json"),
		},
	)

	matches := findingsFor(result, "PFR-DEP-001")
	if len(matches) != 1 {
		t.Fatalf("a deleted lockfile evaded PFR-DEP-001; rules present: %v", ruleIDs(result))
	}
	if matches[0].DecisionHint != finding.DecisionBlock {
		t.Errorf("decision = %q, want block", matches[0].DecisionHint)
	}
}

// TestExactPinDisagreeingWithLockIsAMismatch proves the rule compares the
// resolved version against the declared one, not merely that the name appears.
//
// A manifest pinned to 1.3.0 against a lock resolving 9.9.9 is an inconsistent
// resolved identity, which is what PFR-DEP-001 exists to catch. Checking only
// name presence let that through. Review finding H6.
func TestExactPinDisagreeingWithLockIsAMismatch(t *testing.T) {
	const manifest = `{"name":"example","dependencies":{"left-pad":"1.3.0"}}`
	const lock = `{
  "name": "example",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/left-pad": {
      "version": "9.9.9",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-9.9.9.tgz",
      "integrity": "sha512-left"
    }
  }
}`

	result := analyze(t,
		changed("package.json", nil, []byte(manifest)),
		changed("package-lock.json", nil, []byte(lock)),
	)

	matches := findingsFor(result, "PFR-DEP-001")
	if len(matches) != 1 {
		t.Fatalf("an exact pin disagreeing with the lock evaded PFR-DEP-001; rules present: %v", ruleIDs(result))
	}
	if !strings.Contains(matches[0].Message, "left-pad") {
		t.Errorf("message does not name the package: %q", matches[0].Message)
	}
}

// TestExactPinAgreeingWithLockIsClean guards the H6 fix against over-reach.
func TestExactPinAgreeingWithLockIsClean(t *testing.T) {
	const manifest = `{"name":"example","dependencies":{"left-pad":"1.3.0"}}`

	result := analyze(t,
		changed("package.json", nil, []byte(manifest)),
		changed("package-lock.json", nil, fixture(t, "benign", "pfr-dep-001-lock.json")),
	)

	if matches := findingsFor(result, "PFR-DEP-001"); len(matches) != 0 {
		t.Fatalf("PFR-DEP-001 fired on a pin that agrees with the lock: %+v", matches)
	}
}

// TestDiagnosticsAndCoverageNotesAreRedacted proves the two result channels that
// are not findings still go through redaction.
//
// finding.Finalize redacts messages, evidence, and limitations, but diagnostics
// and coverage notes bypass it entirely while still reaching the console, logs,
// and published reports. Both carry repository-derived key names. Review
// mediums M1a and M1b.
func TestDiagnosticsAndCoverageNotesAreRedacted(t *testing.T) {
	const leaked = "ghp_0123456789abcdef0123456789abcdef0123"

	t.Run("coverage note", func(t *testing.T) {
		// An unmodeled top-level field is reported by name.
		content := `{"name":"example","` + leaked + `":"value"}`
		result := analyze(t, changed("package.json", nil, []byte(content)))

		joined := strings.Join(result.CoverageNotes, "\n")
		if joined == "" {
			t.Fatal("expected a coverage note naming the unmodeled field")
		}
		if strings.Contains(joined, leaked) {
			t.Errorf("a coverage note leaked a credential: %q", joined)
		}
	})

	t.Run("diagnostic", func(t *testing.T) {
		// A duplicate key is reported with the key in the locator.
		content := `{"` + leaked + `":1,"` + leaked + `":2}`
		result := analyze(t, changed("package.json", nil, []byte(content)))

		if len(result.Diagnostics) == 0 {
			t.Fatal("expected a duplicate-key diagnostic")
		}
		for _, d := range result.Diagnostics {
			if strings.Contains(d.Path, leaked) || strings.Contains(d.Message, leaked) {
				t.Errorf("a diagnostic leaked a credential: %+v", d)
			}
		}
	})
}

// TestFindingBudgetIsEnforced proves exceeding the finding ceiling is a budget
// failure rather than a silent truncation.
//
// docs/architecture.md caps a run at 5,000 findings and CLAUDE.md makes any
// budget failure yield incomplete and exit code 2. Nothing read MaxFindings, so
// a hostile manifest could emit an unbounded number. Review medium M3.
func TestFindingBudgetIsEnforced(t *testing.T) {
	var deps []string
	for i := 0; i < 12; i++ {
		deps = append(deps, `"tool-`+strconv.Itoa(i)+`":"git+https://example.invalid/t`+strconv.Itoa(i)+`.git#main"`)
	}
	content := `{"name":"example","dependencies":{` + strings.Join(deps, ",") + `}}`

	limits := run.DefaultLimits()
	limits.MaxFindings = 5

	result := analyzeWithLimits(t, limits, changed("package.json", nil, []byte(content)))

	if result.Completion != run.CompletionFailed {
		t.Fatalf("completion = %q, want failed when the finding budget is exceeded", result.Completion)
	}
	if len(result.Findings) > limits.MaxFindings {
		t.Errorf("returned %d findings, above the %d ceiling", len(result.Findings), limits.MaxFindings)
	}
	var budget bool
	for _, d := range result.Diagnostics {
		if strings.Contains(d.Code, "budget") {
			budget = true
		}
	}
	if !budget {
		t.Errorf("no budget diagnostic explains the failure: %+v", result.Diagnostics)
	}
}

// TestSameNameInDifferentEcosystemsDoesNotCollide proves records are keyed by
// ecosystem as well as name.
//
// `requests` exists on both npm and PyPI. Keying the comparison maps by name
// alone let a Python package already in the base revision mask a genuinely new
// npm package of the same name, so the npm addition was never counted as added.
// Review medium M4.
func TestSameNameInDifferentEcosystemsDoesNotCollide(t *testing.T) {
	const pyproject = `[project]
name = "example"
dependencies = ["requests>=2.31.0"]
`
	const npmBase = `{"name":"example","dependencies":{}}`
	const npmHead = `{"name":"example","dependencies":{"requests":"^1.0.0"}}`

	result := analyze(t,
		unchanged("pyproject.toml", []byte(pyproject)),
		changed("package.json", []byte(npmBase), []byte(npmHead)),
	)

	// Graph expansion counts declarations the head introduced. The npm
	// `requests` is new to npm regardless of what PyPI package shares its name.
	matches := findingsFor(result, "PFR-DEP-005")
	if len(matches) != 1 {
		t.Fatalf("the npm addition was masked by the Python package of the same name; rules present: %v", ruleIDs(result))
	}
	if !strings.Contains(matches[0].Message, "requests") {
		t.Errorf("message does not name the added dependency: %q", matches[0].Message)
	}
}

// TestPathDependencyEscapingTheRepositoryBlocks proves a local path that leaves
// the repository is treated as outside it.
//
// docs/analyzers.md says PFR-DEP-002 blocks when a source is "mutable or
// outside repository". Only Git and URL sources were tested for that, so a
// `file:` specifier climbing out of the tree was routed to review. Review
// medium M5.
func TestPathDependencyEscapingTheRepositoryBlocks(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want finding.Decision
	}{
		{"escaping parent path", "file:../../../shared/lib", finding.DecisionBlock},
		{"absolute path", "file:/opt/vendor/lib", finding.DecisionBlock},
		{"contained path", "file:./packages/lib", finding.DecisionRequireReview},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := `{"name":"example","dependencies":{"local-lib":"` + tc.spec + `"}}`
			result := analyze(t, changed("package.json", nil, []byte(content)))

			matches := findingsFor(result, "PFR-DEP-002")
			if len(matches) != 1 {
				t.Fatalf("expected one PFR-DEP-002 for %q, got %v", tc.spec, ruleIDs(result))
			}
			if matches[0].DecisionHint != tc.want {
				t.Errorf("decision = %q, want %q", matches[0].DecisionHint, tc.want)
			}
		})
	}
}

// TestUnparseableBaseFailsClosed proves a base revision that will not parse is a
// failure rather than an empty baseline.
//
// An empty baseline makes PFR-DEP-004 treat every locked package as new and
// skip it, so a corrupted base lock suppressed the rule entirely. That is
// fail-open, and CLAUDE.md requires the fail-closed reading when a required
// parser input cannot be read. Review medium M6.
func TestUnparseableBaseFailsClosed(t *testing.T) {
	result := analyze(t, changed("package-lock.json",
		[]byte(`{"lockfileVersion":3,"packages":{"a":1,"a":2}}`),
		fixture(t, "benign", "pfr-dep-004-source-unchanged.json")))

	if result.Completion != run.CompletionFailed {
		t.Fatalf("completion = %q, want failed when the base revision cannot be parsed", result.Completion)
	}
	if len(result.Diagnostics) == 0 {
		t.Error("an unreadable base must explain itself with a diagnostic")
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
