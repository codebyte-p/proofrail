package workflow_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	workflowanalyzer "github.com/codebyte-p/proofrail/internal/analyzer/workflow"
	"github.com/codebyte-p/proofrail/internal/finding"
	"github.com/codebyte-p/proofrail/internal/gitdiff"
	"github.com/codebyte-p/proofrail/internal/run"
)

func fixture(t *testing.T, class, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", class, "workflow", name)
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

func inputWith(files ...gitdiff.FileChange) run.AnalysisInput {
	return run.AnalysisInput{
		Identity: testIdentity(),
		Changes: gitdiff.ChangeSet{
			Repository: "codebyte-p/proofrail",
			BaseSHA:    strings.Repeat("a", 40),
			HeadSHA:    strings.Repeat("b", 40),
			Files:      files,
		},
		Limits: run.DefaultLimits(),
	}
}

// addedWorkflow models a workflow file introduced by the pull request, which is
// the common shape: there is no base version to compare against.
func addedWorkflow(t *testing.T, class, name string) gitdiff.FileChange {
	t.Helper()
	return gitdiff.FileChange{
		Path:        ".github/workflows/" + name,
		Kind:        gitdiff.Added,
		Mode:        gitdiff.ModeFile,
		HeadContent: fixture(t, class, name),
	}
}

func analyze(t *testing.T, files ...gitdiff.FileChange) run.AnalyzerResult {
	t.Helper()
	return workflowanalyzer.New().Analyze(context.Background(), inputWith(files...))
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

func hasLocationLine(f finding.Finding, path string, line int) bool {
	for _, loc := range f.Locations {
		if loc.Path == path && loc.StartLine <= line && line <= loc.EndLine {
			return true
		}
	}
	return false
}

func TestAnalyzerIdentity(t *testing.T) {
	if got := workflowanalyzer.New().ID(); got != "github-workflow" {
		t.Fatalf("analyzer id = %q, want github-workflow", got)
	}
}

// ruleCase pins one PFR-WF rule to the malicious fixture it must detect and the
// compensating fixture it must leave alone, together with the exact severity,
// confidence, decision hint, evidence kind, anchor line, and limitation the
// rule is specified to emit.
type ruleCase struct {
	rule         string
	mustDetect   bool
	malicious    string
	benign       string
	severity     finding.Severity
	confidence   finding.Confidence
	decision     finding.Decision
	evidenceKind string
	anchorLine   int
	limitation   string
}

func ruleCases() []ruleCase {
	return []ruleCase{
		{
			rule:         "PFR-WF-001",
			mustDetect:   true,
			malicious:    "pfr-wf-001-privileged-untrusted-checkout.yml",
			benign:       "pfr-wf-001-base-checkout.yml",
			severity:     finding.SeverityHigh,
			confidence:   finding.ConfidenceHigh,
			decision:     finding.DecisionBlock,
			evidenceKind: "workflow_privileged_checkout",
			anchorLine:   12,
			limitation:   "organization",
		},
		{
			rule:         "PFR-WF-002",
			malicious:    "pfr-wf-002-write-all.yml",
			benign:       "pfr-wf-002-read-only.yml",
			severity:     finding.SeverityHigh,
			confidence:   finding.ConfidenceMedium,
			decision:     finding.DecisionRequireReview,
			evidenceKind: "workflow_permission",
			anchorLine:   4,
			limitation:   "publishing",
		},
		{
			rule:         "PFR-WF-003",
			malicious:    "pfr-wf-003-mutable-action.yml",
			benign:       "pfr-wf-003-sha-pinned.yml",
			severity:     finding.SeverityMedium,
			confidence:   finding.ConfidenceHigh,
			decision:     finding.DecisionRequireReview,
			evidenceKind: "workflow_action_reference",
			anchorLine:   8,
			limitation:   "commit SHA",
		},
		{
			rule:         "PFR-WF-004",
			mustDetect:   true,
			malicious:    "pfr-wf-004-expression-injection.yml",
			benign:       "pfr-wf-004-env-indirection.yml",
			severity:     finding.SeverityHigh,
			confidence:   finding.ConfidenceHigh,
			decision:     finding.DecisionBlock,
			evidenceKind: "workflow_expression_sink",
			anchorLine:   10,
			limitation:   "expression",
		},
		{
			rule:         "PFR-WF-005",
			mustDetect:   true,
			malicious:    "pfr-wf-005-secrets-to-untrusted.yml",
			benign:       "pfr-wf-005-secret-on-push.yml",
			severity:     finding.SeverityHigh,
			confidence:   finding.ConfidenceHigh,
			decision:     finding.DecisionBlock,
			evidenceKind: "workflow_secret_reference",
			anchorLine:   15,
			limitation:   "secret",
		},
		{
			rule:         "PFR-WF-006",
			malicious:    "pfr-wf-006-self-hosted.yml",
			benign:       "pfr-wf-006-hosted-runner.yml",
			severity:     finding.SeverityHigh,
			confidence:   finding.ConfidenceMedium,
			decision:     finding.DecisionRequireReview,
			evidenceKind: "workflow_runner_label",
			anchorLine:   6,
			limitation:   "ephemeral",
		},
	}
}

// TestRuleDetectsMaliciousFixture asserts each rule fires on its malicious
// fixture with the exact classification the analyzer contract specifies.
func TestRuleDetectsMaliciousFixture(t *testing.T) {
	for _, tc := range ruleCases() {
		t.Run(tc.rule, func(t *testing.T) {
			change := addedWorkflow(t, "malicious", tc.malicious)
			result := analyze(t, change)

			if result.Completion != run.CompletionComplete {
				t.Fatalf("completion = %q, want complete (diagnostics: %+v)", result.Completion, result.Diagnostics)
			}

			matches := findingsFor(result, tc.rule)
			if len(matches) != 1 {
				t.Fatalf("expected exactly one %s finding, got %d (all rules: %v)", tc.rule, len(matches), ruleIDs(result))
			}
			f := matches[0]

			if f.AnalyzerID != "github-workflow" {
				t.Errorf("analyzer id = %q, want github-workflow", f.AnalyzerID)
			}
			if f.Severity != tc.severity {
				t.Errorf("severity = %q, want %q", f.Severity, tc.severity)
			}
			if f.Confidence != tc.confidence {
				t.Errorf("confidence = %q, want %q", f.Confidence, tc.confidence)
			}
			if f.DecisionHint != tc.decision {
				t.Errorf("decision hint = %q, want %q", f.DecisionHint, tc.decision)
			}
			if !hasEvidenceKind(f, tc.evidenceKind) {
				t.Errorf("evidence kinds %v do not include %q", evidenceKinds(f), tc.evidenceKind)
			}
			if !hasLocationLine(f, change.Path, tc.anchorLine) {
				t.Errorf("locations %+v do not cover %s line %d", f.Locations, change.Path, tc.anchorLine)
			}
			if !limitationContains(f, tc.limitation) {
				t.Errorf("limitations %v do not mention %q", f.Limitations, tc.limitation)
			}
			if f.Fingerprint == "" {
				t.Error("finding was not finalized: fingerprint is empty")
			}
		})
	}
}

// TestRuleIgnoresBenignFixture asserts each compensating fixture is left alone,
// which is what keeps the analyzer from drowning a reviewer in noise.
func TestRuleIgnoresBenignFixture(t *testing.T) {
	for _, tc := range ruleCases() {
		t.Run(tc.rule, func(t *testing.T) {
			result := analyze(t, addedWorkflow(t, "benign", tc.benign))

			if result.Completion != run.CompletionComplete {
				t.Fatalf("completion = %q, want complete (diagnostics: %+v)", result.Completion, result.Diagnostics)
			}
			if matches := findingsFor(result, tc.rule); len(matches) != 0 {
				t.Fatalf("%s fired on its compensating fixture: %+v", tc.rule, matches)
			}
		})
	}
}

// TestMustDetectFixturesAreLabeled keeps the corpus label honest: a rule the
// plan marks must_detect has to say so in the fixture a reviewer reads.
func TestMustDetectFixturesAreLabeled(t *testing.T) {
	for _, tc := range ruleCases() {
		if !tc.mustDetect {
			continue
		}
		t.Run(tc.rule, func(t *testing.T) {
			content := string(fixture(t, "malicious", tc.malicious))
			if !strings.Contains(content, "must_detect: "+tc.rule) {
				t.Errorf("fixture %s is not labeled `must_detect: %s`", tc.malicious, tc.rule)
			}
		})
	}

	// A variant is an independent fixture, so it carries its own label; naming
	// the fixture it is an equivalent spelling of is what lets a reviewer see
	// that the corpus covers a scenario in every syntax GitHub accepts rather
	// than counting one scenario several times.
	for _, vc := range variantCases() {
		t.Run(vc.file, func(t *testing.T) {
			content := string(fixture(t, vc.class, vc.file))
			label := "must_detect: "
			if vc.class == "benign" {
				label = "expected_clean: "
			}
			for _, rule := range vc.rules {
				if !strings.Contains(content, label+rule) {
					t.Errorf("fixture %s is not labeled `%s%s`", vc.file, label, rule)
				}
			}
			if !strings.Contains(content, "variant_of: "+vc.canonical) {
				t.Errorf("fixture %s does not declare `variant_of: %s`", vc.file, vc.canonical)
			}
			// The named canonical fixture has to exist, or the label points at
			// a scenario nothing measures.
			fixture(t, vc.class, vc.canonical)
		})
	}
}

// TestRulesDoNotSuppressEachOther proves a later rule cannot hide an earlier
// one. The self-hosted fixture is also a privileged untrusted checkout, and both
// findings have to survive.
func TestRulesDoNotSuppressEachOther(t *testing.T) {
	result := analyze(t, addedWorkflow(t, "malicious", "pfr-wf-006-self-hosted.yml"))

	for _, want := range []string{"PFR-WF-001", "PFR-WF-006"} {
		if len(findingsFor(result, want)) == 0 {
			t.Errorf("expected %s among %v", want, ruleIDs(result))
		}
	}
}

// TestPermissionRuleRequiresNewlyIntroducedScope proves PFR-WF-002 compares
// against the base revision instead of flagging a permission the pull request
// did not touch.
func TestPermissionRuleRequiresNewlyIntroducedScope(t *testing.T) {
	content := fixture(t, "malicious", "pfr-wf-002-write-all.yml")
	unchanged := gitdiff.FileChange{
		Path:        ".github/workflows/pfr-wf-002-write-all.yml",
		Kind:        gitdiff.Modified,
		Mode:        gitdiff.ModeFile,
		BaseContent: content,
		HeadContent: content,
	}

	result := analyze(t, unchanged)
	if matches := findingsFor(result, "PFR-WF-002"); len(matches) != 0 {
		t.Fatalf("PFR-WF-002 fired on a permission the pull request did not introduce: %+v", matches)
	}
}

// TestAnalyzerIsNotApplicableWithoutWorkflows proves an unrelated change set
// reports not_applicable rather than a hollow complete.
func TestAnalyzerIsNotApplicableWithoutWorkflows(t *testing.T) {
	result := analyze(t, gitdiff.FileChange{
		Path:        "README.md",
		Kind:        gitdiff.Modified,
		Mode:        gitdiff.ModeFile,
		HeadContent: []byte("# docs\n"),
	})

	if result.Completion != run.CompletionNotApplicable {
		t.Fatalf("completion = %q, want not_applicable", result.Completion)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings, got %v", ruleIDs(result))
	}
}

// TestAnalyzerFailsClosedOnRejectedWorkflow proves an unparseable workflow makes
// the analyzer fail rather than silently report a clean run. A failed required
// analyzer is what drives the run to incomplete and exit code 2.
func TestAnalyzerFailsClosedOnRejectedWorkflow(t *testing.T) {
	for _, name := range []string{"duplicate-key.yml", "anchor-alias.yml"} {
		t.Run(name, func(t *testing.T) {
			result := analyze(t, addedWorkflow(t, "malformed", name))

			if result.Completion != run.CompletionFailed {
				t.Fatalf("completion = %q, want failed", result.Completion)
			}
			if len(result.Diagnostics) == 0 {
				t.Error("a failed analyzer must explain itself with diagnostics")
			}
			// A rejected workflow yields no findings of its own. Evidence from
			// workflows that did parse is preserved separately; see
			// TestFindingsSurviveAnotherWorkflowFailingToParse.
			if len(result.Findings) != 0 {
				t.Errorf("a rejected workflow must not yield findings, got %v", ruleIDs(result))
			}
		})
	}
}

// TestNoRuleClaimsCriticalSeverity holds the reservation line: critical is for
// evidence proving exposure of write-capable or equivalently critical
// authority, and no version 1 PFR-WF rule proves that on its own.
func TestNoRuleClaimsCriticalSeverity(t *testing.T) {
	for _, tc := range ruleCases() {
		t.Run(tc.rule, func(t *testing.T) {
			result := analyze(t, addedWorkflow(t, "malicious", tc.malicious))
			for _, f := range result.Findings {
				if f.Severity == finding.SeverityCritical {
					t.Errorf("%s claims critical severity without evidence of write-capable authority", f.RuleID)
				}
			}
		})
	}
}

// TestFindingsSurviveAnotherWorkflowFailingToParse proves completed evidence is
// retained when a different workflow in the same change set is rejected.
//
// The run still fails closed through the completion ledger, but discarding
// findings that were fully analyzed would throw away real evidence and tell a
// reviewer less than the engine actually knows.
func TestFindingsSurviveAnotherWorkflowFailingToParse(t *testing.T) {
	result := analyze(t,
		addedWorkflow(t, "malicious", "pfr-wf-001-privileged-untrusted-checkout.yml"),
		addedWorkflow(t, "malformed", "duplicate-key.yml"),
	)

	if result.Completion != run.CompletionFailed {
		t.Fatalf("completion = %q, want failed", result.Completion)
	}
	if len(result.Diagnostics) == 0 {
		t.Error("a failed analyzer must explain itself with diagnostics")
	}
	if len(findingsFor(result, "PFR-WF-001")) != 1 {
		t.Fatalf("the finding from the workflow that parsed was discarded; rules present: %v", ruleIDs(result))
	}
}

// TestAnalyzerResultCarriesNoOperationalTiming proves the serialized result is
// byte-identical for identical bound inputs.
//
// Canonical JSON is the source of truth and feeds the integrity digest, so no
// clock-derived value may appear in it. Operational timing is telemetry and
// belongs outside the canonical projection.
func TestAnalyzerResultCarriesNoOperationalTiming(t *testing.T) {
	change := addedWorkflow(t, "malicious", "pfr-wf-001-privileged-untrusted-checkout.yml")

	first, err := json.Marshal(analyze(t, change))
	if err != nil {
		t.Fatalf("marshal first result: %v", err)
	}
	second, err := json.Marshal(analyze(t, change))
	if err != nil {
		t.Fatalf("marshal second result: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf("analyzer result is not byte-identical across runs over identical input:\n first: %s\nsecond: %s", first, second)
	}
	for _, forbidden := range []string{"duration", "elapsed", "_ns"} {
		if bytes.Contains(bytes.ToLower(first), []byte(forbidden)) {
			t.Errorf("the canonical projection carries operational timing (%q): %s", forbidden, first)
		}
	}
}

// TestExecutableWorkflowIsStillAnalyzed proves the executable bit does not
// exempt a workflow from analysis.
//
// GitHub runs a workflow regardless of its file mode, so skipping mode 100755
// would let an attacker evade every PFR-WF rule with `chmod +x`. Only entries
// that cannot be read as content -- symlinks and submodules -- are skipped.
// Review finding H1.
func TestExecutableWorkflowIsStillAnalyzed(t *testing.T) {
	change := addedWorkflow(t, "malicious", "pfr-wf-001-privileged-untrusted-checkout.yml")
	change.Mode = gitdiff.ModeExecutable

	result := analyze(t, change)

	if result.Completion != run.CompletionComplete {
		t.Fatalf("completion = %q, want complete (notes: %v)", result.Completion, result.CoverageNotes)
	}
	if len(findingsFor(result, "PFR-WF-001")) != 1 {
		t.Fatalf("an executable workflow evaded analysis; rules present: %v", ruleIDs(result))
	}
}

// TestNonRegularEntriesAreStillSkipped keeps the H1 fix from over-reaching: a
// symlink or submodule carries no readable workflow content and must remain a
// coverage note rather than an analyzed file.
func TestNonRegularEntriesAreStillSkipped(t *testing.T) {
	for _, mode := range []gitdiff.EntryMode{gitdiff.ModeSymlink, gitdiff.ModeSubmodule} {
		t.Run(string(mode), func(t *testing.T) {
			change := addedWorkflow(t, "malicious", "pfr-wf-001-privileged-untrusted-checkout.yml")
			change.Mode = mode

			result := analyze(t, change)
			if len(result.Findings) != 0 {
				t.Errorf("a %s must not be analyzed, got %v", mode, ruleIDs(result))
			}
			if len(result.CoverageNotes) == 0 {
				t.Errorf("a skipped %s must appear in the coverage notes", mode)
			}
		})
	}
}

// TestCheckoutActionMatchIsCaseInsensitive proves the checkout detector is not
// defeated by capitalization.
//
// GitHub resolves `uses:` case-insensitively, so `Actions/Checkout` runs the
// same Action as `actions/checkout`. An exact comparison let a mixed-case
// spelling bypass PFR-WF-001 and PFR-WF-005 entirely. Review finding H3.
func TestCheckoutActionMatchIsCaseInsensitive(t *testing.T) {
	for _, spelling := range []string{"Actions/Checkout", "ACTIONS/CHECKOUT", "actions/Checkout"} {
		t.Run(spelling, func(t *testing.T) {
			content := "name: pr-preview\non: pull_request_target\njobs:\n  preview:\n    runs-on: ubuntu-latest\n    steps:\n" +
				"      - uses: " + spelling + "@3d3c42e5aac5ba805825da76410c181273ba90b1\n" +
				"        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n" +
				"      - run: npm install && npm run build\n"

			result := analyze(t, gitdiff.FileChange{
				Path:        ".github/workflows/preview.yml",
				Kind:        gitdiff.Added,
				Mode:        gitdiff.ModeFile,
				HeadContent: []byte(content),
			})

			if len(findingsFor(result, "PFR-WF-001")) != 1 {
				t.Fatalf("%s bypassed PFR-WF-001; rules present: %v", spelling, ruleIDs(result))
			}
		})
	}
}

// TestAnalyzerIsDeterministic proves two runs over identical input produce
// byte-identical findings in identical order, which canonical output requires.
func TestAnalyzerIsDeterministic(t *testing.T) {
	files := []gitdiff.FileChange{
		addedWorkflow(t, "malicious", "pfr-wf-005-secrets-to-untrusted.yml"),
		addedWorkflow(t, "malicious", "pfr-wf-003-mutable-action.yml"),
		addedWorkflow(t, "malicious", "pfr-wf-006-self-hosted.yml"),
	}

	first := analyze(t, files...)
	second := analyze(t, files...)

	if len(first.Findings) == 0 {
		t.Fatal("expected findings across the malicious corpus")
	}
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("finding count differs between runs: %d vs %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].Fingerprint != second.Findings[i].Fingerprint {
			t.Fatalf("finding %d differs between runs: %q vs %q",
				i, first.Findings[i].Fingerprint, second.Findings[i].Fingerprint)
		}
	}
	for i := 1; i < len(first.Findings); i++ {
		if first.Findings[i-1].Fingerprint > first.Findings[i].Fingerprint {
			t.Fatalf("findings are not ordered by fingerprint at index %d", i)
		}
	}
}

// TestAnalyzerNeverEmitsRawSecretValues proves evidence carrying a secret-shaped
// assignment is redacted before it leaves the analyzer.
func TestAnalyzerNeverEmitsRawSecretValues(t *testing.T) {
	const leaked = "ghp_0123456789abcdef0123456789abcdef0123"
	// The credential sits inside a run script that PFR-WF-004 reports, so the
	// excerpt carrying it is guaranteed to reach the evidence path under test.
	content := "name: leak\non: pull_request_target\njobs:\n  leak:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - run: ./publish.sh --token=" + leaked + " --title=\"${{ github.event.pull_request.title }}\"\n"

	result := analyze(t, gitdiff.FileChange{
		Path:        ".github/workflows/leak.yml",
		Kind:        gitdiff.Added,
		Mode:        gitdiff.ModeFile,
		HeadContent: []byte(content),
	})

	// Guard against a vacuous pass: redaction is only proven if evidence exists.
	if len(findingsFor(result, "PFR-WF-004")) == 0 {
		t.Fatalf("expected PFR-WF-004 to carry the run script as evidence, got %v", ruleIDs(result))
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
	for _, d := range result.Diagnostics {
		if strings.Contains(d.Message, leaked) || strings.Contains(d.Path, leaked) {
			t.Errorf("diagnostic leaked a credential: %+v", d)
		}
	}
}

// TestAnalyzerSkipsDeletedWorkflows proves a removed workflow is recorded as
// coverage rather than analyzed from absent content.
func TestAnalyzerSkipsDeletedWorkflows(t *testing.T) {
	result := analyze(t, gitdiff.FileChange{
		Path:        ".github/workflows/old.yml",
		Kind:        gitdiff.Deleted,
		Mode:        gitdiff.ModeFile,
		BaseContent: fixture(t, "malicious", "pfr-wf-001-privileged-untrusted-checkout.yml"),
	})

	if len(result.Findings) != 0 {
		t.Errorf("a deleted workflow must not produce findings, got %v", ruleIDs(result))
	}
	if len(result.CoverageNotes) == 0 {
		t.Error("a skipped entry must appear in the coverage notes")
	}
}

// variantCase is one equivalent spelling of a canonical fixture.
//
// GitHub accepts several spellings of the same expression, so each spelling is
// an independent fixture rather than a footnote on the original: a corpus that
// only carries the lowercase dotted form measures nothing about the forms an
// attacker actually writes.
type variantCase struct {
	class     string // malicious or benign
	file      string
	canonical string   // the fixture this one is an equivalent spelling of
	rules     []string // malicious: rules that must fire; benign: rules that must stay silent
}

func variantCases() []variantCase {
	return []variantCase{
		{
			class:     "malicious",
			file:      "pfr-wf-001-bracket-notation-ref.yml",
			canonical: "pfr-wf-001-privileged-untrusted-checkout.yml",
			rules:     []string{"PFR-WF-001", "PFR-WF-004"},
		},
		{
			class:     "malicious",
			file:      "pfr-wf-001-uppercase-context-ref.yml",
			canonical: "pfr-wf-001-privileged-untrusted-checkout.yml",
			rules:     []string{"PFR-WF-001", "PFR-WF-004"},
		},
		{
			class:     "malicious",
			file:      "pfr-wf-001-raw-git-checkout.yml",
			canonical: "pfr-wf-001-privileged-untrusted-checkout.yml",
			rules:     []string{"PFR-WF-001"},
		},
		{
			class:     "malicious",
			file:      "pfr-wf-005-capitalized-secrets.yml",
			canonical: "pfr-wf-005-secrets-to-untrusted.yml",
			rules:     []string{"PFR-WF-005"},
		},
		{
			class:     "malicious",
			file:      "pfr-wf-005-bracket-secrets.yml",
			canonical: "pfr-wf-005-secrets-to-untrusted.yml",
			rules:     []string{"PFR-WF-005"},
		},
		{
			class:     "benign",
			file:      "pfr-wf-001-bracket-base-ref.yml",
			canonical: "pfr-wf-001-base-checkout.yml",
			rules:     []string{"PFR-WF-001"},
		},
		{
			class:     "benign",
			file:      "pfr-wf-001-ordinary-git-fetch.yml",
			canonical: "pfr-wf-001-base-checkout.yml",
			rules:     []string{"PFR-WF-001"},
		},
		{
			class:     "benign",
			file:      "pfr-wf-004-bracket-safe-property.yml",
			canonical: "pfr-wf-004-env-indirection.yml",
			rules:     []string{"PFR-WF-004"},
		},
	}
}

// decisionFor returns the decision hint the analyzer contract fixes for a rule,
// so a variant is held to its canonical fixture's classification rather than to
// a value copied into this test.
func decisionFor(t *testing.T, rule string) finding.Decision {
	t.Helper()
	for _, tc := range ruleCases() {
		if tc.rule == rule {
			return tc.decision
		}
	}
	t.Fatalf("no rule case for %s", rule)
	return ""
}

// TestVariantFixturesMatchTheirCanonicalFixture proves an equivalent spelling
// produces an equivalent judgement: the same rules with the same decision on a
// malicious variant, silence on a safe one.
func TestVariantFixturesMatchTheirCanonicalFixture(t *testing.T) {
	for _, vc := range variantCases() {
		t.Run(vc.file, func(t *testing.T) {
			result := analyze(t, addedWorkflow(t, vc.class, vc.file))

			if result.Completion != run.CompletionComplete {
				t.Fatalf("completion = %q, want complete (diagnostics: %+v)", result.Completion, result.Diagnostics)
			}

			for _, rule := range vc.rules {
				matches := findingsFor(result, rule)
				if vc.class == "benign" {
					if len(matches) != 0 {
						t.Errorf("%s fired on a safe spelling: %+v", rule, matches)
					}
					continue
				}
				if len(matches) != 1 {
					t.Fatalf("expected exactly one %s finding, got %d (all rules: %v)", rule, len(matches), ruleIDs(result))
				}
				if want := decisionFor(t, rule); matches[0].DecisionHint != want {
					t.Errorf("%s decision hint = %q, want %q", rule, matches[0].DecisionHint, want)
				}
			}
		})
	}
}

// TestPermissionRuleIgnoresScopeNarrowing proves PFR-WF-002 compares effective
// capability rather than where a grant is written.
//
// Moving a workflow-wide write scope down to the single job that needs it is
// the recommended hardening, and renaming a job changes no capability at all.
// Reporting either as newly granted -- and hardening it to block on an
// untrusted trigger -- punishes the fix.
func TestPermissionRuleIgnoresScopeNarrowing(t *testing.T) {
	workflowWide := "name: release\non: pull_request_target\npermissions:\n  contents: write\njobs:\n" +
		"  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make release\n"
	jobScoped := "name: release\non: pull_request_target\njobs:\n" +
		"  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: make release\n"
	renamed := "name: release\non: pull_request_target\njobs:\n" +
		"  publish:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: make release\n"

	for _, tc := range []struct {
		name string
		base string
		head string
	}{
		{"narrowed to one job", workflowWide, jobScoped},
		{"job renamed", jobScoped, renamed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := analyze(t, gitdiff.FileChange{
				Path:        ".github/workflows/release.yml",
				Kind:        gitdiff.Modified,
				Mode:        gitdiff.ModeFile,
				BaseContent: []byte(tc.base),
				HeadContent: []byte(tc.head),
			})

			if matches := findingsFor(result, "PFR-WF-002"); len(matches) != 0 {
				t.Fatalf("PFR-WF-002 reported a capability the head revision did not gain: %+v", matches)
			}
		})
	}
}

// TestPermissionRuleStillReportsANewScope keeps the narrowing fix from
// over-reaching: a scope the base revision never granted is still a finding,
// and the job that gained it still has to be identifiable from the evidence and
// the location.
func TestPermissionRuleStillReportsANewScope(t *testing.T) {
	base := "name: release\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: make release\n"
	head := "name: release\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n      packages: write\n    steps:\n      - run: make release\n"

	result := analyze(t, gitdiff.FileChange{
		Path:        ".github/workflows/release.yml",
		Kind:        gitdiff.Modified,
		Mode:        gitdiff.ModeFile,
		BaseContent: []byte(base),
		HeadContent: []byte(head),
	})

	matches := findingsFor(result, "PFR-WF-002")
	if len(matches) != 1 {
		t.Fatalf("expected one PFR-WF-002 finding, got %d (%v)", len(matches), ruleIDs(result))
	}
	if !strings.Contains(matches[0].Message, "packages") {
		t.Errorf("message does not name the newly granted scope: %q", matches[0].Message)
	}
	if strings.Contains(matches[0].Message, "contents") {
		t.Errorf("message reports a scope the base revision already granted: %q", matches[0].Message)
	}
	var named bool
	for _, e := range matches[0].Evidence {
		if strings.Contains(e.Excerpt, "build") {
			named = true
		}
	}
	if !named {
		t.Errorf("evidence does not identify the job that gained the scope: %+v", matches[0].Evidence)
	}
	if !hasLocationLine(matches[0], ".github/workflows/release.yml", 8) {
		t.Errorf("locations %+v do not point at the line that granted the scope", matches[0].Locations)
	}
}

// manyMutableActions builds a workflow whose steps each trip PFR-WF-003, which
// is the cheapest way to drive the analyzer at a finding ceiling.
func manyMutableActions(n int) []byte {
	var b strings.Builder
	b.WriteString("name: lint\non: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n")
	for i := 0; i < n; i++ {
		b.WriteString("      - uses: some-vendor/lint-action@v" + strconv.Itoa(i) + "\n")
	}
	return []byte(b.String())
}

func analyzeWithLimits(t *testing.T, limits run.Limits, files ...gitdiff.FileChange) run.AnalyzerResult {
	t.Helper()
	in := inputWith(files...)
	in.Limits = limits
	return workflowanalyzer.New().Analyze(context.Background(), in)
}

// TestFindingBudgetBoundsGeneration proves the ceiling bounds the work rather
// than only the output.
//
// Finalizing -- redaction plus a SHA-256 -- every candidate and truncating
// afterwards let a hostile workflow buy unbounded work, and a budget failure
// has to carry a diagnostic so the run goes incomplete instead of quietly
// truncated.
func TestFindingBudgetBoundsGeneration(t *testing.T) {
	limits := run.DefaultLimits()
	limits.MaxFindings = 5

	result := analyzeWithLimits(t, limits, gitdiff.FileChange{
		Path:        ".github/workflows/lint.yml",
		Kind:        gitdiff.Added,
		Mode:        gitdiff.ModeFile,
		HeadContent: manyMutableActions(12),
	})

	if result.Completion != run.CompletionFailed {
		t.Fatalf("completion = %q, want failed when the finding budget is exceeded", result.Completion)
	}
	if len(result.Findings) > limits.MaxFindings {
		t.Errorf("returned %d findings, above the %d ceiling", len(result.Findings), limits.MaxFindings)
	}
	var budgeted bool
	for _, d := range result.Diagnostics {
		if strings.Contains(d.Code, "budget") {
			budgeted = true
		}
	}
	if !budgeted {
		t.Errorf("a budget failure must explain itself with a diagnostic, got %+v", result.Diagnostics)
	}

	// Generating twelve candidates and keeping the five with the lowest
	// fingerprints would prove the ceiling was applied to the output after the
	// work was already paid for. Stopping at the ceiling keeps the first five
	// the rules produced, which are the first five steps in document order.
	kept := make(map[string]bool)
	for _, f := range result.Findings {
		for _, e := range f.Evidence {
			kept[e.Excerpt] = true
		}
	}
	for i := 0; i < 12; i++ {
		ref := "some-vendor/lint-action@v" + strconv.Itoa(i)
		if got, want := kept[ref], i < limits.MaxFindings; got != want {
			t.Errorf("step %s kept = %v, want %v: candidates are generated past the ceiling", ref, got, want)
		}
	}
}

// TestFindingBudgetReachedIsNotExceeded holds the strict ceiling semantics the
// analyzer has always had: a run that produces exactly MaxFindings dropped
// nothing, so it stays complete. Calling a full-but-intact run a budget failure
// would turn a clean result into exit code 2.
func TestFindingBudgetReachedIsNotExceeded(t *testing.T) {
	limits := run.DefaultLimits()
	limits.MaxFindings = 5

	result := analyzeWithLimits(t, limits, gitdiff.FileChange{
		Path:        ".github/workflows/lint.yml",
		Kind:        gitdiff.Added,
		Mode:        gitdiff.ModeFile,
		HeadContent: manyMutableActions(5),
	})

	if result.Completion != run.CompletionComplete {
		t.Fatalf("completion = %q, want complete when nothing was dropped (diagnostics: %+v)", result.Completion, result.Diagnostics)
	}
	if len(result.Findings) != 5 {
		t.Fatalf("expected exactly 5 findings, got %d", len(result.Findings))
	}
}

func evidenceKinds(f finding.Finding) []string {
	out := make([]string, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		out = append(out, e.Kind)
	}
	return out
}

func limitationContains(f finding.Finding, substr string) bool {
	for _, l := range f.Limitations {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}
