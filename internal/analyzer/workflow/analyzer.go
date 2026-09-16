// Package workflow implements the PFR-WF analyzer family: GitHub Actions
// workflow security, as specified in docs/analyzers.md.
//
// The analyzer reads normalized records produced by internal/parser/workflow and
// emits candidate findings. It has no reporter, policy, filesystem, process, or
// network authority, and it never runs a workflow, resolves an expression, or
// contacts GitHub. Every judgement is made from the bytes of the changed
// revision alone.
//
// A workflow it cannot parse makes the analyzer fail rather than report a clean
// result, because an unreadable workflow is missing coverage, not evidence of
// safety.
package workflow

import (
	"context"
	"strings"

	"github.com/codebyte-p/proofrail/internal/finding"
	"github.com/codebyte-p/proofrail/internal/gitdiff"
	parser "github.com/codebyte-p/proofrail/internal/parser/workflow"
	"github.com/codebyte-p/proofrail/internal/run"
)

// ID and Version identify this analyzer in the completion ledger. Version is
// part of the evidence a reader needs to reproduce a decision.
const (
	ID      = "github-workflow"
	Version = "1.0.0"
)

// workflowDir is the only directory GitHub reads workflows from. Nested paths
// are not executed by Actions, so analyzing them would invent risk.
const workflowDir = ".github/workflows/"

type analyzer struct{}

// New returns the compiled PFR-WF analyzer. Nothing is loaded at runtime.
func New() run.Analyzer { return analyzer{} }

func (analyzer) ID() string { return ID }

// Analyze examines every changed workflow file in the head revision.
//
// It returns a result rather than an error. A parse rejection, a cancelled
// context, or a finding that fails canonical validation all yield Completion
// failed with redacted diagnostics, which the orchestrator turns into an
// incomplete run and exit code 2.
func (a analyzer) Analyze(ctx context.Context, in run.AnalysisInput) run.AnalyzerResult {
	result := run.AnalyzerResult{AnalyzerID: ID, AnalyzerVersion: Version}

	var (
		candidates []finding.Finding
		notes      []string
		diags      []run.Diagnostic
		analyzed   int
	)

	for _, file := range in.Changes.Files {
		if err := ctx.Err(); err != nil {
			diags = append(diags, run.Diagnostic{
				Code:    "workflow.analysis_cancelled",
				Path:    file.Path,
				Message: "workflow analysis stopped before every changed workflow was examined",
			})
			break
		}
		if !isWorkflowPath(file.Path) {
			continue
		}
		if file.Mode != gitdiff.ModeFile {
			notes = append(notes, "workflow "+file.Path+" is not a regular file and was not analyzed")
			continue
		}
		if file.CoverageNote != "" {
			notes = append(notes, "workflow "+file.Path+" was not analyzed: "+file.CoverageNote)
			continue
		}
		if file.Kind == gitdiff.Deleted {
			// A removed workflow cannot introduce a hazard into the head
			// revision, but the skip is recorded rather than hidden.
			notes = append(notes, "workflow "+file.Path+" was deleted and was not analyzed")
			continue
		}

		head, headDiags := parser.Parse(file.Path, file.HeadContent, in.Limits.MaxWorkflowFileBytes)
		if len(headDiags) > 0 {
			diags = append(diags, headDiags...)
			continue
		}
		analyzed++
		notes = append(notes, head.CoverageNotes...)

		base, baseNote := parseBase(file, in.Limits.MaxWorkflowFileBytes)
		if baseNote != "" {
			notes = append(notes, baseNote)
		}

		candidates = append(candidates, evaluate(head, base)...)
	}

	// Finalize is the aggregation step docs/analyzers.md requires: it validates,
	// redacts, orders, and fingerprints. A candidate that cannot survive it is a
	// bug in this analyzer, and failing closed is the only safe response.
	for _, candidate := range candidates {
		f, err := finding.Finalize(candidate)
		if err != nil {
			diags = append(diags, run.Diagnostic{
				Code:    "workflow.finding_rejected",
				Path:    ID,
				Message: "the analyzer produced a finding that failed canonical validation",
			})
			continue
		}
		result.Findings = append(result.Findings, f)
	}
	finding.Sort(result.Findings)

	switch {
	case len(diags) > 0:
		// Failing closed is about coverage, not about evidence. Findings from
		// workflows that were fully analyzed are retained and reported; the
		// failed completion is what drives the run to incomplete and exit code
		// 2. Discarding them would tell a reviewer less than the engine knows
		// while doing nothing to make the run safer.
		result.Completion = run.CompletionFailed
	case analyzed == 0:
		result.Completion = run.CompletionNotApplicable
	default:
		result.Completion = run.CompletionComplete
	}

	result.CoverageNotes = dedupe(notes)
	result.Diagnostics = diags
	return result
}

// parseBase reads the base revision of a changed workflow so rules that depend
// on "newly introduced" can compare against it.
//
// A base that will not parse is not a failure: the head revision is what governs
// the pull request. The comparison falls back to an empty baseline, which is the
// conservative direction, and the substitution is recorded as coverage.
func parseBase(file gitdiff.FileChange, maxBytes int64) (parser.Document, string) {
	if len(file.BaseContent) == 0 {
		return parser.Document{}, ""
	}
	base, diags := parser.Parse(file.Path, file.BaseContent, maxBytes)
	if len(diags) > 0 {
		return parser.Document{}, "base revision of " + file.Path +
			" could not be parsed; permission widening was judged against an empty baseline"
	}
	return base, ""
}

// isWorkflowPath reports whether p is a file GitHub Actions would actually run.
func isWorkflowPath(p string) bool {
	rest, found := strings.CutPrefix(p, workflowDir)
	if !found || rest == "" || strings.Contains(rest, "/") {
		return false
	}
	return strings.HasSuffix(rest, ".yml") || strings.HasSuffix(rest, ".yaml")
}

// dedupe preserves first-seen order so two runs over the same change set emit
// the same coverage notes in the same sequence.
func dedupe(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
