package dependency

import (
	"context"
	"path"

	"github.com/codebyte-p/proofrail/internal/finding"
	"github.com/codebyte-p/proofrail/internal/gitdiff"
	"github.com/codebyte-p/proofrail/internal/parser/npm"
	"github.com/codebyte-p/proofrail/internal/parser/python"
	"github.com/codebyte-p/proofrail/internal/run"
)

// ID and Version identify this analyzer in the completion ledger.
const (
	ID      = "dependency"
	Version = "1.0.0"
)

// supportedFiles maps a base filename to how it is read. Anything else that
// looks like a dependency manifest is recorded as coverage rather than analyzed,
// because docs/analyzers.md requires an unsupported file to produce an explicit
// note instead of silent success.
type fileRole int

const (
	roleNPMManifest fileRole = iota
	roleNPMLock
	rolePythonProject
	rolePythonLock
)

var supportedFiles = map[string]fileRole{
	"package.json":      roleNPMManifest,
	"package-lock.json": roleNPMLock,
	"pyproject.toml":    rolePythonProject,
	"uv.lock":           rolePythonLock,
}

// unsupportedManifests are files that declare dependencies for an ecosystem
// version 1 does not model. Naming them explicitly keeps a reviewer from
// reading a clean result as full coverage.
var unsupportedManifests = map[string]bool{
	"Cargo.toml":       true,
	"Cargo.lock":       true,
	"go.mod":           true,
	"go.sum":           true,
	"Gemfile":          true,
	"Gemfile.lock":     true,
	"pom.xml":          true,
	"build.gradle":     true,
	"composer.json":    true,
	"requirements.txt": true,
	"poetry.lock":      true,
	"yarn.lock":        true,
	"pnpm-lock.yaml":   true,
}

type analyzer struct{}

// New returns the compiled PFR-DEP analyzer. Nothing is loaded at runtime.
func New() run.Analyzer { return analyzer{} }

func (analyzer) ID() string { return ID }

// Analyze compares the dependency declarations and resolutions of the base and
// head revisions.
//
// It returns a result rather than an error. A parse rejection, a cancelled
// context, or a finding that fails canonical validation all yield Completion
// failed with redacted diagnostics. Findings from files that were fully
// analyzed are retained even then, because failing closed is about coverage
// rather than about discarding evidence.
func (a analyzer) Analyze(ctx context.Context, in run.AnalysisInput) run.AnalyzerResult {
	result := run.AnalyzerResult{AnalyzerID: ID, AnalyzerVersion: Version}

	var (
		base     Snapshot
		head     Snapshot
		notes    []string
		diags    []run.Diagnostic
		analyzed int
	)

	for _, file := range in.Changes.Files {
		if err := ctx.Err(); err != nil {
			diags = append(diags, run.Diagnostic{
				Code:    "dependency.analysis_cancelled",
				Path:    file.Path,
				Message: "dependency analysis stopped before every changed file was examined",
			})
			break
		}

		name := path.Base(file.Path)
		role, supported := supportedFiles[name]
		if !supported {
			if unsupportedManifests[name] {
				notes = append(notes, "dependency file "+file.Path+
					" belongs to an ecosystem version 1 does not model and was not analyzed")
			}
			continue
		}
		if file.Mode != gitdiff.ModeFile {
			notes = append(notes, "dependency file "+file.Path+" is not a regular file and was not analyzed")
			continue
		}
		if file.CoverageNote != "" {
			notes = append(notes, "dependency file "+file.Path+" was not analyzed: "+file.CoverageNote)
			continue
		}
		if file.Kind == gitdiff.Deleted {
			notes = append(notes, "dependency file "+file.Path+" was deleted and was not analyzed")
			continue
		}

		ing := ingestion{limits: in.Limits, path: file.Path, role: role}
		headOK := ing.into(&head, file.HeadContent, &notes, &diags)
		if headOK {
			analyzed++
		}
		// A base that will not parse is coverage, not a failure: the head
		// revision is what governs the pull request, and an empty baseline is
		// the conservative direction for every rule that compares the two.
		if len(file.BaseContent) > 0 {
			if !ing.into(&base, file.BaseContent, &notes, nil) {
				notes = append(notes, "base revision of "+file.Path+
					" could not be parsed; the comparison used an empty baseline")
			}
		}
	}

	for _, candidate := range evaluate(base, head) {
		f, err := finding.Finalize(candidate)
		if err != nil {
			diags = append(diags, run.Diagnostic{
				Code:    "dependency.finding_rejected",
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

// ingestion reads one file into one side of the comparison.
type ingestion struct {
	limits run.Limits
	path   string
	role   fileRole
}

// into parses content and appends its records to snap. Diagnostics are recorded
// only when diags is non-nil, which is how a base-revision failure is demoted
// to a coverage note.
func (ing ingestion) into(snap *Snapshot, content []byte, notes *[]string, diags *[]run.Diagnostic) bool {
	if len(content) == 0 {
		return false
	}

	switch ing.role {
	case roleNPMManifest:
		manifest, d := npm.ParseManifest(ing.path, content, ing.limits.MaxManifestBytes)
		if len(d) > 0 {
			if diags != nil {
				*diags = append(*diags, d...)
			}
			return false
		}
		*notes = append(*notes, manifest.CoverageNotes...)
		ing.appendNPMManifest(snap, manifest)

	case roleNPMLock:
		lock, d := npm.ParseLock(ing.path, content, ing.limits.MaxLockfileBytes)
		if len(d) > 0 {
			if diags != nil {
				*diags = append(*diags, d...)
			}
			return false
		}
		*notes = append(*notes, lock.CoverageNotes...)
		ing.appendNPMLock(snap, lock)

	case rolePythonProject:
		project, d := python.ParseProject(ing.path, content, ing.limits.MaxManifestBytes)
		if len(d) > 0 {
			if diags != nil {
				*diags = append(*diags, d...)
			}
			return false
		}
		*notes = append(*notes, project.CoverageNotes...)
		ing.appendPythonProject(snap, project)

	case rolePythonLock:
		lock, d := python.ParseLock(ing.path, content, ing.limits.MaxLockfileBytes)
		if len(d) > 0 {
			if diags != nil {
				*diags = append(*diags, d...)
			}
			return false
		}
		*notes = append(*notes, lock.CoverageNotes...)
		ing.appendPythonLock(snap, lock)
	}
	return true
}

func (ing ingestion) appendNPMManifest(snap *Snapshot, m npm.Manifest) {
	for _, req := range m.Requirements {
		kind, immutable := classifyNPMSpec(req.Spec.Value)
		snap.Declared = append(snap.Declared, Declared{
			Ecosystem: EcosystemNPM,
			Name:      req.Name.Value,
			Spec:      req.Spec.Value,
			Kind:      req.Kind,
			Source:    kind,
			Immutable: immutable,
			Path:      ing.path,
			Pos:       Position{Line: req.Name.Pos.Line, Column: req.Name.Pos.Column},
		})
	}
	for _, script := range m.Scripts {
		snap.Scripts = append(snap.Scripts, Script{
			Ecosystem: EcosystemNPM,
			Name:      script.Name.Value,
			Body:      script.Body.Value,
			Path:      ing.path,
			Pos:       Position{Line: script.Name.Pos.Line, Column: script.Name.Pos.Column},
		})
	}
}

func (ing ingestion) appendNPMLock(snap *Snapshot, l npm.Lock) {
	for _, pkg := range l.Packages {
		snap.Resolved = append(snap.Resolved, Resolved{
			Ecosystem: EcosystemNPM,
			Name:      pkg.Name.Value,
			Version:   pkg.Version.Value,
			Location:  pkg.Resolved.Value,
			Integrity: pkg.Integrity.Value,
			Path:      ing.path,
			Pos:       Position{Line: pkg.Key.Pos.Line, Column: pkg.Key.Pos.Column},
		})
		// A transitive package with an install script expands install-time
		// execution just as a manifest hook does.
		if pkg.HasInstallScript {
			snap.Scripts = append(snap.Scripts, Script{
				Ecosystem: EcosystemNPM,
				Name:      pkg.Name.Value + " (install script)",
				Body:      "declared by the locked package",
				Path:      ing.path,
				Pos:       Position{Line: pkg.Key.Pos.Line, Column: pkg.Key.Pos.Column},
			})
		}
	}
}

func (ing ingestion) appendPythonProject(snap *Snapshot, p python.Project) {
	for _, req := range p.Requirements {
		kind, immutable := classifyPythonSpec(req.Spec.Value)
		snap.Declared = append(snap.Declared, Declared{
			Ecosystem: EcosystemPython,
			Name:      pythonRequirementName(req.Spec.Value),
			Spec:      req.Spec.Value,
			Kind:      req.Kind,
			Source:    kind,
			Immutable: immutable,
			Path:      ing.path,
			Pos:       Position{Line: req.Spec.Pos.Line, Column: req.Spec.Pos.Column},
		})
	}
	// A `[tool.uv.sources]` entry redirects a dependency away from the default
	// index, so it is a source declaration in its own right.
	for _, src := range p.Sources {
		kind, immutable := classifyUVSource(
			src.Git.Value, src.URL.Value, src.Path.Value,
			src.Branch.Value, src.Tag.Value, src.Rev.Value)
		snap.Declared = append(snap.Declared, Declared{
			Ecosystem: EcosystemPython,
			Name:      src.Name.Value,
			Spec:      firstNonEmpty(src.Git.Value, src.URL.Value, src.Path.Value),
			Kind:      "tool.uv.sources",
			Source:    kind,
			Immutable: immutable,
			Path:      ing.path,
			Pos:       Position{Line: src.Name.Pos.Line, Column: src.Name.Pos.Column},
		})
	}
	if p.BuildBackend.Present() {
		snap.Scripts = append(snap.Scripts, Script{
			Ecosystem: EcosystemPython,
			Name:      "build-backend",
			Body:      p.BuildBackend.Value,
			Path:      ing.path,
			Pos:       Position{Line: p.BuildBackend.Pos.Line, Column: p.BuildBackend.Pos.Column},
		})
	}
}

func (ing ingestion) appendPythonLock(snap *Snapshot, l python.Lock) {
	for _, pkg := range l.Packages {
		snap.Resolved = append(snap.Resolved, Resolved{
			Ecosystem: EcosystemPython,
			Name:      pkg.Name.Value,
			Version:   pkg.Version.Value,
			Location: firstNonEmpty(
				pkg.Registry.Value, pkg.Git.Value, pkg.URL.Value, pkg.Path.Value),
			Integrity: pkg.Hash.Value,
			Path:      ing.path,
			Pos:       Position{Line: pkg.Name.Pos.Line, Column: pkg.Name.Pos.Column},
		})
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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

// safe bounds a repository-supplied string and strips everything that is not
// printable ASCII, so a package name cannot carry a control sequence into a
// message, a console line, or a report.
func safe(s string) string {
	const max = 96
	if len(s) > max {
		s = s[:max]
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			b = append(b, '?')
			continue
		}
		b = append(b, c)
	}
	return string(b)
}
