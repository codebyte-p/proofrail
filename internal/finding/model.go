package finding

import "sort"

// Location is one place in the head revision a finding points at. Path is a
// normalized forward-slash repository-relative path; internal/gitdiff produces
// it, and this package re-validates it because analyzer output is untrusted
// until the aggregator has checked it.
type Location struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// Evidence is one bounded, redacted artifact supporting a finding.
//
// Kind names the sort of evidence, which policy may inspect. Source records
// where it came from. Excerpt is redacted and capped at MaxExcerptBytes. Digest
// is the SHA-256 of the redacted excerpt and is what the fingerprint consumes,
// so a finding stays stable across a credential rotation.
type Evidence struct {
	Kind    string `json:"kind"`
	Source  string `json:"source,omitempty"`
	Digest  string `json:"digest"`
	Excerpt string `json:"excerpt,omitempty"`
}

// Finding is one validated, redacted, fingerprinted result.
//
// A Finding is produced only by Finalize. The zero value and any hand-built
// value are not canonical: Fingerprint is assigned during finalization and is
// what waivers bind to.
type Finding struct {
	RuleID       string     `json:"rule_id"`
	AnalyzerID   string     `json:"analyzer_id"`
	Severity     Severity   `json:"severity"`
	Confidence   Confidence `json:"confidence"`
	DecisionHint Decision   `json:"decision_hint"`
	Message      string     `json:"message"`
	Locations    []Location `json:"locations"`
	Evidence     []Evidence `json:"evidence"`
	Limitations  []string   `json:"limitations,omitempty"`
	Fingerprint  string     `json:"fingerprint"`
}

// ValidationError reports a rejected finding with a stable diagnostic code.
// Reason is bounded prose and never echoes the offending value, because a
// finding's fields originate in repository content.
type ValidationError struct {
	Code   string
	Reason string
}

func (e *ValidationError) Error() string { return e.Code + ": " + e.Reason }

func invalid(code, reason string) *ValidationError {
	return &ValidationError{Code: code, Reason: reason}
}

// Sort orders findings by fingerprint ascending, which is the canonical order
// used by the run result and every projection. Two runs over the same inputs
// therefore serialize to identical bytes.
func Sort(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}

// sortLocations orders by path, then start line, then end line.
func sortLocations(locations []Location) {
	sort.Slice(locations, func(i, j int) bool {
		a, b := locations[i], locations[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.EndLine < b.EndLine
	})
}

// sortEvidence orders by kind, then digest. Source and excerpt are not part of
// the ordering key because the digest already distinguishes distinct content and
// is what the fingerprint consumes.
func sortEvidence(evidence []Evidence) {
	sort.Slice(evidence, func(i, j int) bool {
		a, b := evidence[i], evidence[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Digest < b.Digest
	})
}
