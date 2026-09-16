package finding

import (
	"path"
	"strings"
	"unicode/utf8"
)

// MaxLocationPathBytes mirrors the bound internal/gitdiff applies when it
// normalizes a path.
const MaxLocationPathBytes = 4096

// Finalize validates, redacts, orders, and fingerprints a candidate finding.
//
// Analyzer output is untrusted until it has been through here: docs/analyzers.md
// requires the aggregator to validate the schema, confirm every path, bound
// excerpts, and recompute fingerprints rather than accept an analyzer's own.
// Finalize is that aggregation step, and it is the only way to obtain a
// canonical Finding.
//
// It is pure. The caller's slices are copied before anything is sorted or
// rewritten, so an analyzer that reuses a buffer cannot observe a mutation and
// two analyzers cannot alias each other's evidence.
func Finalize(candidate Finding) (Finding, error) {
	f := candidate.clone()

	if f.RuleID == "" || !printableIdentifier(f.RuleID) {
		return Finding{}, invalid("finding.rule_id_invalid", "rule id must be non-empty printable ASCII")
	}
	if f.AnalyzerID == "" || !printableIdentifier(f.AnalyzerID) {
		return Finding{}, invalid("finding.analyzer_id_invalid", "analyzer id must be non-empty printable ASCII")
	}
	if strings.TrimSpace(f.Message) == "" {
		return Finding{}, invalid("finding.message_invalid", "a finding must explain itself")
	}
	if !f.Severity.Valid() {
		return Finding{}, invalid("finding.severity_invalid", "severity is not a registered value")
	}
	if !f.Confidence.Valid() {
		return Finding{}, invalid("finding.confidence_invalid", "confidence is not a registered value")
	}
	// A finding may raise a concern but can never assert that a change is
	// acceptable. Only the absence of a matched rule produces pass, so pass is
	// not an available decision hint.
	if !f.DecisionHint.Valid() || f.DecisionHint == DecisionPass {
		return Finding{}, invalid("finding.decision_hint_invalid", "decision hint must be block, require_review, warn, or observe")
	}

	if len(f.Locations) == 0 {
		return Finding{}, invalid("finding.locations_invalid", "a finding must point at least at one location")
	}
	for _, loc := range f.Locations {
		if !isNormalizedRepoPath(loc.Path) {
			return Finding{}, invalid("finding.location_path_invalid", "a location path is not a normalized repository-relative path")
		}
		if loc.StartLine < 1 || loc.EndLine < loc.StartLine {
			return Finding{}, invalid("finding.location_range_invalid", "a location line range must start at 1 or above and not end before it starts")
		}
	}

	if len(f.Evidence) == 0 {
		return Finding{}, invalid("finding.evidence_invalid", "a finding must carry at least one evidence item")
	}
	for _, e := range f.Evidence {
		if e.Kind == "" || !printableIdentifier(e.Kind) {
			return Finding{}, invalid("finding.evidence_invalid", "every evidence item must declare a printable kind")
		}
	}

	// Redaction runs before truncation. Truncating first could cut a secret in
	// half and leave a recognizable fragment that no detector then matches.
	f.Message = Redact(f.Message)
	for i := range f.Evidence {
		e := &f.Evidence[i]
		e.Source = Redact(e.Source)
		e.Excerpt = TruncateExcerpt(Redact(e.Excerpt))
		e.Digest = digestExcerpt(e.Excerpt)
	}
	for i := range f.Limitations {
		f.Limitations[i] = Redact(f.Limitations[i])
	}

	sortLocations(f.Locations)
	sortEvidence(f.Evidence)

	f.Fingerprint = computeFingerprint(f)
	return f, nil
}

// clone copies every slice so Finalize cannot mutate its caller's value.
func (f Finding) clone() Finding {
	out := f
	out.Locations = append([]Location(nil), f.Locations...)
	out.Evidence = append([]Evidence(nil), f.Evidence...)
	out.Limitations = append([]string(nil), f.Limitations...)
	return out
}

// isNormalizedRepoPath reports whether p is already in the canonical form
// internal/gitdiff produces.
//
// This is a predicate, not a second normalizer. internal/gitdiff owns
// normalization; this package re-checks the result because a finding's path may
// have been assembled by an analyzer rather than copied from the change set, and
// a path that is not canonical would break waiver containment and fingerprint
// stability. Rejecting is correct here -- silently repairing would hide an
// analyzer bug.
func isNormalizedRepoPath(p string) bool {
	if p == "" || len(p) > MaxLocationPathBytes {
		return false
	}
	if !utf8.ValidString(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == 0x00 || c < 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	if p[0] == '/' {
		return false
	}
	// A Windows volume specifier such as `C:` or `c:`.
	if len(p) >= 2 && p[1] == ':' {
		c := p[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return false
		}
	}
	if strings.HasSuffix(p, "/") {
		return false
	}
	if p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return false
	}
	// Already canonical: no doubled separators, no `.` or `..` segments left.
	return path.Clean(p) == p
}

// printableIdentifier keeps a control byte from riding into a report through a
// rule id, analyzer id, or evidence kind, all of which reach SARIF and Markdown
// without further escaping.
func printableIdentifier(s string) bool {
	if len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
