// Package run owns the immutable run contracts shared by every Gate 1 stage:
// the bound run identity, the resource limits, the analyzer completion ledger,
// the canonical run result, and the terminal exit mapping. Later tasks add the
// orchestrator that produces those values.
//
// The package depends on internal/finding for the ordered enums and re-exports
// them as aliases, so `run.Decision` and `finding.Decision` are the same type
// and the dependency runs in one direction only (run -> finding).
package run

import (
	"strings"
	"time"

	"github.com/codebyte-p/proofrail/internal/finding"
)

// SchemaVersion identifies the canonical run-result contract. It is part of the
// serialized output so a consumer can never silently read a different shape.
const SchemaVersion = "https://github.com/codebyte-p/proofrail/schemas/run-result/v1.json"

// Ordered enums re-exported from internal/finding. These are type aliases, not
// definitions, so values cross the package boundary without conversion.
type (
	Severity   = finding.Severity
	Confidence = finding.Confidence
	Decision   = finding.Decision
)

const (
	SeverityNote     = finding.SeverityNote
	SeverityLow      = finding.SeverityLow
	SeverityMedium   = finding.SeverityMedium
	SeverityHigh     = finding.SeverityHigh
	SeverityCritical = finding.SeverityCritical

	ConfidenceLow    = finding.ConfidenceLow
	ConfidenceMedium = finding.ConfidenceMedium
	ConfidenceHigh   = finding.ConfidenceHigh

	DecisionPass          = finding.DecisionPass
	DecisionObserve       = finding.DecisionObserve
	DecisionWarn          = finding.DecisionWarn
	DecisionRequireReview = finding.DecisionRequireReview
	DecisionBlock         = finding.DecisionBlock
)

// Status records whether the engine completed every required stage.
//
// docs/architecture.md describes five reportable run states. Four of them --
// pass, warn, require_review, and block -- differ only in their Decision and all
// require that analysis completed; the fifth, incomplete, is a statement about
// coverage rather than about risk. Splitting the two makes the invariant
// structural: no Decision value can express a complete run, so no reporter or
// policy rule can turn missing analysis into a pass.
type Status string

const (
	StatusComplete   Status = "complete"
	StatusIncomplete Status = "incomplete"
)

// Valid reports whether s is a registered status.
func (s Status) Valid() bool { return s == StatusComplete || s == StatusIncomplete }

// Completion is one analyzer's contribution to the coverage ledger, as defined
// by docs/analyzers.md.
type Completion string

const (
	CompletionComplete      Completion = "complete"
	CompletionNotApplicable Completion = "not_applicable"
	CompletionDisabled      Completion = "disabled"
	CompletionFailed        Completion = "failed"
)

// Valid reports whether c is a registered completion state.
func (c Completion) Valid() bool {
	switch c {
	case CompletionComplete, CompletionNotApplicable, CompletionDisabled, CompletionFailed:
		return true
	default:
		return false
	}
}

// SatisfiesRequirement reports whether this completion state lets a required
// analyzer slot count as covered.
//
// Only an analyzer that ran to completion, or one that correctly determined it
// had nothing in scope, covers its slot. A failed, disabled, or unset analyzer
// leaves a hole, and a hole must drive the run to incomplete rather than let the
// remaining findings stand in for full coverage.
func (c Completion) SatisfiesRequirement() bool {
	return c == CompletionComplete || c == CompletionNotApplicable
}

// Diagnostic is the bounded, redacted way the engine reports a failure.
//
// Code is a stable identifier callers and tests may match on. Path locates the
// failure inside the offending document. Message is human-readable prose that
// must never contain repository content, a rejected input value, a secret, or a
// stack trace: diagnostics reach the console, logs, and published reports.
type Diagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// RunIdentity is the immutable tuple every result is bound to. Two runs are
// comparable only when all of these fields, the limits, and the engine version
// match.
type RunIdentity struct {
	Repository    string    `json:"repository"`
	BaseSHA       string    `json:"base_sha"`
	HeadSHA       string    `json:"head_sha"`
	PolicyDigest  string    `json:"policy_digest"`
	WaiverDigest  string    `json:"waiver_digest"`
	EngineVersion string    `json:"engine_version"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

// Canonical returns a copy of the identity in its normalized form. Only the
// timestamp needs normalizing: it is forced to UTC so that the same instant
// always serializes to the same bytes regardless of the host zone.
//
// Callers normalize before validating; Validate deliberately rejects a
// non-UTC timestamp rather than silently accepting one.
func (i RunIdentity) Canonical() RunIdentity {
	i.EvaluatedAt = i.EvaluatedAt.UTC()
	return i
}

// Validate reports every malformed field, in declaration order so that output is
// deterministic. Diagnostics name the field but never echo its value.
func (i RunIdentity) Validate() []Diagnostic {
	var diags []Diagnostic
	add := func(code, message string) {
		diags = append(diags, Diagnostic{Code: code, Message: message})
	}

	if !validRepository(i.Repository) {
		add("identity.repository_invalid", "repository must be exactly owner/name using letters, digits, hyphen, underscore, or dot")
	}
	if !validCommitSHA(i.BaseSHA) {
		add("identity.base_sha_invalid", "base revision must be a full 40-character lowercase hexadecimal commit hash")
	}
	if !validCommitSHA(i.HeadSHA) {
		add("identity.head_sha_invalid", "head revision must be a full 40-character lowercase hexadecimal commit hash")
	}
	if !validDigest(i.PolicyDigest) {
		add("identity.policy_digest_invalid", "policy digest must be sha256: followed by 64 lowercase hexadecimal characters")
	}
	if !validDigest(i.WaiverDigest) {
		add("identity.waiver_digest_invalid", "waiver digest must be sha256: followed by 64 lowercase hexadecimal characters")
	}
	if !validEngineVersion(i.EngineVersion) {
		add("identity.engine_version_invalid", "engine version must be non-empty printable ASCII of at most 64 bytes")
	}
	switch {
	case i.EvaluatedAt.IsZero():
		add("identity.evaluated_at_invalid", "evaluated_at must be an explicit timestamp supplied by the trusted host")
	default:
		if _, offset := i.EvaluatedAt.Zone(); offset != 0 {
			add("identity.evaluated_at_not_utc", "evaluated_at must carry a zero UTC offset; normalize the identity first")
		}
	}

	return diags
}

// maxRepositoryBytes bounds the repository identity well above GitHub's own
// 39-character owner and 100-character repository limits.
const maxRepositoryBytes = 140

// validRepository accepts exactly `owner/name`. The check is written against a
// literal character set rather than a regular expression so its cost is linear
// and obvious.
func validRepository(s string) bool {
	if s == "" || len(s) > maxRepositoryBytes {
		return false
	}
	owner, name, found := strings.Cut(s, "/")
	if !found || strings.Contains(name, "/") {
		return false
	}
	return validRepositorySegment(owner) && validRepositorySegment(name)
}

func validRepositorySegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	// A leading dot would let a segment resemble a hidden path entry.
	if s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// validCommitSHA requires a full, unabbreviated, lowercase hash. Abbreviated
// hashes and symbolic refs are rejected because they are not immutable.
func validCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	return lowerHex(s)
}

// validDigest requires the `sha256:<64 lowercase hex>` form used throughout the
// canonical result.
func validDigest(s string) bool {
	const prefix = "sha256:"
	rest, found := strings.CutPrefix(s, prefix)
	if !found || len(rest) != 64 {
		return false
	}
	return lowerHex(rest)
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

// validEngineVersion requires printable ASCII so the version can be written into
// the console, Markdown, and SARIF without escaping, and so a control byte
// cannot ride into a report through the identity.
func validEngineVersion(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Limits are the hard resource bounds from docs/architecture.md. They are part
// of the run configuration and the integrity digest, so a result records the
// limits it was produced under. A future schema version may lower them without
// review; raising one requires benchmark and threat-model review.
type Limits struct {
	MaxChangedFiles         int           `json:"max_changed_files"`
	MaxChangedContentBytes  int64         `json:"max_changed_content_bytes"`
	MaxWorkflowFileBytes    int64         `json:"max_workflow_file_bytes"`
	MaxLockfileBytes        int64         `json:"max_lockfile_bytes"`
	MaxManifestBytes        int64         `json:"max_manifest_bytes"`
	MaxPolicyBytes          int64         `json:"max_policy_bytes"`
	MaxWaiverBytes          int64         `json:"max_waiver_bytes"`
	MaxParserDepth          int           `json:"max_parser_depth"`
	AnalyzerTimeout         time.Duration `json:"analyzer_timeout_ns"`
	RunTimeout              time.Duration `json:"run_timeout_ns"`
	MaxFindings             int           `json:"max_findings"`
	MaxSARIFResults         int           `json:"max_sarif_results"`
	MaxCanonicalOutputBytes int64         `json:"max_canonical_output_bytes"`
}

// DefaultLimits returns the approved version 1 limits. Limits is a value type
// with no reference fields, so each call returns an independent copy that a
// caller may lower without affecting anyone else.
func DefaultLimits() Limits {
	return Limits{
		MaxChangedFiles:         5000,
		MaxChangedContentBytes:  50 << 20,
		MaxWorkflowFileBytes:    2 << 20,
		MaxLockfileBytes:        10 << 20,
		MaxManifestBytes:        1 << 20,
		MaxPolicyBytes:          128 << 10,
		MaxWaiverBytes:          128 << 10,
		MaxParserDepth:          64,
		AnalyzerTimeout:         30 * time.Second,
		RunTimeout:              120 * time.Second,
		MaxFindings:             5000,
		MaxSARIFResults:         5000,
		MaxCanonicalOutputBytes: 50 << 20,
	}
}

// AnalyzerResult is one analyzer's entry in the completion ledger.
//
// Findings are added in Task 10, when the orchestration test first requires
// them; see Amendment 2 in the Gate 1 plan.
type AnalyzerResult struct {
	AnalyzerID      string       `json:"analyzer_id"`
	AnalyzerVersion string       `json:"analyzer_version"`
	Completion      Completion   `json:"completion"`
	CoverageNotes   []string     `json:"coverage_notes,omitempty"`
	DurationNanos   int64        `json:"duration_ns"`
	Diagnostics     []Diagnostic `json:"diagnostics,omitempty"`
}

// CanonicalRunResult is the authoritative output of a scan. Console, Markdown,
// checks, and SARIF are projections of this value and may not reinterpret it.
type CanonicalRunResult struct {
	SchemaVersion   string           `json:"schema_version"`
	Identity        RunIdentity      `json:"identity"`
	Status          Status           `json:"status"`
	Decision        Decision         `json:"decision"`
	Limits          Limits           `json:"limits"`
	Analyzers       []AnalyzerResult `json:"analyzers"`
	Diagnostics     []Diagnostic     `json:"diagnostics,omitempty"`
	IntegrityDigest string           `json:"integrity_digest"`
}
