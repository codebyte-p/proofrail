// Package finding owns the canonical finding vocabulary: the ordered severity,
// confidence, and decision enums, and later the validated, redacted, and
// fingerprinted findings themselves.
//
// This package is the leaf of the Gate 1 dependency graph. It imports only the
// standard library so that every other package -- parsers, analyzers, policy,
// reporters, and the orchestrator -- can depend on it without a cycle.
package finding

// Severity describes the impact of a finding under its stated prerequisites.
// The order is fixed by docs/architecture.md: note < low < medium < high <
// critical. Policy `gte` and `lte` compare against these ranks, so reordering
// them would silently change existing merge decisions.
type Severity string

const (
	SeverityNote     Severity = "note"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityOrder is the single source of truth for both validity and rank.
var severityOrder = []Severity{
	SeverityNote,
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// Rank returns the position of s in the severity order, or -1 when s is not a
// registered member. Comparison is exact and case sensitive.
func (s Severity) Rank() int { return rankOf(severityOrder, s) }

// Valid reports whether s is a registered severity.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// Confidence describes the strength of the evidence behind a finding. Per the
// threat model it must never reduce a potentially critical impact; it exists so
// policy can route weak evidence to review instead of to a block.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

var confidenceOrder = []Confidence{
	ConfidenceLow,
	ConfidenceMedium,
	ConfidenceHigh,
}

// Rank returns the position of c in the confidence order, or -1 when c is not a
// registered member.
func (c Confidence) Rank() int { return rankOf(confidenceOrder, c) }

// Valid reports whether c is a registered confidence.
func (c Confidence) Valid() bool { return c.Rank() >= 0 }

// Decision is the response a finding or policy rule calls for. ADR 0001 fixes
// the restrictiveness order as block > require_review > warn > observe > pass,
// so Rank ascends in that same direction and the most restrictive decision is
// simply the highest rank.
//
// `pass` is deliberately unavailable as a policy rule decision: a rule may add
// a restriction but may never cancel another rule's restriction.
type Decision string

const (
	DecisionPass          Decision = "pass"
	DecisionObserve       Decision = "observe"
	DecisionWarn          Decision = "warn"
	DecisionRequireReview Decision = "require_review"
	DecisionBlock         Decision = "block"
)

var decisionOrder = []Decision{
	DecisionPass,
	DecisionObserve,
	DecisionWarn,
	DecisionRequireReview,
	DecisionBlock,
}

// Rank returns the restrictiveness of d, or -1 when d is not a registered
// member. A higher rank is more restrictive.
func (d Decision) Rank() int { return rankOf(decisionOrder, d) }

// Valid reports whether d is a registered decision.
func (d Decision) Valid() bool { return d.Rank() >= 0 }

// MostRestrictive returns the strongest decision among the supplied values.
//
// With no matched rule the result is DecisionPass, which is what an empty rule
// set means. An unrecognized member cannot be ordered against the registry, so
// it fails closed to DecisionBlock rather than being ignored or treated as the
// weakest option.
func MostRestrictive(decisions ...Decision) Decision {
	strongest := DecisionPass
	for _, d := range decisions {
		rank := d.Rank()
		if rank < 0 {
			return DecisionBlock
		}
		if rank > strongest.Rank() {
			strongest = d
		}
	}
	return strongest
}

// rankOf returns the index of want in order, or -1. The registries hold at most
// five members, so the linear scan is both bounded and the clearest statement of
// the ordering.
func rankOf[T comparable](order []T, want T) int {
	for i, have := range order {
		if have == want {
			return i
		}
	}
	return -1
}
