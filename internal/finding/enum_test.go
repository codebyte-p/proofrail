package finding

import "testing"

// The ordered enums are the vocabulary every later Gate 1 package shares.
// Their order is fixed by docs/architecture.md and ADR 0001; a silent change to
// a rank would silently change a merge decision.

func TestSeverityOrderIsNoteToCritical(t *testing.T) {
	ascending := []Severity{SeverityNote, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i, s := range ascending {
		if !s.Valid() {
			t.Fatalf("severity %q must be valid", s)
		}
		if got := s.Rank(); got != i {
			t.Fatalf("severity %q rank = %d, want %d", s, got, i)
		}
	}
}

func TestConfidenceOrderIsLowToHigh(t *testing.T) {
	ascending := []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}
	for i, c := range ascending {
		if !c.Valid() {
			t.Fatalf("confidence %q must be valid", c)
		}
		if got := c.Rank(); got != i {
			t.Fatalf("confidence %q rank = %d, want %d", c, got, i)
		}
	}
}

func TestDecisionRestrictivenessOrder(t *testing.T) {
	// ADR 0001: block > require_review > warn > observe > pass.
	ascending := []Decision{DecisionPass, DecisionObserve, DecisionWarn, DecisionRequireReview, DecisionBlock}
	for i, d := range ascending {
		if !d.Valid() {
			t.Fatalf("decision %q must be valid", d)
		}
		if got := d.Rank(); got != i {
			t.Fatalf("decision %q rank = %d, want %d", d, got, i)
		}
	}
}

func TestUnknownEnumValuesAreRejected(t *testing.T) {
	if Severity("Critical").Valid() {
		t.Fatal("severity comparison must be case sensitive")
	}
	if Severity("").Valid() || Confidence("").Valid() || Decision("").Valid() {
		t.Fatal("the empty string is not a valid enum member")
	}
	if Decision("allow").Valid() {
		t.Fatal("decisions outside the registry must be rejected")
	}
	// An unknown member has no position in the order.
	if got := Severity("unknown").Rank(); got != -1 {
		t.Fatalf("unknown severity rank = %d, want -1", got)
	}
	if got := Decision("unknown").Rank(); got != -1 {
		t.Fatalf("unknown decision rank = %d, want -1", got)
	}
}

func TestMostRestrictiveSelectsTheStrongestDecision(t *testing.T) {
	cases := []struct {
		name string
		in   []Decision
		want Decision
	}{
		{"no matched rule falls through to pass", nil, DecisionPass},
		{"single warn", []Decision{DecisionWarn}, DecisionWarn},
		{"block wins over review", []Decision{DecisionRequireReview, DecisionBlock}, DecisionBlock},
		{"order of arguments does not matter", []Decision{DecisionBlock, DecisionRequireReview}, DecisionBlock},
		{"review wins over warn and observe", []Decision{DecisionObserve, DecisionWarn, DecisionRequireReview}, DecisionRequireReview},
		{"observe outranks pass", []Decision{DecisionPass, DecisionObserve}, DecisionObserve},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MostRestrictive(tc.in...); got != tc.want {
				t.Fatalf("MostRestrictive(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMostRestrictiveFailsClosedOnAnUnknownMember(t *testing.T) {
	// An unrecognized decision must never be treated as the weakest option.
	if got := MostRestrictive(DecisionPass, Decision("sneaky")); got != DecisionBlock {
		t.Fatalf("MostRestrictive with an unknown member = %q, want %q", got, DecisionBlock)
	}
}
