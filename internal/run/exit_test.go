package run

import "testing"

// docs/architecture.md: exit 0 for pass or warn, 1 for require_review or block,
// 2 for incomplete or internal error. No configuration may map incomplete to a
// success code, so ExitCode inspects status before it inspects the decision.

func TestExitCode(t *testing.T) {
	cases := []struct {
		name     string
		status   Status
		decision Decision
		want     int
	}{
		{"pass", StatusComplete, DecisionPass, 0},
		{"warn", StatusComplete, DecisionWarn, 0},
		{"observe", StatusComplete, DecisionObserve, 0},
		{"require review", StatusComplete, DecisionRequireReview, 1},
		{"block", StatusComplete, DecisionBlock, 1},
		{"incomplete", StatusIncomplete, DecisionBlock, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExitCode(CanonicalRunResult{Status: tc.status, Decision: tc.decision})
			if got != tc.want {
				t.Fatalf("ExitCode(%q, %q) = %d, want %d", tc.status, tc.decision, got, tc.want)
			}
		})
	}
}

func TestExitCodeNeverTurnsIncompleteIntoSuccess(t *testing.T) {
	// An incomplete run carries a forced block decision, but even a result that
	// was tampered with so it claims pass must still exit 2.
	for _, d := range []Decision{DecisionPass, DecisionWarn, DecisionObserve, DecisionRequireReview, DecisionBlock, Decision("")} {
		got := ExitCode(CanonicalRunResult{Status: StatusIncomplete, Decision: d})
		if got != 2 {
			t.Fatalf("ExitCode(incomplete, %q) = %d, want 2", d, got)
		}
	}
}

func TestExitCodeFailsClosedOnUnrecognizedValues(t *testing.T) {
	cases := []struct {
		name   string
		result CanonicalRunResult
	}{
		{"zero value result", CanonicalRunResult{}},
		{"unknown status", CanonicalRunResult{Status: Status("ok"), Decision: DecisionPass}},
		{"unknown decision", CanonicalRunResult{Status: StatusComplete, Decision: Decision("allow")}},
		{"empty decision", CanonicalRunResult{Status: StatusComplete, Decision: Decision("")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.result); got != 2 {
				t.Fatalf("ExitCode = %d, want 2 for an unrecognized result", got)
			}
		})
	}
}
