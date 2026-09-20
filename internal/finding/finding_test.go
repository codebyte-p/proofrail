package finding

import (
	"errors"
	"strings"
	"testing"
)

func validFinding() Finding {
	return Finding{
		RuleID:       "PFR-WF-001",
		AnalyzerID:   "github-workflow",
		Severity:     SeverityCritical,
		Confidence:   ConfidenceHigh,
		DecisionHint: DecisionBlock,
		Message:      "Privileged workflow can execute pull-request-controlled content.",
		Locations: []Location{
			{Path: ".github/workflows/ci.yml", StartLine: 3, EndLine: 9},
		},
		Evidence: []Evidence{
			{Kind: "workflow_trigger", Source: ".github/workflows/ci.yml", Excerpt: "on: pull_request_target"},
		},
		Limitations: []string{"static reachability may treat a job as runnable"},
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestFinalizeAcceptsAWellFormedFinding(t *testing.T) {
	got, err := Finalize(validFinding())
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if got.Fingerprint == "" {
		t.Fatal("Finalize must assign a fingerprint")
	}
}

func TestFinalizeRejectsIncompleteOrUnregisteredFindings(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*Finding)
		wantCode string
	}{
		{"missing rule id", func(f *Finding) { f.RuleID = "" }, "finding.rule_id_invalid"},
		{"missing analyzer id", func(f *Finding) { f.AnalyzerID = "" }, "finding.analyzer_id_invalid"},
		{"missing message", func(f *Finding) { f.Message = "" }, "finding.message_invalid"},
		{"no locations", func(f *Finding) { f.Locations = nil }, "finding.locations_invalid"},
		{"no evidence", func(f *Finding) { f.Evidence = nil }, "finding.evidence_invalid"},
		{"evidence without a kind", func(f *Finding) { f.Evidence[0].Kind = "" }, "finding.evidence_invalid"},
		{"unregistered severity", func(f *Finding) { f.Severity = Severity("catastrophic") }, "finding.severity_invalid"},
		{"unregistered confidence", func(f *Finding) { f.Confidence = Confidence("certain") }, "finding.confidence_invalid"},
		{"unregistered decision hint", func(f *Finding) { f.DecisionHint = Decision("allow") }, "finding.decision_hint_invalid"},
		{"decision hint of pass", func(f *Finding) { f.DecisionHint = DecisionPass }, "finding.decision_hint_invalid"},
		{"un-normalized location path", func(f *Finding) { f.Locations[0].Path = "../escape.yml" }, "finding.location_path_invalid"},
		{"absolute location path", func(f *Finding) { f.Locations[0].Path = "/etc/passwd" }, "finding.location_path_invalid"},
		{"backslash location path", func(f *Finding) { f.Locations[0].Path = `a\b.yml` }, "finding.location_path_invalid"},
		{"zero start line", func(f *Finding) { f.Locations[0].StartLine = 0 }, "finding.location_range_invalid"},
		{"negative start line", func(f *Finding) { f.Locations[0].StartLine = -1 }, "finding.location_range_invalid"},
		{"end before start", func(f *Finding) { f.Locations[0].EndLine = 1 }, "finding.location_range_invalid"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validFinding()
			tc.mutate(&f)
			got, err := Finalize(f)
			if err == nil {
				t.Fatalf("Finalize must reject this finding, got %+v", got)
			}
			var fe *ValidationError
			if !errors.As(err, &fe) {
				t.Fatalf("error %v is not a *ValidationError", err)
			}
			if fe.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", fe.Code, tc.wantCode)
			}
		})
	}
}

func TestFinalizeRejectsADecisionHintOfPass(t *testing.T) {
	// A finding may raise a concern; it can never assert that a change is fine.
	// Only the absence of matched rules produces pass.
	f := validFinding()
	f.DecisionHint = DecisionPass
	if _, err := Finalize(f); err == nil {
		t.Fatal("a finding must not be able to hint pass")
	}
}

// ---------------------------------------------------------------------------
// Normalization and ordering
// ---------------------------------------------------------------------------

func TestFinalizeSortsLocationsAndEvidence(t *testing.T) {
	f := validFinding()
	f.Locations = []Location{
		{Path: "z.yml", StartLine: 5, EndLine: 5},
		{Path: "a.yml", StartLine: 9, EndLine: 9},
		{Path: "a.yml", StartLine: 2, EndLine: 4},
		{Path: "a.yml", StartLine: 2, EndLine: 3},
	}
	f.Evidence = []Evidence{
		{Kind: "zeta", Source: "z.yml", Excerpt: "z"},
		{Kind: "alpha", Source: "a.yml", Excerpt: "a"},
		{Kind: "alpha", Source: "a.yml", Excerpt: "b"},
	}

	got, err := Finalize(f)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	wantLocations := []Location{
		{Path: "a.yml", StartLine: 2, EndLine: 3},
		{Path: "a.yml", StartLine: 2, EndLine: 4},
		{Path: "a.yml", StartLine: 9, EndLine: 9},
		{Path: "z.yml", StartLine: 5, EndLine: 5},
	}
	for i, want := range wantLocations {
		if got.Locations[i] != want {
			t.Fatalf("location %d = %+v, want %+v", i, got.Locations[i], want)
		}
	}

	wantKinds := []string{"alpha", "alpha", "zeta"}
	for i, want := range wantKinds {
		if got.Evidence[i].Kind != want {
			t.Fatalf("evidence %d kind = %q, want %q", i, got.Evidence[i].Kind, want)
		}
	}
}

func TestFinalizeRedactsAndBoundsEvidenceExcerpts(t *testing.T) {
	f := validFinding()
	f.Evidence = []Evidence{
		{Kind: "step_run", Source: "ci.yml", Excerpt: "deploy --token ghp_0123456789abcdefghijklmnopqrstuvwxyzA"},
		{Kind: "long", Source: "ci.yml", Excerpt: strings.Repeat("あ", 1000)},
	}

	got, err := Finalize(f)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	for _, e := range got.Evidence {
		if strings.Contains(e.Excerpt, "ghp_0123456789abcdefghijklmnopqrstuvwxyzA") {
			t.Fatal("Finalize must redact evidence excerpts")
		}
		if len(e.Excerpt) > MaxExcerptBytes {
			t.Fatalf("excerpt is %d bytes, want at most %d", len(e.Excerpt), MaxExcerptBytes)
		}
		if e.Digest == "" {
			t.Fatal("Finalize must record an evidence digest")
		}
		if !strings.HasPrefix(e.Digest, "sha256:") {
			t.Fatalf("digest = %q, want a sha256: prefix", e.Digest)
		}
	}
}

func TestFinalizeRedactsTheMessage(t *testing.T) {
	f := validFinding()
	f.Message = "found key AKIAIOSFODNN7EXAMPLE in the workflow"
	got, err := Finalize(f)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if strings.Contains(got.Message, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("message was not redacted: %q", got.Message)
	}
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

func TestFingerprintShapeAndStability(t *testing.T) {
	first, err := Finalize(validFinding())
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if !strings.HasPrefix(first.Fingerprint, "sha256:") {
		t.Fatalf("fingerprint = %q, want a sha256: prefix", first.Fingerprint)
	}
	hex := strings.TrimPrefix(first.Fingerprint, "sha256:")
	if len(hex) != 64 {
		t.Fatalf("fingerprint body is %d characters, want 64", len(hex))
	}
	for _, c := range hex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("fingerprint body is not lowercase hex: %q", hex)
		}
	}

	// A waiver is bound to an exact fingerprint, so instability would silently
	// expire every waiver in a repository.
	for i := 0; i < 100; i++ {
		again, err := Finalize(validFinding())
		if err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		if again.Fingerprint != first.Fingerprint {
			t.Fatalf("repetition %d produced %q, want %q", i, again.Fingerprint, first.Fingerprint)
		}
	}
}

func TestFingerprintChangesWithIdentityLocationAndEvidence(t *testing.T) {
	baseline, err := Finalize(validFinding())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*Finding)
	}{
		{"rule id", func(f *Finding) { f.RuleID = "PFR-WF-002" }},
		{"analyzer id", func(f *Finding) { f.AnalyzerID = "dependency" }},
		{"location path", func(f *Finding) { f.Locations[0].Path = ".github/workflows/other.yml" }},
		{"location start line", func(f *Finding) { f.Locations[0].StartLine = 4 }},
		{"location end line", func(f *Finding) { f.Locations[0].EndLine = 10 }},
		{"an added location", func(f *Finding) {
			f.Locations = append(f.Locations, Location{Path: "b.yml", StartLine: 1, EndLine: 1})
		}},
		{"evidence kind", func(f *Finding) { f.Evidence[0].Kind = "workflow_permission" }},
		{"evidence excerpt", func(f *Finding) { f.Evidence[0].Excerpt = "on: push" }},
		{"an added evidence item", func(f *Finding) {
			f.Evidence = append(f.Evidence, Evidence{Kind: "extra", Source: "x", Excerpt: "y"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validFinding()
			tc.mutate(&f)
			got, err := Finalize(f)
			if err != nil {
				t.Fatalf("Finalize: %v", err)
			}
			if got.Fingerprint == baseline.Fingerprint {
				t.Fatalf("changing %s must change the fingerprint", tc.name)
			}
		})
	}
}

func TestFingerprintIgnoresMutableProseAndInsertionOrder(t *testing.T) {
	baseline, err := Finalize(validFinding())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*Finding)
	}{
		// Retuning a rule's wording or severity must not expire a waiver.
		{"message wording", func(f *Finding) { f.Message = "Completely different prose." }},
		{"limitations", func(f *Finding) { f.Limitations = []string{"another caveat"} }},
		{"severity", func(f *Finding) { f.Severity = SeverityLow }},
		{"confidence", func(f *Finding) { f.Confidence = ConfidenceLow }},
		{"decision hint", func(f *Finding) { f.DecisionHint = DecisionRequireReview }},
		{"evidence source", func(f *Finding) { f.Evidence[0].Source = "somewhere/else.yml" }},
		{"location insertion order", func(f *Finding) {
			f.Locations = []Location{
				{Path: "b.yml", StartLine: 1, EndLine: 1},
				{Path: ".github/workflows/ci.yml", StartLine: 3, EndLine: 9},
			}
		}},
	}

	// The insertion-order case needs its own baseline containing both locations.
	orderBaseline := validFinding()
	orderBaseline.Locations = []Location{
		{Path: ".github/workflows/ci.yml", StartLine: 3, EndLine: 9},
		{Path: "b.yml", StartLine: 1, EndLine: 1},
	}
	orderFinalized, err := Finalize(orderBaseline)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validFinding()
			tc.mutate(&f)
			got, err := Finalize(f)
			if err != nil {
				t.Fatalf("Finalize: %v", err)
			}
			want := baseline.Fingerprint
			if tc.name == "location insertion order" {
				want = orderFinalized.Fingerprint
			}
			if got.Fingerprint != want {
				t.Fatalf("changing %s must not change the fingerprint", tc.name)
			}
		})
	}
}

func TestFingerprintIsNotConfusedByFieldConcatenation(t *testing.T) {
	// Without length prefixing, ("ab","c") and ("a","bc") would hash alike and
	// one waiver could silently suppress a different finding.
	a := validFinding()
	a.RuleID, a.AnalyzerID = "PFR-AB", "C"
	b := validFinding()
	b.RuleID, b.AnalyzerID = "PFR-A", "BC"

	fa, err := Finalize(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := Finalize(b)
	if err != nil {
		t.Fatal(err)
	}
	if fa.Fingerprint == fb.Fingerprint {
		t.Fatal("adjacent fields must be length-prefixed before hashing")
	}
}

func TestFingerprintIsUnaffectedByASecretInTheExcerpt(t *testing.T) {
	// The fingerprint derives from the redacted excerpt, so two findings that
	// differ only in the secret value they caught share a fingerprint and a
	// waiver stays valid after a credential rotation.
	a := validFinding()
	a.Evidence[0].Excerpt = "token = ghp_0123456789abcdefghijklmnopqrstuvwxyzA"
	b := validFinding()
	b.Evidence[0].Excerpt = "token = ghp_zyxwvutsrqponmlkjihgfedcba9876543210B"

	fa, err := Finalize(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := Finalize(b)
	if err != nil {
		t.Fatal(err)
	}
	if fa.Fingerprint != fb.Fingerprint {
		t.Fatal("the fingerprint must derive from redacted evidence, not the secret value")
	}
}

func TestFinalizeIsPureAndDoesNotMutateItsInput(t *testing.T) {
	original := validFinding()
	input := validFinding()
	if _, err := Finalize(input); err != nil {
		t.Fatal(err)
	}
	if input.Locations[0] != original.Locations[0] {
		t.Fatal("Finalize mutated the caller's locations")
	}
	if input.Evidence[0] != original.Evidence[0] {
		t.Fatal("Finalize mutated the caller's evidence")
	}
	if input.Message != original.Message {
		t.Fatal("Finalize mutated the caller's message")
	}
}

// ---------------------------------------------------------------------------
// Ordering across findings
// ---------------------------------------------------------------------------

func TestSortFindingsOrdersByFingerprint(t *testing.T) {
	// The canonical result lists findings by fingerprint ascending so repeated
	// runs are byte-identical.
	var findings []Finding
	for _, rule := range []string{"PFR-DIFF-001", "PFR-WF-001", "PFR-DEP-004", "PFR-WF-004"} {
		f := validFinding()
		f.RuleID = rule
		done, err := Finalize(f)
		if err != nil {
			t.Fatal(err)
		}
		findings = append(findings, done)
	}

	Sort(findings)
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Fingerprint > findings[i].Fingerprint {
			t.Fatalf("findings are not sorted by fingerprint at index %d", i)
		}
	}
}

// TestEvidenceOrderingIsDeterminedByTheWholeItem proves the evidence sort key
// determines the element it orders.
//
// Ordering by kind and digest alone leaves two items that agree on both but
// differ in source in whatever order the sort happened to visit them. Canonical
// JSON carries source, so an ordering that depends on a sort implementation
// detail makes the canonical bytes depend on it too. Independent review finding.
func TestEvidenceOrderingIsDeterminedByTheWholeItem(t *testing.T) {
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	a := Evidence{Kind: "workflow_trigger", Source: "a.yml#on", Digest: digest, Excerpt: "same"}
	b := Evidence{Kind: "workflow_trigger", Source: "b.yml#on", Digest: digest, Excerpt: "same"}

	forward := []Evidence{a, b}
	reversed := []Evidence{b, a}
	sortEvidence(forward)
	sortEvidence(reversed)

	for i := range forward {
		if forward[i] != reversed[i] {
			t.Fatalf("evidence order depends on input order at index %d: %+v vs %+v", i, forward[i], reversed[i])
		}
	}
}
