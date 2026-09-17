package run

import (
	"strings"
	"testing"
	"time"
)

func validIdentity() RunIdentity {
	return RunIdentity{
		Repository:    "codebyte-p/proofrail",
		BaseSHA:       "1111111111111111111111111111111111111111",
		HeadSHA:       "2222222222222222222222222222222222222222",
		PolicyDigest:  "sha256:" + strings.Repeat("a", 64),
		WaiverDigest:  "sha256:" + strings.Repeat("b", 64),
		EngineVersion: "0.1.0-alpha",
		EvaluatedAt:   time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
	}
}

func TestRunIdentityValidation(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*RunIdentity)
		wantCode string
	}{
		{"accepts a fully bound identity", func(*RunIdentity) {}, ""},

		{"repository must be owner/name", func(i *RunIdentity) { i.Repository = "proofrail" }, "identity.repository_invalid"},
		{"repository rejects a nested path", func(i *RunIdentity) { i.Repository = "a/b/c" }, "identity.repository_invalid"},
		{"repository rejects an empty owner", func(i *RunIdentity) { i.Repository = "/proofrail" }, "identity.repository_invalid"},
		{"repository rejects an empty name", func(i *RunIdentity) { i.Repository = "codebyte-p/" }, "identity.repository_invalid"},
		{"repository rejects a traversal segment", func(i *RunIdentity) { i.Repository = "../proofrail" }, "identity.repository_invalid"},
		{"repository rejects whitespace", func(i *RunIdentity) { i.Repository = "code byte/proofrail" }, "identity.repository_invalid"},
		{"repository rejects a NUL byte", func(i *RunIdentity) { i.Repository = "a\x00b/c" }, "identity.repository_invalid"},
		{"repository is required", func(i *RunIdentity) { i.Repository = "" }, "identity.repository_invalid"},

		{"base sha rejects a short value", func(i *RunIdentity) { i.BaseSHA = "abc" }, "identity.base_sha_invalid"},
		{"base sha rejects uppercase hex", func(i *RunIdentity) { i.BaseSHA = strings.Repeat("A", 40) }, "identity.base_sha_invalid"},
		{"base sha rejects a non-hex character", func(i *RunIdentity) { i.BaseSHA = strings.Repeat("g", 40) }, "identity.base_sha_invalid"},
		{"base sha rejects an abbreviated ref", func(i *RunIdentity) { i.BaseSHA = "HEAD~1" }, "identity.base_sha_invalid"},
		{"base sha is required", func(i *RunIdentity) { i.BaseSHA = "" }, "identity.base_sha_invalid"},
		{"head sha rejects a short value", func(i *RunIdentity) { i.HeadSHA = strings.Repeat("c", 39) }, "identity.head_sha_invalid"},

		{"policy digest requires the sha256 prefix", func(i *RunIdentity) { i.PolicyDigest = strings.Repeat("a", 64) }, "identity.policy_digest_invalid"},
		{"policy digest rejects a short body", func(i *RunIdentity) { i.PolicyDigest = "sha256:" + strings.Repeat("a", 63) }, "identity.policy_digest_invalid"},
		{"policy digest rejects another algorithm", func(i *RunIdentity) { i.PolicyDigest = "md5:" + strings.Repeat("a", 32) }, "identity.policy_digest_invalid"},
		{"policy digest is required", func(i *RunIdentity) { i.PolicyDigest = "" }, "identity.policy_digest_invalid"},
		{"waiver digest is required", func(i *RunIdentity) { i.WaiverDigest = "" }, "identity.waiver_digest_invalid"},

		{"engine version is required", func(i *RunIdentity) { i.EngineVersion = "" }, "identity.engine_version_invalid"},
		{"engine version rejects a control byte", func(i *RunIdentity) { i.EngineVersion = "0.1.0\x1b[31m" }, "identity.engine_version_invalid"},

		{"evaluated_at is required", func(i *RunIdentity) { i.EvaluatedAt = time.Time{} }, "identity.evaluated_at_invalid"},
		{"evaluated_at must carry no zone offset", func(i *RunIdentity) {
			i.EvaluatedAt = time.Date(2026, 9, 16, 12, 0, 0, 0, time.FixedZone("IST", 5*3600+1800))
		}, "identity.evaluated_at_not_utc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := validIdentity()
			tc.mutate(&id)
			got := id.Validate()

			if tc.wantCode == "" {
				if len(got) != 0 {
					t.Fatalf("expected no diagnostics, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected exactly one diagnostic, got %+v", got)
			}
			if got[0].Code != tc.wantCode {
				t.Fatalf("diagnostic code = %q, want %q", got[0].Code, tc.wantCode)
			}
			if got[0].Message == "" {
				t.Fatal("a diagnostic must carry a human-readable message")
			}
		})
	}
}

func TestRunIdentityDiagnosticsNeverEchoTheRejectedValue(t *testing.T) {
	// A rejected identity field is attacker-influenced text. Echoing it would put
	// hostile content into console output, logs, and reports.
	//
	// The canaries are deliberately distinctive strings that cannot appear in
	// legitimate diagnostic prose; a common word such as "owner" would collide
	// with the wording that describes the expected owner/name format.
	canaries := []string{"pr00frail-canary", "/../../etc/passwd", "\x1b[2J", "\x00"}
	hostile := "pr00frail-canary\x1b[2J\x00/../../etc/passwd"

	for _, field := range []struct {
		name   string
		mutate func(*RunIdentity)
	}{
		{"repository", func(i *RunIdentity) { i.Repository = hostile }},
		{"base sha", func(i *RunIdentity) { i.BaseSHA = hostile }},
		{"head sha", func(i *RunIdentity) { i.HeadSHA = hostile }},
		{"policy digest", func(i *RunIdentity) { i.PolicyDigest = hostile }},
		{"waiver digest", func(i *RunIdentity) { i.WaiverDigest = hostile }},
		{"engine version", func(i *RunIdentity) { i.EngineVersion = hostile }},
	} {
		t.Run(field.name, func(t *testing.T) {
			id := validIdentity()
			field.mutate(&id)

			diags := id.Validate()
			if len(diags) == 0 {
				t.Fatal("the hostile value must be rejected")
			}
			for _, d := range diags {
				for _, canary := range canaries {
					if strings.Contains(d.Message, canary) || strings.Contains(d.Path, canary) || strings.Contains(d.Code, canary) {
						t.Fatalf("diagnostic leaked the rejected value: %q", d)
					}
				}
			}
		})
	}
}

func TestRunIdentityValidateReportsEveryFailedFieldInOrder(t *testing.T) {
	got := RunIdentity{}.Validate()
	want := []string{
		"identity.repository_invalid",
		"identity.base_sha_invalid",
		"identity.head_sha_invalid",
		"identity.policy_digest_invalid",
		"identity.waiver_digest_invalid",
		"identity.engine_version_invalid",
		"identity.evaluated_at_invalid",
	}
	if len(got) != len(want) {
		t.Fatalf("a zero identity must report all %d fields, got %d: %+v", len(want), len(got), got)
	}
	for i, code := range want {
		if got[i].Code != code {
			t.Fatalf("diagnostic %d = %q, want %q", i, got[i].Code, code)
		}
	}
}

func TestRunIdentityCanonicalNormalizesTheTimestampToUTC(t *testing.T) {
	id := validIdentity()
	id.EvaluatedAt = time.Date(2026, 9, 16, 17, 30, 0, 0, time.FixedZone("IST", 5*3600+1800))

	if len(id.Validate()) == 0 {
		t.Fatal("an un-normalized identity must not validate")
	}

	got := id.Canonical()
	if diags := got.Validate(); len(diags) != 0 {
		t.Fatalf("canonical identity must validate, got %+v", diags)
	}
	want := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	if !got.EvaluatedAt.Equal(want) {
		t.Fatalf("EvaluatedAt = %s, want %s", got.EvaluatedAt, want)
	}
	if name, offset := got.EvaluatedAt.Zone(); offset != 0 {
		t.Fatalf("EvaluatedAt zone = %s (%d), want a zero offset", name, offset)
	}
}

func TestDefaultLimitsMatchTheApprovedArchitecture(t *testing.T) {
	// docs/architecture.md "Resource limits and safe failure". Raising any of
	// these requires benchmark and threat-model review, so they are asserted
	// exactly rather than loosely.
	l := DefaultLimits()
	cases := []struct {
		name string
		got  int64
		want int64
	}{
		{"changed files", int64(l.MaxChangedFiles), 5000},
		{"aggregate changed content", l.MaxChangedContentBytes, 50 << 20},
		{"workflow file", l.MaxWorkflowFileBytes, 2 << 20},
		{"lockfile", l.MaxLockfileBytes, 10 << 20},
		{"manifest", l.MaxManifestBytes, 1 << 20},
		{"policy document", l.MaxPolicyBytes, 128 << 10},
		{"waiver document", l.MaxWaiverBytes, 128 << 10},
		{"parser nesting", int64(l.MaxParserDepth), 64},
		{"findings", int64(l.MaxFindings), 5000},
		{"sarif results", int64(l.MaxSARIFResults), 5000},
		{"canonical output", l.MaxCanonicalOutputBytes, 50 << 20},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s limit = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	if l.AnalyzerTimeout != 30*time.Second {
		t.Errorf("analyzer timeout = %s, want 30s", l.AnalyzerTimeout)
	}
	if l.RunTimeout != 120*time.Second {
		t.Errorf("run timeout = %s, want 120s", l.RunTimeout)
	}
}

func TestDefaultLimitsAreCopiedNotShared(t *testing.T) {
	a := DefaultLimits()
	a.MaxChangedFiles = 1
	if DefaultLimits().MaxChangedFiles != 5000 {
		t.Fatal("DefaultLimits must return an independent value")
	}
}

func TestCompletionStatusRegistry(t *testing.T) {
	// docs/analyzers.md: complete, not_applicable, disabled, or failed.
	for _, c := range []Completion{CompletionComplete, CompletionNotApplicable, CompletionDisabled, CompletionFailed} {
		if !c.Valid() {
			t.Fatalf("completion %q must be valid", c)
		}
	}
	if Completion("skipped").Valid() || Completion("").Valid() {
		t.Fatal("completion values outside the registry must be rejected")
	}
	// Only complete or not_applicable lets a required analyzer slot be treated
	// as covered. Anything else must drive the run to incomplete.
	if CompletionFailed.SatisfiesRequirement() {
		t.Fatal("a failed analyzer can never satisfy a required analyzer slot")
	}
	if CompletionDisabled.SatisfiesRequirement() {
		t.Fatal("a disabled analyzer can never satisfy a required analyzer slot")
	}
	if Completion("").SatisfiesRequirement() {
		t.Fatal("an unset completion can never satisfy a required analyzer slot")
	}
	if !CompletionComplete.SatisfiesRequirement() || !CompletionNotApplicable.SatisfiesRequirement() {
		t.Fatal("complete and not_applicable satisfy a required analyzer slot")
	}
}
