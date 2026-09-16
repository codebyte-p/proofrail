package finding

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// seededSecrets are values that must never survive redaction, whatever
// surrounding bytes the fuzzer wraps them in.
var seededSecrets = []string{
	"ghp_0123456789abcdefghijklmnopqrstuvwxyzA",
	"github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	"AKIAIOSFODNN7EXAMPLE",
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
}

func FuzzRedact(f *testing.F) {
	seeds := []string{
		"",
		"ordinary evidence text",
		"token = ghp_0123456789abcdefghijklmnopqrstuvwxyzA",
		"AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----\ntruncated with no footer",
		"${{ secrets.DEPLOY_KEY }}",
		"\x1b[2J\x07\x00\x7f",
		"\xff\xfe\xfd",
		strings.Repeat("あ", 600),
		strings.Repeat("[REDACTED:", 50),
		"password:",
		"password: ",
		":::::::",
		"=",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got := Redact(in)

		if !utf8.ValidString(got) {
			t.Fatalf("Redact produced invalid UTF-8 from %q", in)
		}
		// Idempotence matters because evidence can pass through redaction more
		// than once on its way to a report.
		if again := Redact(got); again != got {
			t.Fatalf("Redact is not idempotent: %q -> %q -> %q", in, got, again)
		}
		for _, b := range []byte(got) {
			if (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f {
				t.Fatalf("control byte %#x survived redaction of %q", b, in)
			}
		}
	})
}

func FuzzRedactNeverLeaksASeededSecret(f *testing.F) {
	f.Add("prefix ", " suffix", 0)
	f.Add("", "", 1)
	f.Add("\x1b[2J", "\x00", 2)
	f.Add("token = ", "\n", 3)
	f.Add(strings.Repeat("a", 600), strings.Repeat("b", 600), 0)

	f.Fuzz(func(t *testing.T, prefix, suffix string, which int) {
		if which < 0 {
			which = -which
		}
		secret := seededSecrets[which%len(seededSecrets)]

		got := Redact(prefix + secret + suffix)
		if strings.Contains(got, secret) {
			t.Fatalf("seeded secret survived redaction: prefix=%q suffix=%q result=%q", prefix, suffix, got)
		}

		// Truncation must not resurrect a fragment either.
		if bounded := TruncateExcerpt(got); strings.Contains(bounded, secret) {
			t.Fatalf("seeded secret survived truncation: %q", bounded)
		}
	})
}

func FuzzTruncateExcerpt(f *testing.F) {
	f.Add("")
	f.Add("short")
	f.Add(strings.Repeat("a", MaxExcerptBytes))
	f.Add(strings.Repeat("あ", MaxExcerptBytes))
	f.Add(strings.Repeat("😀", MaxExcerptBytes))
	f.Add("\xff\xfe")

	f.Fuzz(func(t *testing.T, in string) {
		got := TruncateExcerpt(in)

		if len(got) > MaxExcerptBytes {
			t.Fatalf("TruncateExcerpt(%d bytes) returned %d bytes", len(in), len(got))
		}
		if !strings.HasPrefix(in, got) {
			t.Fatalf("truncation must return a prefix of its input")
		}
		if utf8.ValidString(in) && !utf8.ValidString(got) {
			t.Fatalf("truncation broke a rune: %q -> %q", in, got)
		}
		if again := TruncateExcerpt(got); again != got {
			t.Fatalf("TruncateExcerpt is not idempotent")
		}
	})
}

func FuzzFinalize(f *testing.F) {
	f.Add("PFR-WF-001", "github-workflow", "message", "a.yml", 1, 2, "kind", "excerpt")
	f.Add("", "", "", "", 0, 0, "", "")
	f.Add("R", "A", "m", "../escape", -1, -1, "k", "\x00")
	f.Add("R", "A", "m", "a//b", 1, 1, "k", strings.Repeat("あ", 900))
	f.Add("R\x1b", "A", "m", "a.yml", 1, 1, "k", "${{ secrets.X }}")

	f.Fuzz(func(t *testing.T, rule, analyzer, message, path string, start, end int, kind, excerpt string) {
		candidate := Finding{
			RuleID:       rule,
			AnalyzerID:   analyzer,
			Severity:     SeverityMedium,
			Confidence:   ConfidenceMedium,
			DecisionHint: DecisionRequireReview,
			Message:      message,
			Locations:    []Location{{Path: path, StartLine: start, EndLine: end}},
			Evidence:     []Evidence{{Kind: kind, Source: path, Excerpt: excerpt}},
		}

		// Finalize either rejects or returns a fully canonical finding. It must
		// never panic and never return a half-built value.
		got, err := Finalize(candidate)
		if err != nil {
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("Finalize returned a non-ValidationError: %v", err)
			}
			if ve.Code == "" {
				t.Fatal("a rejection must carry a stable code")
			}
			return
		}

		if !strings.HasPrefix(got.Fingerprint, "sha256:") || len(got.Fingerprint) != len("sha256:")+64 {
			t.Fatalf("malformed fingerprint %q", got.Fingerprint)
		}
		for _, e := range got.Evidence {
			if len(e.Excerpt) > MaxExcerptBytes {
				t.Fatalf("excerpt exceeded the bound: %d bytes", len(e.Excerpt))
			}
			if !utf8.ValidString(e.Excerpt) {
				t.Fatalf("excerpt is not valid UTF-8: %q", e.Excerpt)
			}
		}
		// Finalization is deterministic, which is what makes waivers durable.
		again, err := Finalize(candidate)
		if err != nil {
			t.Fatalf("second Finalize disagreed with the first: %v", err)
		}
		if again.Fingerprint != got.Fingerprint {
			t.Fatalf("fingerprint is not deterministic: %q vs %q", got.Fingerprint, again.Fingerprint)
		}
	})
}
