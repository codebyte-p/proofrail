package finding

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Redaction is the last line of defence before evidence reaches a report. The
// threat model treats a secret value in a finding, a log, or a SARIF upload as a
// credential-exposure incident, so these tests assert the matched value is gone
// rather than merely that a marker appeared.

func TestRedactReplacesRecognizedSecretShapes(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		kind   string
		secret string
	}{
		{
			"github classic personal access token",
			"token = ghp_0123456789abcdefghijklmnopqrstuvwxyzA",
			"github_token",
			"ghp_0123456789abcdefghijklmnopqrstuvwxyzA",
		},
		{
			"github fine-grained token",
			"use github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb here",
			"github_token",
			"github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		{
			"github server-to-server token",
			"ghs_0123456789abcdefghijklmnopqrstuvwxyzA",
			"github_token",
			"ghs_0123456789abcdefghijklmnopqrstuvwxyzA",
		},
		{
			"aws access key id",
			"aws_key AKIAIOSFODNN7EXAMPLE trailing",
			"aws_access_key_id",
			"AKIAIOSFODNN7EXAMPLE",
		},
		{
			"aws temporary access key id",
			"ASIAIOSFODNN7EXAMPLE",
			"aws_access_key_id",
			"ASIAIOSFODNN7EXAMPLE",
		},
		{
			"pem private key header",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
			"private_key",
			"MIIEow==",
		},
		{
			"openssh private key header",
			"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n",
			"private_key",
			"b3BlbnNzaA==",
		},
		{
			"compact jwt",
			"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			"jwt",
			"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			"github secrets expression",
			"run: deploy --key ${{ secrets.DEPLOY_KEY }}",
			"github_secret_expression",
			"secrets.DEPLOY_KEY",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Fatalf("Redact left the secret in place: %q", got)
			}
			marker := "[REDACTED:" + tc.kind + "]"
			if !strings.Contains(got, marker) {
				t.Fatalf("Redact(%q) = %q, want it to contain %q", tc.in, got, marker)
			}
		})
	}
}

func TestRedactHandlesSecretBearingKeyNames(t *testing.T) {
	// docs/architecture.md: keys whose normalized name contains token, secret,
	// password, passwd, private_key, or api_key have their value replaced.
	cases := []string{
		"token: hunter2-pr00frail",
		"TOKEN = hunter2-pr00frail",
		"secret: hunter2-pr00frail",
		"client_secret=hunter2-pr00frail",
		"password: hunter2-pr00frail",
		"passwd = hunter2-pr00frail",
		"private_key: hunter2-pr00frail",
		"api_key = hunter2-pr00frail",
		"API-KEY: hunter2-pr00frail",
		`"apiKey": "hunter2-pr00frail"`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := Redact(in)
			if strings.Contains(got, "hunter2-pr00frail") {
				t.Fatalf("Redact(%q) = %q, secret value survived", in, got)
			}
			if !strings.Contains(got, "[REDACTED:") {
				t.Fatalf("Redact(%q) = %q, want a redaction marker", in, got)
			}
		})
	}
}

func TestRedactNeutralizesPresentationControlBytes(t *testing.T) {
	// A crafted file name or evidence string must not be able to rewrite a
	// terminal or break out of a Markdown table.
	cases := []struct {
		name string
		in   string
	}{
		{"terminal clear", "before\x1b[2Jafter"},
		{"carriage return overwrite", "visible\rhidden"},
		{"bell", "ding\x07dong"},
		{"backspace", "a\bb"},
		{"NUL", "a\x00b"},
		{"OSC sequence", "x\x1b]0;title\x07y"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			for _, b := range []byte(got) {
				if b < 0x20 && b != '\n' && b != '\t' {
					t.Fatalf("Redact(%q) = %q, control byte %#x survived", tc.in, got, b)
				}
				if b == 0x7f {
					t.Fatalf("Redact(%q) = %q, DEL survived", tc.in, got)
				}
			}
		})
	}
}

func TestRedactPreservesOrdinaryText(t *testing.T) {
	// Over-redaction destroys the evidence that makes a finding actionable.
	cases := []string{
		"uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
		"on: pull_request_target",
		"permissions: write-all",
		"if (!user.hasRole(\"admin\")) return forbidden();",
		"npm install --ignore-scripts",
		"docs/ドキュメント.md",
	}
	for _, in := range cases {
		if got := Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestRedactIsIdempotent(t *testing.T) {
	// Evidence may pass through redaction more than once; a second pass must not
	// corrupt a marker written by the first.
	inputs := []string{
		"token = ghp_0123456789abcdefghijklmnopqrstuvwxyzA",
		"AKIAIOSFODNN7EXAMPLE",
		"password: hunter2-pr00frail",
		"clean text",
		"before\x1b[2Jafter",
	}
	for _, in := range inputs {
		once := Redact(in)
		twice := Redact(once)
		if once != twice {
			t.Errorf("Redact is not idempotent for %q: %q -> %q", in, once, twice)
		}
	}
}

func TestRedactAlwaysReturnsValidUTF8(t *testing.T) {
	inputs := []string{
		"valid text",
		"\xff\xfe invalid bytes",
		"token = ghp_0123456789abcdefghijklmnopqrstuvwxyzA\xff",
		string([]byte{0xc3, 0x28}),
	}
	for _, in := range inputs {
		got := Redact(in)
		if !utf8.ValidString(got) {
			t.Errorf("Redact(%q) produced invalid UTF-8: %q", in, got)
		}
	}
}

func TestTruncateExcerptRespectsTheByteBoundAndEncoding(t *testing.T) {
	// docs/architecture.md caps excerpts at 512 UTF-8 bytes. Cutting mid-rune
	// would emit invalid UTF-8 into canonical JSON.
	cases := []struct {
		name string
		in   string
	}{
		{"ascii well under the bound", "short"},
		{"ascii exactly at the bound", strings.Repeat("a", MaxExcerptBytes)},
		{"ascii one over the bound", strings.Repeat("a", MaxExcerptBytes+1)},
		{"ascii far over the bound", strings.Repeat("a", MaxExcerptBytes*3)},
		// A 3-byte rune repeated does not divide evenly into 512.
		{"multibyte over the bound", strings.Repeat("あ", MaxExcerptBytes)},
		// A 4-byte rune straddles the boundary differently again.
		{"astral plane over the bound", strings.Repeat("😀", MaxExcerptBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TruncateExcerpt(tc.in)
			if len(got) > MaxExcerptBytes {
				t.Fatalf("length = %d, want at most %d", len(got), MaxExcerptBytes)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("truncation produced invalid UTF-8: %q", got)
			}
			if len(tc.in) <= MaxExcerptBytes && got != tc.in {
				t.Fatalf("an excerpt within the bound must be unchanged")
			}
			if !strings.HasPrefix(tc.in, got) {
				t.Fatalf("truncation must keep a prefix of the input")
			}
		})
	}
}

func TestTruncateExcerptIsIdempotent(t *testing.T) {
	for _, in := range []string{strings.Repeat("あ", MaxExcerptBytes), strings.Repeat("a", MaxExcerptBytes+7)} {
		once := TruncateExcerpt(in)
		if twice := TruncateExcerpt(once); once != twice {
			t.Errorf("TruncateExcerpt is not idempotent: %q -> %q", once, twice)
		}
	}
}
