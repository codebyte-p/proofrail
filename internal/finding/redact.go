package finding

import (
	"strings"
	"unicode/utf8"
)

// MaxExcerptBytes is the evidence excerpt cap from docs/architecture.md.
const MaxExcerptBytes = 512

// Redact removes secret-shaped values and presentation control bytes from text
// that is about to reach a finding, a log, or a report.
//
// It is defence in depth, not the primary control: analyzers are expected to
// prefer structural evidence and digests over literal values. Detection is
// deliberately conservative in what it recognizes and aggressive in what it
// removes, because a missed secret is a credential-exposure incident while an
// over-redacted excerpt is only a readability cost.
//
// Every match is replaced by "[REDACTED:<kind>]". The matched bytes never
// survive into the output, so a caller cannot reconstruct the value from the
// result. Redact is idempotent: a marker written by an earlier pass is left
// alone. The result is always valid UTF-8.
//
// Matching is done with hand-written scanners rather than regular expressions:
// this runs over attacker-controlled text, and a linear scan has no catastrophic
// backtracking behaviour to reason about.
func Redact(s string) string {
	s = sanitizeUTF8(s)

	// Control bytes are stripped BEFORE any detector runs, and the order matters
	// for secrecy, not just tidiness.
	//
	// A control byte is invisible once rendered, so `AKIA00000000\x030000000`
	// reads as a valid access key to a human and to a terminal but not to a
	// scanner matching a contiguous run. Stripping afterwards would let that
	// value pass every detector unmatched and then rejoin into the real
	// credential on its way into the report. Detectors must see exactly the text
	// a reader will see. Found by FuzzRedact.
	s = stripControlBytes(s)

	// Shape-based detection runs next so a recognizable credential is reported
	// with its precise kind. The key-name rule then catches whatever is left:
	// an opaque value whose only signal is the name it was assigned to. Running
	// the key-name rule first would redact everything as a generic assignment
	// and throw away the more useful classification.
	s = redactPEMBodies(s)
	s = redactTokenShapes(s)
	s = redactSecretAssignments(s)
	return s
}

// TruncateExcerpt caps text at MaxExcerptBytes without splitting a UTF-8 rune.
// The result is always a prefix of the input, so an excerpt never gains content
// it did not have.
func TruncateExcerpt(s string) string {
	if len(s) <= MaxExcerptBytes {
		return s
	}
	cut := MaxExcerptBytes
	// Walk back to a rune boundary. A UTF-8 continuation byte is 10xxxxxx.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// sanitizeUTF8 replaces invalid byte sequences so that everything downstream --
// scanning, JSON serialization, and the fingerprint -- works on valid text.
func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		if r == utf8.RuneError {
			// Distinguish a real replacement character from a decode failure.
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				b.WriteString("�")
				continue
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

// secretKeyNames are the normalized key fragments from docs/architecture.md. A
// key whose normalized name contains one of these has its value replaced.
var secretKeyNames = []string{
	"private_key",
	"apikey",
	"api_key",
	"passwd",
	"password",
	"secret",
	"token",
}

// redactSecretAssignments finds `<key><separator><value>` on each line and
// replaces the value when the key looks secret-bearing.
func redactSecretAssignments(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = redactAssignmentInLine(line)
	}
	return strings.Join(lines, "\n")
}

func redactAssignmentInLine(line string) string {
	sep := -1
	for i := 0; i < len(line); i++ {
		if line[i] == '=' || line[i] == ':' {
			sep = i
			break
		}
	}
	if sep < 0 || sep == len(line)-1 {
		return line
	}

	key := normalizeKeyName(line[:sep])
	if key == "" || !looksSecretBearing(key) {
		return line
	}

	value := line[sep+1:]
	trimmed := strings.TrimLeft(value, " \t")
	if strings.TrimSpace(trimmed) == "" {
		return line
	}
	// Leave an already-redacted value alone so Redact stays idempotent.
	if strings.HasPrefix(strings.TrimSpace(trimmed), "[REDACTED:") {
		return line
	}
	leading := value[:len(value)-len(trimmed)]
	return line[:sep+1] + leading + "[REDACTED:secret_assignment]"
}

// normalizeKeyName reduces a key to lowercase letters, digits, and underscores
// so that `API-KEY`, `"apiKey"`, and `client_secret` all compare alike.
func normalizeKeyName(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r == '_' || r == '-':
			b.WriteByte('_')
		}
	}
	return b.String()
}

func looksSecretBearing(normalizedKey string) bool {
	for _, name := range secretKeyNames {
		if strings.Contains(normalizedKey, name) {
			return true
		}
	}
	return false
}

// tokenPrefixes are literal prefixes whose following run of token characters is
// a credential. Length bounds keep a short coincidental match from being
// redacted.
var tokenPrefixes = []struct {
	prefix  string
	minBody int
	kind    string
}{
	{"github_pat_", 40, "github_token"},
	{"ghp_", 30, "github_token"},
	{"gho_", 30, "github_token"},
	{"ghu_", 30, "github_token"},
	{"ghs_", 30, "github_token"},
	{"ghr_", 30, "github_token"},
	{"AKIA", 16, "aws_access_key_id"},
	{"ASIA", 16, "aws_access_key_id"},
	{"AROA", 16, "aws_access_key_id"},
	{"AIDA", 16, "aws_access_key_id"},
}

// redactTokenShapes scans once and replaces credential-shaped runs and GitHub
// `secrets.*` expressions.
func redactTokenShapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		// Do not rewrite a marker an earlier pass produced.
		if strings.HasPrefix(s[i:], "[REDACTED:") {
			end := strings.IndexByte(s[i:], ']')
			if end >= 0 {
				b.WriteString(s[i : i+end+1])
				i += end + 1
				continue
			}
		}

		if kind, width, ok := matchJWT(s[i:]); ok {
			b.WriteString("[REDACTED:" + kind + "]")
			i += width
			continue
		}
		if width, ok := matchSecretsExpression(s[i:]); ok {
			b.WriteString("[REDACTED:github_secret_expression]")
			i += width
			continue
		}
		if kind, width, ok := matchTokenPrefix(s[i:]); ok {
			b.WriteString("[REDACTED:" + kind + "]")
			i += width
			continue
		}

		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func matchTokenPrefix(s string) (kind string, width int, ok bool) {
	for _, tp := range tokenPrefixes {
		if !strings.HasPrefix(s, tp.prefix) {
			continue
		}
		body := 0
		for len(s) > len(tp.prefix)+body && isTokenByte(s[len(tp.prefix)+body]) {
			body++
		}
		if body >= tp.minBody {
			return tp.kind, len(tp.prefix) + body, true
		}
	}
	return "", 0, false
}

// matchJWT recognizes the compact three-segment form. Requiring the "eyJ"
// prefix (base64 for `{"`) keeps ordinary dotted identifiers from matching.
func matchJWT(s string) (kind string, width int, ok bool) {
	if !strings.HasPrefix(s, "eyJ") {
		return "", 0, false
	}
	segments, length, current := 0, 0, 0
	for length < len(s) {
		c := s[length]
		if isBase64URLByte(c) {
			current++
			length++
			continue
		}
		if c == '.' && current > 0 && segments < 2 {
			segments++
			current = 0
			length++
			continue
		}
		break
	}
	if segments == 2 && current > 0 {
		return "jwt", length, true
	}
	return "", 0, false
}

// matchSecretsExpression recognizes `secrets.NAME`, which appears inside a
// GitHub `${{ ... }}` expression and names a credential even though the value
// is not present in the text.
func matchSecretsExpression(s string) (width int, ok bool) {
	const prefix = "secrets."
	if !strings.HasPrefix(s, prefix) {
		return 0, false
	}
	name := 0
	for len(s) > len(prefix)+name {
		c := s[len(prefix)+name]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			name++
			continue
		}
		break
	}
	if name == 0 {
		return 0, false
	}
	return len(prefix) + name, true
}

// pemHeaders introduce key material whose body must not survive.
var pemHeaders = []string{
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN DSA PRIVATE KEY-----",
	"-----BEGIN EC PRIVATE KEY-----",
	"-----BEGIN OPENSSH PRIVATE KEY-----",
	"-----BEGIN PGP PRIVATE KEY BLOCK-----",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
	"-----BEGIN PRIVATE KEY-----",
}

// redactPEMBodies replaces everything from a private-key header up to its
// matching footer, or to the end of the text when the footer was truncated
// away. A header with no footer must still not leak the body that follows it.
func redactPEMBodies(s string) string {
	for {
		start, header := earliestPEMHeader(s)
		if start < 0 {
			return s
		}
		rest := s[start+len(header):]
		end := len(s)
		if idx := strings.Index(rest, "-----END"); idx >= 0 {
			if close := strings.Index(rest[idx:], "-----\n"); close >= 0 {
				end = start + len(header) + idx + close + len("-----\n")
			} else if close := strings.LastIndex(rest[idx:], "-----"); close > 0 {
				end = start + len(header) + idx + close + len("-----")
			}
		}
		s = s[:start] + "[REDACTED:private_key]" + s[end:]
	}
}

func earliestPEMHeader(s string) (int, string) {
	best, bestHeader := -1, ""
	for _, h := range pemHeaders {
		if idx := strings.Index(s, h); idx >= 0 && (best < 0 || idx < best) {
			best, bestHeader = idx, h
		}
	}
	return best, bestHeader
}

// stripControlBytes removes bytes that could rewrite a terminal, hide text, or
// break a Markdown table. Newline and tab survive because they are ordinary
// content in a code excerpt.
func stripControlBytes(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if isStrippableControl(s[i]) {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isStrippableControl(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isStrippableControl(c byte) bool {
	if c == '\n' || c == '\t' {
		return false
	}
	return c < 0x20 || c == 0x7f
}

func isTokenByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func isBase64URLByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}
