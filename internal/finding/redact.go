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
	s = redactURLCredentials(s)
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
	// An Authorization value is opaque by design: a bearer or basic credential
	// has no recognizable prefix, so shape detection cannot see it and the key
	// name is the only signal there is. `proxy_authorization` normalizes to a
	// string containing this one, so both headers are covered.
	"authorization",
	"credential",
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

// markerWidth returns the full width of a redaction marker at the start of s,
// or 0 when s does not begin with one.
//
// Only a marker this package could have written counts: `[REDACTED:` followed
// by a lowercase kind and a closing bracket. Trusting any bracketed text that
// merely started with the prefix let attacker-supplied content wear the marker
// as a disguise -- `0[REDACTED: GITHUB_PAT: github_pat_...]` was skipped whole
// by every detector and the token inside survived untouched.
func markerWidth(s string) int {
	const prefix = "[REDACTED:"
	if !strings.HasPrefix(s, prefix) {
		return 0
	}
	i := len(prefix)
	for i < len(s) && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_') {
		i++
	}
	if i == len(prefix) || i >= len(s) || s[i] != ']' {
		return 0
	}
	return i + 1
}

// isKeyByte reports whether c can appear in a key name.
//
// A key is the token immediately touching the separator, nothing more. Walking
// further back swallowed whole sentences of prose, so a finding message
// containing the word "token" before a colon lost its content — evidence
// destroyed in canonical JSON, which is the source of truth.
func isKeyByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
}

// redactAssignmentInLine redacts every secret-bearing assignment on one line.
func redactAssignmentInLine(line string) string {
	var b strings.Builder
	b.Grow(len(line))

	pos := 0
	for pos < len(line) {
		sep := indexOfSeparator(line, pos)
		if sep < 0 {
			break
		}

		key := normalizeKeyName(keyBefore(line, pos, sep))
		valueStart := sep + 1
		valueEnd := endOfValue(line, valueStart)

		value := line[valueStart:valueEnd]
		trimmed := strings.TrimLeft(value, " \t")

		// A quoted value keeps its quotes and only its content is replaced.
		// Swallowing the quotes made an empty `""` look like a value worth
		// redacting, and the marker then absorbed whatever followed the closing
		// quote on the next pass, so `token=""0` lost its `0`.
		open, inner, closing := "", trimmed, ""
		if len(trimmed) >= 2 && (trimmed[0] == '"' || trimmed[0] == '\'') && trimmed[len(trimmed)-1] == trimmed[0] {
			open, inner, closing = trimmed[:1], trimmed[1:len(trimmed)-1], trimmed[len(trimmed)-1:]
		}

		switch {
		case key == "" || !looksSecretBearing(key),
			strings.TrimSpace(inner) == "",
			valueAlreadyClassified(strings.TrimSpace(inner)):
			// Not a secret-bearing assignment. Emit only through the separator
			// and resume scanning inside the value, because a secret can be
			// nested in one: `a: "password: <secret>"` would otherwise be
			// consumed whole as the innocuous value of `a`.
			b.WriteString(line[pos : sep+1])
			pos = sep + 1
		default:
			leading := value[:len(value)-len(trimmed)]
			b.WriteString(line[pos : sep+1])
			b.WriteString(leading)
			b.WriteString(open)
			b.WriteString("[REDACTED:secret_assignment]")
			b.WriteString(closing)
			pos = valueEnd
		}
	}
	b.WriteString(line[pos:])
	return b.String()
}

// indexOfSeparator returns the next assignment separator at or after start.
//
// A separator inside an existing redaction marker is skipped, because the
// marker's own text would otherwise be read as a key/value pair on a later
// pass and break idempotence.
func indexOfSeparator(line string, start int) int {
	for i := start; i < len(line); i++ {
		if w := markerWidth(line[i:]); w > 0 {
			i += w - 1
			continue
		}
		if line[i] == '=' || line[i] == ':' {
			return i
		}
	}
	return -1
}

// keyBefore returns the token immediately preceding a separator, which is the
// key that names the value being assigned.
func keyBefore(line string, start, sep int) string {
	// A JSON or YAML key is quoted, and the closing quote sits between the name
	// and the separator. Stopping at it returned an empty key, so every quoted
	// secret-bearing name went uninspected.
	end := sep
	// `TOKEN = value` puts whitespace between the name and the separator.
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	if end > start && (line[end-1] == '"' || line[end-1] == '\'') {
		end--
	}
	begin := end
	for begin > start && isKeyByte(line[begin-1]) {
		begin--
	}
	return line[begin:end]
}

// endOfValue returns the index just past the assigned value.
//
// The value runs to the next `,` or `;`, to the start of the next assignment,
// or to the end of the line -- whichever comes first. A quoted value instead
// runs to its closing quote, because a comma inside quotes belongs to the
// secret rather than ending it; stopping at one left the tail in cleartext.
func endOfValue(line string, start int) int {
	i := start
	for i < len(line) && (line[i] == ' ' || line[i] == '	') {
		i++
	}
	if i < len(line) && (line[i] == '"' || line[i] == '\'') {
		quote := line[i]
		for j := i + 1; j < len(line); j++ {
			if line[j] == quote {
				return j + 1
			}
		}
		return len(line)
	}

	for ; i < len(line); i++ {
		// A marker an earlier pass wrote is part of this value, not the start
		// of a new pair: its own `kind:` text would otherwise end the value
		// early and the remainder would be re-redacted on every later pass.
		if w := markerWidth(line[i:]); w > 0 {
			i += w - 1
			continue
		}
		if isValueDelimiter(line[i]) {
			return i
		}
	}
	return len(line)
}

// valueAlreadyClassified reports whether a value has already been redacted by a
// shape detector, leaving nothing unclassified behind.
//
// Shape detection runs first precisely so a recognizable credential is reported
// with its exact kind, and overwriting that with the generic assignment marker
// would throw the classification away. `Bearer [REDACTED:jwt]` is therefore left
// alone, while `[REDACTED:jwt] plus_opaque_residue` is not: anything beyond
// whitespace and a short alphabetic scheme word is unclassified text that still
// has to go.
func valueAlreadyClassified(value string) bool {
	if !strings.Contains(value, "[REDACTED:") {
		return false
	}

	var rest strings.Builder
	for i := 0; i < len(value); {
		if w := markerWidth(value[i:]); w > 0 {
			i += w
			continue
		}
		rest.WriteByte(value[i])
		i++
	}

	const maxSchemeWordBytes = 16
	for _, word := range strings.Fields(rest.String()) {
		// Structural punctuation -- a closing brace, a quote, a comma -- belongs
		// to the document around the value, not to the value. Treating it as
		// unclassified text made a marker inside a JSON object look unredacted,
		// so every later pass redacted it again and Redact stopped being
		// idempotent.
		if isPunctuationOnly(word) {
			continue
		}
		if len(word) > maxSchemeWordBytes || !isAlphabeticWord(word) {
			return false
		}
	}
	return true
}

// isPunctuationOnly reports whether s carries no letters or digits, and so no
// credential material.
func isPunctuationOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return false
		}
	}
	return len(s) > 0
}

func isAlphabeticWord(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		return false
	}
	return len(s) > 0
}

// isValueDelimiter reports whether c ends one assignment in a list of them.
// A space is not a delimiter: `Authorization: Bearer <token>` is a single
// value whose scheme and credential are separated by one.
func isValueDelimiter(c byte) bool { return c == ',' || c == ';' }

// redactURLCredentials removes the userinfo from a URL.
//
// `https://user:password@host` carries a credential no key name announces: the
// only separator before it belongs to the scheme, and `user` is not a
// secret-bearing name, so the assignment pass cannot see it. Here the shape
// itself is the signal.
func redactURLCredentials(s string) string {
	const marker = "://"
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		idx := strings.Index(s[i:], marker)
		if idx < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		authorityStart := i + idx + len(marker)
		b.WriteString(s[i:authorityStart])

		end := authorityStart
		for end < len(s) && !strings.ContainsRune("/?# 	\"'", rune(s[end])) {
			end++
		}
		authority := s[authorityStart:end]

		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			b.WriteString("[REDACTED:url_credentials]")
			b.WriteString(authority[at:])
		} else {
			b.WriteString(authority)
		}
		i = end
	}
	return b.String()
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
		if w := markerWidth(s[i:]); w > 0 {
			b.WriteString(s[i : i+w])
			i += w
			continue
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
	const context = "secrets"
	if len(s) < len(context) || !strings.EqualFold(s[:len(context)], context) {
		return 0, false
	}
	rest := s[len(context):]

	// GitHub folds the context name's case and treats `secrets['NAME']` as the
	// same reference as `secrets.NAME`, so matching only the lowercase dotted
	// spelling left both other forms unclassified.
	switch {
	case strings.HasPrefix(rest, "."):
		name := 0
		for len(rest) > 1+name && isSecretNameByte(rest[1+name]) {
			name++
		}
		if name == 0 {
			return 0, false
		}
		return len(context) + 1 + name, true

	case strings.HasPrefix(rest, "["):
		if len(rest) < 2 {
			return 0, false
		}
		quote := rest[1]
		if quote != '\'' && quote != '"' {
			return 0, false
		}
		closing := strings.IndexByte(rest[2:], quote)
		if closing <= 0 {
			return 0, false
		}
		after := 2 + closing + 1
		if after >= len(rest) || rest[after] != ']' {
			return 0, false
		}
		return len(context) + after + 1, true
	}
	return 0, false
}

func isSecretNameByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '_'
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
			// The footer ends at the first `-----` after `-----END`, and the
			// search has to start there. Looking for `-----\n` anywhere in the
			// remaining text instead matched the NEXT block's header when two
			// keys sat on one line, so the replacement swallowed that header
			// and left its body in the clear.
			afterEnd := idx + len("-----END")
			if close := strings.Index(rest[afterEnd:], "-----"); close >= 0 {
				end = start + len(header) + afterEnd + close + len("-----")
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
