package python

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/codebyte-p/proofrail/internal/run"
)

// Parser bounds. These are hard caps, not tuning knobs: raising one requires a
// threat-model update and owner review.
const (
	// MaxDepth bounds array and inline-table nesting. It mirrors
	// run.DefaultLimits().MaxParserDepth, and a test asserts the two agree.
	MaxDepth = 64

	// MaxNodes bounds total value count so a document that is small on disk but
	// pathologically wide cannot exhaust memory.
	MaxNodes = 500_000

	// MaxProjectBytes and MaxLockBytes are the fallback budgets when a caller
	// passes a non-positive bound. The parser is never unbounded.
	MaxProjectBytes = 1 << 20
	MaxLockBytes    = 10 << 20

	maxDiagnostics         = 20
	maxCoverageNotes       = 64
	maxPointerBytes        = 256
	maxPointerSegmentBytes = 64
)

type valueKind int

const (
	vString valueKind = iota
	vInteger
	vFloat
	vBool
	vArray
	vTable
)

// value is one TOML value in the bounded document tree.
type value struct {
	kind    valueKind
	pos     Position
	str     string
	integer int64
	float   float64
	boolean bool
	array   []*value
	table   *table
}

// table keeps its keys in document order rather than in a Go map, so iteration
// is deterministic and two runs over the same bytes report in the same order.
// Keys are unique: duplicates are rejected while scanning.
type table struct {
	pos    Position
	keys   []Scalar
	values []*value
}

func (t *table) get(key string) (*value, Scalar, bool) {
	if t == nil {
		return nil, Scalar{}, false
	}
	for i, k := range t.keys {
		if k.Value == key {
			return t.values[i], k, true
		}
	}
	return nil, Scalar{}, false
}

func (t *table) set(key Scalar, v *value) {
	t.keys = append(t.keys, key)
	t.values = append(t.values, v)
}

// str returns a string field as a Scalar, or the zero Scalar when the key is
// absent or is not a string.
func (t *table) str(key string) Scalar {
	v, _, ok := t.get(key)
	if !ok || v.kind != vString {
		return Scalar{}
	}
	return Scalar{Value: v.str, Pos: v.pos}
}

// reader scans the supported TOML subset.
type reader struct {
	src       []byte
	pos       int
	line      int
	col       int
	path      string
	diags     []run.Diagnostic
	notes     []string
	seenNotes map[string]bool
	declared  map[string]bool
	nodes     int
	stopped   bool
}

func newReader(path string, src []byte) *reader {
	return &reader{
		src:       src,
		line:      1,
		col:       1,
		path:      path,
		seenNotes: make(map[string]bool),
		declared:  make(map[string]bool),
	}
}

// parseDocument scans the whole document into a root table.
func parseDocument(path string, content []byte, maxBytes int64) (*table, *reader) {
	r := newReader(path, content)

	if int64(len(content)) > maxBytes {
		r.reject("too_large", "",
			"document exceeds the "+strconv.FormatInt(maxBytes, 10)+"-byte parser budget")
		return nil, r
	}
	if !utf8.Valid(content) {
		r.reject("invalid_utf8", "", "document is not valid UTF-8")
		return nil, r
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		r.reject("empty", "", "document is empty")
		return nil, r
	}

	root := &table{pos: Position{Line: 1, Column: 1}}
	current := root
	currentPath := ""

	for !r.stopped {
		r.skipIgnorable(true)
		if r.eof() {
			break
		}
		if r.peek() == '[' {
			next, np, ok := r.parseHeader(root)
			if !ok {
				break
			}
			current, currentPath = next, np
			continue
		}
		if !r.parseKeyValue(current, currentPath) {
			break
		}
	}

	if len(r.diags) > 0 {
		return nil, r
	}
	return root, r
}

// parseHeader reads `[a.b]` or `[[a.b]]` and returns the table that subsequent
// key/value lines belong to.
func (r *reader) parseHeader(root *table) (*table, string, bool) {
	headerPos := r.position()
	r.advance() // consume '['

	arrayOfTables := false
	if !r.eof() && r.peek() == '[' {
		arrayOfTables = true
		r.advance()
	}

	segments, ok := r.parseKeyPath()
	if !ok {
		return nil, "", false
	}

	r.skipInlineSpace()
	if r.eof() || r.peek() != ']' {
		r.reject("malformed", "", "table header is not closed")
		return nil, "", false
	}
	r.advance()
	if arrayOfTables {
		if r.eof() || r.peek() != ']' {
			r.reject("malformed", "", "array-of-tables header is not closed")
			return nil, "", false
		}
		r.advance()
	}
	r.skipInlineSpace()
	if !r.eof() && r.peek() != '\n' && r.peek() != '\r' && r.peek() != '#' {
		r.reject("malformed", "", "table header is followed by unexpected content")
		return nil, "", false
	}

	pathKey := joinSegments(segments)
	if !arrayOfTables {
		// An array-of-tables header repeats by design; a plain table header
		// declared twice means two definitions disagree about one path.
		if r.declared[pathKey] {
			r.reject("duplicate_table", pointerOf(pathKey), "document declares the same table twice")
			return nil, "", false
		}
		r.declared[pathKey] = true
	}

	target, ok := r.navigate(root, segments, arrayOfTables, headerPos)
	if !ok {
		return nil, "", false
	}
	return target, pathKey, true
}

// navigate walks or creates the tables named by segments.
//
// When a prefix segment is an array of tables, the walk continues inside its
// most recent element, which is how `[[package.wheels]]` attaches to the
// `[[package]]` entry that precedes it.
func (r *reader) navigate(root *table, segments []Scalar, arrayOfTables bool, pos Position) (*table, bool) {
	current := root

	for i, seg := range segments {
		last := i == len(segments)-1

		existing, _, found := current.get(seg.Value)
		if !found {
			if last && arrayOfTables {
				created := &table{pos: pos}
				current.set(seg, &value{kind: vArray, pos: pos, array: []*value{{kind: vTable, pos: pos, table: created}}})
				return created, true
			}
			created := &table{pos: pos}
			current.set(seg, &value{kind: vTable, pos: pos, table: created})
			current = created
			continue
		}

		switch existing.kind {
		case vTable:
			if last && arrayOfTables {
				r.reject("malformed", pointerOf(seg.Value), "an array-of-tables header names a path already defined as a table")
				return nil, false
			}
			current = existing.table
		case vArray:
			if last && arrayOfTables {
				created := &table{pos: pos}
				existing.array = append(existing.array, &value{kind: vTable, pos: pos, table: created})
				return created, true
			}
			if len(existing.array) == 0 {
				r.reject("malformed", pointerOf(seg.Value), "a table header walks through an empty array of tables")
				return nil, false
			}
			tail := existing.array[len(existing.array)-1]
			if tail.kind != vTable {
				r.reject("malformed", pointerOf(seg.Value), "a table header walks through an array that does not hold tables")
				return nil, false
			}
			current = tail.table
		default:
			r.reject("malformed", pointerOf(seg.Value), "a table header names a path already defined as a scalar")
			return nil, false
		}
	}
	return current, true
}

// parseKeyValue reads one `key = value` line into the current table.
func (r *reader) parseKeyValue(current *table, currentPath string) bool {
	segments, ok := r.parseKeyPath()
	if !ok {
		return false
	}

	r.skipInlineSpace()
	if r.eof() || r.peek() != '=' {
		r.reject("malformed", pointerOf(currentPath), "a key is not followed by a value")
		return false
	}
	r.advance()
	r.skipInlineSpace()

	v := r.parseValue(1)
	if v == nil {
		return false
	}

	// A dotted key defines nested tables under the current one.
	target := current
	for i := 0; i < len(segments)-1; i++ {
		seg := segments[i]
		existing, _, found := target.get(seg.Value)
		if found && existing.kind == vTable {
			target = existing.table
			continue
		}
		if found {
			r.reject("malformed", pointerOf(seg.Value), "a dotted key walks through a value that is not a table")
			return false
		}
		created := &table{pos: seg.Pos}
		target.set(seg, &value{kind: vTable, pos: seg.Pos, table: created})
		target = created
	}

	key := segments[len(segments)-1]
	if _, _, exists := target.get(key.Value); exists {
		r.reject("duplicate_key", pointerOf(key.Value), "table declares the same key twice")
		return false
	}
	target.set(key, v)

	r.skipInlineSpace()
	if !r.eof() && r.peek() != '\n' && r.peek() != '\r' && r.peek() != '#' {
		r.reject("malformed", pointerOf(key.Value), "a value is followed by unexpected content")
		return false
	}
	return true
}

// parseKeyPath reads a bare or quoted key, optionally dotted.
func (r *reader) parseKeyPath() ([]Scalar, bool) {
	var segments []Scalar
	for {
		// The value depth bound does not reach key paths, and each dotted
		// segment creates a nested table, so an unbounded path is unbounded
		// work and unbounded allocation.
		if len(segments) >= MaxDepth {
			r.reject("depth_exceeded", "", "a key path nests deeper than the parser depth bound")
			return nil, false
		}
		r.nodes++
		if r.nodes > MaxNodes {
			r.reject("node_budget_exceeded", "", "document contains more values than the parser budget allows")
			return nil, false
		}
		r.skipInlineSpace()
		seg, ok := r.parseKeySegment()
		if !ok {
			return nil, false
		}
		segments = append(segments, seg)

		r.skipInlineSpace()
		if !r.eof() && r.peek() == '.' {
			r.advance()
			continue
		}
		return segments, true
	}
}

func (r *reader) parseKeySegment() (Scalar, bool) {
	if r.eof() {
		r.reject("malformed", "", "document ends where a key was expected")
		return Scalar{}, false
	}
	pos := r.position()

	if c := r.peek(); c == '"' || c == '\'' {
		s, ok := r.parseString()
		if !ok {
			return Scalar{}, false
		}
		// TOML permits a quoted empty key, but neither file this package reads
		// has a use for one, and an empty name collides with every other empty
		// name once the analyzer keys records by it.
		if s == "" {
			r.reject("malformed", "", "a quoted key is empty")
			return Scalar{}, false
		}
		return Scalar{Value: s, Pos: pos}, true
	}

	start := r.pos
	for !r.eof() && isBareKeyByte(r.peek()) {
		r.advance()
	}
	if r.pos == start {
		r.reject("malformed", "", "a key is empty or uses unsupported characters")
		return Scalar{}, false
	}
	return Scalar{Value: string(r.src[start:r.pos]), Pos: pos}, true
}

// parseValue reads one value. Recursion is bounded by MaxDepth, which is
// checked before descending, so the call stack cannot exceed that many frames.
func (r *reader) parseValue(depth int) *value {
	if depth > MaxDepth {
		r.reject("depth_exceeded", "", "document nests deeper than the parser depth bound")
		r.stopped = true
		return nil
	}
	r.nodes++
	if r.nodes > MaxNodes {
		r.reject("node_budget_exceeded", "", "document contains more values than the parser budget allows")
		r.stopped = true
		return nil
	}
	if r.eof() {
		r.reject("malformed", "", "document ends where a value was expected")
		return nil
	}

	pos := r.position()
	switch c := r.peek(); {
	case c == '"' || c == '\'':
		s, ok := r.parseString()
		if !ok {
			return nil
		}
		return &value{kind: vString, pos: pos, str: s}
	case c == '[':
		return r.parseArray(depth, pos)
	case c == '{':
		return r.parseInlineTable(depth, pos)
	default:
		return r.parseBare(pos)
	}
}

func (r *reader) parseArray(depth int, pos Position) *value {
	r.advance() // consume '['
	arr := &value{kind: vArray, pos: pos}

	for {
		r.skipIgnorable(true)
		if r.eof() {
			r.reject("malformed", "", "an array is not closed")
			return nil
		}
		if r.peek() == ']' {
			r.advance()
			return arr
		}

		element := r.parseValue(depth + 1)
		if element == nil {
			return nil
		}
		arr.array = append(arr.array, element)

		r.skipIgnorable(true)
		if r.eof() {
			r.reject("malformed", "", "an array is not closed")
			return nil
		}
		switch r.peek() {
		case ',':
			r.advance()
		case ']':
			r.advance()
			return arr
		default:
			r.reject("malformed", "", "an array element is not followed by a comma or a closing bracket")
			return nil
		}
	}
}

func (r *reader) parseInlineTable(depth int, pos Position) *value {
	r.advance() // consume '{'
	tbl := &table{pos: pos}

	for {
		r.skipIgnorable(true)
		if r.eof() {
			r.reject("malformed", "", "an inline table is not closed")
			return nil
		}
		if r.peek() == '}' {
			r.advance()
			return &value{kind: vTable, pos: pos, table: tbl}
		}

		key, ok := r.parseKeySegment()
		if !ok {
			return nil
		}
		r.skipIgnorable(true)
		if r.eof() || r.peek() != '=' {
			r.reject("malformed", pointerOf(key.Value), "an inline-table key is not followed by a value")
			return nil
		}
		r.advance()
		r.skipIgnorable(true)

		v := r.parseValue(depth + 1)
		if v == nil {
			return nil
		}
		if _, _, exists := tbl.get(key.Value); exists {
			r.reject("duplicate_key", pointerOf(key.Value), "inline table declares the same key twice")
			return nil
		}
		tbl.set(key, v)

		r.skipIgnorable(true)
		if r.eof() {
			r.reject("malformed", "", "an inline table is not closed")
			return nil
		}
		switch r.peek() {
		case ',':
			r.advance()
		case '}':
			r.advance()
			return &value{kind: vTable, pos: pos, table: tbl}
		default:
			r.reject("malformed", "", "an inline-table entry is not followed by a comma or a closing brace")
			return nil
		}
	}
}

// parseBare reads an unquoted value: an integer, a float, or a boolean.
//
// Every other bare form TOML allows, such as a date or a time, is refused as an
// unsupported construct rather than guessed at.
func (r *reader) parseBare(pos Position) *value {
	start := r.pos
	for !r.eof() {
		c := r.peek()
		if c == ',' || c == ']' || c == '}' || c == '\n' || c == '\r' || c == '#' || c == ' ' || c == '\t' {
			break
		}
		r.advance()
	}
	raw := string(r.src[start:r.pos])

	switch raw {
	case "true":
		return &value{kind: vBool, pos: pos, boolean: true}
	case "false":
		return &value{kind: vBool, pos: pos, boolean: false}
	case "":
		r.reject("malformed", "", "a value is empty")
		return nil
	}

	normalized := strings.ReplaceAll(raw, "_", "")
	if i, err := strconv.ParseInt(normalized, 10, 64); err == nil {
		return &value{kind: vInteger, pos: pos, integer: i, str: raw}
	}
	if f, err := strconv.ParseFloat(normalized, 64); err == nil {
		return &value{kind: vFloat, pos: pos, float: f, str: raw}
	}

	r.reject("unsupported_construct", "",
		"document uses a value form outside the subset this reader models")
	return nil
}

// parseString reads a basic or literal string.
//
// Multi-line strings are refused rather than supported, because they are not
// used by the two files this package reads and every construct the reader does
// not fully model is a chance to misstate the dependency set.
func (r *reader) parseString() (string, bool) {
	quote := r.peek()

	if r.remaining() >= 3 && r.src[r.pos+1] == quote && r.src[r.pos+2] == quote {
		r.reject("unsupported_construct", "",
			"document uses a multi-line string, which is outside the subset this reader models")
		return "", false
	}
	r.advance() // consume the opening quote

	var b strings.Builder
	for {
		if r.eof() {
			r.reject("malformed", "", "a string is not closed")
			return "", false
		}
		c := r.peek()
		if c == '\n' || c == '\r' {
			r.reject("malformed", "", "a single-line string contains a newline")
			return "", false
		}
		if c == quote {
			r.advance()
			return b.String(), true
		}
		// A literal string has no escapes; its bytes are taken verbatim.
		if c == '\\' && quote == '"' {
			r.advance()
			if r.eof() {
				r.reject("malformed", "", "a string ends with an incomplete escape")
				return "", false
			}
			decoded, ok := r.parseEscape()
			if !ok {
				return "", false
			}
			b.WriteString(decoded)
			continue
		}
		b.WriteByte(c)
		r.advance()
	}
}

func (r *reader) parseEscape() (string, bool) {
	c := r.peek()
	r.advance()

	switch c {
	case '"':
		return "\"", true
	case '\\':
		return "\\", true
	case 'n':
		return "\n", true
	case 't':
		return "\t", true
	case 'r':
		return "\r", true
	case 'b':
		return "\b", true
	case 'f':
		return "\f", true
	case 'u', 'U':
		width := 4
		if c == 'U' {
			width = 8
		}
		if r.remaining() < width {
			r.reject("malformed", "", "a string ends with an incomplete unicode escape")
			return "", false
		}
		digits := string(r.src[r.pos : r.pos+width])
		code, err := strconv.ParseUint(digits, 16, 32)
		if err != nil || !utf8.ValidRune(rune(code)) {
			r.reject("malformed", "", "a string contains an invalid unicode escape")
			return "", false
		}
		for i := 0; i < width; i++ {
			r.advance()
		}
		return string(rune(code)), true
	default:
		r.reject("malformed", "", "a string contains an unsupported escape sequence")
		return "", false
	}
}

// ----------------------------------------------------------------------------
// Scanning primitives
// ----------------------------------------------------------------------------

func (r *reader) eof() bool      { return r.pos >= len(r.src) }
func (r *reader) peek() byte     { return r.src[r.pos] }
func (r *reader) remaining() int { return len(r.src) - r.pos }

func (r *reader) position() Position { return Position{Line: r.line, Column: r.col} }

func (r *reader) advance() {
	if r.eof() {
		return
	}
	if r.src[r.pos] == '\n' {
		r.line++
		r.col = 1
	} else {
		r.col++
	}
	r.pos++
}

func (r *reader) skipInlineSpace() {
	for !r.eof() {
		if c := r.peek(); c == ' ' || c == '\t' {
			r.advance()
			continue
		}
		return
	}
}

// skipIgnorable consumes whitespace and comments. Newlines are consumed only
// when the caller is in a context where a value may continue across lines.
func (r *reader) skipIgnorable(newlines bool) {
	for !r.eof() {
		switch c := r.peek(); {
		case c == ' ' || c == '\t':
			r.advance()
		case (c == '\n' || c == '\r') && newlines:
			r.advance()
		case c == '#':
			for !r.eof() && r.peek() != '\n' {
				r.advance()
			}
		default:
			return
		}
	}
}

func isBareKeyByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
}

// ----------------------------------------------------------------------------
// Diagnostics and notes
// ----------------------------------------------------------------------------

func (r *reader) reject(code, pointer, message string) {
	r.stopped = true
	if len(r.diags) >= maxDiagnostics {
		return
	}
	loc := r.path
	if pointer != "" {
		loc = r.path + "#" + pointer
	}
	r.diags = append(r.diags, run.Diagnostic{
		Code:    "python." + code,
		Path:    loc,
		Message: message,
	})
}

func (r *reader) note(s string) {
	if r.seenNotes[s] || len(r.notes) >= maxCoverageNotes {
		return
	}
	r.seenNotes[s] = true
	r.notes = append(r.notes, s)
}

func joinSegments(segments []Scalar) string {
	parts := make([]string, 0, len(segments))
	for _, s := range segments {
		parts = append(parts, s.Value)
	}
	return strings.Join(parts, ".")
}

func pointerOf(path string) string { return sanitize(path, maxPointerBytes) }

// field renders a key name for a coverage note. The name comes from repository
// content, so it is sanitized to bounded printable ASCII and quoted.
func field(s string) string { return strconv.Quote(sanitize(s, maxPointerSegmentBytes)) }

// sanitize bounds a repository-supplied string and replaces every byte that is
// not printable ASCII, so nothing can smuggle control characters into a
// diagnostic, a console line, or a report.
func sanitize(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			b = append(b, '?')
			continue
		}
		b = append(b, c)
	}
	return string(b)
}
