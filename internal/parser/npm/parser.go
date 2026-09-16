package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/codebyte-p/proofrail/internal/run"
)

// Parser bounds. These are hard caps, not tuning knobs: raising one requires a
// threat-model update and owner review.
const (
	// MaxDepth bounds JSON nesting. It mirrors
	// run.DefaultLimits().MaxParserDepth, and a test asserts the two agree.
	MaxDepth = 64

	// MaxNodes bounds total node count so a document that is small on disk but
	// pathologically wide cannot exhaust memory during the walk.
	MaxNodes = 500_000

	// MaxManifestBytes and MaxLockBytes are the fallback budgets when a caller
	// passes a non-positive bound. The parser is never unbounded.
	MaxManifestBytes = 1 << 20
	MaxLockBytes     = 10 << 20

	maxDiagnostics         = 20
	maxCoverageNotes       = 64
	maxPointerBytes        = 256
	maxPointerSegmentBytes = 64
)

// supportedLockfileVersions are the `package-lock.json` formats whose resolved
// identity this parser models. Version 1 stores a nested `dependencies` tree
// with a different integrity model; reading it as if it were version 2 or 3
// would silently produce an empty package set, which is indistinguishable from
// a project with no dependencies.
var supportedLockfileVersions = map[int]bool{2: true, 3: true}

// ParseManifest reads a `package.json` into the normalized manifest model.
//
// The document is validated against the restricted JSON grammar before any
// field is read, so a caller either gets a manifest that satisfied every
// restriction or gets the zero value and diagnostics.
func ParseManifest(path string, content []byte, maxBytes int64) (Manifest, []run.Diagnostic) {
	if maxBytes <= 0 {
		maxBytes = MaxManifestBytes
	}
	p := newParser(path, "npm")

	root, ok := p.read(content, maxBytes)
	if !ok {
		return Manifest{}, p.diags
	}

	manifest := p.decodeManifest(root)
	if len(p.diags) > 0 {
		return Manifest{}, p.diags
	}
	manifest.Path = path
	manifest.CoverageNotes = p.notes
	return manifest, nil
}

// ParseLock reads a `package-lock.json` into the normalized lock model.
func ParseLock(path string, content []byte, maxBytes int64) (Lock, []run.Diagnostic) {
	if maxBytes <= 0 {
		maxBytes = MaxLockBytes
	}
	p := newParser(path, "npm")

	root, ok := p.read(content, maxBytes)
	if !ok {
		return Lock{}, p.diags
	}

	lock := p.decodeLock(root)
	if len(p.diags) > 0 {
		return Lock{}, p.diags
	}
	lock.Path = path
	lock.CoverageNotes = p.notes
	return lock, nil
}

// ----------------------------------------------------------------------------
// Bounded JSON reading
// ----------------------------------------------------------------------------

type nodeKind int

const (
	kindObject nodeKind = iota
	kindArray
	kindString
	kindNumber
	kindBool
	kindNull
)

// node is one element of the bounded document tree.
//
// Objects keep their keys in document order rather than in a Go map so that
// iteration is deterministic and two runs over the same bytes emit findings in
// the same order. Keys are unique: duplicates are rejected during the walk.
type node struct {
	kind     nodeKind
	pos      Position
	str      string
	num      float64
	boolean  bool
	keys     []Scalar
	values   []*node
	elements []*node
}

// field returns the value for key and whether the object declared it.
func (n *node) field(key string) (*node, Scalar, bool) {
	if n == nil || n.kind != kindObject {
		return nil, Scalar{}, false
	}
	for i, k := range n.keys {
		if k.Value == key {
			return n.values[i], k, true
		}
	}
	return nil, Scalar{}, false
}

type parser struct {
	path      string
	prefix    string
	diags     []run.Diagnostic
	notes     []string
	seenNotes map[string]bool
	lines     lineIndex
	nodes     int
	stopped   bool
}

func newParser(path, prefix string) *parser {
	return &parser{path: path, prefix: prefix, seenNotes: make(map[string]bool)}
}

// read validates and decodes content into the bounded document tree.
func (p *parser) read(content []byte, maxBytes int64) (*node, bool) {
	// The byte bound is checked before the JSON machinery ever sees the input,
	// so oversized content costs a length comparison rather than a parse.
	if int64(len(content)) > maxBytes {
		p.reject("too_large", "",
			"document exceeds the "+strconv.FormatInt(maxBytes, 10)+"-byte parser budget")
		return nil, false
	}
	// encoding/json silently substitutes U+FFFD for invalid UTF-8, which would
	// let a malformed name compare equal to a different one. Reject instead.
	if !utf8.Valid(content) {
		p.reject("invalid_utf8", "", "document is not valid UTF-8")
		return nil, false
	}
	if len(bytes.TrimSpace(content)) == 0 {
		p.reject("empty", "", "document is empty")
		return nil, false
	}

	p.lines = newLineIndex(content)
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()

	root := p.parseValue(dec, 1, "")
	if root == nil || len(p.diags) > 0 {
		if root == nil && len(p.diags) == 0 {
			p.reject("malformed", "", "document is not well-formed JSON")
		}
		return nil, false
	}

	// A second value after the document would let a reviewer read the first
	// while a tool acts on the second.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		p.reject("trailing_content", "", "document carries content after the top-level value")
		return nil, false
	}

	if root.kind != kindObject {
		p.reject("root_not_object", "", "document must be a JSON object at its root")
		return nil, false
	}
	return root, true
}

// parseValue reads one JSON value.
//
// Recursion is safe because the depth bound is checked before descending, so
// the call stack can never exceed MaxDepth frames regardless of input.
func (p *parser) parseValue(dec *json.Decoder, depth int, pointer string) *node {
	if p.stopped {
		return nil
	}
	if depth > MaxDepth {
		p.reject("depth_exceeded", pointer, "document nests deeper than the parser depth bound")
		p.stopped = true
		return nil
	}
	p.nodes++
	if p.nodes > MaxNodes {
		p.reject("node_budget_exceeded", pointer, "document contains more nodes than the parser budget allows")
		p.stopped = true
		return nil
	}

	tok, err := dec.Token()
	if err != nil {
		p.rejectJSON(err, pointer)
		return nil
	}
	pos := p.positionAt(dec.InputOffset())

	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return p.parseObject(dec, depth, pointer, pos)
		case '[':
			return p.parseArray(dec, depth, pointer, pos)
		default:
			p.reject("malformed", pointer, "document is not well-formed JSON")
			p.stopped = true
			return nil
		}
	case string:
		return &node{kind: kindString, pos: pos, str: v}
	case json.Number:
		f, convErr := v.Float64()
		if convErr != nil {
			p.reject("malformed", pointer, "document contains a number outside the representable range")
			p.stopped = true
			return nil
		}
		return &node{kind: kindNumber, pos: pos, num: f, str: v.String()}
	case bool:
		return &node{kind: kindBool, pos: pos, boolean: v}
	case nil:
		return &node{kind: kindNull, pos: pos}
	default:
		p.reject("malformed", pointer, "document is not well-formed JSON")
		p.stopped = true
		return nil
	}
}

func (p *parser) parseObject(dec *json.Decoder, depth int, pointer string, pos Position) *node {
	obj := &node{kind: kindObject, pos: pos}
	seen := make(map[string]bool)

	for {
		if p.stopped {
			return nil
		}
		tok, err := dec.Token()
		if err != nil {
			p.rejectJSON(err, pointer)
			return nil
		}
		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			return obj
		}
		key, ok := tok.(string)
		if !ok {
			p.reject("malformed", pointer, "object key is not a string")
			p.stopped = true
			return nil
		}
		keyScalar := Scalar{Value: key, Pos: p.positionAt(dec.InputOffset())}

		// encoding/json keeps the last duplicate silently, so two readers of the
		// same file can disagree about what it declares. Reject instead.
		if seen[key] {
			p.reject("duplicate_key", childPointer(pointer, key), "object declares the same key twice")
			p.stopped = true
			return nil
		}
		seen[key] = true

		value := p.parseValue(dec, depth+1, childPointer(pointer, key))
		if value == nil {
			return nil
		}
		obj.keys = append(obj.keys, keyScalar)
		obj.values = append(obj.values, value)
	}
}

func (p *parser) parseArray(dec *json.Decoder, depth int, pointer string, pos Position) *node {
	arr := &node{kind: kindArray, pos: pos}

	for i := 0; ; i++ {
		if p.stopped {
			return nil
		}
		if dec.More() {
			element := p.parseValue(dec, depth+1, indexPointer(pointer, i))
			if element == nil {
				return nil
			}
			arr.elements = append(arr.elements, element)
			continue
		}
		tok, err := dec.Token()
		if err != nil {
			p.rejectJSON(err, pointer)
			return nil
		}
		if delim, ok := tok.(json.Delim); ok && delim == ']' {
			return arr
		}
		p.reject("malformed", pointer, "document is not well-formed JSON")
		p.stopped = true
		return nil
	}
}

// rejectJSON reports a decoder failure without echoing the library's message,
// which can quote the offending input.
func (p *parser) rejectJSON(err error, pointer string) {
	p.stopped = true
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		p.reject("malformed", pointer, "document ends before the top-level value is complete")
		return
	}
	p.reject("malformed", pointer, "document is not well-formed JSON")
}

// ----------------------------------------------------------------------------
// Manifest and lock decoding
// ----------------------------------------------------------------------------

// requirementKinds are the manifest sections that declare an installed
// dependency, in the order they are reported.
var requirementKinds = []string{
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
}

func (p *parser) decodeManifest(root *node) Manifest {
	var manifest Manifest

	for i, key := range root.keys {
		value := root.values[i]
		switch {
		case key.Value == "name":
			manifest.Name = stringScalar(value)
		case key.Value == "version":
			manifest.Version = stringScalar(value)
		case isRequirementKind(key.Value):
			manifest.Requirements = append(manifest.Requirements, p.decodeRequirements(value, key.Value)...)
		case key.Value == "scripts":
			manifest.Scripts = p.decodeScripts(value)
		default:
			p.note("manifest field " + field(key.Value) + " is not modeled by version 1")
		}
	}
	return manifest
}

func isRequirementKind(key string) bool {
	for _, kind := range requirementKinds {
		if key == kind {
			return true
		}
	}
	return false
}

func (p *parser) decodeRequirements(value *node, kind string) []Requirement {
	if value == nil || value.kind != kindObject {
		p.note("manifest section " + field(kind) + " uses a shape that version 1 does not model")
		return nil
	}
	var out []Requirement
	for i, key := range value.keys {
		spec := value.values[i]
		if spec == nil || spec.kind != kindString {
			p.note("dependency " + field(key.Value) + " has a non-string specifier that version 1 does not model")
			continue
		}
		out = append(out, Requirement{
			Name: key,
			Spec: Scalar{Value: spec.str, Pos: spec.pos},
			Kind: kind,
		})
	}
	return out
}

func (p *parser) decodeScripts(value *node) []ScriptEntry {
	if value == nil || value.kind != kindObject {
		p.note("manifest scripts use a shape that version 1 does not model")
		return nil
	}
	var out []ScriptEntry
	for i, key := range value.keys {
		body := value.values[i]
		if body == nil || body.kind != kindString {
			p.note("script " + field(key.Value) + " has a non-string body that version 1 does not model")
			continue
		}
		// The body is captured as inert text. Nothing here runs it, expands it,
		// or interprets its shell syntax.
		out = append(out, ScriptEntry{Name: key, Body: Scalar{Value: body.str, Pos: body.pos}})
	}
	return out
}

func (p *parser) decodeLock(root *node) Lock {
	var lock Lock

	if versionNode, _, ok := root.field("lockfileVersion"); ok && versionNode.kind == kindNumber {
		lock.LockfileVersion = int(versionNode.num)
	}
	if !supportedLockfileVersions[lock.LockfileVersion] {
		p.reject("unsupported_lockfile_version", "lockfileVersion",
			"lockfile format version is outside the versions this parser models; reading it would understate the dependency set")
		return Lock{}
	}

	for i, key := range root.keys {
		value := root.values[i]
		switch key.Value {
		case "lockfileVersion", "name", "version", "requires":
			// Read above or deliberately not modeled.
		case "packages":
			lock.Packages = p.decodeLockPackages(value)
		default:
			p.note("lock field " + field(key.Value) + " is not modeled by version 1")
		}
	}
	return lock
}

func (p *parser) decodeLockPackages(value *node) []LockedPackage {
	if value == nil || value.kind != kindObject {
		p.note("lock packages use a shape that version 1 does not model")
		return nil
	}

	var out []LockedPackage
	for i, key := range value.keys {
		body := value.values[i]
		// The entry keyed by the empty string is the project itself, not one of
		// its dependencies.
		if key.Value == "" {
			continue
		}
		if body == nil || body.kind != kindObject {
			p.note("lock entry " + field(key.Value) + " uses a shape that version 1 does not model")
			continue
		}

		pkg := LockedPackage{Key: key}
		pkg.Name = Scalar{Value: packageNameFromKey(key.Value), Pos: key.Pos}
		if explicit, _, ok := body.field("name"); ok && explicit.kind == kindString {
			pkg.Name = Scalar{Value: explicit.str, Pos: explicit.pos}
		}
		if n, _, ok := body.field("version"); ok {
			pkg.Version = stringScalar(n)
		}
		if n, _, ok := body.field("resolved"); ok {
			pkg.Resolved = stringScalar(n)
		}
		if n, _, ok := body.field("integrity"); ok {
			pkg.Integrity = stringScalar(n)
		}
		pkg.Dev = boolField(body, "dev")
		pkg.Link = boolField(body, "link")
		pkg.HasInstallScript = boolField(body, "hasInstallScript")

		if pkg.Name.Value == "" {
			p.note("lock entry " + field(key.Value) + " has no derivable package name and was not modeled")
			continue
		}
		out = append(out, pkg)
	}

	// Lock maps are unordered by nature, so a stable sort keeps two runs over
	// equivalent files emitting findings in the same sequence.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key.Value < out[j].Key.Value })
	return out
}

func boolField(obj *node, key string) bool {
	n, _, ok := obj.field(key)
	return ok && n.kind == kindBool && n.boolean
}

func stringScalar(n *node) Scalar {
	if n == nil || n.kind != kindString {
		return Scalar{}
	}
	return Scalar{Value: n.str, Pos: n.pos}
}

// ----------------------------------------------------------------------------
// Diagnostics, notes, and positions
// ----------------------------------------------------------------------------

func (p *parser) reject(code, pointer, message string) {
	if len(p.diags) >= maxDiagnostics {
		p.stopped = true
		return
	}
	p.diags = append(p.diags, run.Diagnostic{
		Code:    p.prefix + "." + code,
		Path:    p.locate(pointer),
		Message: message,
	})
}

func (p *parser) locate(pointer string) string {
	if pointer == "" {
		return p.path
	}
	return p.path + "#" + pointer
}

func (p *parser) note(s string) {
	if p.seenNotes[s] || len(p.notes) >= maxCoverageNotes {
		return
	}
	p.seenNotes[s] = true
	p.notes = append(p.notes, s)
}

// lineIndex maps a byte offset to a source line.
type lineIndex struct {
	starts []int
}

func newLineIndex(content []byte) lineIndex {
	starts := []int{0}
	for i, b := range content {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return lineIndex{starts: starts}
}

// positionAt converts a decoder offset into a source position.
//
// encoding/json reports the offset just past the token it returned, so Column
// is where the token ends rather than where it begins. Line is unaffected,
// because a JSON string cannot contain a raw newline, and Line is what a
// finding location uses.
func (p *parser) positionAt(offset int64) Position {
	idx := sort.Search(len(p.lines.starts), func(i int) bool {
		return int64(p.lines.starts[i]) > offset
	}) - 1
	if idx < 0 {
		idx = 0
	}
	return Position{Line: idx + 1, Column: int(offset) - p.lines.starts[idx] + 1}
}

// field renders a key name for a coverage note. The name comes from repository
// content, so it is sanitized to bounded printable ASCII and quoted.
func field(s string) string {
	return strconv.Quote(sanitize(s, maxPointerSegmentBytes))
}

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

func childPointer(parent, key string) string {
	seg := sanitize(key, maxPointerSegmentBytes)
	if parent == "" {
		return seg
	}
	if len(parent) >= maxPointerBytes {
		return parent
	}
	return parent + "." + seg
}

func indexPointer(parent string, i int) string {
	seg := "[" + strconv.Itoa(i) + "]"
	if parent == "" {
		return seg
	}
	if len(parent) >= maxPointerBytes {
		return parent
	}
	return parent + seg
}
