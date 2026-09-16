package workflow

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/codebyte-p/proofrail/internal/run"
	"go.yaml.in/yaml/v3"
)

// Parser bounds. These are hard caps, not tuning knobs: raising one requires a
// threat-model update and owner review, as CLAUDE.md requires.
const (
	// MaxDepth bounds collection nesting. It mirrors
	// run.DefaultLimits().MaxParserDepth, and a test asserts the two agree.
	MaxDepth = 64

	// MaxNodes bounds total node count so a document that is small on disk but
	// pathologically wide cannot exhaust memory during the walk.
	MaxNodes = 200_000

	// MaxDocumentBytes is the fallback byte budget when a caller passes a
	// non-positive maxBytes. The parser is never unbounded.
	MaxDocumentBytes = 2 << 20

	maxDiagnostics         = 20
	maxCoverageNotes       = 64
	maxPointerBytes        = 256
	maxPointerSegmentBytes = 64
)

// YAML tags this parser accepts. The set is the YAML 1.2 core schema plus
// timestamp, which go.yaml.in resolves for bare dates and which carries no
// transformation risk because the node's literal text is what we keep.
//
// Everything else is refused, including !!binary, which would decode content,
// and any application-specific tag, which is a construct a workflow has no
// legitimate need for.
var allowedTags = map[string]bool{
	"!!str":       true,
	"!!int":       true,
	"!!float":     true,
	"!!bool":      true,
	"!!null":      true,
	"!!map":       true,
	"!!seq":       true,
	"!!timestamp": true,
}

const (
	yamlStrTag   = "!!str"
	yamlNullTag  = "!!null"
	yamlMergeTag = "!!merge"
)

// Parse reads one GitHub Actions workflow document into the normalized model.
//
// It is a reader, never an evaluator. It does not resolve `${{ }}` expressions,
// expand aliases, follow merge keys, read the filesystem, or execute anything.
// Content is rejected before it is decoded when it uses a construct outside the
// restricted grammar, so the caller either gets a document that satisfied every
// restriction or gets the zero value and diagnostics -- never a half-trusted
// mixture.
//
// Diagnostics carry a stable code, a bounded locator of the form
// `<file>#<pointer>`, and prose that never echoes repository content.
func Parse(path string, content []byte, maxBytes int64) (Document, []run.Diagnostic) {
	if maxBytes <= 0 {
		maxBytes = MaxDocumentBytes
	}
	p := &parser{path: path, seenNotes: make(map[string]bool)}

	// The byte bound is checked before the YAML machinery ever sees the input,
	// so oversized content costs a length comparison rather than a parse.
	if int64(len(content)) > maxBytes {
		p.reject("workflow.too_large", "",
			"workflow document exceeds the "+strconv.FormatInt(maxBytes, 10)+"-byte parser budget")
		return Document{}, p.diags
	}

	root, ok := p.decodeSingle(content)
	if !ok {
		return Document{}, p.diags
	}

	// The restricted-syntax pass runs to completion before any typed decoding,
	// so no forbidden construct is ever interpreted, only reported.
	p.checkRestricted(root)
	if len(p.diags) > 0 {
		return Document{}, p.diags
	}

	if root.Kind != yaml.MappingNode {
		p.reject("workflow.root_not_mapping", "", "a workflow document must be a mapping at its root")
		return Document{}, p.diags
	}

	doc := p.decodeDocument(root)
	if len(p.diags) > 0 {
		return Document{}, p.diags
	}
	doc.Path = path
	doc.CoverageNotes = p.notes
	return doc, nil
}

// parser accumulates bounded diagnostics and coverage notes for one document.
type parser struct {
	path      string
	diags     []run.Diagnostic
	notes     []string
	seenNotes map[string]bool
	nodes     int
	stopped   bool
}

// reject records a bounded diagnostic. Once the diagnostic budget is spent the
// parser stops walking: a document with twenty structural violations is already
// rejected, and enumerating the rest only hands an attacker a larger report.
func (p *parser) reject(code, pointer, message string) {
	if len(p.diags) >= maxDiagnostics {
		p.stopped = true
		return
	}
	p.diags = append(p.diags, run.Diagnostic{
		Code:    code,
		Path:    p.locate(pointer),
		Message: message,
	})
}

// locate builds the `<file>#<pointer>` locator. The pointer is already
// sanitized and bounded by childPointer and indexPointer.
func (p *parser) locate(pointer string) string {
	if pointer == "" {
		return p.path
	}
	return p.path + "#" + pointer
}

// note records one deduplicated coverage note in first-seen document order, so
// two runs over the same bytes produce the same notes in the same sequence.
func (p *parser) note(s string) {
	if p.seenNotes[s] || len(p.notes) >= maxCoverageNotes {
		return
	}
	p.seenNotes[s] = true
	p.notes = append(p.notes, s)
}

// decodeSingle returns the single root node of the document, refusing a stream
// that carries more than one. A multi-document file lets a reviewer read the
// first document while the runner acts on a later one.
func (p *parser) decodeSingle(content []byte) (*yaml.Node, bool) {
	dec := yaml.NewDecoder(bytes.NewReader(content))

	var first yaml.Node
	if err := dec.Decode(&first); err != nil {
		if errors.Is(err, io.EOF) {
			p.reject("workflow.empty", "", "workflow document is empty")
		} else {
			p.reject("workflow.malformed", yamlErrorPointer(err), "workflow document is not well-formed YAML")
		}
		return nil, false
	}

	var second yaml.Node
	switch err := dec.Decode(&second); {
	case err == nil:
		p.reject("workflow.multiple_documents", "", "a workflow file must contain exactly one YAML document")
		return nil, false
	case !errors.Is(err, io.EOF):
		p.reject("workflow.malformed", yamlErrorPointer(err), "workflow document is not well-formed YAML")
		return nil, false
	}

	root := &first
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) != 1 {
			p.reject("workflow.malformed", "", "workflow document does not contain exactly one root node")
			return nil, false
		}
		root = root.Content[0]
	}
	return root, true
}

// frame is one pending node in the iterative walk. The walk is iterative rather
// than recursive so that a deeply nested document is bounded by MaxDepth rather
// than by the goroutine stack.
type frame struct {
	node    *yaml.Node
	depth   int
	pointer string
}

// checkRestricted enforces the restricted grammar over the whole tree.
//
// It refuses anchors, aliases, merge keys, non-core tags, duplicate keys, and
// non-string keys, and it bounds depth and node count. Aliases are recorded and
// never dereferenced, which is what keeps an expansion attack from costing
// anything beyond the node that declared it.
func (p *parser) checkRestricted(root *yaml.Node) {
	stack := []frame{{node: root, depth: 1}}

	for len(stack) > 0 && !p.stopped {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		n := f.node
		if n == nil {
			continue
		}

		p.nodes++
		if p.nodes > MaxNodes {
			p.reject("workflow.node_budget_exceeded", f.pointer,
				"workflow document contains more nodes than the parser budget allows")
			return
		}
		if f.depth > MaxDepth {
			p.reject("workflow.depth_exceeded", f.pointer,
				"workflow document nests deeper than the parser depth bound")
			return
		}

		if !p.checkNodeProperties(n, f.pointer) {
			continue
		}

		switch n.Kind {
		case yaml.MappingNode:
			stack = p.pushMapping(stack, n, f)
		case yaml.SequenceNode:
			for i := len(n.Content) - 1; i >= 0; i-- {
				stack = append(stack, frame{
					node:    n.Content[i],
					depth:   f.depth + 1,
					pointer: indexPointer(f.pointer, i),
				})
			}
		}
	}
}

// checkNodeProperties validates the properties every node carries regardless of
// kind. It reports whether the walk may descend into this node.
func (p *parser) checkNodeProperties(n *yaml.Node, pointer string) bool {
	if n.Anchor != "" {
		p.reject("workflow.anchor_forbidden", pointer, "YAML anchors are not accepted in a workflow document")
	}
	if n.Kind == yaml.AliasNode {
		p.reject("workflow.alias_forbidden", pointer, "YAML aliases are not accepted in a workflow document")
		return false
	}
	if n.Tag == yamlMergeTag {
		p.reject("workflow.merge_key_forbidden", pointer, "YAML merge keys are not accepted in a workflow document")
		return false
	}
	if n.Tag != "" && !allowedTags[n.Tag] {
		p.reject("workflow.tag_forbidden", pointer, "workflow document uses a YAML tag outside the accepted core schema")
		return false
	}
	return true
}

// pushMapping validates a mapping's keys and queues its values in document
// order. Key nodes are checked here rather than queued, because a key has
// stricter rules than a value: it must be a plain string and it must be unique.
func (p *parser) pushMapping(stack []frame, n *yaml.Node, f frame) []frame {
	if len(n.Content)%2 != 0 {
		p.reject("workflow.malformed", f.pointer, "workflow mapping has a key without a value")
		return stack
	}

	seen := make(map[string]bool, len(n.Content)/2)
	queued := make([]frame, 0, len(n.Content)/2)

	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]

		if k.Anchor != "" {
			p.reject("workflow.anchor_forbidden", f.pointer, "YAML anchors are not accepted in a workflow document")
		}
		if k.Kind == yaml.AliasNode {
			p.reject("workflow.alias_forbidden", f.pointer, "YAML aliases are not accepted in a workflow document")
			continue
		}
		if k.Tag == yamlMergeTag || (k.Kind == yaml.ScalarNode && k.Value == "<<") {
			p.reject("workflow.merge_key_forbidden", f.pointer, "YAML merge keys are not accepted in a workflow document")
			continue
		}
		if k.Kind != yaml.ScalarNode || (k.Tag != "" && k.Tag != yamlStrTag) {
			p.reject("workflow.key_not_string", f.pointer, "workflow mapping keys must be plain strings")
			continue
		}
		if seen[k.Value] {
			p.reject("workflow.duplicate_key", childPointer(f.pointer, k.Value),
				"workflow mapping declares the same key twice")
			continue
		}
		seen[k.Value] = true

		queued = append(queued, frame{
			node:    v,
			depth:   f.depth + 1,
			pointer: childPointer(f.pointer, k.Value),
		})
	}

	// Reversed, so that popping from the end yields document order and
	// diagnostics read top to bottom.
	for i := len(queued) - 1; i >= 0; i-- {
		stack = append(stack, queued[i])
	}
	return stack
}

// decodeDocument reads the allow-listed workflow fields. Anything else becomes a
// coverage note: version 1 says what it did not model rather than implying that
// an unmodeled field was found safe.
func (p *parser) decodeDocument(root *yaml.Node) Document {
	var doc Document

	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch k.Value {
		case "name":
			doc.Name = scalarOf(v)
		case "on":
			doc.Triggers = p.decodeTriggers(v)
		case "permissions":
			doc.Permissions = p.decodePermissions(v)
		case "env":
			doc.Env = p.decodeMap(v, "workflow env")
		case "jobs":
			doc.Jobs = p.decodeJobs(v)
		default:
			p.note("workflow field " + field(k.Value) + " is not modeled by version 1")
		}
	}
	return doc
}

// decodeTriggers reads the three shapes GitHub accepts for `on:`: a bare
// scalar, a sequence of scalars, and a mapping whose keys are event names.
func (p *parser) decodeTriggers(v *yaml.Node) []Trigger {
	if v == nil {
		return nil
	}
	switch v.Kind {
	case yaml.ScalarNode:
		if v.Tag == yamlNullTag || v.Value == "" {
			return nil
		}
		return []Trigger{{Name: scalarOf(v)}}

	case yaml.SequenceNode:
		var triggers []Trigger
		for _, c := range v.Content {
			if c.Kind != yaml.ScalarNode {
				p.note("workflow trigger list contains a non-scalar entry that version 1 does not model")
				continue
			}
			triggers = append(triggers, Trigger{Name: scalarOf(c)})
		}
		return triggers

	case yaml.MappingNode:
		var triggers []Trigger
		for i := 0; i+1 < len(v.Content); i += 2 {
			k, qualifiers := v.Content[i], v.Content[i+1]
			// The event name is the key, so its position is the line a finding
			// points at when it reports an unsafe trigger.
			t := Trigger{Name: scalarOf(k)}
			if qualifiers != nil && qualifiers.Kind == yaml.MappingNode {
				t.Types = p.decodeScalarList(qualifiers, "types")
				t.Branches = p.decodeScalarList(qualifiers, "branches")
			}
			triggers = append(triggers, t)
		}
		return triggers
	}
	return nil
}

// decodeScalarList reads a named field of a mapping as a list of scalars,
// accepting both the scalar and sequence spellings GitHub allows.
func (p *parser) decodeScalarList(node *yaml.Node, key string) []Scalar {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value != key {
			continue
		}
		return scalarsOf(node.Content[i+1])
	}
	return nil
}

// decodePermissions reads a permissions block at either workflow or job scope.
func (p *parser) decodePermissions(v *yaml.Node) Permissions {
	if v == nil {
		return Permissions{}
	}
	perm := Permissions{Present: true, Pos: posOf(v)}
	switch v.Kind {
	case yaml.ScalarNode:
		perm.Mode = scalarOf(v)
	case yaml.MappingNode:
		// An empty mapping is the explicit "no permissions" spelling, and is
		// correctly represented by a present block with no scopes.
		perm.Scopes = p.decodeMap(v, "permissions")
	default:
		p.note("permissions block uses a shape that version 1 does not model")
	}
	return perm
}

// decodeMap reads a mapping of scalar keys to scalar values.
func (p *parser) decodeMap(v *yaml.Node, context string) Map {
	if v == nil || v.Kind != yaml.MappingNode {
		return nil
	}
	var m Map
	for i := 0; i+1 < len(v.Content); i += 2 {
		k, val := v.Content[i], v.Content[i+1]
		if val == nil || val.Kind != yaml.ScalarNode {
			p.note(context + " entry " + field(k.Value) + " has a non-scalar value that version 1 does not model")
			continue
		}
		m = append(m, MapEntry{Key: scalarOf(k), Value: scalarOf(val)})
	}
	return m
}

func (p *parser) decodeJobs(v *yaml.Node) []Job {
	if v == nil || v.Kind != yaml.MappingNode {
		if v != nil && v.Kind != yaml.MappingNode {
			p.note("jobs block uses a shape that version 1 does not model")
		}
		return nil
	}
	var jobs []Job
	for i := 0; i+1 < len(v.Content); i += 2 {
		k, body := v.Content[i], v.Content[i+1]
		if body == nil || body.Kind != yaml.MappingNode {
			p.note("job " + field(k.Value) + " uses a shape that version 1 does not model")
			continue
		}
		jobs = append(jobs, p.decodeJob(k, body))
	}
	return jobs
}

func (p *parser) decodeJob(key, body *yaml.Node) Job {
	job := Job{ID: scalarOf(key), Pos: posOf(body)}

	for i := 0; i+1 < len(body.Content); i += 2 {
		k, v := body.Content[i], body.Content[i+1]
		switch k.Value {
		case "runs-on":
			job.RunsOn = p.decodeRunsOn(v)
		case "permissions":
			job.Permissions = p.decodePermissions(v)
		case "environment":
			job.Environment = p.decodeEnvironment(v)
		case "if":
			job.If = scalarOf(v)
		case "uses":
			job.Uses = scalarOf(v)
		case "secrets":
			p.decodeJobSecrets(&job, v)
		case "env":
			job.Env = p.decodeMap(v, "job env")
		case "steps":
			job.Steps = p.decodeSteps(v)
		default:
			p.note("job field " + field(k.Value) + " is not modeled by version 1")
		}
	}
	return job
}

// decodeJobSecrets records both spellings: `secrets: inherit`, which hands the
// callee every repository secret, and an explicit mapping of named secrets.
func (p *parser) decodeJobSecrets(job *Job, v *yaml.Node) {
	if v == nil {
		return
	}
	if v.Kind == yaml.ScalarNode {
		job.SecretsInherit = v.Value == "inherit"
		if !job.SecretsInherit {
			p.note("job secrets use a scalar spelling that version 1 does not model")
		}
		return
	}
	job.Secrets = p.decodeMap(v, "job secrets")
}

// decodeRunsOn reads the runner selector, which may be a scalar, a sequence of
// labels, or a mapping carrying `group` and `labels`.
func (p *parser) decodeRunsOn(v *yaml.Node) []Scalar {
	if v == nil {
		return nil
	}
	if v.Kind == yaml.MappingNode {
		var out []Scalar
		out = append(out, p.decodeScalarList(v, "group")...)
		out = append(out, p.decodeScalarList(v, "labels")...)
		return out
	}
	return scalarsOf(v)
}

// decodeEnvironment reads the deployment environment, which may be a scalar or
// a mapping whose `name` identifies it.
func (p *parser) decodeEnvironment(v *yaml.Node) []Scalar {
	if v == nil {
		return nil
	}
	if v.Kind == yaml.MappingNode {
		return p.decodeScalarList(v, "name")
	}
	return scalarsOf(v)
}

func (p *parser) decodeSteps(v *yaml.Node) []Step {
	if v == nil || v.Kind != yaml.SequenceNode {
		if v != nil {
			p.note("job steps use a shape that version 1 does not model")
		}
		return nil
	}
	var steps []Step
	for _, c := range v.Content {
		if c == nil || c.Kind != yaml.MappingNode {
			p.note("a job step uses a shape that version 1 does not model")
			continue
		}
		steps = append(steps, p.decodeStep(c))
	}
	return steps
}

func (p *parser) decodeStep(node *yaml.Node) Step {
	step := Step{Pos: posOf(node)}

	for i := 0; i+1 < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		switch k.Value {
		case "name":
			step.Name = scalarOf(v)
		case "uses":
			step.Uses = scalarOf(v)
		case "run":
			step.Run = scalarOf(v)
		case "shell":
			step.Shell = scalarOf(v)
		case "if":
			step.If = scalarOf(v)
		case "with":
			step.With = p.decodeMap(v, "step with")
		case "env":
			step.Env = p.decodeMap(v, "step env")
		default:
			p.note("step field " + field(k.Value) + " is not modeled by version 1")
		}
	}
	return step
}

// scalarOf converts a scalar node, preserving its literal text. A null scalar
// becomes an empty value that still reports Present, because "written as null"
// and "not written" are different facts.
func scalarOf(n *yaml.Node) Scalar {
	if n == nil || n.Kind != yaml.ScalarNode {
		return Scalar{}
	}
	if n.Tag == yamlNullTag {
		return Scalar{Pos: posOf(n)}
	}
	return Scalar{Value: n.Value, Pos: posOf(n)}
}

// scalarsOf reads either a lone scalar or a sequence of them as a list.
func scalarsOf(n *yaml.Node) []Scalar {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == yamlNullTag {
			return nil
		}
		return []Scalar{scalarOf(n)}
	case yaml.SequenceNode:
		var out []Scalar
		for _, c := range n.Content {
			if c != nil && c.Kind == yaml.ScalarNode {
				out = append(out, scalarOf(c))
			}
		}
		return out
	}
	return nil
}

func posOf(n *yaml.Node) Position {
	if n == nil {
		return Position{}
	}
	return Position{Line: n.Line, Column: n.Column}
}

// yamlErrorPointer extracts only the line number from a YAML error.
//
// The library's message can quote the offending input, which must never reach a
// diagnostic, so nothing but the digits is carried out.
func yamlErrorPointer(err error) string {
	msg := err.Error()
	const marker = "line "
	i := strings.Index(msg, marker)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(marker):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return ""
	}
	return "line " + rest[:j]
}

// field renders a workflow field name for a coverage note. The name comes from
// repository content, so it is sanitized to bounded printable ASCII and quoted.
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
