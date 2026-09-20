// Package workflow turns GitHub Actions workflow YAML into a bounded,
// normalized document the PFR-WF analyzer can inspect without ever running a
// workflow, resolving an expression, or touching the filesystem.
//
// The model is deliberately small: it holds only the fields the six PFR-WF
// rules read. Everything else is recorded as a coverage note so a report can
// state what version 1 did not model, rather than implying full coverage.
//
// Every modeled value is a Scalar carrying its source position, because a
// finding must point at a real line in the head revision.
package workflow

// Position is a one-based source location inside the parsed document. A zero
// Line means the value was absent, which is how Scalar.Present is decided.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Scalar is one leaf value together with where it was written.
//
// Value is the literal text as authored. The parser never expands `${{ }}`
// expressions, shell substitutions, or environment references: preserving the
// bytes verbatim is what lets a rule report an injection sink truthfully.
type Scalar struct {
	Value string   `json:"value"`
	Pos   Position `json:"position"`
}

// Present reports whether the scalar was actually written in the document. An
// absent field and a field explicitly set to the empty string are different
// facts, and several rules depend on telling them apart.
func (s Scalar) Present() bool { return s.Pos.Line > 0 }

// MapEntry is one key/value pair whose value is a scalar.
type MapEntry struct {
	Key   Scalar `json:"key"`
	Value Scalar `json:"value"`
}

// Map preserves document order. It is a slice rather than a Go map so that
// iteration is deterministic and two runs over the same bytes emit findings in
// the same order. Keys are unique: the parser rejects duplicates before the
// document is decoded.
type Map []MapEntry

// Get returns the value for key, or the zero Scalar when the key is absent.
func (m Map) Get(key string) Scalar {
	for _, e := range m {
		if e.Key.Value == key {
			return e.Value
		}
	}
	return Scalar{}
}

// Has reports whether key was written at all, including with an empty value.
func (m Map) Has(key string) bool {
	for _, e := range m {
		if e.Key.Value == key {
			return true
		}
	}
	return false
}

// Trigger is one entry of the workflow `on:` field.
//
// Types and Branches are populated only for the mapping form; the scalar and
// sequence forms carry no qualifiers.
type Trigger struct {
	Name     Scalar   `json:"name"`
	Types    []Scalar `json:"types,omitempty"`
	Branches []Scalar `json:"branches,omitempty"`
}

// Permissions is a `permissions:` block at workflow or job scope.
//
// GitHub accepts two shapes. A bare scalar (`write-all`, `read-all`, or the
// empty mapping) sets every scope at once and lands in Mode. A mapping sets
// individual scopes and lands in Scopes. Present distinguishes "no permissions
// block was written", which inherits the repository default, from an explicit
// one; the two have different security meanings and must not be conflated.
type Permissions struct {
	Present bool     `json:"present"`
	Mode    Scalar   `json:"mode,omitempty"`
	Scopes  Map      `json:"scopes,omitempty"`
	Pos     Position `json:"position"`
}

// Step is one step of a job.
type Step struct {
	Name  Scalar   `json:"name,omitempty"`
	Uses  Scalar   `json:"uses,omitempty"`
	Run   Scalar   `json:"run,omitempty"`
	Shell Scalar   `json:"shell,omitempty"`
	If    Scalar   `json:"if,omitempty"`
	With  Map      `json:"with,omitempty"`
	Env   Map      `json:"env,omitempty"`
	Pos   Position `json:"position"`
}

// Job is one entry of the workflow `jobs:` mapping.
//
// Uses is set when the job calls a reusable workflow instead of declaring
// steps. SecretsInherit records the `secrets: inherit` shorthand, which hands
// every repository secret to the callee.
type Job struct {
	ID             Scalar      `json:"id"`
	If             Scalar      `json:"if,omitempty"`
	RunsOn         []Scalar    `json:"runs_on,omitempty"`
	Permissions    Permissions `json:"permissions"`
	Environment    []Scalar    `json:"environment,omitempty"`
	Uses           Scalar      `json:"uses,omitempty"`
	SecretsInherit bool        `json:"secrets_inherit"`
	Secrets        Map         `json:"secrets,omitempty"`
	Env            Map         `json:"env,omitempty"`
	Steps          []Step      `json:"steps,omitempty"`
	Pos            Position    `json:"position"`
}

// Document is one parsed workflow file.
//
// A Document is produced only by Parse, and only when the document passed every
// restriction. A rejected document yields the zero value plus diagnostics, so a
// caller can never act on partially trusted content.
type Document struct {
	Path          string      `json:"path"`
	Name          Scalar      `json:"name,omitempty"`
	Triggers      []Trigger   `json:"triggers,omitempty"`
	Permissions   Permissions `json:"permissions"`
	Env           Map         `json:"env,omitempty"`
	Jobs          []Job       `json:"jobs,omitempty"`
	CoverageNotes []string    `json:"coverage_notes,omitempty"`
}

// Trigger returns the named trigger and whether it was declared.
func (d Document) Trigger(name string) (Trigger, bool) {
	for _, t := range d.Triggers {
		if t.Name.Value == name {
			return t, true
		}
	}
	return Trigger{}, false
}
