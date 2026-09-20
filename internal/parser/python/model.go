// Package python turns `pyproject.toml` and `uv.lock` into bounded, normalized
// records.
//
// It never invokes Python, uv, pip, a build backend, a package hook, or a
// registry client, and it has no filesystem or network authority. A build
// backend is recorded as a name, never loaded.
//
// The reader implements a narrow TOML subset rather than a general parser.
// `CLAUDE.md` approves no TOML module, and Task 5 of the Gate 1 plan directs
// that the narrow field reader be written in that case. The subset covers what
// these two files actually use; every construct outside it is rejected rather
// than guessed at, because a construct the reader misunderstands would silently
// misstate the dependency set.
package python

// Position is a one-based source location. A zero Line means the value was
// absent, which is how Scalar.Present is decided.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Scalar is one leaf value together with where it was written. Value is the
// literal text as authored, never expanded or evaluated.
type Scalar struct {
	Value string   `json:"value"`
	Pos   Position `json:"position"`
}

// Present reports whether the value was actually written in the document.
func (s Scalar) Present() bool { return s.Pos.Line > 0 }

// Requirement is one declared dependency specifier and the section that
// declared it. Spec is the raw PEP 508 string; the analyzer classifies it,
// because classification is a rule decision and this package only reports what
// the file says.
type Requirement struct {
	Spec  Scalar `json:"spec"`
	Kind  string `json:"kind"`
	Extra string `json:"extra,omitempty"`
}

// Source is one `[tool.uv.sources]` entry, which redirects a dependency away
// from the default index.
type Source struct {
	Name   Scalar `json:"name"`
	Git    Scalar `json:"git,omitempty"`
	URL    Scalar `json:"url,omitempty"`
	Path   Scalar `json:"path,omitempty"`
	Branch Scalar `json:"branch,omitempty"`
	Tag    Scalar `json:"tag,omitempty"`
	Rev    Scalar `json:"rev,omitempty"`
}

// Project is a parsed `pyproject.toml`.
type Project struct {
	Path          string        `json:"path"`
	Name          Scalar        `json:"name,omitempty"`
	Version       Scalar        `json:"version,omitempty"`
	Requirements  []Requirement `json:"requirements,omitempty"`
	BuildRequires []Scalar      `json:"build_requires,omitempty"`
	BuildBackend  Scalar        `json:"build_backend,omitempty"`
	Sources       []Source      `json:"sources,omitempty"`
	CoverageNotes []string      `json:"coverage_notes,omitempty"`
}

// Source returns the named `[tool.uv.sources]` entry and whether it exists.
func (p Project) Source(name string) (Source, bool) {
	for _, s := range p.Sources {
		if s.Name.Value == name {
			return s, true
		}
	}
	return Source{}, false
}

// LockedPackage is one `[[package]]` entry of a `uv.lock`.
//
// Registry, Git, URL, and Path are mutually exclusive: exactly one describes
// where the package came from. Hash is the first artifact digest declared for
// the package, which together with Version is the resolved identity that
// PFR-DEP-004 compares across revisions.
type LockedPackage struct {
	Name     Scalar `json:"name"`
	Version  Scalar `json:"version,omitempty"`
	Registry Scalar `json:"registry,omitempty"`
	Git      Scalar `json:"git,omitempty"`
	URL      Scalar `json:"url,omitempty"`
	Path     Scalar `json:"path,omitempty"`
	Hash     Scalar `json:"hash,omitempty"`
}

// Lock is a parsed `uv.lock`.
type Lock struct {
	Path            string          `json:"path"`
	LockfileVersion int             `json:"lockfile_version"`
	Packages        []LockedPackage `json:"packages,omitempty"`
	CoverageNotes   []string        `json:"coverage_notes,omitempty"`
}

// Package returns the locked entry for a package name and whether it exists.
func (l Lock) Package(name string) (LockedPackage, bool) {
	for _, p := range l.Packages {
		if p.Name.Value == name {
			return p, true
		}
	}
	return LockedPackage{}, false
}
