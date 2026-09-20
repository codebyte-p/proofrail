// Package npm turns npm-compatible `package.json` and `package-lock.json` into
// bounded, normalized records.
//
// It never invokes npm, a package hook, a lifecycle script, or a registry
// client, and it has no filesystem or network authority. A lifecycle script is
// captured as inert text so a rule can report that install-time execution
// exists without any of it being run.
//
// The model holds only the fields the PFR-DEP rules read. Anything else becomes
// a coverage note so a report can state what version 1 did not model.
package npm

import "strings"

// Position is a one-based source location. A zero Line means the value was
// absent, which is how Scalar.Present is decided.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Scalar is one leaf value together with where it was written. Value is the
// decoded JSON string exactly as authored, never expanded or evaluated.
type Scalar struct {
	Value string   `json:"value"`
	Pos   Position `json:"position"`
}

// Present reports whether the value was actually written in the document.
func (s Scalar) Present() bool { return s.Pos.Line > 0 }

// Requirement is one declared dependency and the manifest section that
// declared it. Spec is the raw version range or source specifier; the analyzer
// classifies it rather than the parser, because classification is a rule
// decision and this package only reports what the file says.
type Requirement struct {
	Name Scalar `json:"name"`
	Spec Scalar `json:"spec"`
	Kind string `json:"kind"`
}

// ScriptEntry is one npm lifecycle or user script, captured as text.
type ScriptEntry struct {
	Name Scalar `json:"name"`
	Body Scalar `json:"body"`
}

// Manifest is a parsed `package.json`.
type Manifest struct {
	Path          string        `json:"path"`
	Name          Scalar        `json:"name,omitempty"`
	Version       Scalar        `json:"version,omitempty"`
	Requirements  []Requirement `json:"requirements,omitempty"`
	Scripts       []ScriptEntry `json:"scripts,omitempty"`
	CoverageNotes []string      `json:"coverage_notes,omitempty"`
}

// Script returns the body of the named script, or the zero Scalar when absent.
func (m Manifest) Script(name string) Scalar {
	for _, s := range m.Scripts {
		if s.Name.Value == name {
			return s.Body
		}
	}
	return Scalar{}
}

// Requirement returns the named declared dependency and whether it was found.
func (m Manifest) Requirement(name string) (Requirement, bool) {
	for _, r := range m.Requirements {
		if r.Name.Value == name {
			return r, true
		}
	}
	return Requirement{}, false
}

// LockedPackage is one resolved entry of a `package-lock.json` `packages` map.
//
// Key is the raw map key, an install path such as `node_modules/left-pad`. Name
// is derived from that path, because lockfile v3 entries usually omit an
// explicit name. Resolved and Integrity together are the resolved identity that
// PFR-DEP-004 compares across revisions.
type LockedPackage struct {
	Key              Scalar `json:"key"`
	Name             Scalar `json:"name"`
	Version          Scalar `json:"version,omitempty"`
	Resolved         Scalar `json:"resolved,omitempty"`
	Integrity        Scalar `json:"integrity,omitempty"`
	Dev              bool   `json:"dev,omitempty"`
	Link             bool   `json:"link,omitempty"`
	HasInstallScript bool   `json:"has_install_script,omitempty"`
}

// Lock is a parsed `package-lock.json`.
type Lock struct {
	Path            string          `json:"path"`
	LockfileVersion int             `json:"lockfile_version"`
	Packages        []LockedPackage `json:"packages,omitempty"`
	CoverageNotes   []string        `json:"coverage_notes,omitempty"`
}

// Package returns the locked entry for a package name. The root entry, whose
// key is the empty string, is the project itself and is never returned here.
func (l Lock) Package(name string) (LockedPackage, bool) {
	for _, p := range l.Packages {
		if p.Name.Value == name {
			return p, true
		}
	}
	return LockedPackage{}, false
}

// packageNameFromKey derives the package name from a lockfile install path.
//
// npm nests transitive installs, so `node_modules/a/node_modules/b` resolves to
// `b`. A scoped package keeps both segments, as in `@scope/name`.
func packageNameFromKey(key string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(key, marker)
	if idx < 0 {
		return ""
	}
	name := key[idx+len(marker):]
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "@") {
		// Scoped packages keep both segments, as in `@scope/name`.
		parts := strings.SplitN(name, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return name
	}
	if i := strings.Index(name, "/"); i >= 0 {
		return name[:i]
	}
	return name
}
