// Package dependency implements the PFR-DEP analyzer family: dependency change
// and provenance, as specified in docs/analyzers.md.
//
// It consumes normalized records from internal/parser/npm and
// internal/parser/python and emits candidate findings. It has no reporter,
// policy, filesystem, process, or network authority, and it never invokes npm,
// Python, uv, pip, a build backend, a package hook, or a registry client.
//
// Version 1 does not claim a package is vulnerable or malicious. It reports
// what the repository's own files say about how the build is bound, which is
// the only thing offline evidence can support.
package dependency

import "strings"

// Ecosystem names the package manager a record came from.
type Ecosystem string

const (
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPython Ecosystem = "python"
)

// SourceKind classifies where a dependency resolves from.
//
// The distinction that matters is not which host serves the artifact but
// whether the reference is immutable. A registry version and a Git commit are
// both reproducible; a branch, a bare URL, or a local path is not.
type SourceKind string

const (
	SourceRegistry  SourceKind = "registry"
	SourceGit       SourceKind = "git"
	SourceURL       SourceKind = "url"
	SourcePath      SourceKind = "path"
	SourceUnpinned  SourceKind = "unpinned"
	SourceUnknown   SourceKind = "unknown"
	SourceWorkspace SourceKind = "workspace"
)

// Position is a one-based source location inside the file the record came from.
type Position struct {
	Line   int
	Column int
}

// buildRequirementKind marks a declaration that the build frontend installs in
// an isolated environment rather than one the project lockfile resolves.
const buildRequirementKind = "build-system.requires"

// Declared is one dependency as the manifest declares it, before resolution.
//
// Pinned holds the single version the specifier names, or "" when it names a
// range. Version 1 does not evaluate range satisfaction, so only an exact pin
// can be compared against what the lockfile resolved.
type Declared struct {
	Ecosystem Ecosystem
	Name      string
	Spec      string
	Kind      string
	Source    SourceKind
	Immutable bool
	Pinned    string
	Path      string
	Pos       Position
}

// LockResolved reports whether a lockfile is expected to resolve this
// declaration.
//
// A build requirement is installed by the build frontend into an isolated
// environment that the project lock does not necessarily describe, so its
// absence from the lock is not a mismatch. It remains subject to every source
// and provenance rule.
func (d Declared) LockResolved() bool { return d.Kind != buildRequirementKind }

// Resolved is one dependency as the lockfile resolves it.
//
// Identity is the comparable resolved identity: the artifact location plus its
// integrity value. PFR-DEP-004 compares it across revisions, so it must change
// only when the bytes a build would fetch change.
type Resolved struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
	Location  string
	Integrity string
	Path      string
	Pos       Position
}

// Identity returns the comparable resolved identity.
func (r Resolved) Identity() string { return r.Location + "|" + r.Integrity }

// Script is one install-time hook a manifest declares.
type Script struct {
	Ecosystem Ecosystem
	Name      string
	Body      string
	Path      string
	Pos       Position
}

// ecosystems is the fixed iteration order for per-ecosystem rules, so findings
// are emitted in the same sequence on every run.
var ecosystems = []Ecosystem{EcosystemNPM, EcosystemPython}

// Snapshot is one side of the comparison: everything the analyzer learned about
// a revision's dependency declarations and resolutions.
//
// The coverage maps record what the change set actually contained. PFR-DEP-001
// needs them to tell "the lockfile resolved this" from "no lockfile was part of
// this change", which are different facts with different decisions. They are
// read by key only, never ranged over, so map ordering cannot reach output.
type Snapshot struct {
	Declared []Declared
	Resolved []Resolved
	Scripts  []Script

	ManifestSeen map[Ecosystem]bool
	LockSeen     map[Ecosystem]bool
	LockDeleted  map[Ecosystem]bool
}

func (s *Snapshot) markManifest(eco Ecosystem) {
	if s.ManifestSeen == nil {
		s.ManifestSeen = make(map[Ecosystem]bool, len(ecosystems))
	}
	s.ManifestSeen[eco] = true
}

func (s *Snapshot) markLock(eco Ecosystem) {
	if s.LockSeen == nil {
		s.LockSeen = make(map[Ecosystem]bool, len(ecosystems))
	}
	s.LockSeen[eco] = true
}

func (s *Snapshot) markLockDeleted(eco Ecosystem) {
	if s.LockDeleted == nil {
		s.LockDeleted = make(map[Ecosystem]bool, len(ecosystems))
	}
	s.LockDeleted[eco] = true
}

// recordKey namespaces a record by its ecosystem.
//
// A package name is only unique within its own registry: `requests` exists on
// both npm and PyPI. Keying by name alone let a record from one ecosystem mask
// a different package of the same name in another.
func recordKey(eco Ecosystem, name string) string { return string(eco) + "\x00" + name }

func (s Snapshot) declaredNames() map[string]Declared {
	out := make(map[string]Declared, len(s.Declared))
	for _, d := range s.Declared {
		out[recordKey(d.Ecosystem, d.Name)] = d
	}
	return out
}

func (s Snapshot) resolvedByName() map[string]Resolved {
	out := make(map[string]Resolved, len(s.Resolved))
	for _, r := range s.Resolved {
		out[recordKey(r.Ecosystem, r.Name)] = r
	}
	return out
}

func (s Snapshot) scriptsByName() map[string]Script {
	out := make(map[string]Script, len(s.Scripts))
	for _, sc := range s.Scripts {
		out[recordKey(sc.Ecosystem, sc.Name)] = sc
	}
	return out
}

// lifecycleScripts are the npm hooks that execute during install rather than
// when a developer chooses to run them.
var lifecycleScripts = map[string]bool{
	"preinstall":  true,
	"install":     true,
	"postinstall": true,
	"prepare":     true,
	"prepublish":  true,
	"preprepare":  true,
	"postprepare": true,
}

// isLifecycleScript reports whether a script name runs at install time.
func isLifecycleScript(name string) bool { return lifecycleScripts[strings.ToLower(name)] }
