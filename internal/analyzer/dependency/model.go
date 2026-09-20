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
	// Escapes records that a local path resolves outside the repository tree,
	// which docs/analyzers.md treats as grounds to block independently of
	// whether the reference is mutable.
	Escapes bool
	Pinned  string
	Path    string
	Pos     Position
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
// Instance distinguishes two resolutions of the same package name within one
// lockfile. npm nests transitive installs, so `node_modules/a` and
// `node_modules/b/node_modules/a` are different packages at different versions;
// collapsing them by name kept only whichever came last and let a substitution
// in one hide behind the other.
type Resolved struct {
	Ecosystem Ecosystem
	Name      string
	Instance  string
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

// Record identity.
//
// A package name is unique only within one registry and one declaring file.
// `requests` exists on both npm and PyPI; a monorepo declares the same
// dependency in several workspace manifests; and an npm lockfile resolves the
// same name at several versions under different install paths. Keying by name
// alone collapsed all three, so one record masked another and a change to the
// masked one went unseen.
//
// nameKey is deliberately coarser than the others: it answers "does this
// ecosystem's lock resolve this name anywhere", which is the question
// PFR-DEP-001 asks and which must not be narrowed by install path.
func nameKey(eco Ecosystem, name string) string { return string(eco) + "\x00" + name }

func declaredKey(d Declared) string {
	return string(d.Ecosystem) + "\x00" + d.Path + "\x00" + d.Name
}

func resolvedKey(r Resolved) string {
	return string(r.Ecosystem) + "\x00" + r.Path + "\x00" + r.Instance
}

func scriptKey(s Script) string {
	return string(s.Ecosystem) + "\x00" + s.Path + "\x00" + s.Name
}

// declaredNames indexes declarations by ecosystem, manifest, and name, so the
// same dependency in two workspace manifests stays two records.
func (s Snapshot) declaredNames() map[string]Declared {
	out := make(map[string]Declared, len(s.Declared))
	for _, d := range s.Declared {
		out[declaredKey(d)] = d
	}
	return out
}

// resolvedInstances indexes every resolution separately, so a nested install of
// the same name at a different version is its own record.
func (s Snapshot) resolvedInstances() map[string]Resolved {
	out := make(map[string]Resolved, len(s.Resolved))
	for _, r := range s.Resolved {
		out[resolvedKey(r)] = r
	}
	return out
}

// resolutionsByName groups every resolution of a name within one ecosystem,
// preserving the distinct versions and paths rather than keeping only the last.
func (s Snapshot) resolutionsByName() map[string][]Resolved {
	out := make(map[string][]Resolved, len(s.Resolved))
	for _, r := range s.Resolved {
		key := nameKey(r.Ecosystem, r.Name)
		out[key] = append(out[key], r)
	}
	return out
}

func (s Snapshot) scriptsByName() map[string]Script {
	out := make(map[string]Script, len(s.Scripts))
	for _, sc := range s.Scripts {
		out[scriptKey(sc)] = sc
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
