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

// Declared is one dependency as the manifest declares it, before resolution.
type Declared struct {
	Ecosystem Ecosystem
	Name      string
	Spec      string
	Kind      string
	Source    SourceKind
	Immutable bool
	Path      string
	Pos       Position
}

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

// Snapshot is one side of the comparison: everything the analyzer learned about
// a revision's dependency declarations and resolutions.
type Snapshot struct {
	Declared []Declared
	Resolved []Resolved
	Scripts  []Script
}

func (s Snapshot) declaredNames() map[string]Declared {
	out := make(map[string]Declared, len(s.Declared))
	for _, d := range s.Declared {
		out[d.Name] = d
	}
	return out
}

func (s Snapshot) resolvedByName() map[string]Resolved {
	out := make(map[string]Resolved, len(s.Resolved))
	for _, r := range s.Resolved {
		out[r.Name] = r
	}
	return out
}

func (s Snapshot) scriptsByName() map[string]Script {
	out := make(map[string]Script, len(s.Scripts))
	for _, sc := range s.Scripts {
		out[sc.Name] = sc
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
