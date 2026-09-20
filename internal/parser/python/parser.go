package python

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/codebyte-p/proofrail/internal/run"
)

// supportedLockfileVersions are the `uv.lock` formats whose resolved identity
// this parser models. Reading an unmodeled version would yield an empty package
// set, which is indistinguishable from a project with no dependencies, so an
// unknown version is a diagnostic instead.
var supportedLockfileVersions = map[int64]bool{1: true}

// ParseProject reads a `pyproject.toml` into the normalized project model.
//
// The document is validated against the supported TOML subset before any field
// is read, so a caller either gets a project that satisfied every restriction
// or gets the zero value and diagnostics.
func ParseProject(path string, content []byte, maxBytes int64) (Project, []run.Diagnostic) {
	if maxBytes <= 0 {
		maxBytes = MaxProjectBytes
	}
	root, r := parseDocument(path, content, maxBytes)
	if root == nil {
		return Project{}, r.diags
	}

	project := r.decodeProject(root)
	if len(r.diags) > 0 {
		return Project{}, r.diags
	}
	project.Path = path
	project.CoverageNotes = r.notes
	return project, nil
}

// ParseLock reads a `uv.lock` into the normalized lock model.
func ParseLock(path string, content []byte, maxBytes int64) (Lock, []run.Diagnostic) {
	if maxBytes <= 0 {
		maxBytes = MaxLockBytes
	}
	root, r := parseDocument(path, content, maxBytes)
	if root == nil {
		return Lock{}, r.diags
	}

	lock := r.decodeLock(root)
	if len(r.diags) > 0 {
		return Lock{}, r.diags
	}
	lock.Path = path
	lock.CoverageNotes = r.notes
	return lock, nil
}

func (r *reader) decodeProject(root *table) Project {
	var project Project

	for i, key := range root.keys {
		v := root.values[i]
		switch key.Value {
		case "project":
			if v.kind != vTable {
				r.note("the [project] table uses a shape that version 1 does not model")
				continue
			}
			r.decodeProjectTable(v.table, &project)
		case "build-system":
			if v.kind != vTable {
				r.note("the [build-system] table uses a shape that version 1 does not model")
				continue
			}
			project.BuildRequires = r.stringList(v.table, "requires")
			project.BuildBackend = v.table.str("build-backend")
		case "tool":
			if v.kind != vTable {
				r.note("the [tool] table uses a shape that version 1 does not model")
				continue
			}
			project.Sources = r.decodeToolTable(v.table)
		default:
			r.note("project field " + field(key.Value) + " is not modeled by version 1")
		}
	}
	return project
}

func (r *reader) decodeProjectTable(t *table, project *Project) {
	for i, key := range t.keys {
		v := t.values[i]
		switch key.Value {
		case "name":
			project.Name = t.str("name")
		case "version":
			project.Version = t.str("version")
		case "dependencies":
			for _, spec := range r.stringList(t, "dependencies") {
				project.Requirements = append(project.Requirements, Requirement{Spec: spec, Kind: "dependencies"})
			}
		case "optional-dependencies":
			if v.kind != vTable {
				r.note("optional-dependencies uses a shape that version 1 does not model")
				continue
			}
			for j, extra := range v.table.keys {
				group := v.table.values[j]
				if group.kind != vArray {
					r.note("optional-dependency group " + field(extra.Value) + " uses a shape that version 1 does not model")
					continue
				}
				for _, spec := range r.stringList(v.table, extra.Value) {
					project.Requirements = append(project.Requirements, Requirement{
						Spec:  spec,
						Kind:  "optional-dependencies",
						Extra: extra.Value,
					})
				}
			}
		default:
			r.note("project field " + field("project."+key.Value) + " is not modeled by version 1")
		}
	}
}

// decodeToolTable reads `[tool.uv.sources]` and records every other tool table
// as coverage, because an unmodeled tool table may still redirect a dependency.
func (r *reader) decodeToolTable(t *table) []Source {
	var sources []Source

	for i, key := range t.keys {
		v := t.values[i]
		if key.Value != "uv" {
			r.note("tool table " + field("tool."+key.Value) + " is not modeled by version 1")
			continue
		}
		if v.kind != vTable {
			r.note("the [tool.uv] table uses a shape that version 1 does not model")
			continue
		}
		for j, uvKey := range v.table.keys {
			uvValue := v.table.values[j]
			if uvKey.Value != "sources" {
				r.note("tool table " + field("tool.uv."+uvKey.Value) + " is not modeled by version 1")
				continue
			}
			if uvValue.kind != vTable {
				r.note("the [tool.uv.sources] table uses a shape that version 1 does not model")
				continue
			}
			for k, name := range uvValue.table.keys {
				entry := uvValue.table.values[k]
				if entry.kind != vTable {
					r.note("source " + field(name.Value) + " uses a shape that version 1 does not model")
					continue
				}
				sources = append(sources, Source{
					Name:   name,
					Git:    entry.table.str("git"),
					URL:    entry.table.str("url"),
					Path:   entry.table.str("path"),
					Branch: entry.table.str("branch"),
					Tag:    entry.table.str("tag"),
					Rev:    entry.table.str("rev"),
				})
			}
		}
	}
	return sources
}

func (r *reader) decodeLock(root *table) Lock {
	var lock Lock

	if v, _, ok := root.get("version"); ok && v.kind == vInteger {
		lock.LockfileVersion = int(v.integer)
	}
	if !supportedLockfileVersions[int64(lock.LockfileVersion)] {
		r.reject("unsupported_lockfile_version", "version",
			"lockfile format version is outside the versions this parser models; reading it would understate the dependency set")
		return Lock{}
	}

	for i, key := range root.keys {
		v := root.values[i]
		switch key.Value {
		case "version", "revision", "requires-python":
			// Read above or deliberately not modeled.
		case "package":
			if v.kind != vArray {
				r.note("the [[package]] entries use a shape that version 1 does not model")
				continue
			}
			for _, entry := range v.array {
				if entry.kind != vTable {
					r.note("a [[package]] entry uses a shape that version 1 does not model")
					continue
				}
				pkg, ok := r.decodeLockPackage(entry.table)
				if !ok {
					continue
				}
				lock.Packages = append(lock.Packages, pkg)
			}
		default:
			r.note("lock field " + field(key.Value) + " is not modeled by version 1")
		}
	}
	return lock
}

func (r *reader) decodeLockPackage(t *table) (LockedPackage, bool) {
	pkg := LockedPackage{
		Name:    t.str("name"),
		Version: t.str("version"),
	}
	// Present reports that a name was written, which an empty string satisfies.
	// The analyzer keys packages by name, so an empty one would collide with
	// every other empty name and make unrelated entries compare as the same
	// package. The value has to be non-empty, not merely present.
	if !pkg.Name.Present() || pkg.Name.Value == "" {
		r.note("a [[package]] entry has no usable name and was not modeled")
		return LockedPackage{}, false
	}

	// Exactly one of these describes where the package came from, so only the
	// one actually written is recorded.
	if source, _, ok := t.get("source"); ok && source.kind == vTable {
		pkg.Registry = source.table.str("registry")
		pkg.Git = source.table.str("git")
		pkg.URL = source.table.str("url")
		pkg.Path = source.table.str("path")
	}
	pkg.Hash = r.artifactIdentity(t)
	return pkg, true
}

// artifactIdentity folds every declared artifact digest for a package into one
// fixed-size value.
//
// A uv.lock package lists one wheel per platform, and a package may declare
// many. Taking only the first digest meant substituting any later wheel left
// the identity unchanged; truncating the joined list at a byte budget had the
// same effect for anything past the cut. Every digest is therefore streamed
// into a SHA-256 in document order, so the result is bounded without omitting
// a tail, and any substitution anywhere changes it.
//
// Each digest is length-framed before it is absorbed, so `["ab","c"]` and
// `["a","bc"]` cannot fold to the same value. The position reported is that of
// the first digest, which is where a reader should look.
func (r *reader) artifactIdentity(t *table) Scalar {
	var (
		digest = sha256.New()
		pos    Position
		count  int
	)
	absorb := func(h Scalar) {
		if !h.Present() || h.Value == "" {
			return
		}
		if pos.Line == 0 {
			pos = h.Pos
		}
		count++
		// Length framing keeps two different digest lists from colliding.
		fmt.Fprintf(digest, "%d:", len(h.Value))
		digest.Write([]byte(h.Value))
	}

	if sdist, _, ok := t.get("sdist"); ok && sdist.kind == vTable {
		absorb(sdist.table.str("hash"))
	}
	if wheels, _, ok := t.get("wheels"); ok && wheels.kind == vArray {
		for _, wheel := range wheels.array {
			if wheel.kind != vTable {
				continue
			}
			absorb(wheel.table.str("hash"))
		}
	}

	if count == 0 {
		return Scalar{}
	}
	return Scalar{
		Value: "sha256:" + hex.EncodeToString(digest.Sum(nil)),
		Pos:   pos,
	}
}

// stringList reads a named array of strings, recording any non-string element
// as coverage rather than dropping it silently.
func (r *reader) stringList(t *table, key string) []Scalar {
	v, _, ok := t.get(key)
	if !ok {
		return nil
	}
	if v.kind != vArray {
		r.note("field " + field(key) + " is not a list and was not modeled")
		return nil
	}
	var out []Scalar
	for _, element := range v.array {
		if element.kind != vString {
			r.note("field " + field(key) + " contains a non-string entry that version 1 does not model")
			continue
		}
		out = append(out, Scalar{Value: element.str, Pos: element.pos})
	}
	return out
}
