package dependency

import "strings"

// This file holds the per-ecosystem adapters.
//
// Each parser emits a model faithful to its own file format; normalization into
// the shared record happens here, in the analyzer. That keeps the parsers free
// of any analyzer import and lets one set of rules serve both ecosystems
// instead of each ecosystem carrying its own copy.

// ----------------------------------------------------------------------------
// npm
// ----------------------------------------------------------------------------

// classifyNPMSpec reads an npm version specifier and reports where it resolves
// from and whether the reference is immutable.
//
// Pinning is about reproducibility, not trust: `1.2.3` and a Git URL ending in
// a full commit hash are both immutable, while `^1.2.3` and a branch are not.
func classifyNPMSpec(spec string) (SourceKind, bool) {
	trimmed := strings.TrimSpace(spec)

	switch {
	case trimmed == "":
		return SourceUnknown, false
	case strings.HasPrefix(trimmed, "file:"), strings.HasPrefix(trimmed, "link:"),
		strings.HasPrefix(trimmed, "./"), strings.HasPrefix(trimmed, "../"), strings.HasPrefix(trimmed, "/"):
		return SourcePath, false
	case strings.HasPrefix(trimmed, "workspace:"):
		return SourceWorkspace, false
	case strings.HasPrefix(trimmed, "git+"), strings.HasPrefix(trimmed, "git:"),
		strings.HasPrefix(trimmed, "github:"), strings.HasPrefix(trimmed, "gitlab:"),
		strings.HasPrefix(trimmed, "bitbucket:"):
		return SourceGit, gitReferenceIsImmutable(trimmed)
	case strings.HasPrefix(trimmed, "http://"), strings.HasPrefix(trimmed, "https://"):
		// A tarball URL carries no integrity value of its own, so the bytes it
		// serves can change without the specifier changing.
		return SourceURL, false
	case strings.HasPrefix(trimmed, "npm:"):
		return SourceRegistry, isExactNPMVersion(strings.TrimPrefix(trimmed, "npm:"))
	case isGitHubShorthand(trimmed):
		// npm resolves a bare `owner/repo` to GitHub. Falling through to the
		// registry branch classified it as a registry dependency, which
		// PFR-DEP-002 skips outright, so the shorthand produced no finding.
		return SourceGit, gitReferenceIsImmutable(trimmed)
	default:
		return SourceRegistry, isExactNPMVersion(trimmed)
	}
}

// isGitHubShorthand reports whether spec is npm's `owner/repo` or
// `owner/repo#ref` GitHub shorthand.
//
// A semver range never contains a slash, and every other source form is matched
// by an explicit prefix before this check, so a slash at this point means the
// shorthand.
func isGitHubShorthand(spec string) bool {
	repoPath, _, _ := strings.Cut(spec, "#")
	owner, repo, found := strings.Cut(repoPath, "/")
	if !found || owner == "" || repo == "" {
		return false
	}
	return !strings.Contains(repo, "/")
}

// exactNPMVersion returns the single version a registry specifier pins to, or
// "" when it names a range. It is what PFR-DEP-001 compares against the lock.
func exactNPMVersion(spec string) string {
	s := strings.TrimSpace(spec)
	s = strings.TrimPrefix(s, "npm:")
	// An aliased spec is `npm:<name>@<version>`; a plain one has no `@`.
	if i := strings.LastIndex(s, "@"); i > 0 {
		s = s[i+1:]
	}
	if isExactNPMVersion(s) {
		return s
	}
	return ""
}

// exactPythonVersion returns the single version a PEP 508 specifier pins to
// with `==`, or "" when it names a range, a direct reference, or a wildcard.
func exactPythonVersion(spec string) string {
	s := strings.TrimSpace(spec)
	if strings.Contains(s, "@") {
		return ""
	}
	idx := strings.Index(s, "==")
	if idx < 0 {
		return ""
	}
	rest := s[idx+len("=="):]
	if i := strings.IndexAny(rest, ",; "); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.Contains(rest, "*") {
		return ""
	}
	return rest
}

// gitReferenceIsImmutable reports whether a Git specifier names a full commit
// hash. A branch or tag can be moved, so it is not a reproducible binding.
func gitReferenceIsImmutable(spec string) bool {
	_, fragment, found := strings.Cut(spec, "#")
	if !found {
		return false
	}
	// `#semver:` selects a tag range, which is mutable.
	if strings.HasPrefix(fragment, "semver:") {
		return false
	}
	return isCommitHash(fragment)
}

// isExactNPMVersion reports whether a registry specifier names one version.
// Ranges, tags such as `latest`, and wildcards all resolve differently over
// time.
func isExactNPMVersion(spec string) bool {
	if spec == "" {
		return false
	}
	switch spec[0] {
	case '^', '~', '>', '<', '=', '*', 'v':
		return false
	}
	if strings.ContainsAny(spec, " |*") || strings.Contains(spec, "x") {
		return false
	}
	// An exact version starts with a digit and carries the two dots of semver.
	if spec[0] < '0' || spec[0] > '9' {
		return false
	}
	return strings.Count(spec, ".") >= 2
}

// ----------------------------------------------------------------------------
// Python
// ----------------------------------------------------------------------------

// pythonRequirementName extracts the distribution name from a PEP 508
// specifier, which may carry extras, a direct reference, or a version range.
func pythonRequirementName(spec string) string {
	s := strings.TrimSpace(spec)

	// A direct reference is `name @ url`.
	if name, _, found := strings.Cut(s, "@"); found {
		s = strings.TrimSpace(name)
	}
	// Extras: `name[extra]`.
	if i := strings.IndexByte(s, '['); i >= 0 {
		s = s[:i]
	}
	// A version range follows the name.
	if i := strings.IndexAny(s, "<>=!~; "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// classifyPythonSpec reads a PEP 508 specifier the same way.
func classifyPythonSpec(spec string) (SourceKind, bool) {
	s := strings.TrimSpace(spec)

	if _, reference, found := strings.Cut(s, "@"); found {
		ref := strings.TrimSpace(reference)
		switch {
		case strings.HasPrefix(ref, "git+"):
			return SourceGit, pythonGitReferenceIsImmutable(ref)
		case strings.HasPrefix(ref, "file://"), strings.HasPrefix(ref, "./"), strings.HasPrefix(ref, "/"):
			return SourcePath, false
		case strings.HasPrefix(ref, "http://"), strings.HasPrefix(ref, "https://"):
			return SourceURL, false
		default:
			return SourceUnknown, false
		}
	}

	if !strings.ContainsAny(s, "<>=!~") {
		// A bare name floats to whatever the index serves today.
		return SourceUnpinned, false
	}
	return SourceRegistry, strings.Contains(s, "==")
}

// pythonGitReferenceIsImmutable reports whether `git+<url>@<ref>` names a full
// commit hash rather than a branch or tag.
func pythonGitReferenceIsImmutable(ref string) bool {
	trimmed := strings.TrimPrefix(ref, "git+")
	// Strip the scheme so its `//` cannot be mistaken for the revision marker.
	if _, rest, found := strings.Cut(trimmed, "://"); found {
		trimmed = rest
	}
	idx := strings.LastIndex(trimmed, "@")
	if idx < 0 {
		return false
	}
	return isCommitHash(trimmed[idx+1:])
}

// classifyUVSource reads a `[tool.uv.sources]` entry.
func classifyUVSource(git, url, path, branch, tag, rev string) (SourceKind, bool) {
	switch {
	case git != "":
		// A rev may be a full commit hash; a branch or tag may move.
		return SourceGit, branch == "" && tag == "" && isCommitHash(rev)
	case url != "":
		return SourceURL, false
	case path != "":
		return SourcePath, false
	default:
		return SourceUnknown, false
	}
}

// pathEscapesRepository reports whether a local path specifier resolves outside
// the repository tree.
//
// The check is lexical and slash-based, matching how these specifiers are
// written rather than how the host filesystem would resolve them, so it cannot
// be changed by the platform the scan runs on.
func pathEscapesRepository(spec string) bool {
	s := strings.TrimSpace(spec)
	for _, prefix := range []string{"file:", "link:"} {
		s = strings.TrimPrefix(s, prefix)
	}
	if s == "" {
		return false
	}
	s = strings.ReplaceAll(s, `\`, "/")

	// An absolute path, or a Windows volume specifier, leaves the tree outright.
	if strings.HasPrefix(s, "/") {
		return true
	}
	if len(s) >= 2 && s[1] == ':' {
		c := s[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}

	// Otherwise walk the segments: a `..` that no earlier segment cancels
	// climbs above the repository root.
	depth := 0
	for _, segment := range strings.Split(s, "/") {
		switch segment {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return true
			}
		default:
			depth++
		}
	}
	return false
}

// isCommitHash reports whether s is a full 40-character lowercase hash, the
// only immutable way to name a Git revision.
func isCommitHash(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
