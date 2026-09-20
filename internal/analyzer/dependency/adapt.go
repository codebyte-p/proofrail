package dependency

import (
	"path"
	"strings"
)

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
	case hasPrefixFold(trimmed, "file:"), hasPrefixFold(trimmed, "link:"),
		strings.HasPrefix(trimmed, "./"), strings.HasPrefix(trimmed, "../"), strings.HasPrefix(trimmed, "/"):
		return SourcePath, false
	case hasPrefixFold(trimmed, "workspace:"):
		return SourceWorkspace, false
	case hasPrefixFold(trimmed, "git+"), hasPrefixFold(trimmed, "git:"),
		hasPrefixFold(trimmed, "github:"), hasPrefixFold(trimmed, "gitlab:"),
		hasPrefixFold(trimmed, "bitbucket:"):
		return SourceGit, gitReferenceIsImmutable(trimmed)
	case hasPrefixFold(trimmed, "http://"), hasPrefixFold(trimmed, "https://"):
		// A tarball URL carries no integrity value of its own, so the bytes it
		// serves can change without the specifier changing.
		return SourceURL, false
	case hasPrefixFold(trimmed, "npm:"):
		rest, _ := trimPrefixFold(trimmed, "npm:")
		return SourceRegistry, isExactNPMVersion(rest)
	case isGitHubShorthand(trimmed):
		// npm resolves a bare `owner/repo` to GitHub. Falling through to the
		// registry branch classified it as a registry dependency, which
		// PFR-DEP-002 skips outright, so the shorthand produced no finding.
		return SourceGit, gitReferenceIsImmutable(trimmed)
	default:
		return SourceRegistry, isExactNPMVersion(trimmed)
	}
}

// trimPrefixFold strips prefix from s ignoring case, and reports whether it was
// there.
//
// A URI scheme is case-insensitive and npm resolves `HTTPS://`, `GIT+` and
// `File:` exactly as it resolves their lowercase spellings. Matching them
// case-sensitively dropped every uppercase spelling into the registry branch,
// which PFR-DEP-002 skips outright, so the dependency was not downgraded to
// review but omitted from the report entirely.
//
// Only the scheme is folded. What a caller echoes into evidence keeps the
// spelling the repository wrote, and a reference is still judged immutable on
// its original text, so an uppercase commit hash stays unpinned rather than
// being promoted by a case fold.
func trimPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

func hasPrefixFold(s, prefix string) bool {
	_, found := trimPrefixFold(s, prefix)
	return found
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
	s, _ = trimPrefixFold(s, "npm:")
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
		case hasPrefixFold(ref, "git+"):
			return SourceGit, pythonGitReferenceIsImmutable(ref)
		case hasPrefixFold(ref, "file://"), strings.HasPrefix(ref, "./"), strings.HasPrefix(ref, "/"):
			return SourcePath, false
		case hasPrefixFold(ref, "http://"), hasPrefixFold(ref, "https://"):
			return SourceURL, false
		default:
			return SourceUnknown, false
		}
	}

	if !strings.ContainsAny(s, "<>=!~") {
		// A bare name floats to whatever the index serves today, exactly as an
		// npm range does. Both are ordinary registry practice, so both belong
		// to PFR-DEP-001 through lock resolution rather than to PFR-DEP-002,
		// which would have blocked in one ecosystem what it exempts in the
		// other.
		return SourceRegistry, false
	}
	return SourceRegistry, strings.Contains(s, "==")
}

// pythonGitReferenceIsImmutable reports whether `git+<url>@<ref>` names a full
// commit hash rather than a branch or tag.
func pythonGitReferenceIsImmutable(ref string) bool {
	trimmed, _ := trimPrefixFold(ref, "git+")
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
// The local-path parameter is named localPath so it cannot shadow the `path`
// package this file uses for containment resolution.
func classifyUVSource(git, url, localPath, branch, tag, rev string) (SourceKind, bool) {
	switch {
	case git != "":
		// A rev may be a full commit hash; a branch or tag may move.
		return SourceGit, branch == "" && tag == "" && isCommitHash(rev)
	case url != "":
		return SourceURL, false
	case localPath != "":
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
func pathEscapesRepository(spec, manifestPath string) bool {
	s := strings.TrimSpace(spec)
	// Folded, for the same reason the classifier folds: `File:/opt/lib` and
	// `file:/opt/lib` name one path, and leaving the scheme attached hid the
	// leading slash that makes it absolute.
	for _, prefix := range []string{"file:", "link:", "workspace:"} {
		s, _ = trimPrefixFold(s, prefix)
	}
	if s == "" || s == "*" {
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

	// A relative specifier is written relative to the manifest that declares
	// it, so `../lib` from `packages/a/package.json` stays inside the
	// repository while the same text from a root manifest does not. Resolving
	// it from the repository root instead would have judged both the same.
	resolved := path.Join(path.Dir(manifestPath), s)
	return resolved == ".." || strings.HasPrefix(resolved, "../")
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
