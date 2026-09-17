package dependency

import (
	"sort"
	"strconv"
	"strings"

	"github.com/codebyte-p/proofrail/internal/finding"
)

// graphExpansionReviewThreshold is the number of newly declared direct
// dependencies at which PFR-DEP-005 rises from observe to require review.
// docs/analyzers.md specifies "observe or require review by threshold".
const graphExpansionReviewThreshold = 3

// budget bounds candidate generation.
//
// Enforcing a ceiling only on the returned slice still let a hostile manifest
// drive every rule over every declaration and pay for a Finalize -- redaction
// plus a SHA-256 -- on each result before anything was discarded. The budget is
// therefore consulted while candidates are produced, so the work itself is
// bounded rather than only the output.
type budget struct {
	limit     int
	generated int
	items     []finding.Finding
	exceeded  bool
}

func newBudget(limit int) *budget {
	if limit <= 0 {
		limit = defaultFindingCeiling
	}
	return &budget{limit: limit}
}

// full reports whether the budget is spent. A rule checks this inside its loop
// so it stops iterating rather than building results that will be thrown away.
func (b *budget) full() bool { return len(b.items) >= b.limit }

// add offers one candidate and reports whether the caller may continue.
func (b *budget) add(f finding.Finding) bool {
	b.generated++
	if b.full() {
		b.exceeded = true
		return false
	}
	b.items = append(b.items, f)
	return true
}

// defaultFindingCeiling applies when a caller supplies no limit. It mirrors the
// architecture ceiling so an unconfigured run is still bounded.
const defaultFindingCeiling = 5000

// evaluate runs every PFR-DEP rule over the base/head comparison.
//
// Rules are independent by construction: each appends its own candidates and
// none reads or edits another's output, so a change that trips several rules
// reports all of them.
func evaluate(base, head Snapshot, b *budget) {
	for _, rule := range []func(Snapshot, Snapshot, *budget){
		ruleManifestLockMismatch,
		ruleNonRegistryDependency,
		ruleLifecycleExecution,
		ruleResolvedSourceChanged,
		ruleGraphExpansion,
		ruleNameSimilarity,
	} {
		if b.full() {
			b.exceeded = true
			return
		}
		rule(base, head, b)
	}
}

// ----------------------------------------------------------------------------
// PFR-DEP-001: manifest-lock mismatch
// ----------------------------------------------------------------------------

func ruleManifestLockMismatch(base, head Snapshot, b *budget) {
	for _, eco := range ecosystems {
		for _, f := range mismatchForEcosystem(eco, base, head) {
			if !b.add(f) {
				return
			}
		}
	}
}

// mismatchForEcosystem reports the three shapes of manifest/lock disagreement.
//
// Keying off "the change set contained resolved packages" was not enough: a
// change that only edits the manifest, and a change that deletes the lockfile
// outright, both leave no resolutions to compare against and so evaded the rule
// entirely. Lock state is now a recorded fact rather than an inference from how
// many packages happened to be resolved.
func mismatchForEcosystem(eco Ecosystem, base, head Snapshot) []finding.Finding {
	// Removing the lockfile unbinds every dependency at once and needs no
	// declaration to have changed.
	if head.LockDeleted[eco] {
		return []finding.Finding{{
			RuleID:       "PFR-DEP-001",
			AnalyzerID:   ID,
			Severity:     finding.SeverityHigh,
			Confidence:   finding.ConfidenceHigh,
			DecisionHint: finding.DecisionBlock,
			Message: "The " + string(eco) + " lockfile is deleted by this change, so every dependency it pinned " +
				"resolves freshly at install time and the build is no longer bound to the artifacts that were reviewed.",
			Locations: []finding.Location{{Path: lockPathFor(eco), StartLine: 1, EndLine: 1}},
			Evidence: []finding.Evidence{{
				Kind:    "dependency_declaration",
				Source:  lockPathFor(eco),
				Excerpt: "lockfile deleted",
			}},
			Limitations: []string{
				"A project that intentionally stops pinning produces this same evidence; the reason has to come from the pull request itself.",
			},
		}}
	}

	baseDeclared := base.declaredNames()
	resolutions := head.resolutionsByName()

	var unresolved, inconsistent []Declared
	for _, d := range head.Declared {
		if d.Ecosystem != eco || !d.LockResolved() {
			continue
		}
		// A workspace or local path dependency is resolved by layout rather
		// than by the lock, so its absence is not a mismatch.
		if d.Source == SourcePath || d.Source == SourceWorkspace {
			continue
		}
		previous, existed := baseDeclared[declaredKey(d)]
		newDeclaration := !existed
		changedSpec := existed && previous.Spec != d.Spec

		found := resolutions[nameKey(d.Ecosystem, d.Name)]
		switch {
		case !head.LockSeen[eco], len(found) == 0:
			// Either no lockfile was part of this change, or it resolved
			// nothing under this name. Only a declaration this change
			// introduced or altered is attributable to it.
			if newDeclaration || changedSpec {
				unresolved = append(unresolved, d)
			}
		case d.Pinned != "" && !anyResolutionMatches(found, d.Pinned):
			// The name is present but no resolution carries the version the
			// manifest pins. Checking presence alone missed this.
			inconsistent = append(inconsistent, d)
		}
	}

	if len(unresolved) == 0 && len(inconsistent) == 0 {
		return nil
	}
	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i].Name < unresolved[j].Name })
	sort.Slice(inconsistent, func(i, j int) bool { return inconsistent[i].Name < inconsistent[j].Name })

	var (
		names     []string
		evidence  []finding.Evidence
		locations []finding.Location
	)
	for _, d := range unresolved {
		names = append(names, safe(d.Name))
		evidence = append(evidence, finding.Evidence{
			Kind:    "dependency_declaration",
			Source:  d.Path + " " + d.Kind,
			Excerpt: d.Name + " " + d.Spec,
		})
		locations = append(locations, location(d.Path, d.Pos))
	}
	for _, d := range inconsistent {
		names = append(names, safe(d.Name))
		evidence = append(evidence, finding.Evidence{
			Kind:    "dependency_declaration",
			Source:  d.Path + " " + d.Kind,
			Excerpt: d.Name + " pins " + d.Pinned + ", lock resolves " + resolvedVersions(resolutions[nameKey(d.Ecosystem, d.Name)]),
		})
		locations = append(locations, location(d.Path, d.Pos))
	}

	detail := "with no matching resolution in the lockfile"
	if !head.LockSeen[eco] {
		detail = "without any lockfile update in this change"
	}
	if len(unresolved) == 0 {
		detail = "at a version the lockfile does not resolve"
	}

	return []finding.Finding{{
		RuleID:       "PFR-DEP-001",
		AnalyzerID:   ID,
		Severity:     finding.SeverityHigh,
		Confidence:   finding.ConfidenceHigh,
		DecisionHint: finding.DecisionBlock,
		Message: "The manifest declares " + strings.Join(names, ", ") + " " + detail +
			", so the build is not reproducibly bound to a specific artifact.",
		Locations: locations,
		Evidence:  evidence,
		Limitations: []string{
			"A lockfile regenerated outside this change set would resolve the mismatch without any edit appearing here, and a project that keeps no lockfile at all produces this same evidence.",
			"Workspace and local path dependencies are resolved by repository layout rather than by the lockfile and are excluded, as are build requirements the build frontend installs in an isolated environment.",
			"Only an exact version pin is compared against the lockfile; version 1 does not evaluate whether a range is satisfied.",
		},
	}}
}

// lockPathFor names the lockfile an ecosystem binds with, for the case where the
// file was deleted and carries no surviving declaration to point at.
func lockPathFor(eco Ecosystem) string {
	if eco == EcosystemPython {
		return "uv.lock"
	}
	return "package-lock.json"
}

// ----------------------------------------------------------------------------
// PFR-DEP-002: non-registry dependency
// ----------------------------------------------------------------------------

func ruleNonRegistryDependency(base, head Snapshot, b *budget) {
	baseDeclared := base.declaredNames()

	for _, d := range head.Declared {
		if b.full() {
			b.exceeded = true
			return
		}
		if d.Source == SourceRegistry && d.Immutable {
			continue
		}
		if d.Source == SourceRegistry {
			// A range against a registry is ordinary practice and is covered by
			// lock resolution rather than by this rule.
			continue
		}
		if previous, existed := baseDeclared[declaredKey(d)]; existed && previous.Spec == d.Spec {
			continue
		}

		// docs/analyzers.md blocks when a source is mutable *or* outside the
		// repository. A local path that climbs out of the tree is outside it
		// just as surely as a Git URL, and testing only Git and URL sources
		// routed such a path to review.
		// Outside the repository or mutable means the bytes a build fetches can
		// change without any change here; that is the blocking condition.
		// docs/analyzers.md: "Require review; block if mutable or outside
		// repository." Requiring both conditions let a mutable reference that
		// happened to sit inside the tree, and an escaping path that was not
		// otherwise mutable, each fall through to review.
		outsideRepository := d.Source == SourceGit || d.Source == SourceURL || d.Escapes
		decision := finding.DecisionRequireReview
		severity := finding.SeverityMedium
		if !d.Immutable || outsideRepository {
			decision = finding.DecisionBlock
			severity = finding.SeverityHigh
		}

		if !b.add(finding.Finding{
			RuleID:       "PFR-DEP-002",
			AnalyzerID:   ID,
			Severity:     severity,
			Confidence:   finding.ConfidenceHigh,
			DecisionHint: decision,
			Message: "Dependency " + safe(d.Name) + " resolves from a " + string(d.Source) +
				" source that is not bound to an immutable identity, so the code it supplies can change without any change to this repository.",
			Locations: []finding.Location{location(d.Path, d.Pos)},
			Evidence: []finding.Evidence{{
				Kind:    "dependency_source",
				Source:  d.Path + " " + d.Kind,
				Excerpt: d.Spec,
			}},
			Limitations: []string{
				"A monorepo may intentionally use local or workspace dependencies, and a private registry or mirror can look unfamiliar without repository configuration.",
				"Offline analysis cannot confirm what the reference currently resolves to.",
			},
		}) {
			return
		}
	}
}

// ----------------------------------------------------------------------------
// PFR-DEP-003: lifecycle execution introduced
// ----------------------------------------------------------------------------

func ruleLifecycleExecution(base, head Snapshot, b *budget) {
	previous := base.scriptsByName()

	for _, script := range head.Scripts {
		if b.full() {
			b.exceeded = true
			return
		}
		if !isLifecycleScript(script.Name) && !strings.Contains(script.Name, "install script") &&
			script.Name != "build-backend" {
			continue
		}
		before, existed := previous[scriptKey(script)]
		if existed && before.Body == script.Body {
			continue
		}

		verb := "introduces"
		if existed {
			verb = "changes"
		}

		if !b.add(finding.Finding{
			RuleID:       "PFR-DEP-003",
			AnalyzerID:   ID,
			Severity:     finding.SeverityMedium,
			Confidence:   finding.ConfidenceHigh,
			DecisionHint: finding.DecisionRequireReview,
			Message: "The head revision " + verb + " install-time execution through " + safe(script.Name) +
				", so installing this project runs code that did not run before.",
			Locations: []finding.Location{location(script.Path, script.Pos)},
			Evidence: []finding.Evidence{{
				Kind:    "lifecycle_script",
				Source:  script.Path + " " + script.Name,
				Excerpt: script.Body,
			}},
			Limitations: []string{
				"A lifecycle script may be entirely benign and still expand install-time execution authority, which is why this routes to review rather than asserting misuse.",
				"The script is recorded as inert text; version 1 does not execute or trace it.",
			},
		}) {
			return
		}
	}
}

// ----------------------------------------------------------------------------
// PFR-DEP-004: resolved source changed unexpectedly
// ----------------------------------------------------------------------------

func ruleResolvedSourceChanged(base, head Snapshot, b *budget) {
	previous := base.resolvedInstances()

	for _, current := range head.Resolved {
		if b.full() {
			b.exceeded = true
			return
		}
		before, existed := previous[resolvedKey(current)]
		if !existed {
			continue
		}
		// A version change explains a new artifact. This rule is about the
		// artifact moving while the name and version stand still.
		if before.Version != current.Version {
			continue
		}
		if before.Identity() == current.Identity() {
			continue
		}
		// A baseline that never recorded an identity cannot evidence a change.
		if before.Location == "" && before.Integrity == "" {
			continue
		}

		if !b.add(finding.Finding{
			RuleID:       "PFR-DEP-004",
			AnalyzerID:   ID,
			Severity:     finding.SeverityHigh,
			Confidence:   finding.ConfidenceHigh,
			DecisionHint: finding.DecisionBlock,
			Message: "Locked package " + safe(current.Name) + " keeps version " + safe(current.Version) +
				" while its resolved artifact identity changes, so the same declared version would install different bytes.",
			Locations: []finding.Location{location(current.Path, current.Pos)},
			Evidence: []finding.Evidence{
				{
					Kind:    "resolved_identity",
					Source:  current.Path + " head",
					Excerpt: current.Location + " " + current.Integrity,
				},
				{
					Kind:    "resolved_identity",
					Source:  current.Path + " base",
					Excerpt: before.Location + " " + before.Integrity,
				},
			},
			Limitations: []string{
				"A deliberate registry migration or mirror change produces this same evidence, so the reason for the change has to come from the pull request itself.",
				"Offline analysis cannot fetch either artifact to compare their contents.",
			},
		}) {
			return
		}
	}
}

// ----------------------------------------------------------------------------
// PFR-DEP-005: dependency graph expansion
// ----------------------------------------------------------------------------

func ruleGraphExpansion(base, head Snapshot, b *budget) {
	baseDeclared := base.declaredNames()

	var added []Declared
	for _, d := range head.Declared {
		if _, existed := baseDeclared[declaredKey(d)]; !existed {
			added = append(added, d)
		}
	}
	if len(added) == 0 {
		return
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Name < added[j].Name })

	transitiveDelta := len(head.Resolved) - len(base.Resolved)

	// A larger delta is a larger review surface, so the hint rises with it.
	decision := finding.DecisionObserve
	severity := finding.SeverityNote
	if len(added) >= graphExpansionReviewThreshold {
		decision = finding.DecisionRequireReview
		severity = finding.SeverityLow
	}

	names := make([]string, 0, len(added))
	locations := make([]finding.Location, 0, len(added))
	for _, d := range added {
		names = append(names, safe(d.Name))
		locations = append(locations, location(d.Path, d.Pos))
	}

	b.add(finding.Finding{
		RuleID:       "PFR-DEP-005",
		AnalyzerID:   ID,
		Severity:     severity,
		Confidence:   finding.ConfidenceHigh,
		DecisionHint: decision,
		Message: "The head revision adds " + strconv.Itoa(len(added)) + " direct dependencies (" +
			strings.Join(names, ", ") + ") with a transitive change of " + strconv.Itoa(transitiveDelta) + " locked packages.",
		Locations: locations,
		Evidence: []finding.Evidence{{
			Kind:    "dependency_delta",
			Source:  "manifest and lock comparison",
			Excerpt: "direct +" + strconv.Itoa(len(added)) + ", locked " + signed(transitiveDelta),
		}},
		Limitations: []string{
			"The transitive count is taken from the lockfiles present in this change set; a lock that was not changed contributes no delta.",
			"Graph size is a review-surface signal, not evidence that any particular dependency is unsafe.",
		},
	})
}

// anyResolutionMatches reports whether any resolution of a name carries the
// version the manifest pins. A lockfile may legitimately resolve one name at
// several versions, so a pin is satisfied if any instance matches.
func anyResolutionMatches(found []Resolved, pinned string) bool {
	for _, r := range found {
		if r.Version == "" || r.Version == pinned {
			return true
		}
	}
	return false
}

// resolvedVersions lists the versions a name resolved to, in a stable order, so
// the evidence names every instance rather than an arbitrary one.
func resolvedVersions(found []Resolved) string {
	seen := make(map[string]bool, len(found))
	versions := make([]string, 0, len(found))
	for _, r := range found {
		if r.Version == "" || seen[r.Version] {
			continue
		}
		seen[r.Version] = true
		versions = append(versions, r.Version)
	}
	sort.Strings(versions)
	return strings.Join(versions, ", ")
}

func signed(n int) string {
	if n >= 0 {
		return "+" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// ----------------------------------------------------------------------------
// PFR-DEP-006: suspicious name similarity
// ----------------------------------------------------------------------------

// ruleNameSimilarity reports a newly added dependency whose name closely
// resembles one the project already depends on.
//
// docs/analyzers.md fixes this rule at warn for version 1 because the heuristic
// is noisy. The decision hint is a constant here rather than a computed value,
// so no input can raise it, and a test asserts that property.
func ruleNameSimilarity(base, head Snapshot, b *budget) {
	baseDeclared := base.declaredNames()
	if len(baseDeclared) == 0 {
		return
	}

	// Typosquatting happens within one registry, so a candidate is only
	// compared against names from its own ecosystem. Collecting from the slice
	// rather than from map keys also keeps the comparison list free of the
	// namespacing prefix.
	existingByEcosystem := make(map[Ecosystem][]string, len(ecosystems))
	for _, d := range base.Declared {
		existingByEcosystem[d.Ecosystem] = append(existingByEcosystem[d.Ecosystem], d.Name)
	}
	for eco := range existingByEcosystem {
		sort.Strings(existingByEcosystem[eco])
	}

	for _, d := range head.Declared {
		if b.full() {
			b.exceeded = true
			return
		}
		if _, existed := baseDeclared[declaredKey(d)]; existed {
			continue
		}
		neighbour, similar := nearestNeighbour(d.Name, existingByEcosystem[d.Ecosystem])
		if !similar {
			continue
		}

		if !b.add(finding.Finding{
			RuleID:       "PFR-DEP-006",
			AnalyzerID:   ID,
			Severity:     finding.SeverityLow,
			Confidence:   finding.ConfidenceLow,
			DecisionHint: finding.DecisionWarn,
			Message: "New dependency " + safe(d.Name) + " closely resembles " + safe(neighbour) +
				", which this project already depends on.",
			Locations: []finding.Location{location(d.Path, d.Pos)},
			Evidence: []finding.Evidence{{
				Kind:    "name_similarity",
				Source:  d.Path + " " + d.Kind,
				Excerpt: d.Name + " ~ " + neighbour,
			}},
			Limitations: []string{
				"Name similarity is a noisy heuristic and cannot distinguish a typosquat from a legitimate companion package, so version 1 only warns and never blocks on it.",
				"A genuinely unrelated package with a similar name produces this same evidence.",
			},
		}) {
			return
		}
	}
}

// nearestNeighbour returns the most similar existing name, if any is close
// enough to be worth mentioning.
func nearestNeighbour(candidate string, existing []string) (string, bool) {
	// Very short names produce too many coincidental matches to be useful.
	if len(candidate) < 4 {
		return "", false
	}
	for _, name := range existing {
		if name == candidate || len(name) < 4 {
			continue
		}
		if editDistanceWithin(candidate, name, 1) {
			return name, true
		}
	}
	return "", false
}

// editDistanceWithin reports whether a and b are within max edits of each
// other, using a bounded check rather than a full distance matrix.
func editDistanceWithin(a, b string, max int) bool {
	if a == b {
		return true
	}
	if abs(len(a)-len(b)) > max {
		return false
	}

	// With max of one, the strings differ by a single substitution,
	// insertion, or deletion, each of which is checkable in one pass.
	switch {
	case len(a) == len(b):
		diffs := 0
		for i := 0; i < len(a); i++ {
			if a[i] != b[i] {
				diffs++
				if diffs > max {
					return false
				}
			}
		}
		return diffs > 0
	case len(a) < len(b):
		return isSubsequenceByOne(a, b)
	default:
		return isSubsequenceByOne(b, a)
	}
}

// isSubsequenceByOne reports whether short becomes long by inserting exactly
// one byte.
func isSubsequenceByOne(short, long string) bool {
	i, j, skipped := 0, 0, 0
	for i < len(short) && j < len(long) {
		if short[i] == long[j] {
			i++
			j++
			continue
		}
		skipped++
		if skipped > 1 {
			return false
		}
		j++
	}
	return true
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// location converts a parser position into a canonical finding location.
// finding.Finalize sorts and validates what comes back.
func location(path string, pos Position) finding.Location {
	line := pos.Line
	if line < 1 {
		line = 1
	}
	return finding.Location{Path: path, StartLine: line, EndLine: line}
}
