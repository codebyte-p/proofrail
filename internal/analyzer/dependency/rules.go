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

// evaluate runs every PFR-DEP rule over the base/head comparison.
//
// Rules are independent by construction: each appends its own candidates and
// none reads or edits another's output, so a change that trips several rules
// reports all of them.
func evaluate(base, head Snapshot) []finding.Finding {
	var out []finding.Finding
	out = append(out, ruleManifestLockMismatch(base, head)...)
	out = append(out, ruleNonRegistryDependency(base, head)...)
	out = append(out, ruleLifecycleExecution(base, head)...)
	out = append(out, ruleResolvedSourceChanged(base, head)...)
	out = append(out, ruleGraphExpansion(base, head)...)
	out = append(out, ruleNameSimilarity(base, head)...)
	return out
}

// ----------------------------------------------------------------------------
// PFR-DEP-001: manifest-lock mismatch
// ----------------------------------------------------------------------------

func ruleManifestLockMismatch(base, head Snapshot) []finding.Finding {
	// With no lock in the change set there is nothing to be out of step with,
	// and reporting every declaration as unresolved would be noise.
	if len(head.Resolved) == 0 {
		return nil
	}

	resolved := head.resolvedByName()
	baseDeclared := base.declaredNames()

	var unresolved []Declared
	for _, d := range head.Declared {
		if _, ok := resolved[d.Name]; ok {
			continue
		}
		// A workspace or local path dependency is resolved by layout rather
		// than by the lock, so its absence is not a mismatch.
		if d.Source == SourcePath || d.Source == SourceWorkspace {
			continue
		}
		// Only report what this change introduced; a pre-existing mismatch is
		// not something this pull request did.
		if _, existed := baseDeclared[d.Name]; existed {
			continue
		}
		unresolved = append(unresolved, d)
	}
	if len(unresolved) == 0 {
		return nil
	}

	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i].Name < unresolved[j].Name })

	names := make([]string, 0, len(unresolved))
	evidence := make([]finding.Evidence, 0, len(unresolved))
	locations := make([]finding.Location, 0, len(unresolved))
	for _, d := range unresolved {
		names = append(names, safe(d.Name))
		evidence = append(evidence, finding.Evidence{
			Kind:    "dependency_declaration",
			Source:  d.Path + " " + d.Kind,
			Excerpt: d.Name + " " + d.Spec,
		})
		locations = append(locations, location(d.Path, d.Pos))
	}

	return []finding.Finding{{
		RuleID:       "PFR-DEP-001",
		AnalyzerID:   ID,
		Severity:     finding.SeverityHigh,
		Confidence:   finding.ConfidenceHigh,
		DecisionHint: finding.DecisionBlock,
		Message: "The manifest declares " + strings.Join(names, ", ") +
			" with no matching resolution in the lockfile, so the build is not reproducibly bound to a specific artifact.",
		Locations: locations,
		Evidence:  evidence,
		Limitations: []string{
			"A lockfile regenerated outside this change set would resolve the mismatch without any edit appearing here.",
			"Workspace and local path dependencies are resolved by repository layout rather than by the lockfile and are excluded.",
		},
	}}
}

// ----------------------------------------------------------------------------
// PFR-DEP-002: non-registry dependency
// ----------------------------------------------------------------------------

func ruleNonRegistryDependency(base, head Snapshot) []finding.Finding {
	baseDeclared := base.declaredNames()

	var out []finding.Finding
	for _, d := range head.Declared {
		if d.Source == SourceRegistry && d.Immutable {
			continue
		}
		if d.Source == SourceRegistry {
			// A range against a registry is ordinary practice and is covered by
			// lock resolution rather than by this rule.
			continue
		}
		if previous, existed := baseDeclared[d.Name]; existed && previous.Spec == d.Spec {
			continue
		}

		// Outside the repository or mutable means the bytes a build fetches can
		// change without any change here; that is the blocking condition.
		outsideRepository := d.Source == SourceGit || d.Source == SourceURL
		decision := finding.DecisionRequireReview
		severity := finding.SeverityMedium
		if !d.Immutable && outsideRepository {
			decision = finding.DecisionBlock
			severity = finding.SeverityHigh
		}

		out = append(out, finding.Finding{
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
		})
	}
	return out
}

// ----------------------------------------------------------------------------
// PFR-DEP-003: lifecycle execution introduced
// ----------------------------------------------------------------------------

func ruleLifecycleExecution(base, head Snapshot) []finding.Finding {
	previous := base.scriptsByName()

	var out []finding.Finding
	for _, script := range head.Scripts {
		if !isLifecycleScript(script.Name) && !strings.Contains(script.Name, "install script") &&
			script.Name != "build-backend" {
			continue
		}
		before, existed := previous[script.Name]
		if existed && before.Body == script.Body {
			continue
		}

		verb := "introduces"
		if existed {
			verb = "changes"
		}

		out = append(out, finding.Finding{
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
		})
	}
	return out
}

// ----------------------------------------------------------------------------
// PFR-DEP-004: resolved source changed unexpectedly
// ----------------------------------------------------------------------------

func ruleResolvedSourceChanged(base, head Snapshot) []finding.Finding {
	previous := base.resolvedByName()

	var out []finding.Finding
	for _, current := range head.Resolved {
		before, existed := previous[current.Name]
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

		out = append(out, finding.Finding{
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
		})
	}
	return out
}

// ----------------------------------------------------------------------------
// PFR-DEP-005: dependency graph expansion
// ----------------------------------------------------------------------------

func ruleGraphExpansion(base, head Snapshot) []finding.Finding {
	baseDeclared := base.declaredNames()

	var added []Declared
	for _, d := range head.Declared {
		if _, existed := baseDeclared[d.Name]; !existed {
			added = append(added, d)
		}
	}
	if len(added) == 0 {
		return nil
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

	return []finding.Finding{{
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
	}}
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
func ruleNameSimilarity(base, head Snapshot) []finding.Finding {
	baseDeclared := base.declaredNames()
	if len(baseDeclared) == 0 {
		return nil
	}

	existing := make([]string, 0, len(baseDeclared))
	for name := range baseDeclared {
		existing = append(existing, name)
	}
	sort.Strings(existing)

	var out []finding.Finding
	for _, d := range head.Declared {
		if _, existed := baseDeclared[d.Name]; existed {
			continue
		}
		neighbour, similar := nearestNeighbour(d.Name, existing)
		if !similar {
			continue
		}

		out = append(out, finding.Finding{
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
		})
	}
	return out
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
