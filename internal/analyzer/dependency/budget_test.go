package dependency

import (
	"strconv"
	"testing"
)

// This is a white-box test: it measures the work candidate generation performs,
// which is not observable from the returned result. The independent re-review
// asked for the amount of work to be tested, not only the returned length,
// because a ceiling applied after generation still let every rule run over
// every declaration and pay for a Finalize on each result.

// hostileSnapshot builds a head revision with count mutable Git dependencies,
// each of which trips PFR-DEP-002.
func hostileSnapshot(count int) Snapshot {
	var head Snapshot
	head.markManifest(EcosystemNPM)
	for i := 0; i < count; i++ {
		name := "tool-" + strconv.Itoa(i)
		head.Declared = append(head.Declared, Declared{
			Ecosystem: EcosystemNPM,
			Name:      name,
			Spec:      "git+https://example.invalid/" + name + ".git#main",
			Kind:      "dependencies",
			Source:    SourceGit,
			Path:      "package.json",
			Pos:       Position{Line: i + 1},
		})
	}
	return head
}

func TestBudgetBoundsGenerationNotJustOutput(t *testing.T) {
	const (
		declarations = 20000
		limit        = 5
	)

	head := hostileSnapshot(declarations)
	b := newBudget(limit)
	evaluate(Snapshot{}, head, b)

	if len(b.items) > limit {
		t.Errorf("collected %d candidates, above the %d ceiling", len(b.items), limit)
	}
	if !b.exceeded {
		t.Error("the budget did not record that it was exceeded")
	}

	// The real assertion: generation stopped near the ceiling rather than
	// producing one candidate per declaration and discarding the surplus.
	// One refusal per rule is expected on top of the limit.
	maxGenerated := limit + len(ecosystems) + 8
	if b.generated > maxGenerated {
		t.Fatalf("generated %d candidates for a %d-finding ceiling over %d declarations; "+
			"work is bounded by the input, not by the budget",
			b.generated, limit, declarations)
	}
}

// TestBudgetDefaultsWhenUnset proves an unconfigured run is still bounded rather
// than unlimited.
func TestBudgetDefaultsWhenUnset(t *testing.T) {
	b := newBudget(0)
	if b.limit != defaultFindingCeiling {
		t.Fatalf("limit = %d, want the default ceiling %d", b.limit, defaultFindingCeiling)
	}
}

// TestBudgetStopsBetweenRules proves a rule is not entered at all once the
// ceiling is reached, so a later rule cannot restart the work.
func TestBudgetStopsBetweenRules(t *testing.T) {
	head := hostileSnapshot(100)
	b := newBudget(1)
	evaluate(Snapshot{}, head, b)

	if len(b.items) != 1 {
		t.Fatalf("collected %d candidates, want exactly the 1-finding ceiling", len(b.items))
	}
	if b.generated > 8 {
		t.Errorf("generated %d candidates after the ceiling was reached", b.generated)
	}
}

// TestRecordKeysSeparateWorkspacesAndInstances proves the identity helpers do
// not collapse records the re-review found were being merged.
func TestRecordKeysSeparateWorkspacesAndInstances(t *testing.T) {
	t.Run("same dependency in two workspace manifests", func(t *testing.T) {
		a := Declared{Ecosystem: EcosystemNPM, Name: "left-pad", Path: "packages/a/package.json"}
		b := Declared{Ecosystem: EcosystemNPM, Name: "left-pad", Path: "packages/b/package.json"}
		if declaredKey(a) == declaredKey(b) {
			t.Error("two workspace manifests collapsed to one declaration key")
		}
	})

	t.Run("same name resolved at two install paths", func(t *testing.T) {
		a := Resolved{Ecosystem: EcosystemNPM, Name: "left-pad", Instance: "node_modules/left-pad", Path: "package-lock.json"}
		b := Resolved{Ecosystem: EcosystemNPM, Name: "left-pad", Instance: "node_modules/x/node_modules/left-pad", Path: "package-lock.json"}
		if resolvedKey(a) == resolvedKey(b) {
			t.Error("two install instances collapsed to one resolution key")
		}
		if nameKey(a.Ecosystem, a.Name) != nameKey(b.Ecosystem, b.Name) {
			t.Error("the name index must still group both instances under one name")
		}
	})

	t.Run("same name in two ecosystems", func(t *testing.T) {
		a := Declared{Ecosystem: EcosystemNPM, Name: "requests", Path: "package.json"}
		b := Declared{Ecosystem: EcosystemPython, Name: "requests", Path: "pyproject.toml"}
		if declaredKey(a) == declaredKey(b) {
			t.Error("two ecosystems collapsed to one declaration key")
		}
	})
}

// TestDuplicateResolvedInstancesArePreserved proves a lockfile resolving one
// name at two versions keeps both, so a substitution in either is comparable.
func TestDuplicateResolvedInstancesArePreserved(t *testing.T) {
	head := Snapshot{Resolved: []Resolved{
		{Ecosystem: EcosystemNPM, Name: "left-pad", Instance: "node_modules/left-pad", Version: "1.3.0", Path: "package-lock.json"},
		{Ecosystem: EcosystemNPM, Name: "left-pad", Instance: "node_modules/x/node_modules/left-pad", Version: "2.0.0", Path: "package-lock.json"},
	}}

	if got := len(head.resolvedInstances()); got != 2 {
		t.Errorf("resolvedInstances kept %d of 2 instances", got)
	}
	found := head.resolutionsByName()[nameKey(EcosystemNPM, "left-pad")]
	if len(found) != 2 {
		t.Fatalf("resolutionsByName kept %d of 2 instances", len(found))
	}
	// A pin matching either instance is satisfied; one matching neither is not.
	if !anyResolutionMatches(found, "2.0.0") {
		t.Error("a pin matching the nested instance was reported unsatisfied")
	}
	if anyResolutionMatches(found, "9.9.9") {
		t.Error("a pin matching no instance was reported satisfied")
	}
}

// TestPathContainmentIsRelativeToTheManifest proves a relative specifier is
// resolved from the directory of the manifest that declares it.
//
// Judging `../lib` from the repository root instead marked a legitimate
// workspace sibling as escaping, and would have missed a genuine escape from a
// nested manifest. Independent re-review finding.
func TestPathContainmentIsRelativeToTheManifest(t *testing.T) {
	cases := []struct {
		name     string
		spec     string
		manifest string
		want     bool
	}{
		{"sibling from a nested manifest stays inside", "file:../b", "packages/a/package.json", false},
		{"two levels up from a nested manifest stays inside", "file:../../lib", "packages/a/package.json", false},
		{"three levels up from a nested manifest escapes", "file:../../../lib", "packages/a/package.json", true},
		{"parent from the root manifest escapes", "file:../lib", "package.json", true},
		{"child from the root manifest stays inside", "file:./packages/lib", "package.json", false},
		{"absolute always escapes", "file:/opt/lib", "packages/a/package.json", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathEscapesRepository(tc.spec, tc.manifest); got != tc.want {
				t.Errorf("pathEscapesRepository(%q, %q) = %v, want %v", tc.spec, tc.manifest, got, tc.want)
			}
		})
	}
}
