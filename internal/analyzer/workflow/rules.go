package workflow

import (
	"strconv"
	"strings"

	"github.com/codebyte-p/proofrail/internal/finding"
	parser "github.com/codebyte-p/proofrail/internal/parser/workflow"
)

// budget bounds candidate generation.
//
// Enforcing a ceiling only on the returned slice still let a hostile workflow
// drive every rule over every step and pay for a Finalize -- redaction plus a
// SHA-256 -- on each result before anything was discarded. The budget is
// therefore consulted while candidates are produced, so the work itself is
// bounded rather than only the output.
type budget struct {
	limit    int
	items    []finding.Finding
	exceeded bool
}

// defaultFindingCeiling applies when a caller supplies no limit. It mirrors the
// architecture ceiling so an unconfigured run is still bounded.
const defaultFindingCeiling = 5000

func newBudget(limit int) *budget {
	if limit <= 0 {
		limit = defaultFindingCeiling
	}
	return &budget{limit: limit}
}

// add offers one candidate and reports whether the caller may continue.
//
// exceeded is set only where a candidate is actually refused. A run that fills
// the ceiling exactly has dropped nothing and stays complete; calling it a
// budget failure would turn a whole clean result into exit code 2.
func (b *budget) add(f finding.Finding) bool {
	if len(b.items) >= b.limit {
		b.exceeded = true
		return false
	}
	b.items = append(b.items, f)
	return true
}

// evaluate runs every PFR-WF rule over one workflow document.
//
// Rules are independent by construction: each offers its own candidates and
// none of them reads or edits another's output. A workflow that is both a
// privileged untrusted checkout and a self-hosted job produces both findings,
// because suppressing one would understate the change.
//
// Every rule is offered the budget even once it is full, because refusing a
// candidate is what records that evidence was dropped. Skipping the remaining
// rules instead would either hide a real truncation or fail a run that lost
// nothing.
func evaluate(head, base parser.Document, b *budget) {
	rulePrivilegedUntrustedCheckout(head, b)
	ruleExcessiveTokenPermission(head, base, b)
	ruleMutableActionReference(head, b)
	ruleExpressionInjection(head, b)
	ruleSecretsToUntrustedExecution(head, b)
	ruleSelfHostedRunner(head, b)
}

// privilegedUntrustedTriggers run with the base repository's token and secrets
// while handling content proposed by someone without write access. They are the
// events that turn a checkout into a privilege boundary.
var privilegedUntrustedTriggers = map[string]bool{
	"pull_request_target": true,
	"workflow_run":        true,
}

// untrustedInputTriggers carry an attacker-influenced payload. `pull_request`
// is included because a fork can set titles, branch names, and body text even
// though the job itself is unprivileged.
var untrustedInputTriggers = map[string]bool{
	"pull_request_target":         true,
	"workflow_run":                true,
	"pull_request":                true,
	"issues":                      true,
	"issue_comment":               true,
	"pull_request_review":         true,
	"pull_request_review_comment": true,
	"discussion":                  true,
	"discussion_comment":          true,
	"fork":                        true,
	"watch":                       true,
}

// untrustedRefExpressions identify a checkout that resolves to code the pull
// request author controls rather than the reviewed base revision.
var untrustedRefExpressions = []string{
	"github.event.pull_request.head.",
	"github.event.pull_request.merge_commit_sha",
	"github.event.pull_request.number",
	"github.event.workflow_run.head_",
	"github.head_ref",
	"refs/pull/",
}

// untrustedExpressionProperties are the event fields an unprivileged actor can
// set. Interpolating one into a script splices attacker text into the command
// the runner executes.
var untrustedExpressionProperties = []string{
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo",
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.head_commit.message",
	"github.event.head_commit.author",
	"github.event.commits",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.head_ref",
}

// ----------------------------------------------------------------------------
// PFR-WF-001: privileged untrusted checkout
// ----------------------------------------------------------------------------

func rulePrivilegedUntrustedCheckout(doc parser.Document, b *budget) {
	trigger, ok := firstTrigger(doc, privilegedUntrustedTriggers)
	if !ok {
		return
	}

	for _, job := range doc.Jobs {
		checkout, ref, source, found := untrustedCheckout(job)
		if !found {
			continue
		}
		executing, executes := firstExecutingStepAfter(job, checkout)
		if !executes {
			continue
		}

		evidence := []finding.Evidence{
			triggerEvidence(doc, trigger),
			{
				Kind:    "workflow_privileged_checkout",
				Source:  source,
				Excerpt: ref.Value,
			},
			stepEvidence(job, executing),
		}

		if !b.add(finding.Finding{
			RuleID:       "PFR-WF-001",
			AnalyzerID:   ID,
			Severity:     finding.SeverityHigh,
			Confidence:   finding.ConfidenceHigh,
			DecisionHint: finding.DecisionBlock,
			Message: "Job " + safe(job.ID.Value) + " runs on the privileged " + safe(trigger.Name.Value) +
				" trigger, checks out pull-request-controlled code, and then executes it with the base repository's token.",
			Locations: locations(doc.Path,
				trigger.Name.Pos, ref.Pos, stepAnchor(executing)),
			Evidence:    evidence,
			Limitations: checkoutLimitations(checkout),
		}) {
			return
		}
	}
}

// checkoutLimitations states what this finding did not establish. A checkout
// recognized from shell text carries one more caveat than an `actions/checkout`
// input, and saying so is the difference between honest evidence and a claim.
func checkoutLimitations(checkout parser.Step) []string {
	out := []string{
		"Compensating organization or repository Actions policy is not visible in offline analysis.",
		"A required approval or environment protection rule on this job cannot be read from the repository.",
	}
	if !checkout.Uses.Present() {
		out = append(out,
			"The checkout was recognized from the text of a `run:` script, which version 1 matches lexically rather than executing, so a script that reaches the same ref indirectly is not covered and a script that only names a pull-request ref is still reported.")
	}
	return out
}

// untrustedCheckout finds the step that lands pull-request-controlled code on
// the runner, returning the step, the deciding scalar, and the pointer that
// names it.
//
// `actions/checkout` is not the only way in. The canonical pwn request fetches
// `refs/pull/*/head` with raw Git and checks it out by hand, which an
// Action-only search could not see at all, so a `run:` script that names a
// pull-request ref counts as the same checkout.
func untrustedCheckout(job parser.Job) (parser.Step, parser.Scalar, string, bool) {
	for _, step := range job.Steps {
		if isCheckoutAction(step.Uses.Value) {
			for _, key := range []string{"ref", "repository"} {
				value := step.With.Get(key)
				if value.Present() && referencesUntrustedRef(value.Value) {
					return step, value, pointer("jobs", job.ID.Value, "checkout ref"), true
				}
			}
			continue
		}
		if step.Run.Present() && gitCheckoutOfPullRequest(step.Run.Value) {
			return step, step.Run, pointer("jobs", job.ID.Value, "checkout script"), true
		}
	}
	return parser.Step{}, parser.Scalar{}, "", false
}

// gitCheckoutOfPullRequest reports whether a `run:` script brings a pull
// request's own commits onto the runner with raw Git.
//
// The test is deliberately narrow: a Git fetch or checkout verb has to appear
// together with a ref that only a pull request supplies. An ordinary
// `git fetch origin main` in a privileged workflow therefore stays silent,
// which is what keeps this from flooding every release pipeline.
func gitCheckoutOfPullRequest(script string) bool {
	s := normalizeExpression(script)
	if !strings.Contains(s, "git ") {
		return false
	}
	if !strings.Contains(s, "fetch") && !strings.Contains(s, "checkout") {
		return false
	}
	return namesPullRequestRef(s)
}

// namesPullRequestRef reports whether normalized script text names a ref the
// pull request author controls, either as a literal `refs/pull/<n>/head` and
// its shorthand or through an untrusted expression the fetch resolves.
func namesPullRequestRef(s string) bool {
	for _, marker := range untrustedRefExpressions {
		if strings.Contains(s, marker) {
			return true
		}
	}
	if i := strings.Index(s, "pull/"); i >= 0 && strings.Contains(s[i:], "/head") {
		return true
	}
	// A fetch of the pull-request number resolves to fork-controlled code just
	// as `head.sha` does, and the shorthand scripts use it directly.
	return strings.Contains(s, "github.event.number")
}

func isCheckoutAction(uses string) bool {
	name, _, ok := splitActionRef(uses)
	// GitHub resolves `uses:` case-insensitively, so `Actions/Checkout` runs
	// the same Action. An exact comparison let a mixed-case spelling bypass
	// PFR-WF-001 and PFR-WF-005 entirely.
	return ok && strings.EqualFold(name, "actions/checkout")
}

func referencesUntrustedRef(value string) bool {
	normalized := normalizeExpression(value)
	for _, marker := range untrustedRefExpressions {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

// normalizeExpression rewrites text into the single spelling the rule tables are
// written in: lowercase, dotted property access.
//
// GitHub resolves context and property names case-insensitively and treats
// `github['event']` as `github.event`, so comparing against literal lowercase
// dotted paths missed both spellings and a workflow written either way produced
// no finding at all. Normalizing the input is what makes the tables complete;
// listing every spelling in them never could be.
func normalizeExpression(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '[' {
			if name, next, ok := indexedProperty(s, i); ok {
				b.WriteByte('.')
				b.WriteString(name)
				i = next - 1
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return strings.ToLower(b.String())
}

// indexedProperty reads a `['name']` or `["name"]` index starting at the
// bracket and returns the property name with the offset just past the closing
// bracket.
//
// Any other index form -- a variable, a number, a nested expression -- is left
// exactly as written, because rewriting it would invent a property nobody put
// in the document.
func indexedProperty(s string, i int) (string, int, bool) {
	j := skipSpaces(s, i+1)
	if j >= len(s) || (s[j] != '\'' && s[j] != '"') {
		return "", 0, false
	}
	quote := s[j]
	j++
	start := j
	for j < len(s) && s[j] != quote {
		j++
	}
	if j >= len(s) {
		return "", 0, false
	}
	name := s[start:j]
	j = skipSpaces(s, j+1)
	if j >= len(s) || s[j] != ']' {
		return "", 0, false
	}
	return name, j + 1, true
}

func skipSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// firstExecutingStepAfter returns the first step after the checkout that runs a
// command or a non-checkout Action.
//
// Version 1 treats any `uses:` other than a checkout as executing. A setup-only
// Action may therefore be counted conservatively, which is recorded as a
// limitation rather than resolved by guessing.
func firstExecutingStepAfter(job parser.Job, checkout parser.Step) (parser.Step, bool) {
	seen := false
	for _, step := range job.Steps {
		if step.Pos == checkout.Pos {
			seen = true
			continue
		}
		if !seen {
			continue
		}
		if step.Run.Present() {
			return step, true
		}
		if step.Uses.Present() && !isCheckoutAction(step.Uses.Value) {
			return step, true
		}
	}
	return parser.Step{}, false
}

// ----------------------------------------------------------------------------
// PFR-WF-002: excessive token permission
// ----------------------------------------------------------------------------

// grant is one write capability the workflow token gains: the scope that names
// the capability, where it was written, and the line that granted it.
//
// scope is the comparison key and where is only evidence, because the token's
// capability is the same whether a scope is granted at workflow level or inside
// one job.
type grant struct {
	scope string
	where string
	pos   parser.Position
}

func ruleExcessiveTokenPermission(head, base parser.Document, b *budget) {
	introduced := newWriteGrants(head, base)
	if len(introduced) == 0 {
		return
	}

	// An untrusted trigger turns a widened token into an immediately reachable
	// privilege, so the hint hardens from review to block.
	decision := finding.DecisionRequireReview
	trigger, untrusted := firstTrigger(head, untrustedInputTriggers)
	if untrusted {
		decision = finding.DecisionBlock
	}

	evidence := make([]finding.Evidence, 0, len(introduced)+1)
	positions := make([]parser.Position, 0, len(introduced)+1)
	scopes := make([]string, 0, len(introduced))
	for _, g := range introduced {
		evidence = append(evidence, finding.Evidence{
			Kind:    "workflow_permission",
			Source:  "permissions",
			Excerpt: g.where + ": " + g.scope,
		})
		positions = append(positions, g.pos)
		scopes = append(scopes, safe(g.scope))
	}
	if untrusted {
		evidence = append(evidence, triggerEvidence(head, trigger))
		positions = append(positions, trigger.Name.Pos)
	}

	b.add(finding.Finding{
		RuleID:       "PFR-WF-002",
		AnalyzerID:   ID,
		Severity:     finding.SeverityHigh,
		Confidence:   finding.ConfidenceMedium,
		DecisionHint: decision,
		Message: "The head revision newly grants the workflow token write access to " +
			strings.Join(scopes, ", ") + ".",
		Locations: locations(head.Path, positions...),
		Evidence:  evidence,
		Limitations: []string{
			"A write scope can be legitimately required by a release or publishing job, so version 1 routes the expansion to review rather than asserting misuse.",
			"The repository default workflow permission is a GitHub setting that offline analysis cannot read.",
		},
	})
}

// newWriteGrants returns the write capabilities the head revision gains,
// comparing capability rather than placement.
//
// Keying a grant by the block that declared it made moving a workflow-wide
// `contents: write` down into the one job that needs it -- the recommended
// hardening -- look like a brand new grant, and a job rename did the same. Both
// then hardened to block on an untrusted trigger, which punished the fix. The
// scope name alone decides; where it was written survives as evidence.
func newWriteGrants(head, base parser.Document) []grant {
	before := writeGrants(base)
	seen := make(map[string]bool)
	var introduced []grant
	for _, g := range collectWriteGrants(head) {
		if before[g.scope] || seen[g.scope] {
			continue
		}
		seen[g.scope] = true
		introduced = append(introduced, g)
	}
	return introduced
}

// writeGrants collects every write capability a document declares, keyed so the
// head and base sides compare exactly.
func writeGrants(doc parser.Document) map[string]bool {
	out := make(map[string]bool)
	for _, g := range collectWriteGrants(doc) {
		out[g.scope] = true
	}
	return out
}

func collectWriteGrants(doc parser.Document) []grant {
	var out []grant
	out = append(out, permissionGrants("workflow", doc.Permissions)...)
	for _, job := range doc.Jobs {
		out = append(out, permissionGrants("job "+job.ID.Value, job.Permissions)...)
	}
	return out
}

// permissionGrants reads one permissions block. A `write-all` mode grants every
// scope at once; a scoped mapping grants only the scopes set to write.
func permissionGrants(scopeName string, perm parser.Permissions) []grant {
	if !perm.Present {
		return nil
	}
	var out []grant
	if perm.Mode.Present() {
		if strings.EqualFold(perm.Mode.Value, "write-all") {
			out = append(out, grant{scope: "all scopes", where: scopeName, pos: perm.Mode.Pos})
		}
		return out
	}
	for _, entry := range perm.Scopes {
		if strings.EqualFold(entry.Value.Value, "write") {
			out = append(out, grant{scope: entry.Key.Value, where: scopeName, pos: entry.Value.Pos})
		}
	}
	return out
}

// ----------------------------------------------------------------------------
// PFR-WF-003: mutable third-party Action
// ----------------------------------------------------------------------------

func ruleMutableActionReference(doc parser.Document, b *budget) {
	for _, job := range doc.Jobs {
		if job.Uses.Present() {
			if f, ok := mutableReferenceFinding(doc, job.Uses, "jobs."+safe(job.ID.Value)+".uses"); ok {
				if !b.add(f) {
					return
				}
			}
		}
		for i, step := range job.Steps {
			if !step.Uses.Present() {
				continue
			}
			source := "jobs." + safe(job.ID.Value) + ".steps[" + strconv.Itoa(i) + "].uses"
			if f, ok := mutableReferenceFinding(doc, step.Uses, source); ok {
				if !b.add(f) {
					return
				}
			}
		}
	}
}

func mutableReferenceFinding(doc parser.Document, uses parser.Scalar, source string) (finding.Finding, bool) {
	name, ref, ok := splitActionRef(uses.Value)
	if !ok || isCommitSHA(ref) {
		return finding.Finding{}, false
	}

	detail := "is pinned to the mutable reference " + safe(ref)
	if ref == "" {
		detail = "is used without any version reference"
	}

	return finding.Finding{
		RuleID:       "PFR-WF-003",
		AnalyzerID:   ID,
		Severity:     finding.SeverityMedium,
		Confidence:   finding.ConfidenceHigh,
		DecisionHint: finding.DecisionRequireReview,
		Message: "Action " + safe(name) + " " + detail +
			", so the code it runs can change without any change to this repository.",
		Locations: locations(doc.Path, uses.Pos),
		Evidence: []finding.Evidence{{
			Kind:    "workflow_action_reference",
			Source:  source,
			Excerpt: uses.Value,
		}},
		Limitations: []string{
			"Pinning to a full commit SHA can conflict with a local update convention, but a mutable reference remains a real supply-chain risk.",
			"Whether the owning account is trusted is an organization policy question offline analysis cannot answer.",
		},
	}, true
}

// splitActionRef separates `owner/repo@ref` into its parts.
//
// Local actions (`./path`) and container actions (`docker://`) are excluded:
// a local action lives in the revision under review, and a container reference
// is governed by registry digest rules rather than by Git refs.
func splitActionRef(uses string) (name, ref string, ok bool) {
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		return "", "", false
	}
	if strings.HasPrefix(uses, "docker://") {
		return "", "", false
	}
	name, ref, found := strings.Cut(uses, "@")
	if !found {
		return uses, "", true
	}
	return name, ref, true
}

// isCommitSHA reports whether ref is a full 40-character lowercase hash, the
// only immutable way to name an Action revision.
func isCommitSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

// ----------------------------------------------------------------------------
// PFR-WF-004: expression injection into shell
// ----------------------------------------------------------------------------

func ruleExpressionInjection(doc parser.Document, b *budget) {

	trigger, untrusted := firstTrigger(doc, untrustedInputTriggers)

	for _, job := range doc.Jobs {
		for i, step := range job.Steps {
			if !step.Run.Present() {
				continue
			}
			properties := untrustedExpressionsIn(step.Run.Value)
			if len(properties) == 0 {
				continue
			}

			// Reachability from an untrusted event is what separates a proven
			// injection from one that needs a human to confirm the path.
			decision := finding.DecisionRequireReview
			confidence := finding.ConfidenceMedium
			limitations := []string{
				"No untrusted trigger was found in this file, so reachability from an attacker-controlled event could not be proven and the expression is reported for review rather than blocked.",
			}
			positions := []parser.Position{step.Run.Pos}
			evidence := []finding.Evidence{{
				Kind:    "workflow_expression_sink",
				Source:  "jobs." + safe(job.ID.Value) + ".steps[" + strconv.Itoa(i) + "].run",
				Excerpt: step.Run.Value,
			}}

			if untrusted {
				decision = finding.DecisionBlock
				confidence = finding.ConfidenceHigh
				limitations = []string{
					"A step-level condition that version 1 does not evaluate could restrict when this expression is reached.",
					"Novel expression sinks outside the version 1 taint rules are not covered.",
				}
				positions = append(positions, trigger.Name.Pos)
				evidence = append(evidence, triggerEvidence(doc, trigger))
			}

			if !b.add(finding.Finding{
				RuleID:       "PFR-WF-004",
				AnalyzerID:   ID,
				Severity:     finding.SeverityHigh,
				Confidence:   confidence,
				DecisionHint: decision,
				Message: "Step " + strconv.Itoa(i) + " of job " + safe(job.ID.Value) +
					" interpolates the attacker-controlled expression " + safe(properties[0]) +
					" directly into a shell script, so the value is spliced into the command the runner executes.",
				Locations:   locations(doc.Path, positions...),
				Evidence:    evidence,
				Limitations: limitations,
			}) {
				return
			}
		}
	}
}

// untrustedExpressionsIn returns the attacker-controlled properties referenced
// by `${{ }}` expressions in script, in the order they appear.
func untrustedExpressionsIn(script string) []string {
	var found []string
	for _, expr := range expressions(script) {
		normalized := normalizeExpression(expr)
		for _, property := range untrustedExpressionProperties {
			if strings.Contains(normalized, property) {
				found = append(found, property)
				break
			}
		}
	}
	return found
}

// expressions extracts the bodies of `${{ ... }}` templates without evaluating
// them. This is lexical scanning, not interpretation.
func expressions(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		start := strings.Index(s[i:], "${{")
		if start < 0 {
			break
		}
		start += i + len("${{")
		end := strings.Index(s[start:], "}}")
		if end < 0 {
			break
		}
		out = append(out, strings.TrimSpace(s[start:start+end]))
		i = start + end + len("}}")
	}
	return out
}

// ----------------------------------------------------------------------------
// PFR-WF-005: secrets exposed to untrusted execution
// ----------------------------------------------------------------------------

func ruleSecretsToUntrustedExecution(doc parser.Document, b *budget) {
	trigger, ok := firstTrigger(doc, privilegedUntrustedTriggers)
	if !ok {
		return
	}

	for _, job := range doc.Jobs {
		checkout, ref, checkoutSource, hasUntrustedCode := untrustedCheckout(job)
		if !hasUntrustedCode {
			continue
		}
		if _, executes := firstExecutingStepAfter(job, checkout); !executes {
			continue
		}
		secret, source, hasSecret := jobSecretReference(job)
		if !hasSecret {
			continue
		}

		if !b.add(finding.Finding{
			RuleID:       "PFR-WF-005",
			AnalyzerID:   ID,
			Severity:     finding.SeverityHigh,
			Confidence:   finding.ConfidenceHigh,
			DecisionHint: finding.DecisionBlock,
			Message: "Job " + safe(job.ID.Value) + " exposes a repository secret to code checked out from the pull request under the privileged " +
				safe(trigger.Name.Value) + " trigger, so fork-controlled code runs with access to that secret.",
			Locations: locations(doc.Path, trigger.Name.Pos, ref.Pos, secret.Pos),
			Evidence: []finding.Evidence{
				triggerEvidence(doc, trigger),
				{
					Kind:    "workflow_secret_reference",
					Source:  source,
					Excerpt: secret.Value,
				},
				{
					Kind:    "workflow_privileged_checkout",
					Source:  checkoutSource,
					Excerpt: ref.Value,
				},
			},
			Limitations: []string{
				"Whether the named secret is populated in this repository is a GitHub setting offline analysis cannot read.",
				"An environment protection rule requiring approval before the secret is issued cannot be observed from the repository contents.",
			},
		}) {
			return
		}
	}
}

// jobSecretReference finds the first secret this job hands to its steps, and
// the document pointer that names it.
func jobSecretReference(job parser.Job) (parser.Scalar, string, bool) {
	if job.SecretsInherit {
		return job.ID, "jobs." + safe(job.ID.Value) + ".secrets", true
	}
	for _, entry := range job.Secrets {
		return entry.Value, "jobs." + safe(job.ID.Value) + ".secrets." + safe(entry.Key.Value), true
	}
	for _, entry := range job.Env {
		if referencesSecret(entry.Value.Value) {
			return entry.Value, "jobs." + safe(job.ID.Value) + ".env." + safe(entry.Key.Value), true
		}
	}
	for i, step := range job.Steps {
		prefix := "jobs." + safe(job.ID.Value) + ".steps[" + strconv.Itoa(i) + "]"
		for _, entry := range step.Env {
			if referencesSecret(entry.Value.Value) {
				return entry.Value, prefix + ".env." + safe(entry.Key.Value), true
			}
		}
		for _, entry := range step.With {
			if referencesSecret(entry.Value.Value) {
				return entry.Value, prefix + ".with." + safe(entry.Key.Value), true
			}
		}
		if step.Run.Present() && referencesSecret(step.Run.Value) {
			return step.Run, prefix + ".run", true
		}
	}
	return parser.Scalar{}, "", false
}

func referencesSecret(value string) bool {
	for _, expr := range expressions(value) {
		if strings.Contains(normalizeExpression(expr), "secrets.") {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// PFR-WF-006: persistence on a self-hosted runner
// ----------------------------------------------------------------------------

func ruleSelfHostedRunner(doc parser.Document, b *budget) {
	trigger, ok := firstTrigger(doc, untrustedInputTriggers)
	if !ok {
		return
	}

	for _, job := range doc.Jobs {
		label, isSelfHosted := selfHostedLabel(job)
		if !isSelfHosted {
			continue
		}

		if !b.add(finding.Finding{
			RuleID:       "PFR-WF-006",
			AnalyzerID:   ID,
			Severity:     finding.SeverityHigh,
			Confidence:   finding.ConfidenceMedium,
			DecisionHint: finding.DecisionRequireReview,
			Message: "Job " + safe(job.ID.Value) + " runs on a self-hosted runner in response to the " +
				safe(trigger.Name.Value) + " trigger, so work influenced by a pull request touches a machine that persists between jobs.",
			Locations: locations(doc.Path, trigger.Name.Pos, label.Pos),
			Evidence: []finding.Evidence{
				triggerEvidence(doc, trigger),
				{
					Kind:    "workflow_runner_label",
					Source:  "jobs." + safe(job.ID.Value) + ".runs-on",
					Excerpt: label.Value,
				},
			},
			Limitations: []string{
				"An approved ephemeral-runner policy, which would make this safe, is an organization setting offline analysis cannot read.",
				"Runner group membership and its access restrictions are not visible from the repository contents.",
			},
		}) {
			return
		}
	}
}

func selfHostedLabel(job parser.Job) (parser.Scalar, bool) {
	for _, label := range job.RunsOn {
		if strings.EqualFold(label.Value, "self-hosted") {
			return label, true
		}
	}
	return parser.Scalar{}, false
}

// ----------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------

// firstTrigger returns the first declared trigger belonging to set, in document
// order, so the same file always reports the same trigger.
func firstTrigger(doc parser.Document, set map[string]bool) (parser.Trigger, bool) {
	for _, t := range doc.Triggers {
		if set[t.Name.Value] {
			return t, true
		}
	}
	return parser.Trigger{}, false
}

func triggerEvidence(doc parser.Document, t parser.Trigger) finding.Evidence {
	return finding.Evidence{
		Kind:    "workflow_trigger",
		Source:  "on." + safe(t.Name.Value),
		Excerpt: t.Name.Value,
	}
}

func stepEvidence(job parser.Job, step parser.Step) finding.Evidence {
	excerpt := step.Run.Value
	if !step.Run.Present() {
		excerpt = step.Uses.Value
	}
	return finding.Evidence{
		Kind:    "workflow_step_command",
		Source:  pointer("jobs", job.ID.Value, "executing step"),
		Excerpt: excerpt,
	}
}

// stepAnchor is the line a finding points at for a step: the command itself
// when there is one, otherwise the Action reference, otherwise the step.
func stepAnchor(step parser.Step) parser.Position {
	switch {
	case step.Run.Present():
		return step.Run.Pos
	case step.Uses.Present():
		return step.Uses.Pos
	default:
		return step.Pos
	}
}

// locations converts source positions into canonical finding locations,
// dropping any that the parser never filled in. finding.Finalize sorts and
// deduplicates what comes back.
func locations(path string, positions ...parser.Position) []finding.Location {
	out := make([]finding.Location, 0, len(positions))
	seen := make(map[int]bool, len(positions))
	for _, pos := range positions {
		if pos.Line < 1 || seen[pos.Line] {
			continue
		}
		seen[pos.Line] = true
		out = append(out, finding.Location{Path: path, StartLine: pos.Line, EndLine: pos.Line})
	}
	return out
}

func pointer(parts ...string) string {
	safeParts := make([]string, 0, len(parts))
	for _, p := range parts {
		safeParts = append(safeParts, safe(p))
	}
	return strings.Join(safeParts, ".")
}

// safe bounds a repository-supplied string and strips everything that is not
// printable ASCII, so a job id or an Action name cannot carry a control
// sequence into a message, a console line, or a report.
func safe(s string) string {
	const max = 64
	if len(s) > max {
		s = s[:max]
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			b = append(b, '?')
			continue
		}
		b = append(b, c)
	}
	return string(b)
}
