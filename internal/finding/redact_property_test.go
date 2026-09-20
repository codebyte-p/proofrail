package finding

import (
	"strings"
	"testing"
)

// Redaction is judged here by a property, not by a list of examples.
//
// The under-redaction that shipped -- an innocuous first key swallowing the rest
// of its line, so the `password:` in `status: ok password: <secret>` was never
// even looked at -- was not a case anybody had thought to write down, and adding
// more examples does not make the next unthought-of case more likely to be
// written down. The invariant below is asserted over the cross product of
// credential shape and surrounding context instead: whatever wraps a credential,
// the credential itself never reaches the output.

// credentialShape is one credential and the substring of it that a leak would
// consist of. secret is empty when the whole value is the secret.
type credentialShape struct {
	name   string
	key    string
	value  string
	secret string
}

func (c credentialShape) leaked() string {
	if c.secret != "" {
		return c.secret
	}
	return c.value
}

const pemBody = "MIIEowIBAAKCAQEAxAbC0123456789deadbeefKEYMATERIALzz"

var credentialShapes = []credentialShape{
	{name: "github classic token", key: "token", value: "ghp_0123456789abcdefghijklmnopqrstuvwxyzA"},
	{name: "github fine-grained token", key: "GITHUB_PAT", value: "github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	{name: "aws access key id", key: "aws_access_key_id", value: "AKIAIOSFODNN7EXAMPLE"},
	{name: "compact jwt", key: "authorization", value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	{
		name:   "pem private key body",
		key:    "private_key",
		value:  "-----BEGIN RSA PRIVATE KEY-----\n" + pemBody + "\n-----END RSA PRIVATE KEY-----",
		secret: pemBody,
	},
	// An opaque value has no shape at all. The key it is assigned to is the only
	// signal there is, which is why every secret-bearing key name gets its own
	// row rather than one representative.
	{name: "opaque password", key: "password", value: "hunter2Opaque0paqueV4lue"},
	{name: "opaque api key", key: "api_key", value: "hunter2Opaque0paqueV4lue"},
	{name: "opaque token", key: "token", value: "hunter2Opaque0paqueV4lue"},
	{name: "opaque secret", key: "client_secret", value: "hunter2Opaque0paqueV4lue"},
	{name: "opaque authorization", key: "Authorization", value: "hunter2Opaque0paqueV4lue"},
	{name: "opaque credential", key: "credential", value: "hunter2Opaque0paqueV4lue"},
}

// redactionContexts are the surroundings a credential turns up in. Each one is
// a place a scanner can lose track of where a value begins or ends, which is
// what every confirmed leak in this package has had in common.
var redactionContexts = []struct {
	name string
	wrap func(key, value string) string
}{
	{"bare", func(k, v string) string { return k + ": " + v }},
	{"equals", func(k, v string) string { return k + "=" + v }},
	{"double quoted", func(k, v string) string { return k + ": \"" + v + "\"" }},
	{"single quoted", func(k, v string) string { return k + ": '" + v + "'" }},
	{"quoted with a comma inside", func(k, v string) string { return k + ": \"" + v + ", and more of it\"" }},
	{"url userinfo", func(k, v string) string { return "Fetching from https://user:" + v + "@example.com/repo.git" }},
	{"after one innocuous pair", func(k, v string) string { return "status: ok " + k + ": " + v }},
	{"after several innocuous pairs", func(k, v string) string { return "level=info component=cli attempt=3 " + k + "=" + v }},
	{"json fragment", func(k, v string) string { return "{\"user\": \"alice\", \"" + k + "\": \"" + v + "\"}" }},
	{"yaml fragment", func(k, v string) string { return "env:\n  FOO: bar\n  " + k + ": " + v }},
	{"comma separated", func(k, v string) string { return "user=alice, " + k + "=" + v + ", region=eu" }},
	{"semicolon separated", func(k, v string) string { return "host: example.com; " + k + ": " + v }},
	{"space separated", func(k, v string) string { return "user=alice " + k + "=" + v + " region=eu" }},
	{"repeated twice on one line", func(k, v string) string { return k + ": " + v + " " + k + ": " + v }},
	{"beside an existing marker", func(k, v string) string { return "[REDACTED:jwt] " + k + ": " + v }},
	{"beside an unterminated marker", func(k, v string) string { return "[REDACTED: " + k + ": " + v }},
}

func TestRedactNeverLeaksACredentialInAnyContext(t *testing.T) {
	for _, shape := range credentialShapes {
		for _, ctx := range redactionContexts {
			t.Run(shape.name+"/"+ctx.name, func(t *testing.T) {
				in := ctx.wrap(shape.key, shape.value)
				got := Redact(in)
				if strings.Contains(got, shape.leaked()) {
					t.Fatalf("credential survived redaction\n  in: %q\n out: %q", in, got)
				}
				if again := Redact(got); again != got {
					t.Fatalf("Redact is not idempotent\n once: %q\ntwice: %q", got, again)
				}
			})
		}
	}
}

func FuzzRedactNeverLeaksACredentialInContext(f *testing.F) {
	f.Add(0, 0, "", "")
	f.Add(5, 6, "prefix ", " suffix")
	f.Add(5, 0, "a: \"", "\"")
	f.Add(2, 9, "[REDACTED: ", "\n")
	f.Add(3, 5, "https://", "@host")
	f.Add(4, 13, "\x1b[2J", "\x00")
	f.Add(7, 11, strings.Repeat("x", 600), strings.Repeat("y", 600))

	f.Fuzz(func(t *testing.T, shapeIdx, ctxIdx int, prefix, suffix string) {
		shape := credentialShapes[pick(shapeIdx, len(credentialShapes))]
		ctx := redactionContexts[pick(ctxIdx, len(redactionContexts))]

		in := prefix + ctx.wrap(shape.key, shape.value) + suffix
		got := Redact(in)
		if strings.Contains(got, shape.leaked()) {
			t.Fatalf("credential survived redaction\n  in: %q\n out: %q", in, got)
		}
		if again := Redact(got); again != got {
			t.Fatalf("Redact is not idempotent\n once: %q\ntwice: %q", got, again)
		}
		if bounded := TruncateExcerpt(got); strings.Contains(bounded, shape.leaked()) {
			t.Fatalf("credential survived truncation: %q", bounded)
		}
	})
}

func pick(i, n int) int {
	if i < 0 {
		i = -i
	}
	return i % n
}

// safeFindingProse is the other half of the property: text that carries no
// credential must come back byte for byte.
//
// Over-redaction is not a cosmetic problem here. Canonical JSON is the source of
// truth for a decision, and a finding whose message has been eaten by the
// redactor no longer tells a reviewer what to act on. These are the messages,
// limitations, and locators this project actually emits, with the analyzer's
// interpolated values filled in -- including the ones that talk about tokens,
// secrets, and passwords, which is the prose a key-name rule is most likely to
// mistake for an assignment.
var safeFindingProse = []string{
	"Job build runs on the privileged pull_request_target trigger, checks out pull-request-controlled code, and then executes it with the base repository's token.",
	"The head revision newly grants the workflow token write access to contents, packages.",
	"The head revision newly grants the workflow token write access to job build: contents.",
	"Action actions/checkout is referenced by a mutable tag, so the code it runs can change without any change to this repository.",
	"Step 0 of job build interpolates the attacker-controlled expression github.event.pull_request.title directly into a shell script, so the value is spliced into the command the runner executes.",
	"Job publish exposes a repository secret to code checked out from the pull request under the privileged pull_request_target trigger, so fork-controlled code runs with access to that secret.",
	"Job build runs on a self-hosted runner in response to the pull_request trigger, so work influenced by a pull request touches a machine that persists between jobs.",
	"The npm lockfile is deleted by this change, so every dependency it pinned resolves freshly at install time and the build is no longer bound to the artifacts that were reviewed.",
	"The manifest declares left-pad, lodash with a floating range, so the build is not reproducibly bound to a specific artifact.",
	"Dependency example resolves from a git source that is not bound to an immutable identity, so the code it supplies can change without any change to this repository.",
	"The head revision adds install-time execution through postinstall, so installing this project runs code that did not run before.",
	"Locked package lodash keeps version 4.17.21 while its resolved artifact identity changes, so the same declared version would install different bytes.",
	"The head revision adds 3 direct dependencies (left-pad, lodash, minimist) with a transitive change of 12 locked packages.",
	"New dependency lodahs closely resembles lodash, which this project already depends on.",
	"A write scope can be legitimately required by a release or publishing job, so version 1 routes the expansion to review rather than asserting misuse.",
	"Compensating organization or repository Actions policy is not visible in offline analysis.",
	"A required approval or environment protection rule on this job cannot be read from the repository.",
	"the analyzer reached the configured finding ceiling and stopped before examining every change",
	"workflow analysis stopped before every changed workflow was examined",
	".github/workflows/ci.yml#jobs.build.steps[0].run",
	"package.json#scripts.postinstall",
	"uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
	"permissions: write-all",
	"on: pull_request_target",
}

func TestRedactPreservesRealFindingProse(t *testing.T) {
	for _, in := range safeFindingProse {
		if got := Redact(in); got != in {
			t.Errorf("Redact over-redacted evidence prose\n  in: %q\n out: %q", in, got)
		}
	}
}

func FuzzRedactPreservesSafeProse(f *testing.F) {
	f.Add(0, 1, false)
	f.Add(2, 19, true)
	f.Add(5, 5, false)
	f.Add(-7, 23, true)

	f.Fuzz(func(t *testing.T, i, j int, newline bool) {
		// Every entry is a complete sentence or locator, so joining two of them
		// with whitespace cannot manufacture an assignment that was in neither.
		// Anything the redactor removes from a join is therefore something it
		// would also have removed from a real finding.
		sep := " "
		if newline {
			sep = "\n"
		}
		in := safeFindingProse[pick(i, len(safeFindingProse))] + sep + safeFindingProse[pick(j, len(safeFindingProse))]
		if got := Redact(in); got != in {
			t.Fatalf("Redact over-redacted safe prose\n  in: %q\n out: %q", in, got)
		}
	})
}

// TestRedactClosesTheReviewedRedactionDefects anchors the exact strings from the
// security review, so a regression is reported as the defect it was rather than
// as an anonymous property failure.
func TestRedactClosesTheReviewedRedactionDefects(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		gone    string
		survive string
	}{
		{"D1 later key after an innocuous one", "status: ok password: hunter2xyz", "hunter2xyz", "status: ok"},
		{"D1 later key after a log level", "level=info api_key=verysecretvalue1234567890", "verysecretvalue1234567890", "level=info"},
		{"D1 url userinfo behind a scheme colon", "Fetching from https://user:S3cr3tPassw0rd@example.com/repo.git", "S3cr3tPassw0rd", "example.com/repo.git"},
		{"D2 quoted value containing a comma", `password: "hunter2, still part of pw"`, "still part of pw", "password:"},
		{"D4 capitalized secrets expression", "run: deploy --key ${{ Secrets.DEPLOY_KEY }}", "Secrets.DEPLOY_KEY", "run:"},
		{"D4 bracketed secrets expression", "run: deploy --key ${{ secrets['DEPLOY_KEY'] }}", "secrets['DEPLOY_KEY']", "run:"},
		{"D4 bracketed secrets expression double quoted", `run: deploy --key ${{ secrets["DEPLOY_KEY"] }}`, `secrets["DEPLOY_KEY"]`, "run:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if strings.Contains(got, tc.gone) {
				t.Errorf("Redact(%q) = %q, want %q gone", tc.in, got, tc.gone)
			}
			if !strings.Contains(got, tc.survive) {
				t.Errorf("Redact(%q) = %q, want %q kept", tc.in, got, tc.survive)
			}
		})
	}
}

// TestRedactKeepsProseWhoseSecretWordIsNotAKey proves a sentence is not an
// assignment just because a secret-bearing word appears somewhere before a
// colon. Walking back to the previous list delimiter made a whole clause the
// key and deleted the evidence behind it.
func TestRedactKeepsProseWhoseSecretWordIsNotAKey(t *testing.T) {
	cases := []string{
		"The head revision newly grants the workflow token write access to job build: contents.",
		"Job publish exposes a repository secret to the fork, see jobs.publish: steps.",
		"The password policy document lives at docs/policy: read it before reviewing.",
	}
	for _, in := range cases {
		if got := Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
}
