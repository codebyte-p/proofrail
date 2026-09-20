package finding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"strconv"
)

// Fingerprint is the stable identity of a finding. A waiver binds to an exact
// fingerprint, so what goes into it decides what a waiver keeps covering.
//
// Included: rule identity, analyzer identity, every sorted location, and, for
// every sorted evidence item, its kind and the digest of its redacted excerpt.
//
// Excluded on purpose:
//
//   - Message, limitations, severity, confidence, and decision hint. These are
//     mutable prose and tuning. Including them would silently expire every
//     waiver in a repository the moment a rule's wording or severity was
//     retuned, which is exactly when reviewers are least expecting it.
//   - The raw excerpt. The digest is taken over the redacted text, so rotating a
//     leaked credential does not move the fingerprint and does not invalidate a
//     reviewed waiver. It also means a secret value never reaches the hash.
//
// Every field is length-prefixed before hashing. Without that, the field pair
// ("ab", "c") and ("a", "bc") would produce the same byte stream, and a waiver
// approved for one finding could suppress a different one.
func computeFingerprint(f Finding) string {
	h := sha256.New()

	writeField(h, f.RuleID)
	writeField(h, f.AnalyzerID)

	writeCount(h, len(f.Locations))
	for _, loc := range f.Locations {
		writeField(h, loc.Path)
		writeField(h, strconv.Itoa(loc.StartLine))
		writeField(h, strconv.Itoa(loc.EndLine))
	}

	writeCount(h, len(f.Evidence))
	for _, e := range f.Evidence {
		writeField(h, e.Kind)
		writeField(h, e.Digest)
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// digestExcerpt is the evidence digest: SHA-256 over the redacted excerpt.
func digestExcerpt(redacted string) string {
	sum := sha256.Sum256([]byte(redacted))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeField appends a length-prefixed value to the hash.
func writeField(h hash.Hash, s string) {
	writeCount(h, len(s))
	_, _ = h.Write([]byte(s))
}

// writeCount appends a fixed-width big-endian length, so the framing itself
// cannot be confused with content.
func writeCount(h hash.Hash, n int) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	_, _ = h.Write(buf[:])
}
