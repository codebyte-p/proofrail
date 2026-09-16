package run

// ExitCode maps a canonical result to the process exit status defined in
// docs/architecture.md:
//
//	0  pass or warn      analysis completed and nothing requires a human
//	1  require_review or block
//	                     analysis completed and the change needs a decision
//	2  incomplete or internal error
//	                     coverage is missing, so no judgement was reached
//
// Status is inspected before Decision. An incomplete run already carries a
// forced block decision, but checking status first means that even a result
// which has been corrupted into claiming `pass` still exits 2. Presentation
// settings cannot reach this function, so no configuration can map incomplete
// to a success code.
//
// Anything outside the two registries is an internal error rather than a
// judgement, so it fails closed to 2.
func ExitCode(result CanonicalRunResult) int {
	if result.Status != StatusComplete {
		return 2
	}
	switch result.Decision {
	case DecisionPass, DecisionWarn, DecisionObserve:
		return 0
	case DecisionRequireReview, DecisionBlock:
		return 1
	default:
		return 2
	}
}
