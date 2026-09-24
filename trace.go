package keycheck

// TraceEntry records one reached top-level key during [Program.AppendTrace].
// Groups produce one entry; errors from their children include nested group indices.
// Entries contain no selected values or input references of their own.
// An error supplied by a custom predicate may itself retain caller-owned data.
type TraceEntry struct {
	// Chain is the original zero-based chain index.
	Chain int

	// Key is the zero-based top-level key index within the chain.
	Key int

	// Matched is the boolean returned by the predicate.
	// When Err is non-nil, this value does not represent a successful decision.
	Matched bool

	// Err is the original predicate error, without the enclosing [EvalError].
	Err error
}

// AppendTrace evaluates input once and appends a trace of reached top-level keys to dst.
// It makes the same decisions as [Program.Evaluate], including first-match ordering,
// short-circuiting, fallback results, and immediate error propagation.
// Skipped keys produce no entries; a reached group produces one entry for the whole group.
// A failing key is appended before an [EvalError] is returned, even if it returned true.
// Existing entries are preserved, and the returned slice may reuse dst's backing array.
// Capacity for the existing entries plus all reached keys avoids output allocations.
// Callers must exclusively own dst during the call and may reuse its storage afterward.
// Input, callback, and concurrency rules are the same as [Program.Evaluate].
// A nil receiver returns the fallback, unchanged dst, and [ErrNilProgram].
func (p *Program[T]) AppendTrace(dst []TraceEntry, input T, fallback Status) (Result, []TraceEntry, error) {
	result := Result{Status: fallback, Chain: -1}
	if p == nil {
		return result, dst, ErrNilProgram
	}
	for i := range p.chains {
		chain := &p.chains[i]
		if chain.mode == And {
			matched := true
			for j, key := range chain.keys {
				ok, err := key(input)
				dst = append(dst, TraceEntry{Chain: chain.index, Key: j, Matched: ok, Err: err})
				if err != nil {
					return result, dst, &EvalError{Chain: chain.index, Key: j, Err: err}
				}
				if !ok {
					matched = false
					break
				}
			}
			if matched {
				return Result{Status: chain.status, Matched: true, Chain: chain.index}, dst, nil
			}
			continue
		}
		for j, key := range chain.keys {
			ok, err := key(input)
			dst = append(dst, TraceEntry{Chain: chain.index, Key: j, Matched: ok, Err: err})
			if err != nil {
				return result, dst, &EvalError{Chain: chain.index, Key: j, Err: err}
			}
			if ok {
				return Result{Status: chain.status, Matched: true, Chain: chain.index}, dst, nil
			}
		}
	}
	return result, dst, nil
}
