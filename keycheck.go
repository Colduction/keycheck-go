// Package keycheck compiles ordered keychains into reusable, in-memory evaluators.
//
// Compile rules once and share the resulting [Program] across goroutines.
// Evaluation borrows caller-owned input and performs no I/O.
// Selectors and custom predicates must be safe for their callers' concurrency.
package keycheck

import (
	"errors"
	"fmt"
)

// Status identifies an evaluation outcome.
// Applications may define additional statuses by converting strings.
type Status string

// Conventional statuses have no control-flow effects beyond identifying a result.
const (
	Success Status = "SUCCESS"
	Fail    Status = "FAIL"
	Invalid Status = "INVALID"
	Custom  Status = "CUSTOM"
	Retry   Status = "RETRY"
	Ban     Status = "BAN"
	None    Status = "NONE"
)

// Mode determines how a chain combines its keys.
// The zero value is [Or].
type Mode uint8

const (
	// Or matches when any key matches.
	Or Mode = iota
	// And matches when every key matches.
	And
)

// Operator identifies a built-in comparison.
// Each key constructor documents its supported operators.
// [Compile] rejects operators unsupported by a key's value type.
type Operator uint8

// Built-in comparison operators follow Go equality and ordering rules.
// Existence is determined by the selector's presence result.
const (
	EqualTo Operator = iota
	NotEqualTo
	Contains
	DoesNotContain
	Exists
	DoesNotExist
	MatchesRegex
	DoesNotMatchRegex
	LessThan
	LessThanOrEqualTo
	GreaterThan
	GreaterThanOrEqualTo
	Is
	IsNot
	HasKey
	DoesNotHaveKey
	HasValue
	DoesNotHaveValue
	StartsWith
	DoesNotStartWith
	EndsWith
	DoesNotEndWith
)

// Configuration and receiver errors can be classified with [errors.Is].
var (
	ErrInvalidMode      = errors.New("keycheck: invalid chain mode")
	ErrInvalidStatus    = errors.New("keycheck: empty chain status")
	ErrInvalidKey       = errors.New("keycheck: invalid key or nil selector")
	ErrInvalidOperator  = errors.New("keycheck: unsupported operator")
	ErrInvalidPattern   = errors.New("keycheck: invalid regular expression")
	ErrInvalidOption    = errors.New("keycheck: invalid text option")
	ErrInvalidThreshold = errors.New("keycheck: invalid match threshold")
	ErrNestingTooDeep   = errors.New("keycheck: key nesting limit exceeded")
	ErrTooManyKeys      = errors.New("keycheck: expanded key limit exceeded")
	ErrInvalidLimit     = errors.New("keycheck: invalid compiler limit")
	ErrNilProgram       = errors.New("keycheck: nil program")
)

// Selector returns a value from input and reports whether it is present.
// Presence is independent of the value: empty strings, nil slices, nil maps,
// and numeric zero are present when the second result is true.
// A selector is called once for each operand reached during evaluation.
// It must not retain borrowed input beyond the caller's permitted lifetime.
type Selector[T, V any] func(T) (V, bool)

// Key describes a predicate to compile as part of a [Chain].
// Use the typed key constructors or [CustomKey] to create one.
// The zero value is invalid.
// Keys can be reused across chains and compilations.
type Key[T any] struct {
	compile func(*compiler) (predicate[T], error)
}

// Chain associates a status with an ordered group of keys.
// Empty chains never match, including chains using [And].
type Chain[T any] struct {
	// Status is the result when this chain matches and must not be empty.
	Status Status

	// Mode combines keys using [Or] or [And], with left-to-right short-circuiting.
	Mode Mode

	// Keys contains the predicates in evaluation order.
	// [Compile] snapshots this slice; later changes do not affect the program.
	Keys []Key[T]
}

// Result describes an evaluation without retaining its input.
type Result struct {
	// Status is the matching chain's status, or the supplied fallback.
	Status Status

	// Matched reports whether a chain matched.
	Matched bool

	// Chain is the matching chain's original zero-based index, or -1 on no match or error.
	Chain int
}

// CompileError identifies invalid configuration.
// It supports [errors.Is] and [errors.As] through [CompileError.Unwrap].
type CompileError struct {
	// Chain is the original zero-based chain index.
	Chain int

	// Key is the zero-based key index, or -1 for a chain-level error.
	Key int

	// Err describes the invalid configuration.
	Err error
}

// Error returns the configuration error with its location.
func (e *CompileError) Error() string {
	if e.Key < 0 {
		return fmt.Sprintf("keycheck: chain %d: %v", e.Chain, e.Err)
	}
	return fmt.Sprintf("keycheck: chain %d key %d: %v", e.Chain, e.Key, e.Err)
}

// Unwrap returns the underlying configuration error.
func (e *CompileError) Unwrap() error {
	return e.Err
}

// EvalError identifies a failing custom predicate.
// It supports [errors.Is] and [errors.As] through [EvalError.Unwrap].
type EvalError struct {
	// Chain is the original zero-based chain index.
	Chain int

	// Key is the zero-based key index.
	Key int

	// Err is the error returned by the custom predicate.
	Err error
}

// Error returns the predicate error with its location.
func (e *EvalError) Error() string {
	return fmt.Sprintf("keycheck: chain %d key %d: %v", e.Chain, e.Key, e.Err)
}

// Unwrap returns the custom predicate's error.
func (e *EvalError) Unwrap() error {
	return e.Err
}

// Program is an immutable collection of compiled chains.
// Its zero value contains no chains and always returns the fallback.
// Programs can be evaluated concurrently if their selectors, custom predicates,
// and caller-owned inputs permit concurrent access.
// Compilation allocates; ordinary built-in evaluation with allocation-free selectors does not allocate.
// Regular expressions may allocate internal execution storage on cold use or pool misses.
type Program[T any] struct {
	chains []compiledChain[T]
}

// Compiler configures resource limits for compiling any input type.
// Its zero value uses the default limits.
// A Compiler can be reused across input types through its generic [Compiler.Compile] method.
// It retains no programs, caches, or input values between calls.
// Concurrent compilation is safe while its configuration remains unchanged.
type Compiler struct {
	// MaxDepth limits nested key levels, counting the outer key and deepest leaf.
	// Zero selects 64; negative values are invalid.
	MaxDepth int

	// MaxKeys limits expanded key occurrences across all chains.
	// Reused groups count at each occurrence.
	// Zero selects 65,536; negative values are invalid.
	// This bounds expanded key occurrences and compiled node storage,
	// not total compilation time or operand and callback memory.
	MaxKeys int
}

type predicate[T any] func(T) (bool, error)

type compiledChain[T any] struct {
	status Status
	mode   Mode
	index  int
	keys   []predicate[T]
}

type compiler struct {
	regexes  map[string]textTest
	depth    int
	keys     int
	maxDepth int
	maxKeys  int
}

func (c *compiler) key[T any](key Key[T]) (predicate[T], error) {
	if key.compile == nil {
		return nil, ErrInvalidKey
	}
	if c.depth >= c.maxDepth {
		return nil, ErrNestingTooDeep
	}
	if c.keys >= c.maxKeys {
		return nil, ErrTooManyKeys
	}
	c.keys++
	c.depth++
	defer func() { c.depth-- }()
	return key.compile(c)
}

// Compile validates and snapshots chains into an immutable [Program].
// It preserves chain and key order, including original indices for diagnostics.
// Empty chains are ignored after their mode and status have been validated.
// Zero chains are valid.
// Keys may nest up to 64 levels, counting the outer key and its deepest leaf.
// A program may contain at most 65,536 expanded key occurrences across all chains,
// including repeated occurrences inside shared groups.
// Identical regex patterns share one compiled expression within this compilation.
// The program retains selectors and custom predicates, including their captured state.
// Callers must not mutate configuration slices while Compile reads them.
// Invalid configuration returns a [CompileError] and no partial program.
func Compile[T any](chains ...Chain[T]) (*Program[T], error) {
	return (Compiler{}).Compile(chains...)
}

// Compile validates and snapshots chains according to the compiler's limits.
// It has the same evaluation, ownership, ordering, and regex-reuse contracts as [Compile].
// Zero limits select defaults; negative limits return [ErrInvalidLimit].
// Depth or expanded-key exhaustion returns a [CompileError] wrapping
// [ErrNestingTooDeep] or [ErrTooManyKeys], respectively.
// Each call uses separate compilation state and returns an independent [Program].
func (c Compiler) Compile[T any](chains ...Chain[T]) (*Program[T], error) {
	if c.MaxDepth < 0 || c.MaxKeys < 0 {
		return nil, ErrInvalidLimit
	}
	if c.MaxDepth == 0 {
		c.MaxDepth = 64
	}
	if c.MaxKeys == 0 {
		c.MaxKeys = 65536
	}
	state := compiler{maxDepth: c.MaxDepth, maxKeys: c.MaxKeys}
	program := new(Program[T])
	for i, chain := range chains {
		if chain.Mode != Or && chain.Mode != And {
			return nil, &CompileError{Chain: i, Key: -1, Err: ErrInvalidMode}
		}
		if chain.Status == "" {
			return nil, &CompileError{Chain: i, Key: -1, Err: ErrInvalidStatus}
		}
		if len(chain.Keys) == 0 {
			continue
		}
		if len(chain.Keys) > state.maxKeys-state.keys {
			return nil, &CompileError{Chain: i, Key: -1, Err: ErrTooManyKeys}
		}
		compiled := compiledChain[T]{
			status: chain.Status,
			mode:   chain.Mode,
			index:  i,
			keys:   make([]predicate[T], len(chain.Keys)),
		}
		for j, key := range chain.Keys {
			match, err := state.key(key)
			if err != nil {
				return nil, &CompileError{Chain: i, Key: j, Err: err}
			}
			compiled.keys[j] = match
		}
		program.chains = append(program.chains, compiled)
	}
	return program, nil
}

// Evaluate checks chains in order and returns the first match.
// It returns fallback with [Result.Matched] false and [Result.Chain] -1 when no chain matches.
// Use [Ban] as fallback for the OpenBullet2 default, or pass an existing status to preserve it.
// Keys short-circuit in their original order; skipped selectors are not called.
// A custom predicate error immediately returns the fallback and an [EvalError],
// even if the predicate also returned true.
// Callback panics propagate to the caller.
// Evaluate neither mutates nor retains input and performs no I/O of its own.
// Callers control the behavior and concurrency of their selectors and custom predicates.
// A nil receiver returns [ErrNilProgram].
func (p *Program[T]) Evaluate(input T, fallback Status) (Result, error) {
	result := Result{Status: fallback, Chain: -1}
	if p == nil {
		return result, ErrNilProgram
	}
	for i := range p.chains {
		chain := &p.chains[i]
		matched, err := chain.evaluate(input)
		if err != nil {
			return result, err
		}
		if matched {
			return Result{Status: chain.status, Matched: true, Chain: chain.index}, nil
		}
	}
	return result, nil
}

// AppendMatches appends every matching chain to dst in declaration order.
// Unlike [Program.Evaluate], it continues after a matching chain.
// Each chain still short-circuits its keys according to its mode.
// No match leaves dst unchanged; there is no fallback result.
// A custom predicate error stops evaluation and returns dst with earlier matches and an [EvalError].
// Capacity for existing entries plus all matches avoids output allocations.
// The returned slice may reuse dst's backing array; callers must exclusively own it during this call.
// Input and callback lifetime and concurrency rules are the same as [Program.Evaluate].
// A nil receiver returns dst and [ErrNilProgram].
func (p *Program[T]) AppendMatches(dst []Result, input T) ([]Result, error) {
	if p == nil {
		return dst, ErrNilProgram
	}
	for i := range p.chains {
		chain := &p.chains[i]
		matched, err := chain.evaluate(input)
		if err != nil {
			return dst, err
		}
		if matched {
			dst = append(dst, Result{Status: chain.status, Matched: true, Chain: chain.index})
		}
	}
	return dst, nil
}

func (c *compiledChain[T]) evaluate(input T) (bool, error) {
	if c.mode == And {
		for i, key := range c.keys {
			ok, err := key(input)
			if err != nil {
				return false, &EvalError{Chain: c.index, Key: i, Err: err}
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	}
	for i, key := range c.keys {
		ok, err := key(input)
		if err != nil {
			return false, &EvalError{Chain: c.index, Key: i, Err: err}
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// CustomKey creates a key from a caller-owned predicate.
// [Compile] rejects a nil predicate.
// Predicate errors stop evaluation and are returned through [EvalError].
// The predicate must honor the input's lifetime and any concurrent use of the program.
// Its allocation, blocking, and I/O behavior remains the caller's responsibility.
func CustomKey[T any](match func(T) (bool, error)) Key[T] {
	return Key[T]{compile: func(*compiler) (predicate[T], error) {
		if match == nil {
			return nil, ErrInvalidKey
		}
		return match, nil
	}}
}
