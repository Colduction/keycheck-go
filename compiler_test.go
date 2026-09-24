package keycheck

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestCompilerGenericMethod(t *testing.T) {
	compiler := Compiler{MaxDepth: 2, MaxKeys: 3}
	integers, err := compiler.Compile(Chain[int64]{Status: Success, Keys: []Key[int64]{
		All(
			IntKey(func(value int64) (int64, bool) { return value, true }, GreaterThanOrEqualTo, 200),
			IntKey(func(value int64) (int64, bool) { return value, true }, LessThan, 300),
		),
	}})
	if err != nil {
		t.Fatal(err)
	}
	strings, err := compiler.Compile(Chain[string]{Status: Custom, Keys: []Key[string]{
		StringKey(func(value string) (string, bool) { return value, true }, MatchesRegex, `^ready-[0-9]+$`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := compiler.Compile[bool]()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := integers.Evaluate(204, None); err != nil || got != (Result{Status: Success, Matched: true, Chain: 0}) {
		t.Fatalf("integer program = %+v, %v", got, err)
	}
	if got, err := strings.Evaluate("ready-42", None); err != nil || got != (Result{Status: Custom, Matched: true, Chain: 0}) {
		t.Fatalf("string program = %+v, %v", got, err)
	}
	if got, err := empty.Evaluate(true, Ban); err != nil || got != (Result{Status: Ban, Chain: -1}) {
		t.Fatalf("empty program = %+v, %v", got, err)
	}
	if compiler != (Compiler{MaxDepth: 2, MaxKeys: 3}) {
		t.Fatalf("compilation mutated configuration: %+v", compiler)
	}
}

func TestCompilerRejectsNegativeLimits(t *testing.T) {
	for _, compiler := range []Compiler{{MaxDepth: -1}, {MaxKeys: -1}, {MaxDepth: -1, MaxKeys: -1}} {
		program, err := compiler.Compile[bool]()
		if program != nil || err != ErrInvalidLimit {
			t.Fatalf("compiler %+v: Compile = %v, %v; want nil, ErrInvalidLimit", compiler, program, err)
		}
	}
}

func TestCompilerDepthLimit(t *testing.T) {
	leaf := CustomKey(func(bool) (bool, error) { return false, nil })
	chain := Chain[bool]{Status: Success, Keys: []Key[bool]{Not(leaf)}}
	for _, depth := range []int{1, 2} {
		compiler := Compiler{MaxDepth: depth}
		program, err := compiler.Compile(chain)
		if depth == 1 {
			if program != nil || !errors.Is(err, ErrNestingTooDeep) {
				t.Fatalf("depth 1: Compile = %v, %v", program, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got, err := program.Evaluate(false, None); err != nil || !got.Matched {
			t.Fatalf("depth 2 program = %+v, %v", got, err)
		}
	}
}

func TestCompilerExpandedKeyLimit(t *testing.T) {
	leaf := CustomKey(func(bool) (bool, error) { return true, nil })
	group := All(leaf, leaf)
	for _, limit := range []int{2, 3} {
		compiler := Compiler{MaxKeys: limit}
		program, err := compiler.Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{group}})
		if limit == 2 {
			if program != nil || !errors.Is(err, ErrTooManyKeys) {
				t.Fatalf("two-node limit: Compile = %v, %v", program, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got, err := program.Evaluate(false, None); err != nil || !got.Matched {
			t.Fatalf("three-node program = %+v, %v", got, err)
		}
	}
	for _, tt := range []struct {
		name   string
		limit  int
		chains []Chain[bool]
		chain  int
		key    int
	}{
		{"root_list_exceeds_budget", 1, []Chain[bool]{{Status: Success, Keys: []Key[bool]{leaf, leaf}}}, 0, -1},
		{"later_root_list_exceeds_remaining", 2, []Chain[bool]{
			{Status: Success, Keys: []Key[bool]{leaf}},
			{Status: Custom, Keys: []Key[bool]{leaf, leaf}},
		}, 1, -1},
		{"nested_expansion_across_chains", 3, []Chain[bool]{
			{Status: Success, Keys: []Key[bool]{leaf}},
			{Status: Custom, Keys: []Key[bool]{group}},
		}, 1, 0},
		{"empty_chain_preserves_error_index", 3, []Chain[bool]{
			{Status: Success, Keys: []Key[bool]{group}},
			{Status: None},
			{Status: Custom, Keys: []Key[bool]{leaf}},
		}, 2, -1},
		{"shared_group_counts_every_occurrence", 5, []Chain[bool]{
			{Status: Success, Keys: []Key[bool]{group, group}},
		}, 0, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			program, err := (Compiler{MaxKeys: tt.limit}).Compile(tt.chains...)
			var location *CompileError
			if program != nil || !errors.Is(err, ErrTooManyKeys) || !errors.As(err, &location) {
				t.Fatalf("Compile = %v, %v; want expanded-key error", program, err)
			}
			if location.Chain != tt.chain || location.Key != tt.key {
				t.Fatalf("location = %+v; want chain %d key %d", location, tt.chain, tt.key)
			}
		})
	}
}

func TestCompilerDefaultLimits(t *testing.T) {
	var compiler Compiler
	leaf := CustomKey(func(bool) (bool, error) { return true, nil })
	key := leaf
	for range 63 {
		key = Not(key)
	}
	if _, err := compiler.Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{key}}); err != nil {
		t.Fatalf("default depth 64 rejected: %v", err)
	}
	if program, err := compiler.Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{Not(key)}}); program != nil || !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("default depth 65: Compile = %v, %v", program, err)
	}
	keys := make([]Key[bool], 65537)
	for i := range keys {
		keys[i] = leaf
	}
	if _, err := compiler.Compile(Chain[bool]{Status: Success, Keys: keys[:65536]}); err != nil {
		t.Fatalf("default 65,536-key limit rejected: %v", err)
	}
	if program, err := compiler.Compile(Chain[bool]{Status: Success, Keys: keys}); program != nil || !errors.Is(err, ErrTooManyKeys) {
		t.Fatalf("default 65,537-key limit: Compile = %v, %v", program, err)
	}
	if compiler != (Compiler{}) {
		t.Fatalf("default configuration changed: %+v", compiler)
	}
}

func TestCompilerResetsBudgetAfterFailure(t *testing.T) {
	compiler := Compiler{MaxDepth: 2, MaxKeys: 3}
	leaf := CustomKey(func(bool) (bool, error) { return true, nil })
	for range 3 {
		if _, err := compiler.Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{Not(Not(leaf))}}); !errors.Is(err, ErrNestingTooDeep) {
			t.Fatalf("expected failed depth-limited compile, got %v", err)
		}
		if _, err := compiler.Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{All(leaf, leaf, leaf)}}); !errors.Is(err, ErrTooManyKeys) {
			t.Fatalf("expected failed node-limited compile, got %v", err)
		}
		program, err := compiler.Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{All(leaf, leaf)}})
		if err != nil {
			t.Fatalf("previous failures consumed the next call's budget: %v", err)
		}
		if got, err := program.Evaluate(false, None); err != nil || !got.Matched {
			t.Fatalf("program after failure = %+v, %v", got, err)
		}
	}
}

func TestCompilerConcurrentCompilation(t *testing.T) {
	compiler := Compiler{MaxDepth: 2, MaxKeys: 3}
	selector := func(value string) (string, bool) { return value, true }
	leaf := StringKey(selector, MatchesRegex, `^ready-[0-9]+$`)
	valid := Chain[string]{Status: Success, Keys: []Key[string]{All(leaf, leaf)}}
	invalid := Chain[string]{Status: Success, Keys: []Key[string]{All(leaf, leaf, leaf)}}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 25 {
				if _, err := compiler.Compile(invalid); !errors.Is(err, ErrTooManyKeys) {
					t.Errorf("invalid concurrent compile error = %v", err)
					return
				}
				program, err := compiler.Compile(valid)
				if err != nil {
					t.Error(err)
					return
				}
				if got, err := program.Evaluate("ready-42", None); err != nil || !got.Matched {
					t.Errorf("concurrently compiled program = %+v, %v", got, err)
					return
				}
			}
		})
	}
	workers.Wait()
}

func ExampleCompiler_Compile() {
	compiler := Compiler{MaxDepth: 4, MaxKeys: 16}
	selector := func(value int64) (int64, bool) { return value, true }
	program, err := compiler.Compile(Chain[int64]{Status: Success, Keys: []Key[int64]{
		All(IntKey(selector, GreaterThanOrEqualTo, 200), IntKey(selector, LessThan, 300)),
	}})
	if err != nil {
		panic(err)
	}
	result, err := program.Evaluate(204, None)
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Status, result.Matched)
	// Output: SUCCESS true
}
