package keycheck

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestAppendTraceDecisions(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mode   Mode
		values []bool
		want   Result
		trace  []TraceEntry
	}{
		{"or_first", Or, []bool{true, false, false}, Result{Status: Success, Matched: true, Chain: 1}, []TraceEntry{{Chain: 1, Key: 0, Matched: true}}},
		{"or_last", Or, []bool{false, false, true}, Result{Status: Success, Matched: true, Chain: 1}, []TraceEntry{{Chain: 1, Key: 0}, {Chain: 1, Key: 1}, {Chain: 1, Key: 2, Matched: true}}},
		{"or_no_match", Or, []bool{false, false, false}, Result{Status: None, Chain: -1}, []TraceEntry{{Chain: 1, Key: 0}, {Chain: 1, Key: 1}, {Chain: 1, Key: 2}}},
		{"and_first", And, []bool{false, true, true}, Result{Status: None, Chain: -1}, []TraceEntry{{Chain: 1, Key: 0}}},
		{"and_last", And, []bool{true, true, false}, Result{Status: None, Chain: -1}, []TraceEntry{{Chain: 1, Key: 0, Matched: true}, {Chain: 1, Key: 1, Matched: true}, {Chain: 1, Key: 2}}},
		{"and_all", And, []bool{true, true, true}, Result{Status: Success, Matched: true, Chain: 1}, []TraceEntry{{Chain: 1, Key: 0, Matched: true}, {Chain: 1, Key: 1, Matched: true}, {Chain: 1, Key: 2, Matched: true}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []int
			keys := make([]Key[int], len(tt.values))
			for i, value := range tt.values {
				keys[i] = CustomKey(func(int) (bool, error) { calls = append(calls, i); return value, nil })
			}
			program, err := Compile(Chain[int]{Status: Invalid, Mode: And}, Chain[int]{Status: Success, Mode: tt.mode, Keys: keys})
			if err != nil {
				t.Fatal(err)
			}
			result, trace, err := program.AppendTrace(nil, 0, None)
			if err != nil || result != tt.want || !slices.Equal(trace, tt.trace) {
				t.Fatalf("AppendTrace = %+v, %+v, %v; want %+v, %+v", result, trace, err, tt.want, tt.trace)
			}
			if len(calls) != len(trace) {
				t.Fatalf("calls = %v; want each reached key once", calls)
			}
			for i, called := range calls {
				if called != i {
					t.Fatalf("calls = %v; want left-to-right order", calls)
				}
			}
			calls = nil
			plain, err := program.Evaluate(0, None)
			if err != nil || plain != result || len(calls) != len(trace) {
				t.Fatalf("Evaluate disagrees: %+v, %v, calls %v", plain, err, calls)
			}
		})
	}
}

func TestAppendTraceMultipleChains(t *testing.T) {
	var calls int
	miss := CustomKey(func(int) (bool, error) { calls++; return false, nil })
	match := CustomKey(func(int) (bool, error) { calls++; return true, nil })
	unreached := CustomKey(func(int) (bool, error) { t.Fatal("reached skipped key or chain"); return false, nil })
	program, err := Compile(
		Chain[int]{Status: Fail, Mode: And, Keys: []Key[int]{miss, unreached}},
		Chain[int]{Status: Invalid, Mode: Or},
		Chain[int]{Status: Success, Mode: Or, Keys: []Key[int]{miss, match, unreached}},
		Chain[int]{Status: Ban, Keys: []Key[int]{unreached}},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, trace, err := program.AppendTrace(nil, 0, None)
	wantTrace := []TraceEntry{{Chain: 0, Key: 0}, {Chain: 2, Key: 0}, {Chain: 2, Key: 1, Matched: true}}
	if err != nil || result != (Result{Status: Success, Matched: true, Chain: 2}) || !slices.Equal(trace, wantTrace) || calls != 3 {
		t.Fatalf("AppendTrace = %+v, %+v, %v, calls %d", result, trace, err, calls)
	}
}

func TestAppendTracePreservesPrefix(t *testing.T) {
	program, err := Compile(Chain[int64]{Status: Success, Keys: []Key[int64]{
		IntKey(func(value int64) (int64, bool) { return value, true }, EqualTo, 42),
	}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := TraceEntry{Chain: 77, Key: 99, Matched: true, Err: errors.New("earlier trace")}
	dst := make([]TraceEntry, 1, 3)
	dst[0] = prefix
	result, trace, err := program.AppendTrace(dst, 42, None)
	if err != nil || !result.Matched || len(trace) != 2 || trace[0] != prefix || &trace[0] != &dst[0] {
		t.Fatalf("AppendTrace did not preserve prefix/storage: %+v, %+v, %v", result, trace, err)
	}
	if trace[1] != (TraceEntry{Chain: 0, Key: 0, Matched: true}) {
		t.Fatalf("appended entry = %+v", trace[1])
	}
	result, trace, err = program.AppendTrace(trace[:1], 0, None)
	if err != nil || result.Matched || len(trace) != 2 || trace[0] != prefix || trace[1].Matched {
		t.Fatalf("reused trace = %+v, %+v, %v", result, trace, err)
	}
}

func TestAppendTraceErrors(t *testing.T) {
	broken := errors.New("predicate failed")
	for _, mode := range []Mode{Or, And} {
		for _, matched := range []bool{false, true} {
			var calls int
			program, err := Compile(Chain[int]{Status: None}, Chain[int]{Status: Success, Mode: mode, Keys: []Key[int]{
				CustomKey(func(int) (bool, error) { calls++; return mode == And, nil }),
				CustomKey(func(int) (bool, error) { calls++; return matched, broken }),
				CustomKey(func(int) (bool, error) { t.Fatal("called after error"); return true, nil }),
			}})
			if err != nil {
				t.Fatal(err)
			}
			result, trace, err := program.AppendTrace(nil, 0, Retry)
			var location *EvalError
			if result != (Result{Status: Retry, Chain: -1}) || !errors.Is(err, broken) || !errors.As(err, &location) || calls != 2 {
				t.Fatalf("AppendTrace = %+v, %+v, %v, calls %d", result, trace, err, calls)
			}
			if location.Chain != 1 || location.Key != 1 || location.Err != broken {
				t.Fatalf("error location = %+v", location)
			}
			if len(trace) != 2 || trace[1] != (TraceEntry{Chain: 1, Key: 1, Matched: matched, Err: broken}) {
				t.Fatalf("failing predicate entry = %+v", trace)
			}
			calls = 0
			plain, plainErr := program.Evaluate(0, Retry)
			if plain != result || !errors.Is(plainErr, broken) || calls != 2 {
				t.Fatalf("Evaluate disagrees: %+v, %v, calls %d", plain, plainErr, calls)
			}
		}
	}
}

func TestAppendTraceGroups(t *testing.T) {
	var calls int
	match := CustomKey(func(int) (bool, error) { calls++; return true, nil })
	miss := CustomKey(func(int) (bool, error) { calls++; return false, nil })
	program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{All(match, Any(miss, match))}})
	if err != nil {
		t.Fatal(err)
	}
	result, trace, err := program.AppendTrace(nil, 0, None)
	if err != nil || !result.Matched || calls != 3 || !slices.Equal(trace, []TraceEntry{{Matched: true}}) {
		t.Fatalf("group trace = %+v, %+v, %v, calls %d", result, trace, err, calls)
	}
	broken := errors.New("nested failure")
	program, err = Compile(Chain[int]{Status: Success, Keys: []Key[int]{All(match, Not(CustomKey(func(int) (bool, error) { return true, broken })))}})
	if err != nil {
		t.Fatal(err)
	}
	result, trace, err = program.AppendTrace(nil, 0, None)
	if !errors.Is(err, broken) || result.Matched || len(trace) != 1 || !errors.Is(trace[0].Err, broken) || !strings.Contains(trace[0].Err.Error(), "group key 1: group key 0:") {
		t.Fatalf("nested failing trace = %+v, %+v, %v", result, trace, err)
	}
}

func TestAppendTraceNilAndEmpty(t *testing.T) {
	empty, err := Compile(Chain[int]{Status: Success, Mode: And}, Chain[int]{Status: Fail, Mode: Or})
	if err != nil {
		t.Fatal(err)
	}
	var nilProgram *Program[int]
	for _, program := range []*Program[int]{nilProgram, new(Program[int]), empty} {
		dst := []TraceEntry{{Chain: 7, Key: 3, Matched: true}}
		result, trace, err := program.AppendTrace(dst, 0, Ban)
		if result != (Result{Status: Ban, Chain: -1}) || !slices.Equal(trace, dst) || &trace[0] != &dst[0] {
			t.Fatalf("empty/nil AppendTrace = %+v, %+v, %v", result, trace, err)
		}
		if program == nil && !errors.Is(err, ErrNilProgram) || program != nil && err != nil {
			t.Fatalf("empty/nil error = %v", err)
		}
		_, trace, _ = program.AppendTrace(nil, 0, None)
		if trace != nil {
			t.Fatalf("nil destination became non-nil: %+v", trace)
		}
	}
}

func TestAppendTraceAllocationsAndConcurrency(t *testing.T) {
	selector := func(value int64) (int64, bool) { return value, true }
	program, err := Compile(
		Chain[int64]{Status: Success, Mode: And, Keys: []Key[int64]{IntKey(selector, GreaterThan, 10), IntKey(selector, LessThan, 20)}},
		Chain[int64]{Status: Custom, Mode: Or, Keys: []Key[int64]{IntKey(selector, EqualTo, 5), IntKey(selector, EqualTo, 6)}},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		input int64
		want  Result
		count int
	}{
		{"first_match", 15, Result{Status: Success, Matched: true, Chain: 0}, 2},
		{"second_match", 5, Result{Status: Custom, Matched: true, Chain: 1}, 2},
		{"all_miss", 100, Result{Status: None, Chain: -1}, 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]TraceEntry, 0, 4)
			if got := testing.AllocsPerRun(1000, func() {
				result, trace, err := program.AppendTrace(dst, tt.input, None)
				if err != nil || result != tt.want || len(trace) != tt.count {
					t.Fatalf("AppendTrace = %+v, %+v, %v", result, trace, err)
				}
			}); got != 0 {
				t.Fatalf("AppendTrace allocated %g times; want 0", got)
			}
		})
	}
	t.Run("pooled_destination", func(t *testing.T) {
		pool := sync.Pool{New: func() any { return new([4]TraceEntry) }}
		storage := pool.Get().(*[4]TraceEntry)
		if got := testing.AllocsPerRun(1000, func() {
			result, trace, err := program.AppendTrace(storage[:0], 100, None)
			if err != nil || result.Matched || len(trace) != 4 {
				t.Fatalf("pooled trace = %+v, %+v, %v", result, trace, err)
			}
		}); got != 0 {
			t.Fatalf("pooled AppendTrace allocated %g times; want 0", got)
		}
		clear(storage[:])
		pool.Put(storage)
	})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			var storage [4]TraceEntry
			for range 100 {
				for _, input := range []int64{5, 6, 15, 100} {
					want, err := program.Evaluate(input, None)
					if err != nil {
						t.Error(err)
						return
					}
					result, trace, err := program.AppendTrace(storage[:0], input, None)
					if err != nil || result != want || len(trace) == 0 {
						t.Errorf("concurrent AppendTrace = %+v, %+v, %v", result, trace, err)
						return
					}
				}
			}
		})
	}
	workers.Wait()
}

func ExampleProgram_AppendTrace() {
	selector := func(value int64) (int64, bool) { return value, true }
	program, err := Compile(Chain[int64]{Status: Success, Mode: And, Keys: []Key[int64]{
		IntKey(selector, GreaterThanOrEqualTo, 200),
		IntKey(selector, LessThan, 300),
	}})
	if err != nil {
		panic(err)
	}
	var storage [2]TraceEntry
	result, trace, err := program.AppendTrace(storage[:0], 204, None)
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Status)
	for _, entry := range trace {
		fmt.Println(entry.Chain, entry.Key, entry.Matched)
	}
	// Output:
	// SUCCESS
	// 0 0 true
	// 0 1 true
}
