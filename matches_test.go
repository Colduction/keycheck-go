package keycheck

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestAppendMatches(t *testing.T) {
	selector := func(value int64) (int64, bool) { return value, true }
	program, err := Compile(
		Chain[int64]{Status: Success, Mode: And},
		Chain[int64]{Status: "positive", Keys: []Key[int64]{IntKey(selector, GreaterThan, 0)}},
		Chain[int64]{Status: "negative", Keys: []Key[int64]{IntKey(selector, LessThan, 0)}},
		Chain[int64]{Status: "small", Keys: []Key[int64]{IntKey(selector, LessThan, 10)}},
	)
	if err != nil {
		t.Fatal(err)
	}
	storage := make([]Result, 1, 4)
	storage[0] = Result{Status: "existing", Chain: -1}
	want := []Result{storage[0], {Status: "positive", Matched: true, Chain: 1}, {Status: "small", Matched: true, Chain: 3}}
	got, err := program.AppendMatches(storage, 3)
	if err != nil || !slices.Equal(got, want) || &got[0] != &storage[0] {
		t.Fatalf("AppendMatches = %+v, %v; want %+v sharing storage", got, err, want)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		got, err = program.AppendMatches(storage, 3)
	}); allocations != 0 {
		t.Fatalf("AppendMatches allocated %g times", allocations)
	}
	if err != nil || !slices.Equal(got, want) {
		t.Fatal("repeated AppendMatches changed result")
	}
	var empty Program[int64]
	got, err = empty.AppendMatches(nil, 3)
	if got != nil || err != nil {
		t.Fatalf("empty AppendMatches = %+v, %v", got, err)
	}
	var absent *Program[int64]
	got, err = absent.AppendMatches(storage, 3)
	if !slices.Equal(got, storage) || !errors.Is(err, ErrNilProgram) {
		t.Fatalf("nil AppendMatches = %+v, %v", got, err)
	}
}

func TestAppendMatchesPartialError(t *testing.T) {
	failure := errors.New("predicate failed")
	program, err := Compile(
		Chain[int]{Status: Success, Keys: []Key[int]{CustomKey(func(int) (bool, error) { return true, nil })}},
		Chain[int]{Status: Fail, Keys: []Key[int]{CustomKey(func(int) (bool, error) { return true, failure })}},
		Chain[int]{Status: Invalid, Keys: []Key[int]{CustomKey(func(int) (bool, error) { t.Fatal("evaluated after error"); return true, nil })}},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := program.AppendMatches(nil, 0)
	var location *EvalError
	if !errors.Is(err, failure) || !errors.As(err, &location) || location.Chain != 1 || location.Key != 0 || !slices.Equal(got, []Result{{Status: Success, Matched: true, Chain: 0}}) {
		t.Fatalf("AppendMatches = %+v, %v", got, err)
	}
}

func ExampleProgram_AppendMatches() {
	selector := func(value int64) (int64, bool) { return value, true }
	program, err := Compile(
		Chain[int64]{Status: "positive", Keys: []Key[int64]{IntKey(selector, GreaterThan, 0)}},
		Chain[int64]{Status: "small", Keys: []Key[int64]{IntKey(selector, LessThan, 10)}},
	)
	if err != nil {
		panic(err)
	}
	var storage [2]Result
	matches, err := program.AppendMatches(storage[:0], 3)
	if err != nil {
		panic(err)
	}
	for _, match := range matches {
		fmt.Println(match.Status)
	}
	// Output:
	// positive
	// small
}
