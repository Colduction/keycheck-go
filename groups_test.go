package keycheck

import (
	"errors"
	"math/bits"
	"strings"
	"sync"
	"testing"
)

func TestGroupsTruthTables(t *testing.T) {
	keys := make([]Key[uint8], 3)
	for i := range keys {
		keys[i] = CustomKey(func(value uint8) (bool, error) { return value&(1<<i) != 0, nil })
	}
	for input := range uint8(8) {
		count := bits.OnesCount8(input)
		assertKeyMatch(t, All(keys...), input, count == len(keys))
		assertKeyMatch(t, Any(keys...), input, count > 0)
		assertKeyMatch(t, Not(All(keys...)), input, count != len(keys))
		for threshold := range len(keys) + 1 {
			assertKeyMatch(t, AtLeast(threshold, keys...), input, count >= threshold)
			assertKeyMatch(t, Exactly(threshold, keys...), input, count == threshold)
		}
	}
	assertKeyMatch(t, All[int](), 0, true)
	assertKeyMatch(t, Any[int](), 0, false)
	assertKeyMatch(t, AtLeast[int](0), 0, true)
	assertKeyMatch(t, Exactly[int](0), 0, true)
	assertKeyMatch(t, Not(Any[int]()), 0, true)
}

func TestGroupsShortCircuit(t *testing.T) {
	tests := []struct {
		name   string
		group  func(...Key[int]) Key[int]
		values []bool
		calls  int
		want   bool
	}{
		{"all", All[int], []bool{true, false, true}, 2, false},
		{"any", Any[int], []bool{false, true, false}, 2, true},
		{"at_least_enough", func(keys ...Key[int]) Key[int] { return AtLeast(2, keys...) }, []bool{true, true, false}, 2, true},
		{"at_least_impossible", func(keys ...Key[int]) Key[int] { return AtLeast(3, keys...) }, []bool{true, false, true}, 2, false},
		{"at_least_zero", func(keys ...Key[int]) Key[int] { return AtLeast(0, keys...) }, []bool{true, false}, 0, true},
		{"exactly_excess", func(keys ...Key[int]) Key[int] { return Exactly(1, keys...) }, []bool{true, true, false}, 2, false},
		{"exactly_impossible", func(keys ...Key[int]) Key[int] { return Exactly(2, keys...) }, []bool{false, false, true}, 2, false},
		{"exactly_zero_miss", func(keys ...Key[int]) Key[int] { return Exactly(0, keys...) }, []bool{false, true, false}, 2, false},
		{"exactly_zero_match", func(keys ...Key[int]) Key[int] { return Exactly(0, keys...) }, []bool{false, false}, 2, true},
		{"exactly_match", func(keys ...Key[int]) Key[int] { return Exactly(2, keys...) }, []bool{true, false, true}, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			keys := make([]Key[int], len(tt.values))
			for i, value := range tt.values {
				keys[i] = CustomKey(func(int) (bool, error) {
					if calls != i {
						t.Fatalf("child %d called after %d calls", i, calls)
					}
					calls++
					if calls > tt.calls {
						return false, errors.New("child should have been skipped")
					}
					return value, nil
				})
			}
			assertKeyMatch(t, tt.group(keys...), 0, tt.want)
			if calls != tt.calls {
				t.Fatalf("calls = %d, want %d", calls, tt.calls)
			}
		})
	}
}

func TestGroupsCompileValidation(t *testing.T) {
	match := CustomKey(func(int) (bool, error) { return true, nil })
	miss := CustomKey(func(int) (bool, error) { return false, nil })
	var invalid Key[int]
	for _, key := range []Key[int]{
		All(miss, invalid), Any(match, invalid), Not(invalid), AtLeast(0, invalid), Exactly(0, match, invalid),
	} {
		program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{key}})
		if program != nil || !errors.Is(err, ErrInvalidKey) || !strings.Contains(err.Error(), "group key ") {
			t.Fatalf("Compile = %v, %v; want invalid child", program, err)
		}
	}
	for _, key := range []Key[int]{AtLeast(-1, match), AtLeast(2, match), Exactly(-1, match), Exactly(2, match)} {
		program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{key}})
		if program != nil || !errors.Is(err, ErrInvalidThreshold) {
			t.Fatalf("Compile = %v, %v; want invalid threshold", program, err)
		}
	}
}

func TestGroupsErrorPaths(t *testing.T) {
	broken := errors.New("child failed")
	match := CustomKey(func(int) (bool, error) { return true, nil })
	miss := CustomKey(func(int) (bool, error) { return false, nil })
	unreached := CustomKey(func(int) (bool, error) { t.Fatal("child evaluated after error"); return false, nil })
	for _, result := range []bool{false, true} {
		failure := CustomKey(func(int) (bool, error) { return result, broken })
		for _, key := range []Key[int]{
			All(match, failure, unreached), Any(miss, failure, unreached), Not(failure), AtLeast(2, match, failure, unreached), Exactly(1, miss, failure, unreached),
		} {
			program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{key}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := program.Evaluate(0, None)
			if got != (Result{Status: None, Chain: -1}) || !errors.Is(err, broken) || !strings.Contains(err.Error(), "group key ") {
				t.Fatalf("Evaluate = %+v, %v; want child error and fallback", got, err)
			}
		}
	}
	program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{
		All(match, Any(miss, Not(CustomKey(func(int) (bool, error) { return true, broken })))),
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = program.Evaluate(0, None)
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "group key 1: group key 1: group key 0:") {
		t.Fatalf("nested error path = %v", err)
	}
}

func TestNotMissingValue(t *testing.T) {
	key := StringKey(func(int) (string, bool) { return "", false }, Contains, "ready")
	assertKeyMatch(t, Not(key), 0, true)
	assertKeyMatch(t, Not(Not(key)), 0, false)
}

func TestGroupsOwnChildren(t *testing.T) {
	for _, group := range []func(...Key[int]) Key[int]{
		All[int], Any[int],
		func(keys ...Key[int]) Key[int] { return AtLeast(1, keys...) },
		func(keys ...Key[int]) Key[int] { return Exactly(1, keys...) },
	} {
		children := []Key[int]{CustomKey(func(int) (bool, error) { return true, nil })}
		key := group(children...)
		children[0] = CustomKey(func(int) (bool, error) { return false, nil })
		program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{key}})
		if err != nil {
			t.Fatal(err)
		}
		children[0] = Key[int]{}
		result, err := program.Evaluate(0, None)
		if err != nil || !result.Matched {
			t.Fatalf("child mutation changed group: %+v, %v", result, err)
		}
		assertKeyMatch(t, key, 0, true)
	}
}

func TestGroupsNestingLimit(t *testing.T) {
	leaf := CustomKey(func(int) (bool, error) { return true, nil })
	for _, depth := range []int{64, 65} {
		key := leaf
		for i := 1; i < depth; i++ {
			key = Not(key)
		}
		program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{key}})
		if depth == 65 {
			if program != nil || !errors.Is(err, ErrNestingTooDeep) {
				t.Fatalf("depth %d: Compile = %v, %v; want nesting error", depth, program, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		result, err := program.Evaluate(0, None)
		if err != nil || result.Matched {
			t.Fatalf("depth %d: Evaluate = %+v, %v", depth, result, err)
		}
	}
	key := AtLeast(0, leaf)
	for range 63 {
		key = AtLeast(0, key)
	}
	if _, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{key}}); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("unreachable nested child error = %v", err)
	}
}

func TestGroupsAllocationsAndConcurrency(t *testing.T) {
	selector := func(value int64) (int64, bool) { return value, true }
	positive := IntKey(selector, GreaterThan, 0)
	lessThanTen := IntKey(selector, LessThan, 10)
	for _, key := range []Key[int64]{
		All(positive, lessThanTen), Any(IntKey(selector, EqualTo, 5), IntKey(selector, EqualTo, 6)),
		Not(IntKey(selector, EqualTo, 20)), AtLeast(2, positive, lessThanTen), Exactly(2, positive, lessThanTen),
	} {
		assertKeyAllocations(t, key, int64(5), int64(20))
	}
	program, err := Compile(Chain[int64]{Status: Success, Keys: []Key[int64]{
		All(positive, Any(IntKey(selector, EqualTo, 5), IntKey(selector, EqualTo, 6)), Not(IntKey(selector, EqualTo, 6)), Exactly(2, positive, lessThanTen)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 100 {
				for _, input := range []int64{-1, 5, 6, 20} {
					result, err := program.Evaluate(input, None)
					if err != nil || result.Matched != (input == 5) {
						t.Errorf("input %d: Evaluate = %+v, %v", input, result, err)
						return
					}
				}
			}
		})
	}
	workers.Wait()
}

func FuzzGroups(f *testing.F) {
	f.Add([]byte{1, 0, 1}, uint8(0), uint8(1), false)
	f.Add([]byte{}, uint8(1), uint8(0), false)
	f.Add([]byte{0, 0}, uint8(3), uint8(0), true)
	f.Add([]byte{1}, uint8(2), uint8(2), false)
	f.Add([]byte{1, 0}, uint8(2), uint8(1), false)
	f.Fuzz(func(t *testing.T, values []byte, operation, threshold uint8, negate bool) {
		if len(values) > 64 {
			return
		}
		keys := make([]Key[bool], len(values))
		var matches int
		for i, value := range values {
			matched := value&1 != 0
			if matched {
				matches++
			}
			keys[i] = CustomKey(func(bool) (bool, error) { return matched, nil })
		}
		count := int(threshold % 67)
		var key Key[bool]
		var want bool
		valid := true
		switch operation % 4 {
		case 0:
			key, want = All(keys...), matches == len(keys)
		case 1:
			key, want = Any(keys...), matches > 0
		case 2:
			key, want, valid = AtLeast(count, keys...), matches >= count, count <= len(keys)
		case 3:
			key, want, valid = Exactly(count, keys...), matches == count, count <= len(keys)
		}
		if negate {
			key, want = Not(key), !want
		}
		program, err := Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{key}})
		if !valid {
			if program != nil || !errors.Is(err, ErrInvalidThreshold) {
				t.Fatalf("invalid threshold: Compile = %v, %v", program, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		result, err := program.Evaluate(false, None)
		if err != nil || result.Matched != want {
			t.Fatalf("Evaluate = %+v, %v; want match %v", result, err, want)
		}
	})
}
