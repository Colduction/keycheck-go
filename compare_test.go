package keycheck

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"testing"
)

// TestCompareKey checks all supported operators against both runtime operands.
func TestCompareKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   Operator
		want [3]bool
	}{
		{"equal", EqualTo, [3]bool{false, true, false}},
		{"not_equal", NotEqualTo, [3]bool{true, false, true}},
		{"less", LessThan, [3]bool{true, false, false}},
		{"less_or_equal", LessThanOrEqualTo, [3]bool{true, true, false}},
		{"greater", GreaterThan, [3]bool{false, false, true}},
		{"greater_or_equal", GreaterThanOrEqualTo, [3]bool{false, true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := CompareKey(
				func(v [2]int) (int, bool) { return v[0], true },
				tc.op,
				func(v [2]int) (int, bool) { return v[1], true },
			)
			program, err := Compile(Chain[[2]int]{Status: Success, Keys: []Key[[2]int]{key}})
			if err != nil {
				t.Fatal(err)
			}
			for i, input := range [][2]int{{-9, 4}, {4, 4}, {8, -3}} {
				got, err := program.Evaluate(input, None)
				if err != nil || got.Matched != tc.want[i] {
					t.Fatalf("Evaluate(%v) = %+v, %v; want matched %v", input, got, err, tc.want[i])
				}
			}
		})
	}
}

// TestCompareKeySelectorOrder checks one call per reached selector and missing operands.
func TestCompareKeySelectorOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		left  bool
		right bool
		calls []string
		want  bool
	}{
		{"both_present", true, true, []string{"left", "right"}, true},
		{"left_missing", false, true, []string{"left"}, false},
		{"right_missing", true, false, []string{"left", "right"}, false},
		{"both_missing", false, false, []string{"left"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			key := CompareKey(
				func(v [2]int) (int, bool) {
					calls = append(calls, "left")
					return v[0], tc.left
				},
				NotEqualTo,
				func(v [2]int) (int, bool) {
					calls = append(calls, "right")
					return v[1], tc.right
				},
			)
			assertKeyMatch(t, key, [2]int{1, 2}, tc.want)
			if !slices.Equal(calls, tc.calls) {
				t.Fatalf("selector calls = %v; want %v", calls, tc.calls)
			}
		})
	}
}

// TestCompareKeyConfiguration checks eager validation without invoking selectors.
func TestCompareKeyConfiguration(t *testing.T) {
	selector := func(int) (int, bool) {
		t.Fatal("Compile called selector")
		return 0, false
	}
	for _, tc := range []struct {
		name  string
		left  Selector[int, int]
		op    Operator
		right Selector[int, int]
		want  error
	}{
		{"nil_left", nil, EqualTo, selector, ErrInvalidKey},
		{"nil_right", selector, EqualTo, nil, ErrInvalidKey},
		{"both_nil", nil, EqualTo, nil, ErrInvalidKey},
		{"contains", selector, Contains, selector, ErrInvalidOperator},
		{"existence", selector, Exists, selector, ErrInvalidOperator},
		{"regex", selector, MatchesRegex, selector, ErrInvalidOperator},
		{"boolean", selector, Is, selector, ErrInvalidOperator},
		{"unknown", selector, Operator(255), selector, ErrInvalidOperator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := CompareKey(tc.left, tc.op, tc.right)
			program, err := Compile(Chain[int]{Status: Success, Keys: []Key[int]{key}})
			var location *CompileError
			if program != nil || !errors.Is(err, tc.want) || !errors.As(err, &location) {
				t.Fatalf("Compile = %v, %v; want nil and %v", program, err, tc.want)
			}
			if location.Chain != 0 || location.Key != 0 {
				t.Fatalf("error location = %+v; want chain 0 key 0", location)
			}
		})
	}
}

func assertCompareOrdered[V cmp.Ordered](t *testing.T, lower, upper V) {
	t.Helper()
	key := CompareKey(
		func(v [2]V) (V, bool) { return v[0], true },
		LessThan,
		func(v [2]V) (V, bool) { return v[1], true },
	)
	assertKeyMatch(t, key, [2]V{lower, upper}, true)
	assertKeyMatch(t, key, [2]V{upper, lower}, false)
	assertKeyMatch(t, key, [2]V{lower, lower}, false)
}

// TestCompareKeyOrderedTypes covers supported underlying types without lossy conversion.
func TestCompareKeyOrderedTypes(t *testing.T) {
	type count uint64
	type label string
	type temperature float32
	assertCompareOrdered(t, int(math.MinInt), int(math.MaxInt))
	assertCompareOrdered(t, int8(math.MinInt8), int8(math.MaxInt8))
	assertCompareOrdered(t, int16(math.MinInt16), int16(math.MaxInt16))
	assertCompareOrdered(t, int32(math.MinInt32), int32(math.MaxInt32))
	assertCompareOrdered(t, int64(math.MinInt64), int64(math.MaxInt64))
	assertCompareOrdered(t, uint(0), uint(math.MaxUint))
	assertCompareOrdered(t, uint8(0), uint8(math.MaxUint8))
	assertCompareOrdered(t, uint16(0), uint16(math.MaxUint16))
	assertCompareOrdered(t, uint32(0), uint32(math.MaxUint32))
	assertCompareOrdered(t, uint64(math.MaxInt64)+1, uint64(math.MaxUint64))
	assertCompareOrdered(t, uintptr(0), ^uintptr(0))
	assertCompareOrdered(t, float32(-math.MaxFloat32), float32(math.MaxFloat32))
	assertCompareOrdered(t, -math.MaxFloat64, math.MaxFloat64)
	assertCompareOrdered(t, "Z", "a")
	assertCompareOrdered(t, "a", "aa")
	assertCompareOrdered(t, "\x00", "\xff")
	assertCompareOrdered(t, count(math.MaxUint64-1), count(math.MaxUint64))
	assertCompareOrdered(t, label("alpha"), label("beta"))
	assertCompareOrdered(t, temperature(-0.25), temperature(0.25))
}

// TestCompareKeyFloatSemantics checks native NaN, infinity, and signed-zero behavior.
func TestCompareKeyFloatSemantics(t *testing.T) {
	for _, op := range []Operator{EqualTo, NotEqualTo, LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo} {
		key := CompareKey(
			func(v [2]float64) (float64, bool) { return v[0], true },
			op,
			func(v [2]float64) (float64, bool) { return v[1], true },
		)
		for _, input := range [][2]float64{{math.NaN(), 1}, {1, math.NaN()}, {math.NaN(), math.NaN()}} {
			assertKeyMatch(t, key, input, op == NotEqualTo)
		}
	}
	assertCompareOrdered(t, math.Inf(-1), math.Inf(1))
	equal := CompareKey(
		func(v [2]float64) (float64, bool) { return v[0], true },
		EqualTo,
		func(v [2]float64) (float64, bool) { return v[1], true },
	)
	assertKeyMatch(t, equal, [2]float64{math.Copysign(0, -1), 0}, true)
	assertKeyMatch(t, equal, [2]float64{math.Inf(1), math.Inf(1)}, true)
}

// TestCompareKeyAllocations checks repeated evaluation with allocation-free selectors.
func TestCompareKeyAllocations(t *testing.T) {
	key := CompareKey(
		func(v [2]uint64) (uint64, bool) { return v[0], true },
		GreaterThan,
		func(v [2]uint64) (uint64, bool) { return v[1], true },
	)
	program, err := Compile(Chain[[2]uint64]{Status: Success, Keys: []Key[[2]uint64]{key}})
	if err != nil {
		t.Fatal(err)
	}
	if got := testing.AllocsPerRun(1000, func() {
		result, err := program.Evaluate([2]uint64{math.MaxUint64, 1}, None)
		if err != nil || !result.Matched {
			t.Fatalf("Evaluate = %+v, %v; want match", result, err)
		}
	}); got != 0 {
		t.Fatalf("allocations = %v; want 0", got)
	}
}

// TestCompareKeyConcurrent checks one compiled program with independently owned inputs.
func TestCompareKeyConcurrent(t *testing.T) {
	key := CompareKey(
		func(v [2]int) (int, bool) { return v[0], true },
		LessThan,
		func(v [2]int) (int, bool) { return v[1], true },
	)
	program, err := Compile(Chain[[2]int]{Status: Success, Keys: []Key[[2]int]{key}})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			for i := range 100 {
				result, err := program.Evaluate([2]int{worker, i}, None)
				if err != nil || result.Matched != (worker < i) {
					t.Errorf("Evaluate(%d, %d) = %+v, %v", worker, i, result, err)
					return
				}
			}
		})
	}
	workers.Wait()
}

// ExampleCompareKey compares two fields of the same input.
func ExampleCompareKey() {
	type measurement struct {
		observed int
		limit    int
	}
	program, err := Compile(Chain[measurement]{
		Status: Success,
		Keys: []Key[measurement]{CompareKey(
			func(v measurement) (int, bool) { return v.observed, true },
			LessThanOrEqualTo,
			func(v measurement) (int, bool) { return v.limit, true },
		)},
	})
	if err != nil {
		panic(err)
	}
	result, err := program.Evaluate(measurement{observed: 12, limit: 20}, Fail)
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Status, result.Matched)
	// Output: SUCCESS true
}
