package keycheck

import (
	"fmt"
	"testing"
)

// BenchmarkEvaluateGroups measures reused nested and threshold groups with 16 conditions.
func BenchmarkEvaluateGroups(b *testing.B) {
	keys := make([]Key[[16]bool], 16)
	for i := range keys {
		keys[i] = BoolKey(func(input [16]bool) (bool, bool) { return input[i], true }, Is, true)
	}
	var (
		nestedInput    [16]bool
		thresholdInput [16]bool
	)
	for i := range nestedInput {
		nestedInput[i] = i%4 == 3
		thresholdInput[i] = i%2 == 1
	}
	for _, tc := range []struct {
		name  string
		key   Key[[16]bool]
		input [16]bool
	}{
		{"nested/all_any_last", All(Any(keys[:4]...), Any(keys[4:8]...), Any(keys[8:12]...), Any(keys[12:]...)), nestedInput},
		{"threshold/at_least_8_last", AtLeast(8, keys...), thresholdInput},
		{"threshold/exactly_8", Exactly(8, keys...), thresholdInput},
	} {
		b.Run(tc.name, func(b *testing.B) {
			program := benchmarkCompile(b, Or, []Key[[16]bool]{tc.key})
			benchmarkEvaluate(b, program, tc.input, true)
		})
	}
}

// BenchmarkAppendMatches measures reuse of caller-owned result storage across 16 chains.
func BenchmarkAppendMatches(b *testing.B) {
	chains := make([]Chain[int64], 16)
	for i := range chains {
		chains[i] = Chain[int64]{
			Status: Success,
			Keys: []Key[int64]{IntKey(
				func(value int64) (int64, bool) { return value, true },
				GreaterThanOrEqualTo,
				int64(i),
			)},
		}
	}
	for _, count := range []int{0, 8, 16} {
		b.Run(fmt.Sprintf("matches=%d", count), func(b *testing.B) {
			program, err := Compile(chains...)
			if err != nil {
				b.Fatal(err)
			}
			results := make([]Result, 0, len(chains))
			input := int64(count - 1)
			b.ReportAllocs()
			for b.Loop() {
				results, err = program.AppendMatches(results[:0], input)
			}
			if err != nil || len(results) != count {
				b.Fatalf("AppendMatches returned %d results, %v; want %d results", len(results), err, count)
			}
			for i, result := range results {
				if result != (Result{Status: Success, Matched: true, Chain: i}) {
					b.Fatalf("result %d = %+v; want matching chain %d", i, result, i)
				}
			}
		})
	}
}

// BenchmarkCompareKey measures runtime operand selection with reused integer comparisons.
func BenchmarkCompareKey(b *testing.B) {
	for _, count := range []int{1, 16} {
		keys := make([]Key[[2]uint64], count)
		for i := range keys {
			keys[i] = CompareKey(
				func(input [2]uint64) (uint64, bool) { return input[0] + uint64(i), true },
				LessThan,
				func(input [2]uint64) (uint64, bool) { return input[1], true },
			)
		}
		for _, tc := range []struct {
			name    string
			input   [2]uint64
			matched bool
		}{
			{"all", [2]uint64{1, uint64(count + 1)}, true},
			{"last_miss", [2]uint64{1, uint64(count)}, false},
		} {
			b.Run(fmt.Sprintf("keys=%d/%s", count, tc.name), func(b *testing.B) {
				program := benchmarkCompile(b, And, keys)
				benchmarkEvaluate(b, program, tc.input, tc.matched)
			})
		}
	}
}

// BenchmarkAppendTrace measures first-match tracing with caller-owned storage.
func BenchmarkAppendTrace(b *testing.B) {
	keys := make([]Key[int], 16)
	for i := range keys {
		keys[i] = CustomKey(func(value int) (bool, error) { return value == i, nil })
	}
	program := benchmarkCompile(b, Or, keys)
	var storage [16]TraceEntry
	var (
		result Result
		trace  []TraceEntry
		err    error
	)
	b.ReportAllocs()
	for b.Loop() {
		result, trace, err = program.AppendTrace(storage[:0], 15, None)
	}
	if err != nil || !result.Matched || len(trace) != 16 || trace[15].Key != 15 || !trace[15].Matched {
		b.Fatalf("AppendTrace = %+v, %d entries, %v", result, len(trace), err)
	}
}
