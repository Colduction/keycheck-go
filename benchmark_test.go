package keycheck

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func benchmarkCompile[T any](b *testing.B, mode Mode, keys []Key[T]) *Program[T] {
	b.Helper()
	program, err := Compile(Chain[T]{Status: Success, Mode: mode, Keys: keys})
	if err != nil {
		b.Fatal(err)
	}
	return program
}

func benchmarkString(value string) (string, bool) {
	return value, true
}

func benchmarkBytes(value []byte) ([]byte, bool) {
	return value, true
}

func benchmarkEvaluate[T any](b *testing.B, program *Program[T], input T, matched bool) {
	b.Helper()
	b.ReportAllocs()
	var (
		result Result
		err    error
	)
	for b.Loop() {
		result, err = program.Evaluate(input, None)
	}
	if err != nil || result.Matched != matched {
		b.Fatalf("Evaluate = %+v, %v; want matched %v", result, err, matched)
	}
}

// BenchmarkEvaluateBody measures reused programs with borrowed string and byte bodies.
func BenchmarkEvaluateBody(b *testing.B) {
	cases := []struct {
		size     int
		keys     int
		position string
		match    int
	}{
		{256, 1, "first", 0},
		{256, 1, "miss", -1},
		{4096, 16, "first", 0},
		{4096, 16, "middle", 8},
		{4096, 16, "last", 15},
		{4096, 16, "miss", -1},
		{65536, 128, "last", 127},
		{65536, 128, "miss", -1},
	}
	for _, tc := range cases {
		body := strings.Repeat("x", tc.size-len("present-token")) + "present-token"
		name := fmt.Sprintf("bytes=%d/keys=%d/%s", tc.size, tc.keys, tc.position)
		b.Run("string/"+name, func(b *testing.B) {
			keys := make([]Key[string], tc.keys)
			for i := range keys {
				right := "absent-" + strconv.Itoa(i)
				if i == tc.match {
					right = "present-token"
				}
				keys[i] = StringKey(benchmarkString, Contains, right)
			}
			program := benchmarkCompile(b, Or, keys)
			b.SetBytes(int64(tc.size))
			benchmarkEvaluate(b, program, body, tc.match >= 0)
		})
		b.Run("bytes/"+name, func(b *testing.B) {
			keys := make([]Key[[]byte], tc.keys)
			for i := range keys {
				right := "absent-" + strconv.Itoa(i)
				if i == tc.match {
					right = "present-token"
				}
				keys[i] = BytesKey(benchmarkBytes, Contains, []byte(right))
			}
			program := benchmarkCompile(b, Or, keys)
			b.SetBytes(int64(tc.size))
			benchmarkEvaluate(b, program, []byte(body), tc.match >= 0)
		})
	}
}

// BenchmarkEvaluateCallbacks isolates short-circuit dispatch with allocation-free callbacks.
func BenchmarkEvaluateCallbacks(b *testing.B) {
	for _, count := range []int{1, 16, 128} {
		for _, tc := range []struct {
			name    string
			mode    Mode
			input   int
			matched bool
		}{
			{"or/first", Or, 0, true},
			{"or/last", Or, count - 1, true},
			{"or/miss", Or, -1, false},
			{"and/first", And, 0, false},
			{"and/last", And, count - 1, false},
			{"and/all", And, -1, true},
		} {
			b.Run(fmt.Sprintf("%s/keys=%d", tc.name, count), func(b *testing.B) {
				keys := make([]Key[int], count)
				for i := range keys {
					if tc.mode == Or {
						keys[i] = CustomKey(func(value int) (bool, error) { return value == i, nil })
					} else {
						keys[i] = CustomKey(func(value int) (bool, error) { return value != i, nil })
					}
				}
				benchmarkEvaluate(b, benchmarkCompile(b, tc.mode, keys), tc.input, tc.matched)
			})
		}
	}
}

// BenchmarkCompile measures program construction, including cold regex compilation.
func BenchmarkCompile(b *testing.B) {
	for _, count := range []int{1, 16, 128} {
		for _, kind := range []string{"literal", "regex/repeated", "regex/unique"} {
			b.Run(fmt.Sprintf("%s/keys=%d", kind, count), func(b *testing.B) {
				keys := make([]Key[string], count)
				for i := range keys {
					operator, right := Contains, "present-token"
					if kind != "literal" {
						operator, right = MatchesRegex, "present-[a-z]+-0$"
						if kind == "regex/unique" {
							right = "present-[a-z]+-" + strconv.Itoa(i) + "$"
						}
					}
					keys[i] = StringKey(benchmarkString, operator, right)
				}
				chain := Chain[string]{Status: Success, Mode: Or, Keys: keys}
				b.ReportAllocs()
				var (
					program *Program[string]
					err     error
				)
				for b.Loop() {
					program, err = Compile(chain)
				}
				if err != nil {
					b.Fatal(err)
				}
				runtime.KeepAlive(program)
			})
		}
	}
}

// BenchmarkEvaluateRegex measures matching after compilation and one warm-up evaluation.
func BenchmarkEvaluateRegex(b *testing.B) {
	for _, size := range []int{256, 4096, 65536} {
		body := strings.Repeat("x", size-len("present-token")) + "present-token"
		b.Run(fmt.Sprintf("string/bytes=%d", size), func(b *testing.B) {
			program := benchmarkCompile(b, Or, []Key[string]{StringKey(benchmarkString, MatchesRegex, "present-[a-z]+$")})
			if result, err := program.Evaluate(body, None); err != nil || !result.Matched {
				b.Fatalf("warm-up Evaluate = %+v, %v; want match", result, err)
			}
			b.SetBytes(int64(size))
			benchmarkEvaluate(b, program, body, true)
		})
		b.Run(fmt.Sprintf("bytes/bytes=%d", size), func(b *testing.B) {
			input := []byte(body)
			program := benchmarkCompile(b, Or, []Key[[]byte]{BytesKey(benchmarkBytes, MatchesRegex, []byte("present-[a-z]+$"))})
			if result, err := program.Evaluate(input, None); err != nil || !result.Matched {
				b.Fatalf("warm-up Evaluate = %+v, %v; want match", result, err)
			}
			b.SetBytes(int64(size))
			benchmarkEvaluate(b, program, input, true)
		})
	}
}

// BenchmarkEvaluateRegexAfterGC measures a first match after two forced garbage collections.
// Run it with -benchtime=1x; larger iteration counts are skipped to bound diagnostic work.
// Setup and garbage collection time and allocations are excluded from the reported match statistics.
func BenchmarkEvaluateRegexAfterGC(b *testing.B) {
	if b.N != 1 {
		b.Skip("use -benchtime=1x for the bounded post-GC diagnostic")
	}
	b.StopTimer()
	input := []byte(strings.Repeat("x", 4096-len("present-token")) + "present-token")
	program := benchmarkCompile(b, Or, []Key[[]byte]{BytesKey(benchmarkBytes, MatchesRegex, []byte("present-[a-z]+$"))})
	if result, err := program.Evaluate(input, None); err != nil || !result.Matched {
		b.Fatalf("warm-up Evaluate = %+v, %v; want match", result, err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	var (
		result Result
		err    error
	)
	b.ResetTimer()
	for range b.N {
		runtime.GC()
		runtime.GC()
		b.StartTimer()
		result, err = program.Evaluate(input, None)
		b.StopTimer()
	}
	if err != nil || !result.Matched {
		b.Fatalf("Evaluate = %+v, %v; want match", result, err)
	}
}

// BenchmarkEvaluateParallel measures aggregate throughput with one program shared by all workers.
func BenchmarkEvaluateParallel(b *testing.B) {
	input := []byte(strings.Repeat("x", 4096-len("present-token")) + "present-token")
	for _, tc := range []struct {
		name     string
		operator Operator
		right    string
	}{
		{"literal", Contains, "present-token"},
		{"regex", MatchesRegex, "present-[a-z]+$"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			program := benchmarkCompile(b, Or, []Key[[]byte]{BytesKey(benchmarkBytes, tc.operator, []byte(tc.right))})
			if result, err := program.Evaluate(input, None); err != nil || !result.Matched {
				b.Fatalf("warm-up Evaluate = %+v, %v; want match", result, err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				var (
					result    Result
					err       error
					evaluated bool
				)
				for pb.Next() {
					result, err = program.Evaluate(input, None)
					evaluated = true
				}
				if evaluated && (err != nil || !result.Matched) {
					b.Errorf("Evaluate = %+v, %v; want match", result, err)
				}
				runtime.KeepAlive(result)
			})
		})
	}
}
