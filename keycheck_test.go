package keycheck

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestEvaluateOrderAndShortCircuit(t *testing.T) {
	for _, test := range []struct {
		name        string
		mode        Mode
		first, want bool
		calls       int
	}{
		{"or first", Or, true, true, 1},
		{"or last", Or, false, true, 2},
		{"and first", And, false, false, 1},
		{"and all", And, true, true, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			program, err := Compile(
				Chain[int]{Status: Invalid, Mode: And},
				Chain[int]{Status: Success, Mode: test.mode, Keys: []Key[int]{
					CustomKey(func(int) (bool, error) { calls++; return test.first, nil }),
					CustomKey(func(int) (bool, error) { calls++; return true, nil }),
				}},
				Chain[int]{Status: Fail, Keys: []Key[int]{CustomKey(func(int) (bool, error) {
					if test.want {
						t.Fatal("evaluated a chain after the first match")
					}
					return false, nil
				})}},
			)
			if err != nil {
				t.Fatal(err)
			}
			got, err := program.Evaluate(0, None)
			want := Result{Status: None, Chain: -1}
			if test.want {
				want = Result{Status: Success, Matched: true, Chain: 1}
			}
			if got != want || err != nil || calls != test.calls {
				t.Fatalf("Evaluate = %+v, %v, calls %d; want %+v, nil, calls %d", got, err, calls, want, test.calls)
			}
		})
	}
}

func TestCompileRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		chain Chain[int]
		err   error
		key   int
	}{
		{"mode", Chain[int]{Status: Success, Mode: Mode(255)}, ErrInvalidMode, -1},
		{"status", Chain[int]{}, ErrInvalidStatus, -1},
		{"zero key", Chain[int]{Status: Success, Keys: []Key[int]{{}}}, ErrInvalidKey, 0},
		{"nil callback", Chain[int]{Status: Success, Keys: []Key[int]{CustomKey[int](nil)}}, ErrInvalidKey, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			program, err := Compile(Chain[int]{Status: None}, test.chain)
			var location *CompileError
			if program != nil || !errors.Is(err, test.err) || !errors.As(err, &location) {
				t.Fatalf("Compile = %v, %v; want nil, %v", program, err, test.err)
			}
			if location.Chain != 1 || location.Key != test.key || location.Error() == "" {
				t.Fatalf("wrong error location: %+v", location)
			}
		})
	}
}

func TestEvaluateFallbackAndEmptyChains(t *testing.T) {
	program, err := Compile(Chain[int]{Status: Success, Mode: And}, Chain[int]{Status: Fail, Mode: Or})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Compile[int]()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*Program[int]{program, new(Program[int]), empty} {
		for _, fallback := range []Status{None, Ban, "previous", ""} {
			got, err := p.Evaluate(0, fallback)
			if got != (Result{Status: fallback, Chain: -1}) || err != nil {
				t.Fatalf("Evaluate = %+v, %v", got, err)
			}
		}
	}
	var nilProgram *Program[int]
	got, err := nilProgram.Evaluate(0, Retry)
	if got != (Result{Status: Retry, Chain: -1}) || !errors.Is(err, ErrNilProgram) {
		t.Fatalf("nil Evaluate = %+v, %v", got, err)
	}
}

func TestEvaluateCustomError(t *testing.T) {
	broken := errors.New("custom failure")
	for _, mode := range []Mode{Or, And} {
		for _, matched := range []bool{false, true} {
			program, err := Compile(Chain[int]{Status: None}, Chain[int]{Status: Success, Mode: mode, Keys: []Key[int]{
				CustomKey(func(int) (bool, error) { return mode == And, nil }),
				CustomKey(func(int) (bool, error) { return matched, broken }),
				CustomKey(func(int) (bool, error) { t.Fatal("called after error"); return true, nil }),
			}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := program.Evaluate(0, None)
			var location *EvalError
			if got != (Result{Status: None, Chain: -1}) || !errors.Is(err, broken) || !errors.As(err, &location) {
				t.Fatalf("Evaluate = %+v, %v", got, err)
			}
			if location.Chain != 1 || location.Key != 1 || location.Error() == "" {
				t.Fatalf("wrong error location: %+v", location)
			}
		}
	}
}

func TestEvaluateSkippedErrors(t *testing.T) {
	for _, mode := range []Mode{Or, And} {
		program, err := Compile(Chain[int]{Status: Success, Mode: mode, Keys: []Key[int]{
			CustomKey(func(int) (bool, error) { return mode == Or, nil }),
			CustomKey(func(int) (bool, error) { return false, errors.New("unreached") }),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := program.Evaluate(0, None); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCompileSnapshotsConfiguration(t *testing.T) {
	chains := []Chain[int]{{Status: Success, Keys: []Key[int]{CustomKey(func(int) (bool, error) { return true, nil })}}}
	program, err := Compile(chains...)
	if err != nil {
		t.Fatal(err)
	}
	chains[0].Status = Fail
	chains[0].Mode = And
	chains[0].Keys[0] = CustomKey(func(int) (bool, error) { return false, nil })
	got, err := program.Evaluate(0, None)
	if got != (Result{Status: Success, Matched: true, Chain: 0}) || err != nil {
		t.Fatalf("configuration mutation changed result: %+v, %v", got, err)
	}
}

func TestProgramConcurrentPublication(t *testing.T) {
	selector := func(value int64) (int64, bool) { return value, true }
	first, err := Compile(Chain[int64]{Status: Success, Keys: []Key[int64]{IntKey(selector, EqualTo, 42)}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(Chain[int64]{Status: Status("ready"), Keys: []Key[int64]{IntKey(selector, EqualTo, 42)}})
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[Program[int64]]
	current.Store(first)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 1000 {
				got, err := current.Load().Evaluate(42, None)
				if err != nil || !got.Matched || (got.Status != Success && got.Status != "ready") {
					t.Errorf("concurrent Evaluate = %+v, %v", got, err)
					return
				}
			}
		})
	}
	for range 1000 {
		current.Store(second)
		current.Store(first)
	}
	workers.Wait()
}

func TestCompileRegexReuse(t *testing.T) {
	var c compiler
	first, err := c.regexTest("ready[0-9]+", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.regexTest("ready[0-9]+", false)
	if err != nil || first.regex == nil || first.regex != second.regex {
		t.Fatalf("identical patterns were not shared: %v", err)
	}
	folded, err := c.regexTest("ready[0-9]+", true)
	if err != nil || folded.regex == first.regex {
		t.Fatalf("different patterns shared an expression: %v", err)
	}
	inline, err := c.regexTest("(?i)ready[0-9]+", false)
	if err != nil || inline.regex != folded.regex {
		t.Fatalf("equivalent case-insensitive patterns were not shared: %v", err)
	}
	if _, err := c.regexTest("(", false); !errors.Is(err, ErrInvalidPattern) {
		t.Fatalf("invalid pattern error = %v; want ErrInvalidPattern", err)
	}
}

func TestCompileExpandedKeyLimit(t *testing.T) {
	key := CustomKey(func(bool) (bool, error) { return true, nil })
	for range 16 {
		key = All(key, key)
	}
	program, err := Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{key}})
	if program != nil || !errors.Is(err, ErrTooManyKeys) {
		t.Fatalf("Compile expanded group = %v, %v; want ErrTooManyKeys", program, err)
	}
}

func FuzzEvaluateChains(f *testing.F) {
	f.Add([]byte{0, 3, 0, 1, 0, 1, 2, 1, 1})
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024 {
			return
		}
		var chains []Chain[bool]
		want := Result{Status: None, Chain: -1}
		for offset := 0; offset+2 <= len(data); {
			mode := Mode(data[offset] & 1)
			count := int(data[offset+1] % 16)
			offset += 2
			count = min(count, len(data)-offset)
			chain := Chain[bool]{Status: Status(fmt.Sprintf("chain-%d", len(chains))), Mode: mode}
			matches := mode == And && count > 0
			for _, value := range data[offset : offset+count] {
				ok := value&1 != 0
				chain.Keys = append(chain.Keys, CustomKey(func(bool) (bool, error) { return ok, nil }))
				if mode == Or {
					matches = matches || ok
				} else {
					matches = matches && ok
				}
			}
			if matches && !want.Matched {
				want = Result{Status: chain.Status, Matched: true, Chain: len(chains)}
			}
			chains = append(chains, chain)
			offset += count
		}
		program, err := Compile(chains...)
		if err != nil {
			t.Fatal(err)
		}
		got, err := program.Evaluate(false, None)
		if got != want || err != nil {
			t.Fatalf("Evaluate = %+v, %v; want %+v", got, err, want)
		}
	})
}

func ExampleCompile() {
	selector := func(value int64) (int64, bool) { return value, true }
	program, err := Compile(Chain[int64]{Status: Success, Mode: And, Keys: []Key[int64]{
		IntKey(selector, GreaterThanOrEqualTo, 200), IntKey(selector, LessThan, 300),
	}})
	if err != nil {
		panic(err)
	}
	result, err := program.Evaluate(204, None)
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Status, result.Matched, result.Chain)
	// Output: SUCCESS true 0
}
