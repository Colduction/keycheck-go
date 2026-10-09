package keycheck

import (
	"errors"
	"runtime"
	"testing"
)

// TestMustCompile verifies ordered matching and short-circuiting with defined operand types.
func TestMustCompile(t *testing.T) {
	type integer uint16
	type input struct {
		value integer
	}
	var selected, skipped, later int
	program := MustCompile(
		Chain[input]{Status: Success, Keys: []Key[input]{
			IntKey(func(value input) (integer, bool) { selected++; return value.value, true }, EqualTo, 42),
			CustomKey(func(input) (bool, error) { skipped++; return false, nil }),
		}},
		Chain[input]{Status: Fail, Keys: []Key[input]{
			CustomKey(func(input) (bool, error) { later++; return true, nil }),
		}},
	)
	if program == nil || selected != 0 || skipped != 0 || later != 0 {
		t.Fatalf("MustCompile = %v with selector counts %d, %d, %d; want nonnil program and no calls", program, selected, skipped, later)
	}
	if got, err := program.Evaluate(input{42}, None); err != nil || got != (Result{Status: Success, Matched: true, Chain: 0}) || selected != 1 || skipped != 0 || later != 0 {
		t.Fatalf("first chain = %+v, %v with selector counts %d, %d, %d", got, err, selected, skipped, later)
	}
	if got, err := program.Evaluate(input{43}, None); err != nil || got != (Result{Status: Fail, Matched: true, Chain: 1}) || selected != 2 || skipped != 1 || later != 1 {
		t.Fatalf("second chain = %+v, %v with selector counts %d, %d, %d", got, err, selected, skipped, later)
	}
}

// TestMustCompileEmpty verifies fallback results for programs containing no keys.
func TestMustCompileEmpty(t *testing.T) {
	for _, test := range []struct {
		name   string
		chains []Chain[int]
	}{
		{"noChains", nil},
		{"emptyChain", []Chain[int]{{Status: Success}}},
		{"emptyAndChain", []Chain[int]{{Status: Success, Mode: And}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			program := MustCompile(test.chains...)
			if program == nil {
				t.Fatal("MustCompile returned a nil program")
			}
			want := Result{Status: Retry, Chain: -1}
			if got, err := program.Evaluate(42, Retry); err != nil || got != want {
				t.Fatalf("Evaluate = %+v, %v; want %+v", got, err, want)
			}
		})
	}
	if program := MustCompile[int](); program == nil {
		t.Fatal("MustCompile without chains returned a nil program")
	}
}

// TestMustCompilePanics verifies that configuration panics preserve [CompileError] and error classification.
func TestMustCompilePanics(t *testing.T) {
	tooDeep := CustomKey(func(bool) (bool, error) { return true, nil })
	for range 64 {
		tooDeep = Not(tooDeep)
	}
	for _, test := range []struct {
		name   string
		chains []Chain[bool]
		want   error
		chain  int
		key    int
	}{
		{"invalidStatus", []Chain[bool]{{Status: Success}, {}}, ErrInvalidStatus, 1, -1},
		{"invalidOperator", []Chain[bool]{
			{Status: Success},
			{Status: Fail, Keys: []Key[bool]{
				BoolKey(func(value bool) (bool, bool) { return value, true }, Is, true),
				IntKey(func(bool) (uint8, bool) { return 0, true }, Contains, 0),
			}},
		}, ErrInvalidOperator, 1, 1},
		{"nilCustom", []Chain[bool]{{Status: Success, Keys: []Key[bool]{CustomKey[bool](nil)}}}, ErrInvalidKey, 0, 0},
		{"depthLimit", []Chain[bool]{{Status: Success, Keys: []Key[bool]{tooDeep}}}, ErrNestingTooDeep, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				value := recover()
				got, ok := value.(*CompileError)
				if !ok || !errors.Is(got, test.want) || got.Chain != test.chain || got.Key != test.key {
					t.Fatalf("panic = %#v; want configuration error %v at chain %d key %d", value, test.want, test.chain, test.key)
				}
			}()
			MustCompile(test.chains...)
		})
	}
}

// TestMustCompileSnapshots verifies that compiled keys and statuses survive configuration mutation.
func TestMustCompileSnapshots(t *testing.T) {
	selector := func(value uint64) (uint64, bool) { return value, true }
	keys := []Key[uint64]{IntKey(selector, EqualTo, 42)}
	chains := []Chain[uint64]{{Status: Success, Keys: keys}}
	program := MustCompile(chains...)
	keys[0] = IntKey(selector, EqualTo, 43)
	chains[0].Status = Fail
	chains[0].Keys = nil
	if got, err := program.Evaluate(42, None); err != nil || got != (Result{Status: Success, Matched: true, Chain: 0}) {
		t.Fatalf("Evaluate after configuration mutation = %+v, %v", got, err)
	}
	if got, err := program.Evaluate(43, None); err != nil || got != (Result{Status: None, Chain: -1}) {
		t.Fatalf("Evaluate mutated key target = %+v, %v", got, err)
	}
}

// BenchmarkMustCompile compares [Compile] and [MustCompile] using the same prepared configuration.
func BenchmarkMustCompile(b *testing.B) {
	chain := Chain[uint64]{Status: Success, Keys: []Key[uint64]{
		IntKey(func(value uint64) (uint64, bool) { return value, true }, EqualTo, 42),
	}}
	b.Run("Compile", func(b *testing.B) {
		b.ReportAllocs()
		var (
			program *Program[uint64]
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
	b.Run("MustCompile", func(b *testing.B) {
		b.ReportAllocs()
		var program *Program[uint64]
		for b.Loop() {
			program = MustCompile(chain)
		}
		runtime.KeepAlive(program)
	})
}
