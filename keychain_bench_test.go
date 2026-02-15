package keycheck

import (
	"errors"
	"strconv"
	"testing"
)

var benchErr = errors.New("fail")

func buildBenchKeyChain(b *testing.B, condition BitwiseID, validators int, passAt int) KeyChain[int] {
	b.Helper()

	kc, err := NewKeyChain[int](condition)
	if err != nil {
		b.Fatalf("new keychain: %v", err)
	}

	for i := range validators {
		status := Status{ID: "S" + strconv.Itoa(i)}
		fn := func(v int) (bool, error) {
			if i == passAt {
				return true, nil
			}
			return false, benchErr
		}
		if err := kc.SetValidator(status, fn); err != nil {
			b.Fatalf("set validator: %v", err)
		}
	}

	return kc
}

func BenchmarkValidateOR(b *testing.B) {
	kc := buildBenchKeyChain(b, OR, 16, 15)
	b.ReportAllocs()

	for b.Loop() {
		_, _, _ = kc.Validate(42, NONE)
	}
}

func BenchmarkValidateAND(b *testing.B) {
	kc := buildBenchKeyChain(b, AND, 16, 0)
	b.ReportAllocs()

	for b.Loop() {
		_, _, _ = kc.Validate(42, NONE)
	}
}

func BenchmarkValidateXOR(b *testing.B) {
	kc := buildBenchKeyChain(b, XOR, 16, 0)
	b.ReportAllocs()

	for b.Loop() {
		_, _, _ = kc.Validate(42, NONE)
	}
}

func BenchmarkValidateNOT(b *testing.B) {
	kc := buildBenchKeyChain(b, NOT, 16, 15)
	b.ReportAllocs()

	for b.Loop() {
		_, _, _ = kc.Validate(42, NONE)
	}
}
