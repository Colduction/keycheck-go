package keycheck

import "testing"

func BenchmarkComparable(b *testing.B) {
	for _, mode := range []Mode{Or, And} {
		name := "OrLast"
		if mode == And {
			name = "AndAll"
		}
		b.Run(name, func(b *testing.B) {
			keys := make([]Key[int], 16)
			for i := range keys {
				pass := mode == And || i == 15
				keys[i] = CustomKey(func(input int) (bool, error) { return input == 42 && pass, nil })
			}
			program, err := Compile(Chain[int]{Status: Success, Mode: mode, Keys: keys})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				result, err := program.Evaluate(42, None)
				if !result.Matched || err != nil {
					b.Fatal("unexpected result")
				}
			}
		})
	}
}
