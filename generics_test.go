package keycheck

import (
	"errors"
	"math"
	"testing"
)

// TestIntKeyGenericTypes verifies native integer widths and defined integer types.
func TestIntKeyGenericTypes(t *testing.T) {
	type machineInt int
	type signed8 int8
	type signed16 int16
	type signed32 int32
	type signed64 int64
	type machineUint uint
	type unsigned8 uint8
	type unsigned16 uint16
	type unsigned32 uint32
	type unsigned64 uint64
	type address uintptr
	maximumInt := int(^uint(0) >> 1)
	t.Run("int", func(t *testing.T) { assertGenericInteger(t, -maximumInt-1, maximumInt) })
	t.Run("int8", func(t *testing.T) { assertGenericInteger(t, int8(-128), int8(127)) })
	t.Run("int16", func(t *testing.T) { assertGenericInteger(t, int16(-32768), int16(32767)) })
	t.Run("int32", func(t *testing.T) { assertGenericInteger(t, int32(-2147483648), int32(2147483647)) })
	t.Run("int64", func(t *testing.T) { assertGenericInteger(t, int64(-1<<63), int64(1<<63-1)) })
	t.Run("uint", func(t *testing.T) { assertGenericInteger(t, uint(0), ^uint(0)) })
	t.Run("uint8", func(t *testing.T) { assertGenericInteger(t, uint8(0), ^uint8(0)) })
	t.Run("uint16", func(t *testing.T) { assertGenericInteger(t, uint16(0), ^uint16(0)) })
	t.Run("uint32", func(t *testing.T) { assertGenericInteger(t, uint32(0), ^uint32(0)) })
	t.Run("uint64", func(t *testing.T) { assertGenericInteger(t, uint64(0), ^uint64(0)) })
	t.Run("uintptr", func(t *testing.T) { assertGenericInteger(t, uintptr(0), ^uintptr(0)) })
	t.Run("definedInt", func(t *testing.T) { assertGenericInteger(t, machineInt(-maximumInt-1), machineInt(maximumInt)) })
	t.Run("definedInt8", func(t *testing.T) { assertGenericInteger(t, signed8(-128), signed8(127)) })
	t.Run("definedInt16", func(t *testing.T) { assertGenericInteger(t, signed16(-32768), signed16(32767)) })
	t.Run("definedInt32", func(t *testing.T) { assertGenericInteger(t, signed32(-2147483648), signed32(2147483647)) })
	t.Run("definedInt64", func(t *testing.T) { assertGenericInteger(t, signed64(-1<<63), signed64(1<<63-1)) })
	t.Run("definedUint", func(t *testing.T) { assertGenericInteger(t, machineUint(0), ^machineUint(0)) })
	t.Run("definedUint8", func(t *testing.T) { assertGenericInteger(t, unsigned8(0), ^unsigned8(0)) })
	t.Run("definedUint16", func(t *testing.T) { assertGenericInteger(t, unsigned16(0), ^unsigned16(0)) })
	t.Run("definedUint32", func(t *testing.T) { assertGenericInteger(t, unsigned32(0), ^unsigned32(0)) })
	t.Run("definedUint64", func(t *testing.T) { assertGenericInteger(t, unsigned64(0), ^unsigned64(0)) })
	t.Run("definedUintptr", func(t *testing.T) { assertGenericInteger(t, address(0), ^address(0)) })
}

func assertGenericInteger[V ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr](t *testing.T, minimum, maximum V) {
	t.Helper()
	selector := func(value V) (V, bool) { return value, true }
	for _, test := range []struct {
		name     string
		op       Operator
		lowEqual bool
		lowHigh  bool
		highLow  bool
	}{
		{"equal", EqualTo, true, false, false},
		{"notEqual", NotEqualTo, false, true, true},
		{"less", LessThan, false, true, false},
		{"lessEqual", LessThanOrEqualTo, true, true, false},
		{"greater", GreaterThan, false, false, true},
		{"greaterEqual", GreaterThanOrEqualTo, true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertKeyMatch(t, IntKey(selector, test.op, minimum), minimum, test.lowEqual)
			assertKeyMatch(t, IntKey(selector, test.op, maximum), minimum, test.lowHigh)
			assertKeyMatch(t, IntKey(selector, test.op, minimum), maximum, test.highLow)
			assertKeyMatch(t, IntKey(func(value V) (V, bool) { return value, false }, test.op, maximum), minimum, false)
		})
	}
}

// TestFloatKeyGenericTypes verifies floating-point edge cases without widening their type.
func TestFloatKeyGenericTypes(t *testing.T) {
	type single float32
	type double float64
	t.Run("float32", func(t *testing.T) {
		assertGenericFloat(t, float32(math.NaN()), float32(math.Inf(1)), float32(math.Copysign(0, -1)), float32(math.SmallestNonzeroFloat32))
	})
	t.Run("float64", func(t *testing.T) {
		assertGenericFloat(t, math.NaN(), math.Inf(1), math.Copysign(0, -1), math.SmallestNonzeroFloat64)
	})
	t.Run("definedFloat32", func(t *testing.T) {
		assertGenericFloat(t, single(math.NaN()), single(math.Inf(1)), single(math.Copysign(0, -1)), single(math.SmallestNonzeroFloat32))
	})
	t.Run("definedFloat64", func(t *testing.T) {
		assertGenericFloat(t, double(math.NaN()), double(math.Inf(1)), double(math.Copysign(0, -1)), double(math.SmallestNonzeroFloat64))
	})
}

func assertGenericFloat[V ~float32 | ~float64](t *testing.T, nan, infinity, negativeZero, subnormal V) {
	t.Helper()
	selector := func(value V) (V, bool) { return value, true }
	for _, test := range []struct {
		name           string
		op             Operator
		zeroEqual      bool
		subnormalAbove bool
		infinityAbove  bool
		negativeBelow  bool
		nan            bool
	}{
		{"equal", EqualTo, true, false, false, false, false},
		{"notEqual", NotEqualTo, false, true, true, true, true},
		{"less", LessThan, false, false, false, true, false},
		{"lessEqual", LessThanOrEqualTo, true, false, false, true, false},
		{"greater", GreaterThan, false, true, true, false, false},
		{"greaterEqual", GreaterThanOrEqualTo, true, true, true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := FloatKey(selector, test.op, V(0))
			assertKeyMatch(t, key, negativeZero, test.zeroEqual)
			assertKeyMatch(t, key, subnormal, test.subnormalAbove)
			assertKeyMatch(t, key, infinity, test.infinityAbove)
			assertKeyMatch(t, key, -infinity, test.negativeBelow)
			assertKeyMatch(t, key, nan, test.nan)
			assertKeyMatch(t, FloatKey(selector, test.op, nan), V(1), test.nan)
			assertKeyMatch(t, FloatKey(selector, test.op, nan), nan, test.nan)
			assertKeyMatch(t, FloatKey(func(value V) (V, bool) { return value, false }, test.op, V(0)), nan, false)
		})
	}
	assertKeyMatch(t, FloatKey(selector, EqualTo, infinity), infinity, true)
	assertKeyMatch(t, FloatKey(selector, EqualTo, -infinity), -infinity, true)
}

// TestTextKeysGenericTypes verifies defined text types and byte target ownership.
func TestTextKeysGenericTypes(t *testing.T) {
	type text string
	type data []byte
	textSelector := func(value text) (text, bool) { return value, true }
	dataSelector := func(value data) (data, bool) { return value, true }
	for _, test := range []struct {
		name   string
		op     Operator
		right  string
		want   bool
		option []TextOption
	}{
		{"equal", EqualTo, "Ready", true, nil},
		{"notEqual", NotEqualTo, "Ready", false, nil},
		{"contains", Contains, "ead", true, nil},
		{"notContains", DoesNotContain, "ead", false, nil},
		{"prefix", StartsWith, "Re", true, nil},
		{"notPrefix", DoesNotStartWith, "Re", false, nil},
		{"suffix", EndsWith, "dy", true, nil},
		{"notSuffix", DoesNotEndWith, "dy", false, nil},
		{"regex", MatchesRegex, "^R[a-z]+$", true, nil},
		{"notRegex", DoesNotMatchRegex, "^R[a-z]+$", false, nil},
		{"exists", Exists, "", true, nil},
		{"missing", DoesNotExist, "", false, nil},
		{"fold", EqualTo, "ready", true, []TextOption{IgnoreCase}},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertKeyMatch(t, StringKey(textSelector, test.op, text(test.right), test.option...), text("Ready"), test.want)
			assertKeyMatch(t, BytesKey(dataSelector, test.op, data(test.right), test.option...), data("Ready"), test.want)
		})
	}
	assertKeyMatch(t, StringKey(textSelector, EqualTo, text("key"), IgnoreCase), text("Key"), true)
	assertKeyMatch(t, BytesKey(dataSelector, Contains, data("key"), IgnoreCase), data("aKeyb"), true)
	target := data("ready")
	key := BytesKey(dataSelector, EqualTo, target)
	target[0] = 'x'
	assertKeyMatch(t, key, data("ready"), true)
	assertKeyMatch(t, key, data("xeady"), false)
	for _, op := range []Operator{EqualTo, NotEqualTo, Contains, DoesNotContain, StartsWith, DoesNotStartWith, EndsWith, DoesNotEndWith, MatchesRegex, DoesNotMatchRegex, Exists, DoesNotExist} {
		assertKeyMatch(t, StringKey(func(bool) (text, bool) { return "", false }, op, text("")), false, op == DoesNotExist)
		assertKeyMatch(t, BytesKey(func(bool) (data, bool) { return nil, false }, op, data(nil)), false, op == DoesNotExist)
	}
	assertKeyMatch(t, BytesKey(dataSelector, EqualTo, data(nil)), data(nil), true)
	assertKeyMatch(t, BytesKey(dataSelector, Exists, data(nil)), data(nil), true)
}

// TestBoolKeyGenericTypes verifies defined booleans and missing selections.
func TestBoolKeyGenericTypes(t *testing.T) {
	type flag bool
	selector := func(value flag) (flag, bool) { return value, true }
	for _, op := range []Operator{Is, IsNot} {
		assertKeyMatch(t, BoolKey(selector, op, flag(true)), flag(true), op == Is)
		assertKeyMatch(t, BoolKey(selector, op, flag(true)), flag(false), op == IsNot)
		assertKeyMatch(t, BoolKey(func(value flag) (flag, bool) { return value, false }, op, flag(true)), flag(false), false)
	}
}

// TestBoolKeyGenericRepeatedCompilation verifies that repeated [Compile] calls preserve a reusable negated boolean key.
func TestBoolKeyGenericRepeatedCompilation(t *testing.T) {
	type flag bool
	selector := func(value flag) (flag, bool) { return value, true }
	for _, test := range []struct {
		name  string
		right flag
	}{
		{"false", false},
		{"true", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := BoolKey(selector, IsNot, test.right)
			var programs [2]*Program[flag]
			for i := range programs {
				program, err := Compile(Chain[flag]{Status: Success, Keys: []Key[flag]{key}})
				if err != nil {
					t.Fatal(err)
				}
				programs[i] = program
			}
			for i, program := range programs {
				for _, value := range []struct {
					input flag
					want  bool
				}{
					{test.right, false},
					{!test.right, true},
				} {
					got, err := program.Evaluate(value.input, None)
					if err != nil || got.Matched != value.want {
						t.Fatalf("program %d with input %v: Evaluate = %+v, %v; want matched %v", i, value.input, got, err, value.want)
					}
				}
			}
		})
	}
}

// TestListKeyGenericTypes verifies comparable list elements and defined slices.
func TestListKeyGenericTypes(t *testing.T) {
	type element int
	type list []element
	type record struct {
		value int
		label string
	}
	selector := func(value list) (list, bool) { return value, true }
	assertKeyMatch(t, ListKey(selector, Contains, element(7)), list{1, 7, 9}, true)
	assertKeyMatch(t, ListKey(selector, DoesNotContain, element(7)), list{1, 9}, true)
	assertKeyMatch(t, ListKey(selector, Contains, element(7)), list(nil), false)
	assertKeyMatch(t, ListKey(selector, DoesNotContain, element(7)), list(nil), true)
	assertKeyMatch(t, ListKey(func(value []record) ([]record, bool) { return value, true }, Contains, record{7, "ready"}), []record{{7, "ready"}}, true)
	assertKeyMatch(t, ListKey(func(value []record) ([]record, bool) { return value, true }, Contains, record{7, "ready"}), []record{{7, "other"}}, false)
	first, second := new(int), new(int)
	assertKeyMatch(t, ListKey(func(value []*int) ([]*int, bool) { return value, true }, Contains, first), []*int{first}, true)
	assertKeyMatch(t, ListKey(func(value []*int) ([]*int, bool) { return value, true }, Contains, first), []*int{second}, false)
	nan := math.NaN()
	assertKeyMatch(t, ListKey(func(value []float64) ([]float64, bool) { return value, true }, Contains, nan), []float64{nan}, false)
	assertKeyMatch(t, ListKey(func(value []float64) ([]float64, bool) { return value, true }, DoesNotContain, nan), []float64{nan}, true)
	for _, op := range []Operator{Contains, DoesNotContain, Exists, DoesNotExist} {
		assertKeyMatch(t, ListKey(func(bool) (list, bool) { return nil, false }, op, element(7)), false, op == DoesNotExist)
	}
	assertKeyMatch(t, ListKey(selector, Exists, element(7)), list(nil), true)
	assertKeyMatch(t, ListKey(selector, DoesNotExist, element(7)), list(nil), false)
}

// TestDictionaryKeyGenericTypes verifies comparable map operands and defined maps.
func TestDictionaryKeyGenericTypes(t *testing.T) {
	type element uint64
	type dictionary map[element]element
	type record struct {
		value int
		label string
	}
	selector := func(value dictionary) (dictionary, bool) { return value, true }
	input := dictionary{1: 7, 9: element(1<<64 - 1)}
	for _, test := range []struct {
		op    Operator
		right element
		want  bool
	}{
		{HasKey, 1, true},
		{HasKey, 7, false},
		{DoesNotHaveKey, 7, true},
		{DoesNotHaveKey, 1, false},
		{HasValue, 7, true},
		{HasValue, element(1<<64 - 1), true},
		{HasValue, 1, false},
		{DoesNotHaveValue, 1, true},
		{DoesNotHaveValue, 7, false},
		{Exists, 0, true},
		{DoesNotExist, 0, false},
	} {
		assertKeyMatch(t, DictionaryKey(selector, test.op, test.right), input, test.want)
	}
	key, value := record{1, "key"}, record{7, "value"}
	recordSelector := func(value map[record]record) (map[record]record, bool) { return value, true }
	assertKeyMatch(t, DictionaryKey(recordSelector, HasKey, key), map[record]record{key: value}, true)
	assertKeyMatch(t, DictionaryKey(recordSelector, HasValue, value), map[record]record{key: value}, true)
	first, second := new(int), new(int)
	pointerSelector := func(value map[*int]*int) (map[*int]*int, bool) { return value, true }
	assertKeyMatch(t, DictionaryKey(pointerSelector, HasKey, first), map[*int]*int{first: second}, true)
	assertKeyMatch(t, DictionaryKey(pointerSelector, HasValue, second), map[*int]*int{first: second}, true)
	nan := math.NaN()
	nanSelector := func(value map[float64]float64) (map[float64]float64, bool) { return value, true }
	for _, op := range []Operator{HasKey, DoesNotHaveKey, HasValue, DoesNotHaveValue} {
		assertKeyMatch(t, DictionaryKey(nanSelector, op, nan), map[float64]float64{nan: nan}, op == DoesNotHaveKey || op == DoesNotHaveValue)
	}
	for _, op := range []Operator{HasKey, DoesNotHaveKey, HasValue, DoesNotHaveValue, Exists, DoesNotExist} {
		assertKeyMatch(t, DictionaryKey(func(bool) (dictionary, bool) { return nil, false }, op, element(7)), false, op == DoesNotExist)
		assertKeyMatch(t, DictionaryKey(selector, op, element(7)), dictionary(nil), op == DoesNotHaveKey || op == DoesNotHaveValue || op == Exists)
	}
}

// TestGenericCollectionsInterfaceComparison verifies native interface comparison and hashing behavior.
func TestGenericCollectionsInterfaceComparison(t *testing.T) {
	listSelector := func(value []any) ([]any, bool) { return value, true }
	dictionarySelector := func(value map[any]any) (map[any]any, bool) { return value, true }
	assertKeyMatch(t, ListKey(listSelector, Contains, any(7)), []any{"ready", 7}, true)
	assertKeyMatch(t, ListKey(listSelector, DoesNotContain, any(7)), []any{"ready", 9}, true)
	assertKeyMatch(t, DictionaryKey(dictionarySelector, HasKey, any(7)), map[any]any{7: "ready"}, true)
	assertKeyMatch(t, DictionaryKey(dictionarySelector, HasValue, any("ready")), map[any]any{7: "ready"}, true)
	for _, test := range []struct {
		name string
		key  Key[bool]
	}{
		{"listContains", ListKey(func(bool) ([]any, bool) { return []any{[]int{1}}, true }, Contains, any([]int{1}))},
		{"listDoesNotContain", ListKey(func(bool) ([]any, bool) { return []any{[]int{1}}, true }, DoesNotContain, any([]int{1}))},
		{"dictionaryHasKey", DictionaryKey(func(bool) (map[any]any, bool) { return map[any]any{1: 1}, true }, HasKey, any([]int{1}))},
		{"dictionaryDoesNotHaveKey", DictionaryKey(func(bool) (map[any]any, bool) { return map[any]any{1: 1}, true }, DoesNotHaveKey, any([]int{1}))},
		{"dictionaryHasValue", DictionaryKey(func(bool) (map[any]any, bool) { return map[any]any{1: []int{1}}, true }, HasValue, any([]int{1}))},
		{"dictionaryDoesNotHaveValue", DictionaryKey(func(bool) (map[any]any, bool) { return map[any]any{1: []int{1}}, true }, DoesNotHaveValue, any([]int{1}))},
	} {
		t.Run(test.name, func(t *testing.T) {
			program, err := Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{test.key}})
			if err != nil {
				t.Fatal(err)
			}
			assertGenericPanic(t, func() { _, _ = program.Evaluate(true, None) })
		})
	}
	for _, op := range []Operator{Exists, DoesNotExist} {
		for _, present := range []bool{false, true} {
			want := present == (op == Exists)
			assertKeyMatch(t, ListKey(func(present bool) ([]any, bool) { return nil, present }, op, any([]int{1})), present, want)
			assertKeyMatch(t, DictionaryKey(func(present bool) (map[any]any, bool) { return nil, present }, op, any([]int{1})), present, want)
		}
	}
}

func assertGenericPanic(t *testing.T, evaluate func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("Evaluate did not panic for a noncomparable interface operand")
		}
	}()
	evaluate()
}

// TestGenericKeysSelectorEvaluation verifies that constructors and compilation defer selection until evaluation.
func TestGenericKeysSelectorEvaluation(t *testing.T) {
	type text string
	type data []byte
	type integer uint32
	type number float32
	type flag bool
	type list []integer
	type dictionary map[integer]integer
	for _, test := range []struct {
		name string
		key  func(*int) Key[bool]
	}{
		{"string", func(calls *int) Key[bool] {
			return StringKey(func(present bool) (text, bool) { *calls++; return "ready", present }, Contains, text("ready"))
		}},
		{"bytes", func(calls *int) Key[bool] {
			return BytesKey(func(present bool) (data, bool) { *calls++; return data("ready"), present }, Contains, data("ready"))
		}},
		{"integer", func(calls *int) Key[bool] {
			return IntKey(func(present bool) (integer, bool) { *calls++; return 7, present }, GreaterThan, integer(1))
		}},
		{"float", func(calls *int) Key[bool] {
			return FloatKey(func(present bool) (number, bool) { *calls++; return 7, present }, GreaterThan, number(1))
		}},
		{"boolean", func(calls *int) Key[bool] {
			return BoolKey(func(present bool) (flag, bool) { *calls++; return true, present }, Is, flag(true))
		}},
		{"list", func(calls *int) Key[bool] {
			return ListKey(func(present bool) (list, bool) { *calls++; return list{7}, present }, Contains, integer(7))
		}},
		{"dictionary", func(calls *int) Key[bool] {
			return DictionaryKey(func(present bool) (dictionary, bool) { *calls++; return dictionary{1: 7}, present }, HasValue, integer(7))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			key := test.key(&calls)
			program, err := Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{key}})
			if err != nil || calls != 0 {
				t.Fatalf("Compile = %v with %d selector calls; want no calls", err, calls)
			}
			for i, present := range []bool{true, false, true} {
				result, err := program.Evaluate(present, None)
				if err != nil || result.Matched != present || calls != i+1 {
					t.Fatalf("Evaluate = %+v, %v with %d selector calls; want matched %v and %d calls", result, err, calls, present, i+1)
				}
			}
		})
	}
}

// TestGenericKeysInvalidConfiguration verifies validation of typed nil selectors and unsupported operators.
func TestGenericKeysInvalidConfiguration(t *testing.T) {
	type text string
	type data []byte
	type integer uint16
	type number float32
	type flag bool
	type list []integer
	type dictionary map[integer]integer
	var (
		selectText       Selector[bool, text]
		selectData       Selector[bool, data]
		selectInteger    Selector[bool, integer]
		selectNumber     Selector[bool, number]
		selectFlag       Selector[bool, flag]
		selectList       Selector[bool, list]
		selectDictionary Selector[bool, dictionary]
	)
	for _, test := range []struct {
		name string
		key  Key[bool]
		want error
	}{
		{"stringNil", StringKey(selectText, EqualTo, text("")), ErrInvalidKey},
		{"bytesNil", BytesKey(selectData, EqualTo, data(nil)), ErrInvalidKey},
		{"integerNil", IntKey(selectInteger, EqualTo, integer(0)), ErrInvalidKey},
		{"floatNil", FloatKey(selectNumber, EqualTo, number(0)), ErrInvalidKey},
		{"booleanNil", BoolKey(selectFlag, Is, flag(false)), ErrInvalidKey},
		{"listNil", ListKey(selectList, Contains, integer(0)), ErrInvalidKey},
		{"dictionaryNil", DictionaryKey(selectDictionary, HasKey, integer(0)), ErrInvalidKey},
		{"stringOperator", StringKey(func(bool) (text, bool) { return "", true }, Is, text("")), ErrInvalidOperator},
		{"bytesOperator", BytesKey(func(bool) (data, bool) { return nil, true }, Is, data(nil)), ErrInvalidOperator},
		{"integerOperator", IntKey(func(bool) (integer, bool) { return 0, true }, Exists, integer(0)), ErrInvalidOperator},
		{"floatOperator", FloatKey(func(bool) (number, bool) { return 0, true }, Exists, number(0)), ErrInvalidOperator},
		{"booleanOperator", BoolKey(func(bool) (flag, bool) { return false, true }, EqualTo, flag(false)), ErrInvalidOperator},
		{"listOperator", ListKey(func(bool) (list, bool) { return nil, true }, EqualTo, integer(0)), ErrInvalidOperator},
		{"dictionaryOperator", DictionaryKey(func(bool) (dictionary, bool) { return nil, true }, EqualTo, integer(0)), ErrInvalidOperator},
		{"stringOption", StringKey(func(bool) (text, bool) { return "", true }, EqualTo, text(""), TextOption(255)), ErrInvalidOption},
		{"bytesOption", BytesKey(func(bool) (data, bool) { return nil, true }, EqualTo, data(nil), TextOption(255)), ErrInvalidOption},
		{"stringPattern", StringKey(func(bool) (text, bool) { return "", true }, MatchesRegex, text("[")), ErrInvalidPattern},
		{"bytesPattern", BytesKey(func(bool) (data, bool) { return nil, true }, MatchesRegex, data("[")), ErrInvalidPattern},
	} {
		t.Run(test.name, func(t *testing.T) {
			program, err := Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{test.key}})
			if program != nil || !errors.Is(err, test.want) {
				t.Fatalf("Compile = %v, %v; want nil program and %v", program, err, test.want)
			}
		})
	}
}

// TestGenericKeysTypeInference verifies inferred and partially supplied type arguments with defined operands.
func TestGenericKeysTypeInference(t *testing.T) {
	type text string
	type data []byte
	type id uint64
	type score float32
	type flag bool
	type list []id
	type dictionary map[id]id
	selectText := func(value text) (text, bool) { return value, true }
	selectData := func(value data) (data, bool) { return value, true }
	selectID := func(value id) (id, bool) { return value, true }
	selectScore := func(value score) (score, bool) { return value, true }
	selectFlag := func(value flag) (flag, bool) { return value, true }
	selectList := func(value list) (list, bool) { return value, true }
	selectDictionary := func(value dictionary) (dictionary, bool) { return value, true }
	assertKeyMatch(t, StringKey(selectText, EqualTo, "ready"), text("ready"), true)
	assertKeyMatch(t, IntKey(selectID, GreaterThan, 42), id(43), true)
	assertKeyMatch(t, FloatKey(selectScore, GreaterThanOrEqualTo, 0.5), score(0.5), true)
	assertKeyMatch(t, FloatKey(selectScore, GreaterThanOrEqualTo, 1), score(1), true)
	assertKeyMatch(t, BoolKey(selectFlag, Is, true), flag(true), true)
	assertKeyMatch(t, ListKey(selectList, Contains, 42), list{42}, true)
	assertKeyMatch(t, DictionaryKey(selectDictionary, HasKey, 42), dictionary{42: 7}, true)
	assertKeyMatch(t, BytesKey(selectData, EqualTo, []byte("ready")), data("ready"), true)
	assertKeyMatch(t, BytesKey(selectData, EqualTo, nil), data(nil), true)
	assertKeyMatch(t, StringKey(selectText, EqualTo, "ready"), text("ready"), true)
	assertKeyMatch(t, IntKey(selectID, GreaterThan, 42), id(43), true)
	assertKeyMatch(t, FloatKey(selectScore, GreaterThanOrEqualTo, 0.5), score(0.5), true)
	assertKeyMatch(t, BoolKey(selectFlag, Is, true), flag(true), true)
	assertKeyMatch(t, ListKey(selectList, Contains, 42), list{42}, true)
	assertKeyMatch(t, DictionaryKey(selectDictionary, HasValue, 7), dictionary{42: 7}, true)
	assertKeyMatch(t, BytesKey(selectData, EqualTo, []byte("ready")), data("ready"), true)
	assertKeyMatch(t, BytesKey(selectData, EqualTo, nil), data(nil), true)
}

// TestGenericKeysAllocations verifies allocation-free evaluation for defined operand types.
func TestGenericKeysAllocations(t *testing.T) {
	type text string
	type data []byte
	type integer uint64
	type number float32
	type flag bool
	type list []integer
	type dictionary map[integer]integer
	t.Run("string", func(t *testing.T) {
		assertKeyAllocations(t, StringKey(func(value text) (text, bool) { return value, true }, Contains, text("ready")), text("state=ready"), text("state=failed"))
	})
	t.Run("bytes", func(t *testing.T) {
		assertKeyAllocations(t, BytesKey(func(value data) (data, bool) { return value, true }, Contains, data("ready")), data("state=ready"), data("state=failed"))
	})
	t.Run("integer", func(t *testing.T) {
		assertKeyAllocations(t, IntKey(func(value integer) (integer, bool) { return value, true }, GreaterThan, integer(1<<63)), integer(1<<64-1), integer(1<<63))
	})
	t.Run("float", func(t *testing.T) {
		assertKeyAllocations(t, FloatKey(func(value number) (number, bool) { return value, true }, GreaterThan, number(0)), number(1), number(-1))
	})
	t.Run("boolean", func(t *testing.T) {
		assertKeyAllocations(t, BoolKey(func(value flag) (flag, bool) { return value, true }, Is, flag(true)), flag(true), flag(false))
	})
	t.Run("list", func(t *testing.T) {
		assertKeyAllocations(t, ListKey(func(value list) (list, bool) { return value, true }, Contains, integer(7)), list{1, 7}, list{1, 9})
	})
	t.Run("dictionaryKey", func(t *testing.T) {
		assertKeyAllocations(t, DictionaryKey(func(value dictionary) (dictionary, bool) { return value, true }, HasKey, integer(7)), dictionary{7: 1}, dictionary{9: 1})
	})
	t.Run("dictionaryValue", func(t *testing.T) {
		assertKeyAllocations(t, DictionaryKey(func(value dictionary) (dictionary, bool) { return value, true }, HasValue, integer(7)), dictionary{1: 7}, dictionary{1: 9})
	})
}
