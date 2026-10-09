package keycheck

import (
	"runtime"
	"testing"
)

type benchmarkKeyInput struct {
	integer      int64
	floating     float64
	boolean      bool
	list         []string
	dictionary   map[string]string
	limit        int64
	present      bool
	rightPresent bool
}

type benchmarkKeyCase struct {
	name    string
	key     Key[*benchmarkKeyInput]
	input   *benchmarkKeyInput
	matched bool
}

func benchmarkKeyCases() []benchmarkKeyCase {
	integer := func(input *benchmarkKeyInput) (int64, bool) { return input.integer, input.present }
	floating := func(input *benchmarkKeyInput) (float64, bool) { return input.floating, input.present }
	boolean := func(input *benchmarkKeyInput) (bool, bool) { return input.boolean, input.present }
	list := func(input *benchmarkKeyInput) ([]string, bool) { return input.list, input.present }
	dictionary := func(input *benchmarkKeyInput) (map[string]string, bool) { return input.dictionary, input.present }
	limit := func(input *benchmarkKeyInput) (int64, bool) { return input.limit, input.rightPresent }
	var cases []benchmarkKeyCase
	for _, operator := range []struct {
		name string
		op   Operator
		hit  int64
		miss int64
	}{
		{"equal", EqualTo, 10, 9},
		{"notEqual", NotEqualTo, 9, 10},
		{"less", LessThan, 9, 10},
		{"lessOrEqual", LessThanOrEqualTo, 10, 11},
		{"greater", GreaterThan, 11, 10},
		{"greaterOrEqual", GreaterThanOrEqualTo, 10, 9},
	} {
		for _, kind := range []struct {
			name string
			key  Key[*benchmarkKeyInput]
		}{
			{"int", IntKey(integer, operator.op, 10)},
			{"float", FloatKey(floating, operator.op, 10)},
			{"compare", CompareKey(integer, operator.op, limit)},
		} {
			for _, state := range []struct {
				name    string
				value   int64
				present bool
				matched bool
			}{
				{"hit", operator.hit, true, true},
				{"miss", operator.miss, true, false},
				{"missing", operator.hit, false, false},
			} {
				cases = append(cases, benchmarkKeyCase{
					name:    kind.name + "/" + operator.name + "/" + state.name,
					key:     kind.key,
					input:   &benchmarkKeyInput{integer: state.value, floating: float64(state.value), limit: 10, present: state.present, rightPresent: true},
					matched: state.matched,
				})
			}
			if kind.name == "compare" {
				cases = append(cases, benchmarkKeyCase{
					name:  kind.name + "/" + operator.name + "/rightMissing",
					key:   kind.key,
					input: &benchmarkKeyInput{integer: operator.hit, limit: 10, present: true},
				})
			}
		}
	}
	for _, operator := range []struct {
		name string
		op   Operator
	}{
		{"is", Is},
		{"isNot", IsNot},
	} {
		key := BoolKey(boolean, operator.op, true)
		for _, state := range []struct {
			name    string
			value   bool
			present bool
			matched bool
		}{
			{"hit", operator.op == Is, true, true},
			{"miss", operator.op != Is, true, false},
			{"missing", true, false, false},
		} {
			cases = append(cases, benchmarkKeyCase{
				name:    "bool/" + operator.name + "/" + state.name,
				key:     key,
				input:   &benchmarkKeyInput{boolean: state.value, present: state.present},
				matched: state.matched,
			})
		}
	}
	for _, kind := range []struct {
		name string
		keys []struct {
			name string
			op   Operator
			key  Key[*benchmarkKeyInput]
		}
	}{
		{"list", []struct {
			name string
			op   Operator
			key  Key[*benchmarkKeyInput]
		}{
			{"contains", Contains, ListKey(list, Contains, "target")},
			{"doesNotContain", DoesNotContain, ListKey(list, DoesNotContain, "target")},
			{"exists", Exists, ListKey(list, Exists, "")},
			{"doesNotExist", DoesNotExist, ListKey(list, DoesNotExist, "")},
		}},
		{"dictionary", []struct {
			name string
			op   Operator
			key  Key[*benchmarkKeyInput]
		}{
			{"hasKey", HasKey, DictionaryKey(dictionary, HasKey, "target")},
			{"doesNotHaveKey", DoesNotHaveKey, DictionaryKey(dictionary, DoesNotHaveKey, "target")},
			{"hasValue", HasValue, DictionaryKey(dictionary, HasValue, "target")},
			{"doesNotHaveValue", DoesNotHaveValue, DictionaryKey(dictionary, DoesNotHaveValue, "target")},
			{"exists", Exists, DictionaryKey(dictionary, Exists, "")},
			{"doesNotExist", DoesNotExist, DictionaryKey(dictionary, DoesNotExist, "")},
		}},
	} {
		for _, operator := range kind.keys {
			for _, state := range []struct {
				name    string
				member  bool
				present bool
			}{
				{"member", true, true},
				{"absent", false, true},
				{"missing", false, false},
			} {
				input := &benchmarkKeyInput{
					list:         []string{"a", "b", "c", "d", "e", "f", "g", "h"},
					dictionary:   map[string]string{"a": "aa", "b": "bb", "c": "cc", "d": "dd", "e": "ee", "f": "ff", "g": "gg", "h": "hh"},
					present:      state.present,
					rightPresent: true,
				}
				if state.member {
					input.list[7] = "target"
					delete(input.dictionary, "h")
					input.dictionary["target"] = "target"
				}
				matched := state.member
				switch operator.op {
				case DoesNotContain, DoesNotHaveKey, DoesNotHaveValue:
					matched = !matched
				case Exists:
					matched = true
				case DoesNotExist:
					matched = false
				}
				if !state.present {
					matched = operator.op == DoesNotExist
				}
				cases = append(cases, benchmarkKeyCase{
					name:    kind.name + "/" + operator.name + "/" + state.name,
					key:     operator.key,
					input:   input,
					matched: matched,
				})
			}
		}
	}
	return cases
}

// BenchmarkKeyPredicates measures compiled built-in predicates with allocation-free selectors.
func BenchmarkKeyPredicates(b *testing.B) {
	for _, tc := range benchmarkKeyCases() {
		b.Run(tc.name, func(b *testing.B) {
			match, err := tc.key.compile(&compiler{})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			var got bool
			for b.Loop() {
				got, err = match(tc.input)
			}
			if err != nil || got != tc.matched {
				b.Fatalf("predicate = %v, %v; want %v", got, err, tc.matched)
			}
		})
	}
}

// BenchmarkEvaluateKeys measures one-key programs for scalar and collection operators.
func BenchmarkEvaluateKeys(b *testing.B) {
	for _, tc := range benchmarkKeyCases() {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkEvaluate(b, benchmarkCompile(b, Or, []Key[*benchmarkKeyInput]{tc.key}), tc.input, tc.matched)
		})
	}
}

// BenchmarkCompileKeys measures construction of one-key programs, including their predicates.
func BenchmarkCompileKeys(b *testing.B) {
	for _, tc := range benchmarkKeyCases() {
		if tc.name != "int/equal/hit" && tc.name != "float/equal/hit" && tc.name != "compare/equal/hit" && tc.name != "bool/is/hit" && tc.name != "list/contains/member" && tc.name != "dictionary/hasKey/member" {
			continue
		}
		b.Run(tc.name, func(b *testing.B) {
			chain := Chain[*benchmarkKeyInput]{Status: Success, Keys: []Key[*benchmarkKeyInput]{tc.key}}
			b.ReportAllocs()
			var (
				program *Program[*benchmarkKeyInput]
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
