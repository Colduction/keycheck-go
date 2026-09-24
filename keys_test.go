package keycheck

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestStringKeyAndBytesKey(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		left  string
		right string
		want  bool
	}{
		{"equal", EqualTo, "alpha", "alpha", true},
		{"unequal", EqualTo, "alpha", "beta", false},
		{"case_sensitive_equal", EqualTo, "Alpha", "alpha", false},
		{"not_equal", NotEqualTo, "alpha", "beta", true},
		{"not_equal_same", NotEqualTo, "alpha", "alpha", false},
		{"contains", Contains, "alpha beta", "beta", true},
		{"contains_missing", Contains, "alpha beta", "gamma", false},
		{"case_sensitive_contains", Contains, "Alpha", "alpha", false},
		{"contains_empty", Contains, "", "", true},
		{"does_not_contain", DoesNotContain, "alpha", "beta", true},
		{"does_not_contain_present", DoesNotContain, "alpha", "alpha", false},
		{"does_not_contain_empty", DoesNotContain, "alpha", "", false},
		{"empty_exists", Exists, "", "ignored", true},
		{"empty_does_not_exist", DoesNotExist, "", "ignored", false},
		{"regex_search", MatchesRegex, "prefix123suffix", `[0-9]+`, true},
		{"regex_anchors", MatchesRegex, "prefix123suffix", `^[0-9]+$`, false},
		{"regex_case_sensitive", MatchesRegex, "ALPHA", `alpha`, false},
		{"regex_case_insensitive", MatchesRegex, "ALPHA", `(?i)alpha`, true},
		{"regex_multiline", MatchesRegex, "alpha\nbeta", `(?m)^beta$`, true},
		{"regex_dot_default", MatchesRegex, "alpha\nbeta", `alpha.beta`, false},
		{"regex_dot_all", MatchesRegex, "alpha\nbeta", `(?s)alpha.beta`, true},
		{"regex_empty", MatchesRegex, "", ``, true},
		{"regex_unicode", MatchesRegex, "αβγ", `^\p{Greek}+$`, true},
		{"regex_negative", DoesNotMatchRegex, "alpha", `[0-9]+`, true},
		{"regex_negative_match", DoesNotMatchRegex, "alpha123", `[0-9]+`, false},
		{"regex_negative_empty", DoesNotMatchRegex, "alpha", ``, false},
		{"binary_equal", EqualTo, "\xff\x00", "\xff\x00", true},
		{"binary_contains", Contains, "a\xff\x00z", "\xff\x00", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertKeyMatch(t, StringKey(func(s string) (string, bool) { return s, true }, tt.op, tt.right), tt.left, tt.want)
			assertKeyMatch(t, BytesKey(func(b []byte) ([]byte, bool) { return b, true }, tt.op, []byte(tt.right)), []byte(tt.left), tt.want)
		})
	}
}

func TestIntKey(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		left  int64
		right int64
		want  bool
	}{
		{"equal", EqualTo, -4, -4, true},
		{"unequal", EqualTo, -4, 4, false},
		{"not_equal", NotEqualTo, -4, 4, true},
		{"not_equal_same", NotEqualTo, -4, -4, false},
		{"less", LessThan, -4, 0, true},
		{"less_equal_values", LessThan, 4, 4, false},
		{"less_or_equal", LessThanOrEqualTo, 4, 4, true},
		{"less_or_equal_greater", LessThanOrEqualTo, 5, 4, false},
		{"greater", GreaterThan, 4, -4, true},
		{"greater_equal_values", GreaterThan, 4, 4, false},
		{"greater_or_equal", GreaterThanOrEqualTo, 4, 4, true},
		{"greater_or_equal_less", GreaterThanOrEqualTo, -4, 4, false},
		{"minimum", LessThan, math.MinInt64, math.MaxInt64, true},
		{"maximum", GreaterThan, math.MaxInt64, math.MinInt64, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertKeyMatch(t, IntKey(func(n int64) (int64, bool) { return n, true }, tt.op, tt.right), tt.left, tt.want)
		})
	}
}

func TestFloatKey(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		left  float64
		right float64
		want  bool
	}{
		{"equal", EqualTo, 1.25, 1.25, true},
		{"unequal", EqualTo, 1.25, 1.5, false},
		{"not_equal", NotEqualTo, 1.25, 1.5, true},
		{"not_equal_same", NotEqualTo, 1.25, 1.25, false},
		{"less", LessThan, -1.25, 0, true},
		{"less_equal_values", LessThan, 1.25, 1.25, false},
		{"less_or_equal", LessThanOrEqualTo, 1.25, 1.25, true},
		{"less_or_equal_greater", LessThanOrEqualTo, 1.5, 1.25, false},
		{"greater", GreaterThan, 1.25, -1.25, true},
		{"greater_equal_values", GreaterThan, 1.25, 1.25, false},
		{"greater_or_equal", GreaterThanOrEqualTo, 1.25, 1.25, true},
		{"greater_or_equal_less", GreaterThanOrEqualTo, -1.25, 1.25, false},
		{"positive_infinity_equal", EqualTo, math.Inf(1), math.Inf(1), true},
		{"positive_infinity_not_equal", NotEqualTo, math.Inf(1), math.Inf(1), false},
		{"negative_infinity", LessThan, math.Inf(-1), -math.MaxFloat64, true},
		{"infinity_order", GreaterThan, math.Inf(1), math.Inf(-1), true},
		{"nan_equal", EqualTo, math.NaN(), math.NaN(), false},
		{"nan_not_equal", NotEqualTo, math.NaN(), math.NaN(), true},
		{"nan_less", LessThan, math.NaN(), 0, false},
		{"nan_less_or_equal", LessThanOrEqualTo, math.NaN(), 0, false},
		{"nan_greater", GreaterThan, math.NaN(), 0, false},
		{"nan_greater_or_equal", GreaterThanOrEqualTo, math.NaN(), 0, false},
		{"subnormal_unequal", EqualTo, math.SmallestNonzeroFloat64, 0, false},
		{"subnormal_not_equal", NotEqualTo, math.SmallestNonzeroFloat64, 0, true},
		{"signed_zero_equal", EqualTo, math.Copysign(0, -1), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertKeyMatch(t, FloatKey(func(n float64) (float64, bool) { return n, true }, tt.op, tt.right), tt.left, tt.want)
		})
	}
}

func TestBoolKey(t *testing.T) {
	for _, right := range []bool{false, true} {
		assertKeyMatch(t, BoolKey(func(v bool) (bool, bool) { return v, true }, Is, right), right, true)
		assertKeyMatch(t, BoolKey(func(v bool) (bool, bool) { return v, true }, Is, right), !right, false)
		assertKeyMatch(t, BoolKey(func(v bool) (bool, bool) { return v, true }, IsNot, right), right, false)
		assertKeyMatch(t, BoolKey(func(v bool) (bool, bool) { return v, true }, IsNot, right), !right, true)
	}
}

func TestListKey(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		left  []string
		right string
		want  bool
	}{
		{"contains", Contains, []string{"alpha", "beta"}, "beta", true},
		{"missing", Contains, []string{"alpha", "beta"}, "gamma", false},
		{"whole_elements", Contains, []string{"alpha beta"}, "beta", false},
		{"case_sensitive", Contains, []string{"Alpha"}, "alpha", false},
		{"empty_element", Contains, []string{""}, "", true},
		{"not_contains", DoesNotContain, []string{"alpha"}, "beta", true},
		{"not_contains_match", DoesNotContain, []string{"alpha"}, "alpha", false},
		{"nil_exists", Exists, nil, "ignored", true},
		{"nil_does_not_exist", DoesNotExist, nil, "ignored", false},
		{"nil_contains_empty", Contains, nil, "", false},
		{"nil_not_contains", DoesNotContain, nil, "", true},
		{"empty_exists", Exists, []string{}, "ignored", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertKeyMatch(t, ListKey(func(v []string) ([]string, bool) { return v, true }, tt.op, tt.right), tt.left, tt.want)
		})
	}
}

func TestDictionaryKey(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		left  map[string]string
		right string
		want  bool
	}{
		{"has_key", HasKey, map[string]string{"alpha": "one"}, "alpha", true},
		{"has_key_empty_value", HasKey, map[string]string{"alpha": ""}, "alpha", true},
		{"missing_key", HasKey, map[string]string{"alpha": "one"}, "beta", false},
		{"case_sensitive_key", HasKey, map[string]string{"Alpha": "one"}, "alpha", false},
		{"not_has_key", DoesNotHaveKey, map[string]string{"alpha": "one"}, "beta", true},
		{"not_has_key_present", DoesNotHaveKey, map[string]string{"alpha": ""}, "alpha", false},
		{"has_value", HasValue, map[string]string{"alpha": "one", "beta": "two"}, "two", true},
		{"missing_value", HasValue, map[string]string{"alpha": "one"}, "two", false},
		{"whole_value", HasValue, map[string]string{"alpha": "one two"}, "one", false},
		{"case_sensitive_value", HasValue, map[string]string{"alpha": "One"}, "one", false},
		{"has_empty_value", HasValue, map[string]string{"alpha": ""}, "", true},
		{"not_has_value", DoesNotHaveValue, map[string]string{"alpha": "one"}, "two", true},
		{"not_has_value_present", DoesNotHaveValue, map[string]string{"alpha": "one"}, "one", false},
		{"nil_exists", Exists, nil, "ignored", true},
		{"nil_does_not_exist", DoesNotExist, nil, "ignored", false},
		{"nil_has_key", HasKey, nil, "", false},
		{"nil_not_has_key", DoesNotHaveKey, nil, "", true},
		{"nil_has_value", HasValue, nil, "", false},
		{"nil_not_has_value", DoesNotHaveValue, nil, "", true},
		{"empty_exists", Exists, map[string]string{}, "ignored", true},
		{"existence_is_not_membership", Exists, map[string]string{"alpha": "one"}, "missing", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertKeyMatch(t, DictionaryKey(func(v map[string]string) (map[string]string, bool) { return v, true }, tt.op, tt.right), tt.left, tt.want)
		})
	}
}

func TestKeysMissingValues(t *testing.T) {
	for _, op := range []Operator{EqualTo, NotEqualTo, Contains, DoesNotContain, Exists, DoesNotExist, MatchesRegex, DoesNotMatchRegex} {
		assertKeyMatch(t, StringKey(func(bool) (string, bool) { return "value", false }, op, "value"), false, op == DoesNotExist)
		assertKeyMatch(t, BytesKey(func(bool) ([]byte, bool) { return []byte("value"), false }, op, []byte("value")), false, op == DoesNotExist)
	}
	for _, op := range []Operator{EqualTo, NotEqualTo, LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo} {
		assertKeyMatch(t, IntKey(func(bool) (int64, bool) { return 1, false }, op, 2), false, false)
		assertKeyMatch(t, FloatKey(func(bool) (float64, bool) { return 1, false }, op, 2), false, false)
	}
	for _, op := range []Operator{Is, IsNot} {
		assertKeyMatch(t, BoolKey(func(bool) (bool, bool) { return false, false }, op, true), false, false)
	}
	for _, op := range []Operator{Contains, DoesNotContain, Exists, DoesNotExist} {
		assertKeyMatch(t, ListKey(func(bool) ([]string, bool) { return nil, false }, op, "value"), false, op == DoesNotExist)
	}
	for _, op := range []Operator{HasKey, DoesNotHaveKey, HasValue, DoesNotHaveValue, Exists, DoesNotExist} {
		assertKeyMatch(t, DictionaryKey(func(bool) (map[string]string, bool) { return nil, false }, op, "value"), false, op == DoesNotExist)
	}
}

func TestBytesKeyPresentNil(t *testing.T) {
	for _, tt := range []struct {
		op   Operator
		want bool
	}{
		{EqualTo, true},
		{NotEqualTo, false},
		{Contains, true},
		{DoesNotContain, false},
		{Exists, true},
		{DoesNotExist, false},
		{MatchesRegex, true},
		{DoesNotMatchRegex, false},
	} {
		assertKeyMatch(t, BytesKey(func(bool) ([]byte, bool) { return nil, true }, tt.op, nil), true, tt.want)
	}
}

func TestKeysInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		key  Key[bool]
		want error
	}{
		{"string_nil_selector", StringKey[bool](nil, EqualTo, ""), ErrInvalidKey},
		{"bytes_nil_selector", BytesKey[bool](nil, EqualTo, nil), ErrInvalidKey},
		{"int_nil_selector", IntKey[bool](nil, EqualTo, 0), ErrInvalidKey},
		{"float_nil_selector", FloatKey[bool](nil, EqualTo, 0), ErrInvalidKey},
		{"bool_nil_selector", BoolKey[bool](nil, Is, false), ErrInvalidKey},
		{"list_nil_selector", ListKey[bool](nil, Contains, ""), ErrInvalidKey},
		{"dictionary_nil_selector", DictionaryKey[bool](nil, HasKey, ""), ErrInvalidKey},
		{"string_invalid_operator", StringKey(func(bool) (string, bool) { return "", true }, GreaterThan, ""), ErrInvalidOperator},
		{"bytes_invalid_operator", BytesKey(func(bool) ([]byte, bool) { return nil, true }, HasKey, nil), ErrInvalidOperator},
		{"int_invalid_operator", IntKey(func(bool) (int64, bool) { return 0, true }, Exists, 0), ErrInvalidOperator},
		{"float_invalid_operator", FloatKey(func(bool) (float64, bool) { return 0, true }, Contains, 0), ErrInvalidOperator},
		{"bool_invalid_operator", BoolKey(func(bool) (bool, bool) { return false, true }, EqualTo, false), ErrInvalidOperator},
		{"list_invalid_operator", ListKey(func(bool) ([]string, bool) { return nil, true }, EqualTo, ""), ErrInvalidOperator},
		{"dictionary_invalid_operator", DictionaryKey(func(bool) (map[string]string, bool) { return nil, true }, Contains, ""), ErrInvalidOperator},
		{"unknown_operator", StringKey(func(bool) (string, bool) { return "", true }, Operator(255), ""), ErrInvalidOperator},
		{"string_invalid_regex", StringKey(func(bool) (string, bool) { return "", true }, MatchesRegex, "["), ErrInvalidPattern},
		{"bytes_invalid_regex", BytesKey(func(bool) ([]byte, bool) { return nil, true }, DoesNotMatchRegex, []byte("[")), ErrInvalidPattern},
		{"unsupported_lookahead", StringKey(func(bool) (string, bool) { return "", true }, MatchesRegex, "a(?=b)"), ErrInvalidPattern},
		{"unsupported_backreference", StringKey(func(bool) (string, bool) { return "", true }, MatchesRegex, `(a)\1`), ErrInvalidPattern},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile(Chain[bool]{Status: Success, Keys: []Key[bool]{tt.key}})
			if !errors.Is(err, tt.want) {
				t.Fatalf("Compile error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestBytesKeyOwnsExpectedValue(t *testing.T) {
	for _, op := range []Operator{EqualTo, Contains, MatchesRegex} {
		right := []byte("token")
		key := BytesKey(func(b []byte) ([]byte, bool) { return b, true }, op, right)
		right[0] = 'b'
		program, err := Compile(Chain[[]byte]{Status: Success, Keys: []Key[[]byte]{key}})
		if err != nil {
			t.Fatal(err)
		}
		right[1] = 'r'
		for _, input := range []string{"token", "broken"} {
			result, err := program.Evaluate([]byte(input), Status("fallback"))
			if err != nil || result.Matched != (input == "token") {
				t.Fatalf("operator %v, input %q: result = %+v, error = %v", op, input, result, err)
			}
		}
		assertKeyMatch(t, key, []byte("token"), true)
	}
}

func TestKeysAllocations(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		key := StringKey(func(value string) (string, bool) { return value, true }, Contains, "ready")
		assertKeyAllocations(t, key, "service ready", "service pending")
	})
	t.Run("bytes", func(t *testing.T) {
		key := BytesKey(func(value []byte) ([]byte, bool) { return value, true }, Contains, []byte("ready"))
		assertKeyAllocations(t, key, []byte("service ready"), []byte("service pending"))
	})
	t.Run("integer", func(t *testing.T) {
		key := IntKey(func(value int64) (int64, bool) { return value, true }, GreaterThanOrEqualTo, 200)
		assertKeyAllocations(t, key, int64(204), int64(199))
	})
	t.Run("float", func(t *testing.T) {
		key := FloatKey(func(value float64) (float64, bool) { return value, true }, LessThan, 1.5)
		assertKeyAllocations(t, key, 1.25, 1.75)
	})
	t.Run("boolean", func(t *testing.T) {
		key := BoolKey(func(value bool) (bool, bool) { return value, true }, Is, true)
		assertKeyAllocations(t, key, true, false)
	})
	t.Run("list", func(t *testing.T) {
		key := ListKey(func(value []string) ([]string, bool) { return value, true }, Contains, "ready")
		assertKeyAllocations(t, key, []string{"pending", "ready"}, []string{"pending", "waiting"})
	})
	t.Run("dictionary_key", func(t *testing.T) {
		key := DictionaryKey(func(value map[string]string) (map[string]string, bool) { return value, true }, HasKey, "state")
		assertKeyAllocations(t, key, map[string]string{"state": "ready"}, map[string]string{"other": "ready"})
	})
	t.Run("dictionary_value", func(t *testing.T) {
		key := DictionaryKey(func(value map[string]string) (map[string]string, bool) { return value, true }, HasValue, "ready")
		assertKeyAllocations(t, key, map[string]string{"first": "pending", "second": "ready"}, map[string]string{"first": "pending", "second": "waiting"})
	})
	t.Run("multiple_chains_all_miss", func(t *testing.T) {
		selector := func(value int64) (int64, bool) { return value, true }
		chains := make([]Chain[int64], 16)
		for i := range chains {
			chains[i] = Chain[int64]{Status: Success, Keys: []Key[int64]{IntKey(selector, EqualTo, int64(i))}}
		}
		program, err := Compile(chains...)
		if err != nil {
			t.Fatal(err)
		}
		if got := testing.AllocsPerRun(1000, func() {
			result, err := program.Evaluate(100, None)
			if err != nil || result != (Result{Status: None, Chain: -1}) {
				t.Fatalf("Evaluate = %+v, %v; want fallback", result, err)
			}
		}); got != 0 {
			t.Fatalf("all-miss evaluation allocated %g times; want 0", got)
		}
	})
}

func TestRegexKeysWarmAllocations(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		key := StringKey(func(value string) (string, bool) { return value, true }, MatchesRegex, `^ready-[0-9]+$`)
		assertKeyAllocations(t, key, "ready-123", "ready-no")
	})
	t.Run("bytes", func(t *testing.T) {
		key := BytesKey(func(value []byte) ([]byte, bool) { return value, true }, MatchesRegex, []byte(`^ready-[0-9]+$`))
		assertKeyAllocations(t, key, []byte("ready-123"), []byte("ready-no"))
	})
}

func TestKeysConcurrentEvaluation(t *testing.T) {
	type input struct {
		text       string
		body       []byte
		integer    int64
		float      float64
		boolean    bool
		list       []string
		dictionary map[string]string
	}
	program, err := Compile(Chain[input]{Status: Success, Mode: And, Keys: []Key[input]{
		StringKey(func(value input) (string, bool) { return value.text, true }, MatchesRegex, `^[a-z]+-[0-9]+$`),
		BytesKey(func(value input) ([]byte, bool) { return value.body, true }, MatchesRegex, []byte(`^[a-z]+-[0-9]+$`)),
		IntKey(func(value input) (int64, bool) { return value.integer, true }, EqualTo, 204),
		FloatKey(func(value input) (float64, bool) { return value.float, true }, LessThan, 1.5),
		BoolKey(func(value input) (bool, bool) { return value.boolean, true }, Is, true),
		ListKey(func(value input) ([]string, bool) { return value.list, true }, Contains, "ready"),
		DictionaryKey(func(value input) (map[string]string, bool) { return value.dictionary, true }, HasValue, "ready"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var inputs [8]input
	for i := range inputs {
		inputs[i] = input{
			text: "ready-42", body: []byte("ready-42"), integer: 204, float: 1.25, boolean: true,
			list: []string{"pending", "ready"}, dictionary: map[string]string{"first": "pending", "second": "ready"},
		}
	}
	inputs[1].text = "not-ready"
	inputs[2].body = []byte("not-ready")
	inputs[3].integer = 503
	inputs[4].float = 1.75
	inputs[5].boolean = false
	inputs[6].list = []string{"pending"}
	inputs[7].dictionary = map[string]string{"state": "pending"}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 100 {
				for i, value := range inputs {
					want := Result{Status: None, Chain: -1}
					if i == 0 {
						want = Result{Status: Success, Matched: true, Chain: 0}
					}
					result, err := program.Evaluate(value, None)
					if err != nil || result != want {
						t.Errorf("input %d: Evaluate = %+v, %v; want %+v", i, result, err, want)
						return
					}
				}
			}
		})
	}
	workers.Wait()
}

func FuzzStringAndBytesKeys(f *testing.F) {
	f.Add([]byte("service ready"), []byte("ready"), uint8(2), true)
	f.Add([]byte("service ready"), []byte("pending"), uint8(3), false)
	f.Add([]byte(nil), []byte(nil), uint8(0), true)
	f.Add([]byte{}, []byte{}, uint8(5), false)
	f.Add([]byte{0xff, 0, 'x'}, []byte{0xff, 0}, uint8(2), true)
	f.Add([]byte{0xff, 0, 'x'}, []byte(`^.*$`), uint8(6), true)
	f.Add([]byte("READY\n123"), []byte(`(?ims)^ready.[0-9]+$`), uint8(6), true)
	f.Add([]byte("ready"), []byte(`[`), uint8(6), true)
	f.Add([]byte("ready"), []byte(`(?=ready)`), uint8(7), false)
	f.Add([]byte("ready"), []byte{0xff}, uint8(6), true)
	f.Fuzz(func(t *testing.T, data, right []byte, operation uint8, present bool) {
		if len(data) > 512 || len(right) > 64 {
			return
		}
		operators := [...]Operator{EqualTo, NotEqualTo, Contains, DoesNotContain, Exists, DoesNotExist, MatchesRegex, DoesNotMatchRegex}
		op := operators[int(operation)%len(operators)]
		text, target := string(data), string(right)
		stringProgram, stringErr := Compile(Chain[string]{Status: Success, Keys: []Key[string]{
			StringKey(func(value string) (string, bool) { return value, present }, op, target),
		}})
		bytesProgram, bytesErr := Compile(Chain[[]byte]{Status: Success, Keys: []Key[[]byte]{
			BytesKey(func(value []byte) ([]byte, bool) { return value, present }, op, right),
		}})
		var expression *regexp.Regexp
		if op == MatchesRegex || op == DoesNotMatchRegex {
			var err error
			expression, err = regexp.Compile(target)
			if err != nil {
				if stringProgram != nil || bytesProgram != nil || !errors.Is(stringErr, ErrInvalidPattern) || !errors.Is(bytesErr, ErrInvalidPattern) {
					t.Fatalf("invalid pattern accepted: string error %v, bytes error %v", stringErr, bytesErr)
				}
				return
			}
		}
		if stringErr != nil || bytesErr != nil {
			t.Fatalf("Compile: string error %v, bytes error %v", stringErr, bytesErr)
		}
		want := op == DoesNotExist && !present
		if present {
			switch op {
			case EqualTo:
				want = text == target
			case NotEqualTo:
				want = text != target
			case Contains:
				want = strings.Contains(text, target)
			case DoesNotContain:
				want = !strings.Contains(text, target)
			case Exists:
				want = true
			case MatchesRegex:
				want = expression.MatchString(text)
			case DoesNotMatchRegex:
				want = !expression.MatchString(text)
			}
		}
		stringResult, stringErr := stringProgram.Evaluate(text, None)
		bytesResult, bytesErr := bytesProgram.Evaluate(data, None)
		wantResult := Result{Status: None, Chain: -1}
		if want {
			wantResult = Result{Status: Success, Matched: true, Chain: 0}
		}
		if stringErr != nil || bytesErr != nil || stringResult != wantResult || bytesResult != wantResult {
			t.Fatalf("operator %v, present %v: string %+v, %v; bytes %+v, %v; want %+v", op, present, stringResult, stringErr, bytesResult, bytesErr, wantResult)
		}
	})
}

func assertKeyAllocations[T any](t *testing.T, key Key[T], match, miss T) {
	t.Helper()
	program, err := Compile(Chain[T]{Status: Success, Keys: []Key[T]{key}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		input T
		want  Result
	}{
		{"match", match, Result{Status: Success, Matched: true, Chain: 0}},
		{"miss", miss, Result{Status: None, Chain: -1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(1000, func() {
				result, err := program.Evaluate(tt.input, None)
				if err != nil || result != tt.want {
					t.Fatalf("Evaluate = %+v, %v; want %+v", result, err, tt.want)
				}
			}); got != 0 {
				t.Fatalf("Evaluate allocated %g times; want 0", got)
			}
		})
	}
}

func assertKeyMatch[T any](t *testing.T, key Key[T], input T, want bool) {
	t.Helper()
	program, err := Compile(Chain[T]{Status: Success, Keys: []Key[T]{key}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	result, err := program.Evaluate(input, Status("fallback"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Matched != want {
		t.Fatalf("Matched = %v, want %v (input %v)", result.Matched, want, input)
	}
	wantStatus := Status("fallback")
	if want {
		wantStatus = Success
	}
	if result.Status != wantStatus {
		t.Fatalf("Status = %v, want %v", result.Status, wantStatus)
	}
}
