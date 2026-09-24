package keycheck

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

func TestRegexIgnoreCaseParsesPattern(t *testing.T) {
	selector := func(value string) (string, bool) { return value, true }
	for _, test := range []struct {
		pattern string
		value   string
		want    bool
	}{
		{`\Qa.b`, "A.B", true},
		{`\Qa.b`, "AxB", false},
		{`a|b`, "B", true},
		{`(?-i:a)b`, "aB", true},
		{`(?-i:a)b`, "AB", false},
	} {
		assertKeyMatch(t, StringKey(selector, MatchesRegex, test.pattern, IgnoreCase), test.value, test.want)
		assertKeyMatch(t, BytesKey(func(b []byte) ([]byte, bool) { return b, true }, MatchesRegex, []byte(test.pattern), IgnoreCase), []byte(test.value), test.want)
	}
	for _, pattern := range []string{`a)(b`, `x)|(?-i:y`, `(`, `\`} {
		key := StringKey(selector, MatchesRegex, pattern, IgnoreCase)
		if _, err := Compile(Chain[string]{Status: Success, Keys: []Key[string]{key}}); !errors.Is(err, ErrInvalidPattern) {
			t.Fatalf("pattern %q: Compile error = %v; want ErrInvalidPattern", pattern, err)
		}
	}
}

func TestRegexPlansMissingValues(t *testing.T) {
	for _, pattern := range []string{`ready|done`, `(?i)ready|done`, `ready`, `^ready$`, `[0-9]+-ready`} {
		for _, op := range []Operator{MatchesRegex, DoesNotMatchRegex} {
			assertKeyMatch(t, StringKey(func(bool) (string, bool) { return "ready", false }, op, pattern), false, false)
			assertKeyMatch(t, BytesKey(func(bool) ([]byte, bool) { return []byte("ready"), false }, op, []byte(pattern)), false, false)
		}
	}
}

func TestRegexLiteralPlans(t *testing.T) {
	for _, test := range []struct {
		pattern    string
		ignoreCase bool
		kind       textKind
		fold       bool
		literal    string
	}{
		{`ready`, false, textContains, false, "ready"},
		{`^ready`, false, textPrefix, false, "ready"},
		{`ready$`, false, textSuffix, false, "ready"},
		{`^ready$`, false, textEqual, false, "ready"},
		{`\Aready\z`, false, textEqual, false, "ready"},
		{`^(ready)$`, false, textEqual, false, "ready"},
		{`a{3}`, false, textContains, false, "aaa"},
		{``, false, textContains, false, ""},
		{`^$`, false, textEqual, false, ""},
		{`(?i)ready`, false, textContains, true, "READY"},
		{`ready`, true, textContains, true, "READY"},
		{`\x{fffd}`, true, textContains, true, "�"},
		{`\x{fffd}`, false, textRegex, false, ""},
		{`(?m)^ready$`, false, textRegex, false, ""},
		{`a(?i)b`, false, textRegex, false, ""},
		{`ready|done`, false, textContainsAny, false, "ready|done"},
		{`(ready|done)`, false, textContainsAny, false, "ready|done"},
		{`(?i)ready|done`, false, textContainsAny, true, "READY|DONE"},
		{`ready|x{2}`, false, textContainsAny, false, "ready|xx"},
		{`ready|`, false, textContains, false, ""},
		{`ready|(?i)done`, false, textRegex, false, ""},
		{`^ready|done`, false, textRegex, false, ""},
		{`^^ready`, false, textRegex, false, ""},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			var c compiler
			got, err := c.regexTest(test.pattern, test.ignoreCase)
			if err != nil {
				t.Fatal(err)
			}
			literal := got.literal
			if got.kind == textContainsAny {
				literal = strings.Join(got.alternatives, "|")
			}
			if got.kind != test.kind || got.kind != textRegex && (got.fold != test.fold || literal != test.literal) {
				t.Fatalf("regexTest = kind %d, fold %v, literal %q; want kind %d, fold %v, literal %q",
					got.kind, got.fold, literal, test.kind, test.fold, test.literal)
			}
		})
	}
}

func TestRegexRequiredLiterals(t *testing.T) {
	for _, test := range []struct {
		pattern string
		exact   string
		folded  string
	}{
		{`[0-9]+-ready`, "-ready", ""},
		{`[0-9]+(?:alpha|beta)[a-z]*done`, "done", ""},
		{`(?i)[0-9]+ready`, "", "READY"},
		{`x*(?:token)+[0-9]`, "token", ""},
		{`[0-9]+(?:ab)?c`, "c", ""},
		{`[0-9](?i:ab)cd[0-9]`, "cd", ""},
		{`[0-9](?i:abc)d[0-9]`, "", "ABC"},
		{`^[0-9]+ready`, "", ""},
		{`ready[0-9]+`, "", ""},
		{`"id":[0-9]+,"ready":true`, `,"ready":true`, ""},
		{`ready-[0-9]+-done`, "", ""},
		{`[0-9]+(?:alpha|beta)`, "", ""},
		{`[0-9]\x{fffd}`, "", ""},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			var c compiler
			got, err := c.regexTest(test.pattern, false)
			if err != nil {
				t.Fatal(err)
			}
			if got.kind != textRegex {
				t.Fatalf("kind = %d; want regex", got.kind)
			}
			var exact, folded string
			if got.regex.exact != nil {
				exact = got.regex.exact.needle
			}
			if got.regex.folded != nil {
				folded = string(got.regex.folded.pattern)
			}
			if exact != test.exact || folded != test.folded {
				t.Fatalf("required literals = %q, %q; want %q, %q", exact, folded, test.exact, test.folded)
			}
		})
	}
}

func TestRegexDifferential(t *testing.T) {
	random := rand.New(rand.NewPCG(7, 8))
	atoms := []string{
		"a", "b", "K", "k", "s", "K", "ſ", "Σ", "é", ".", "[a-c]", "[^a]", `\d`, `\x{fffd}`,
		"(?i:ab)", "(?-i:k)", "(ab)", "(?:a|b)", `\Qa.\E`, "ab", "tok",
	}
	suffixes := []string{"", "", "", "*", "+", "?", "{2}", "{0,2}"}
	inputs := []string{"", "a", "ab", "AB", "k", "KK", "ſS", "\xff", "�", "a\xffb", "Éé", "xxtokab", "abab", "Tok"}
	selector := func(value string) (string, bool) { return value, true }
	for range 5000 {
		var pattern strings.Builder
		if random.IntN(4) == 0 {
			pattern.WriteString("^")
		}
		for i := range 1 + random.IntN(4) {
			if i > 0 && random.IntN(4) == 0 {
				pattern.WriteString("|")
			}
			pattern.WriteString(atoms[random.IntN(len(atoms))])
			pattern.WriteString(suffixes[random.IntN(len(suffixes))])
		}
		if random.IntN(4) == 0 {
			pattern.WriteString("$")
		}
		ignoreCase := random.IntN(2) == 0
		source := pattern.String()
		if ignoreCase {
			source = "(?i)" + source
		}
		expression := regexp.MustCompile(source)
		var options []TextOption
		if ignoreCase {
			options = append(options, IgnoreCase)
		}
		key := StringKey(selector, MatchesRegex, pattern.String(), options...)
		negated := BytesKey(func(value string) ([]byte, bool) { return []byte(value), true }, DoesNotMatchRegex, []byte(pattern.String()), options...)
		for range 4 {
			input := inputs[random.IntN(len(inputs))] + randomText(random, []rune("abkKKét"), random.IntN(6)) + inputs[random.IntN(len(inputs))]
			want := expression.MatchString(input)
			assertKeyMatch(t, key, input, want)
			assertKeyMatch(t, negated, input, !want)
		}
	}
}

func FuzzRegexKeys(f *testing.F) {
	f.Add(`[0-9]+-ready`, "id 12-ready", false)
	f.Add(`(?i)k\x{fffd}`, "K\xff", false)
	f.Add(`^ready$`, "ready", true)
	f.Add(`\Qa.b`, "A.B", true)
	f.Fuzz(func(t *testing.T, pattern, input string, ignoreCase bool) {
		if len(pattern) > 64 || len(input) > 256 {
			return
		}
		source := pattern
		var options []TextOption
		if ignoreCase {
			source, options = "(?i)"+pattern, []TextOption{IgnoreCase}
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return
		}
		expression, err := regexp.Compile(source)
		if err != nil {
			t.Fatalf("valid pattern %q failed with (?i): %v", pattern, err)
		}
		key := StringKey(func(value string) (string, bool) { return value, true }, MatchesRegex, pattern, options...)
		assertKeyMatch(t, key, input, expression.MatchString(input))
	})
}

// BenchmarkRegexPlans measures literal regex plans and required-literal filters on a non-matching body.
func BenchmarkRegexPlans(b *testing.B) {
	body := benchmarkHTML(4096)
	for _, test := range []struct {
		name, pattern string
		options       []TextOption
	}{
		{"literal", `Invalid password`, nil},
		{"literal_fold", `invalid password`, []TextOption{IgnoreCase}},
		{"inline_fold", `(?i)invalid password`, nil},
		{"required_literal", `[0-9]+ attempts? remaining`, nil},
		{"required_fold", `(?i)[0-9]+ attempts? remaining`, nil},
		{"required_after_prefix", `class="item-[0-9]+"><a href="/logout"`, nil},
		{"alternation", `Invalid password|Account locked|Too many attempts`, nil},
		{"alternation_fold", `(?i)invalid password|account locked|too many attempts`, nil},
		{"anchored", `^HTTP/1\.[01] 5[0-9]{2}`, nil},
	} {
		program := benchmarkCompile(b, Or, []Key[string]{StringKey(benchmarkString, MatchesRegex, test.pattern, test.options...)})
		expression := regexp.MustCompile(test.pattern)
		if len(test.options) > 0 {
			expression = regexp.MustCompile("(?i)" + test.pattern)
		}
		b.Run(fmt.Sprintf("%s/StringKey", test.name), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			benchmarkEvaluate(b, program, body, false)
		})
		b.Run(fmt.Sprintf("%s/Regexp", test.name), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if expression.MatchString(body) {
					b.Fatal("unexpected match")
				}
			}
		})
	}
}
