package keycheck

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCanonicalFoldUnicode(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		want, size := r, 1
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			want, size = min(want, next), size+1
		}
		if got := canonicalFold(r); got != want {
			t.Fatalf("canonicalFold(%U) = %U; want %U", r, got, want)
		}
		// foldedLiteral stores each orbit in four slots.
		if size > 4 {
			t.Fatalf("simple folding orbit of %U has %d runes; want at most 4", r, size)
		}
	}
}

func TestTextLiteralOperators(t *testing.T) {
	for _, test := range []struct {
		name     string
		value    string
		needle   string
		equal    bool
		contains bool
		prefix   bool
		suffix   bool
	}{
		{"ascii", "Alpha Beta", "ALPHA", false, true, true, false},
		{"ascii suffix", "Alpha Beta", "bETA", false, true, false, true},
		{"middle", "Alpha Beta Gamma", "BETA", false, true, false, false},
		{"equal", "Alpha", "ALPHA", true, true, true, true},
		{"kelvin", "\u212a", "k", true, true, true, true},
		{"kelvin needle", "K", "\u212a", true, true, true, true},
		{"long s", "\u017f", "S", true, true, true, true},
		{"sigma", "\u03c3\u03c2\u03a3", "\u03a3", false, true, true, true},
		{"sharp s", "Stra\u00dfe", "STRASSE", false, false, false, false},
		{"capital sharp s", "\u1e9e", "\u00df", true, true, true, true},
		{"dotted i", "\u0130", "i", false, false, false, false},
		{"dotless i", "\u0131", "I", false, false, false, false},
		{"invalid byte", "\xffK", "\ufffdk", true, true, true, true},
		{"invalid needle", "\ufffdK", "\xffk", true, true, true, true},
		{"two invalid bytes", "\xff\xfe", "\ufffd", false, true, true, true},
		{"rune boundary", "\u00e9", "\xa9", false, false, false, false},
		{"empty", "", "", true, true, true, true},
		{"empty needle", "Alpha", "", false, true, true, true},
		{"empty value", "", "Alpha", false, false, false, false},
		{"overlap", "ababababac", "ABABAC", false, true, false, true},
		{"overlap miss", "aaaaaaaaaaaaaaab", "AAAAAAAAC", false, false, false, false},
		{"longer needle", "AA", "AAA", false, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, comparison := range []struct {
				op   Operator
				want bool
			}{
				{EqualTo, test.equal}, {NotEqualTo, !test.equal},
				{Contains, test.contains}, {DoesNotContain, !test.contains},
				{StartsWith, test.prefix}, {DoesNotStartWith, !test.prefix},
				{EndsWith, test.suffix}, {DoesNotEndWith, !test.suffix},
			} {
				assertKeyMatch(t, StringKey(func(s string) (string, bool) { return s, true }, comparison.op, test.needle, IgnoreCase), test.value, comparison.want)
				assertKeyMatch(t, BytesKey(func(b []byte) ([]byte, bool) { return b, true }, comparison.op, []byte(test.needle), IgnoreCase), []byte(test.value), comparison.want)
			}
			for _, comparison := range []struct {
				op   Operator
				want bool
			}{
				{StartsWith, strings.HasPrefix(test.value, test.needle)},
				{DoesNotStartWith, !strings.HasPrefix(test.value, test.needle)},
				{EndsWith, strings.HasSuffix(test.value, test.needle)},
				{DoesNotEndWith, !strings.HasSuffix(test.value, test.needle)},
			} {
				assertKeyMatch(t, StringKey(func(s string) (string, bool) { return s, true }, comparison.op, test.needle), test.value, comparison.want)
				assertKeyMatch(t, BytesKey(func(b []byte) ([]byte, bool) { return b, true }, comparison.op, []byte(test.needle)), []byte(test.value), comparison.want)
			}
		})
	}
}

func TestTextPresence(t *testing.T) {
	for _, op := range []Operator{EqualTo, NotEqualTo, Contains, DoesNotContain, StartsWith, DoesNotStartWith, EndsWith, DoesNotEndWith, MatchesRegex, DoesNotMatchRegex, Exists, DoesNotExist} {
		assertKeyMatch(t, StringKey(func(bool) (string, bool) { return "Alpha", false }, op, "Alpha", IgnoreCase), false, op == DoesNotExist)
		assertKeyMatch(t, BytesKey(func(bool) ([]byte, bool) { return nil, false }, op, []byte("Alpha"), IgnoreCase), false, op == DoesNotExist)
	}
	for _, op := range []Operator{Exists, DoesNotExist} {
		assertKeyMatch(t, StringKey(func(bool) (string, bool) { return "", true }, op, "[", IgnoreCase), false, op == Exists)
		assertKeyMatch(t, BytesKey(func(bool) ([]byte, bool) { return nil, true }, op, []byte("["), IgnoreCase), false, op == Exists)
	}
}

func TestTextRegexOptions(t *testing.T) {
	for _, op := range []Operator{MatchesRegex, DoesNotMatchRegex} {
		for _, value := range []string{"ALPHA", "Beta"} {
			want := (value == "ALPHA") == (op == MatchesRegex)
			assertKeyMatch(t, StringKey(func(s string) (string, bool) { return s, true }, op, "^alpha$", IgnoreCase), value, want)
			assertKeyMatch(t, BytesKey(func(b []byte) ([]byte, bool) { return b, true }, op, []byte("^alpha$"), IgnoreCase), []byte(value), want)
		}
	}
	assertKeyMatch(t, StringKey(func(s string) (string, bool) { return s, true }, MatchesRegex, "(?-i:alpha)", IgnoreCase), "ALPHA", false)
}

func TestTextInvalidOptions(t *testing.T) {
	for _, op := range []Operator{EqualTo, Exists, DoesNotExist, MatchesRegex} {
		for _, option := range []TextOption{0, 255} {
			keys := []Key[string]{
				StringKey(func(s string) (string, bool) { return s, true }, op, "", option),
				BytesKey(func(s string) ([]byte, bool) { return nil, true }, op, nil, option),
			}
			for _, key := range keys {
				if _, err := Compile(Chain[string]{Status: Success, Keys: []Key[string]{key}}); !errors.Is(err, ErrInvalidOption) {
					t.Fatalf("Compile option %d, operator %d: %v; want ErrInvalidOption", option, op, err)
				}
			}
		}
	}
}

func TestTextOptionsSnapshot(t *testing.T) {
	options := []TextOption{IgnoreCase, IgnoreCase}
	stringKey := StringKey(func(s string) (string, bool) { return s, true }, Contains, "alpha", options...)
	needle := []byte("alpha")
	bytesKey := BytesKey(func(b []byte) ([]byte, bool) { return b, true }, StartsWith, needle, options...)
	options[0] = 255
	needle[0] = 'z'
	assertKeyMatch(t, stringKey, "ALPHA", true)
	assertKeyMatch(t, bytesKey, []byte("ALPHA"), true)
	invalid := StringKey(func(s string) (string, bool) { return s, true }, Contains, "alpha", options...)
	options[0] = IgnoreCase
	if _, err := Compile(Chain[string]{Status: Success, Keys: []Key[string]{invalid}}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("Compile changed after option slice mutation: %v", err)
	}
}

func TestTextIgnoreCaseAllocations(t *testing.T) {
	value := "\u212aELVIN \u03a3igma \u017fAMPLE"
	for _, op := range []Operator{EqualTo, NotEqualTo, Contains, DoesNotContain, StartsWith, DoesNotStartWith, EndsWith, DoesNotEndWith} {
		stringProgram, err := Compile(Chain[string]{Status: Success, Keys: []Key[string]{StringKey(func(s string) (string, bool) { return s, true }, op, "kelvin", IgnoreCase)}})
		if err != nil {
			t.Fatal(err)
		}
		bytesProgram, err := Compile(Chain[[]byte]{Status: Success, Keys: []Key[[]byte]{BytesKey(func(b []byte) ([]byte, bool) { return b, true }, op, []byte("kelvin"), IgnoreCase)}})
		if err != nil {
			t.Fatal(err)
		}
		input := []byte(value)
		if got := testing.AllocsPerRun(100, func() {
			if _, err := stringProgram.Evaluate(value, None); err != nil {
				t.Fatal(err)
			}
			if _, err := bytesProgram.Evaluate(input, None); err != nil {
				t.Fatal(err)
			}
		}); got != 0 {
			t.Fatalf("operator %d allocated %g times; want 0", op, got)
		}
	}
}

func FuzzTextSearch(f *testing.F) {
	for _, seed := range [][2]string{
		{"ababababac", "ABABAC"}, {"\u212a\u017f\u03c2", "ks\u03a3"}, {"\xff\xfeK", "\ufffdk"},
		{"\xe2\x82x\xa9", "\ufffd"}, {"", ""}, {"\u00e9", "\xa9"}, {"aaaaaaab", "AAAAC"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, value, needle string) {
		if len(value) > 1024 || len(needle) > 128 {
			return
		}
		assertFoldedSearch(t, value, needle)
	})
}

func assertFoldedSearch(t *testing.T, value, needle string) {
	t.Helper()
	matcher := compileFoldedLiteral(needle)
	for _, test := range []struct {
		op    Operator
		match func(string) bool
	}{
		{EqualTo, matcher.equal}, {Contains, matcher.contains}, {StartsWith, matcher.hasPrefix}, {EndsWith, matcher.hasSuffix},
	} {
		if got, want := test.match(value), referenceFoldedSearch(value, needle, test.op); got != want {
			t.Fatalf("operator %d, value %q, needle %q: %v; want %v", test.op, value, needle, got, want)
		}
	}
}

// TestFoldedSearchPhases drives candidate, word-scan, and KMP fallback paths with dense anchors.
func TestFoldedSearchPhases(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	alphabets := []string{"aAb-", "kKsKſS", "αΑσΣςx", "ab\xff\xc3\xa9É", "zZKk", "éÉ-."}
	for range 20000 {
		alphabet := []rune(alphabets[random.IntN(len(alphabets))])
		value := randomText(random, alphabet, random.IntN(400))
		needle := randomText(random, alphabet, 1+random.IntN(6))
		if random.IntN(3) == 0 && len(value) > 0 {
			start := random.IntN(len(value))
			needle = value[start:min(len(value), start+1+random.IntN(8))]
		}
		assertFoldedSearch(t, value, needle)
	}
}

func randomText(random *rand.Rand, alphabet []rune, size int) string {
	var text strings.Builder
	for text.Len() < size {
		text.WriteRune(alphabet[random.IntN(len(alphabet))])
	}
	return text.String()
}

func referenceFoldedSearch(value, needle string, op Operator) bool {
	boundaries := make([]int, 0, utf8.RuneCountInString(value)+1)
	for offset := range value {
		boundaries = append(boundaries, offset)
	}
	boundaries = append(boundaries, len(value))
	count := utf8.RuneCountInString(needle)
	for start := 0; start+count < len(boundaries); start++ {
		end := start + count
		if (op == StartsWith || op == EqualTo) && start != 0 || (op == EndsWith || op == EqualTo) && end != len(boundaries)-1 {
			continue
		}
		if strings.EqualFold(value[boundaries[start]:boundaries[end]], needle) {
			return true
		}
	}
	return false
}

func BenchmarkIgnoreCaseContains(b *testing.B) {
	for _, size := range []int{4096, 65536} {
		for _, text := range []struct {
			name   string
			fill   string
			token  string
			needle string
		}{
			{"ASCII", "x", "present-TOKEN", "PRESENT-token"},
			{"Unicode", "\u03b1", "\u212aelvin-\u017fAMPLE", "KELVIN-sample"},
			{"Greek", "\u03b1\u03b2\u03b3 ", "\u039b\u039f\u0393\u0399\u039d", "\u03bb\u03bf\u03b3\u03b9\u03bd"},
		} {
			value := strings.Repeat(text.fill, (size-len(text.token))/len(text.fill)) + text.token
			input := []byte(value)
			pattern := regexp.MustCompile("(?i:" + regexp.QuoteMeta(text.needle) + ")")
			stringProgram, err := Compile(Chain[string]{Status: Success, Keys: []Key[string]{StringKey(func(s string) (string, bool) { return s, true }, Contains, text.needle, IgnoreCase)}})
			if err != nil {
				b.Fatal(err)
			}
			bytesProgram, err := Compile(Chain[[]byte]{Status: Success, Keys: []Key[[]byte]{BytesKey(func(v []byte) ([]byte, bool) { return v, true }, Contains, []byte(text.needle), IgnoreCase)}})
			if err != nil {
				b.Fatal(err)
			}
			name := fmt.Sprintf("%s/bytes=%d", text.name, len(value))
			b.Run(name+"/StringKey", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(value)))
				for b.Loop() {
					if result, err := stringProgram.Evaluate(value, None); err != nil || !result.Matched {
						b.Fatalf("Evaluate = %+v, %v", result, err)
					}
				}
			})
			b.Run(name+"/BytesKey", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(value)))
				for b.Loop() {
					if result, err := bytesProgram.Evaluate(input, None); err != nil || !result.Matched {
						b.Fatalf("Evaluate = %+v, %v", result, err)
					}
				}
			})
			b.Run(name+"/RegexpString", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(value)))
				if !pattern.MatchString(value) {
					b.Fatal("warm regex did not match")
				}
				for b.Loop() {
					if !pattern.MatchString(value) {
						b.Fatal("regex did not match")
					}
				}
			})
			b.Run(name+"/RegexpBytes", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(value)))
				if !pattern.Match(input) {
					b.Fatal("warm regex did not match")
				}
				for b.Loop() {
					if !pattern.Match(input) {
						b.Fatal("regex did not match")
					}
				}
			})
		}
	}
}
