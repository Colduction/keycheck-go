package keycheck

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

func TestExactLiteralIndex(t *testing.T) {
	random := rand.New(rand.NewPCG(3, 4))
	for _, alphabet := range []string{"ab", "ab\"c:", "xyz\x00\xff", "e t"} {
		for range 20000 {
			value := randomBytes(random, alphabet, random.IntN(600))
			needle := randomBytes(random, alphabet, random.IntN(12))
			switch random.IntN(4) {
			case 0:
				if len(value) > 0 {
					start := random.IntN(len(value))
					needle = value[start:min(len(value), start+random.IntN(90))]
				}
			case 1:
				needle = strings.Repeat(alphabet[:1], random.IntN(80))
			}
			if got, want := newExactLiteral(needle).index(value), strings.Index(value, needle); got != want {
				t.Fatalf("index(%q, %q) = %d; want %d", value, needle, got, want)
			}
		}
	}
}

func TestExactLiteralDenseCandidates(t *testing.T) {
	for _, test := range []struct {
		name, value, needle string
	}{
		{"word scan", strings.Repeat("ab", 400) + "abc", "abc"},
		{"word scan miss", strings.Repeat("a-", 400), "a-b"},
		{"standard fallback", strings.Repeat("a", 800) + "b", "aab"},
		{"standard fallback miss", strings.Repeat("a", 800), "aaab"},
		{"long needle", strings.Repeat("xy", 900) + strings.Repeat("x", 100) + "z", strings.Repeat("x", 100) + "z"},
		{"tail", strings.Repeat("q", 70) + "qz", "qz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, want := newExactLiteral(test.needle).index(test.value), strings.Index(test.value, test.needle); got != want {
				t.Fatalf("index = %d; want %d", got, want)
			}
		})
	}
}

func FuzzExactLiteral(f *testing.F) {
	f.Add("abababababababababababababababababababc", "abc")
	f.Add(strings.Repeat("a", 200)+"b", "aaab")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, value, needle string) {
		if len(value) > 4096 || len(needle) > 256 {
			return
		}
		if got, want := newExactLiteral(needle).index(value), strings.Index(value, needle); got != want {
			t.Fatalf("index(%q, %q) = %d; want %d", value, needle, got, want)
		}
	})
}

func randomBytes(random *rand.Rand, alphabet string, size int) string {
	text := make([]byte, size)
	for i := range text {
		text[i] = alphabet[random.IntN(len(alphabet))]
	}
	return string(text)
}

// BenchmarkLiteralSearch compares literal keys with standard-library searches on structured bodies.
func BenchmarkLiteralSearch(b *testing.B) {
	for _, size := range []int{4096, 65536} {
		for _, test := range []struct {
			name, body, needle string
		}{
			{"json/quoted_key", benchmarkJSON(size), `"status":"success"`},
			{"json/rare_byte", benchmarkJSON(size), `access_token`},
			{"html/tag", benchmarkHTML(size), `<title>Dashboard</title>`},
			{"html/attribute", benchmarkHTML(size), `href="/logout"`},
		} {
			name := fmt.Sprintf("%s/bytes=%d", test.name, size)
			sensitive := benchmarkCompile(b, Or, []Key[string]{StringKey(benchmarkString, Contains, test.needle)})
			folded := benchmarkCompile(b, Or, []Key[string]{StringKey(benchmarkString, Contains, strings.ToUpper(test.needle), IgnoreCase)})
			b.Run(name+"/StringKey", func(b *testing.B) {
				b.SetBytes(int64(size))
				benchmarkEvaluate(b, sensitive, test.body, false)
			})
			b.Run(name+"/StringsContains", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					if strings.Contains(test.body, test.needle) {
						b.Fatal("unexpected match")
					}
				}
			})
			b.Run(name+"/IgnoreCase", func(b *testing.B) {
				b.SetBytes(int64(size))
				benchmarkEvaluate(b, folded, test.body, false)
			})
		}
	}
}

// BenchmarkLiteralSearchAdversarial measures 64 KiB near-misses that reach every fallback phase.
// The rarest needle byte, the first/last byte pairs, and every Unicode anchor occur densely without a match.
func BenchmarkLiteralSearchAdversarial(b *testing.B) {
	for _, size := range []int{8, 256} {
		for _, test := range []struct {
			name, body, needle string
			options            []TextOption
		}{
			{"exact", strings.Repeat("aaab", 16384), strings.Repeat("a", size-1) + "b", nil},
			{"fold", strings.Repeat("aaab", 16384), strings.Repeat("A", size-1) + "B", []TextOption{IgnoreCase}},
			{"fold_unicode", strings.Repeat("αααβ", 8192), strings.Repeat("Α", size-1) + "Β", []TextOption{IgnoreCase}},
		} {
			program := benchmarkCompile(b, Or, []Key[string]{StringKey(benchmarkString, Contains, test.needle, test.options...)})
			b.Run(fmt.Sprintf("%s/needle=%d", test.name, size), func(b *testing.B) {
				b.SetBytes(int64(len(test.body)))
				benchmarkEvaluate(b, program, test.body, false)
			})
		}
	}
}

func benchmarkJSON(size int) string {
	random := rand.New(rand.NewPCG(1, 2))
	names := []string{"alice", "bob", "carol", "dave", "eve", "mallory", "trent", "peggy"}
	var body strings.Builder
	body.WriteString(`{"data":[`)
	for body.Len() < size {
		fmt.Fprintf(&body, `{"id":%d,"name":"%s","email":"%s@example.com","active":%v,"score":%d.%d,"tags":["a","b"]},`,
			random.IntN(100000), names[random.IntN(len(names))], names[random.IntN(len(names))], random.IntN(2) == 0, random.IntN(1000), random.IntN(100))
	}
	return body.String()[:size]
}

func benchmarkHTML(size int) string {
	random := rand.New(rand.NewPCG(3, 4))
	words := []string{"the", "account", "settings", "profile", "login", "welcome", "back", "dashboard", "your", "order", "history"}
	var body strings.Builder
	body.WriteString("<!DOCTYPE html><html><head><title>Page</title></head><body>")
	for body.Len() < size {
		fmt.Fprintf(&body, "<div class=\"item-%d\"><a href=\"/p/%d\">%s %s</a><span>%s</span></div>\n",
			random.IntN(50), random.IntN(1000), words[random.IntN(len(words))], words[random.IntN(len(words))], words[random.IntN(len(words))])
	}
	return body.String()[:size]
}
