package httpcheck

import (
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/colduction/keycheck-go"
)

type untouchedBody struct{}

func (untouchedBody) Read([]byte) (int, error) {
	panic("response body read")
}

func (untouchedBody) Close() error {
	panic("response body closed")
}

type forkHeader map[string][]string

// TestAddress checks exact caller-supplied text and independent presence.
func TestAddress(t *testing.T) {
	for _, test := range []struct {
		name  string
		input Input
	}{
		{name: "absent"},
		{
			name: "absent with metadata",
			input: Input{
				StatusCode: http.StatusOK,
				Header:     http.Header{"X-Example": {"header"}},
				Trailer:    http.Header{"X-Example": {"trailer"}},
				Body:       []byte("ready"),
			},
		},
		{name: "address only", input: Input{Address: "https://example.com/ready"}},
		{
			name: "case escaping query fragment",
			input: Input{
				Address:    "HTTPS://Example.COM/Ready%2fNow?q=A%2FB&x=One+Two#Part",
				StatusCode: http.StatusOK,
				Header:     http.Header{"X-Example": {"header"}},
				Trailer:    http.Header{"X-Example": {"trailer"}},
				Body:       []byte("ready"),
			},
		},
		{name: "surrounding whitespace", input: Input{Address: " https://example.com/ready\t"}},
		{name: "whitespace only", input: Input{Address: " \t\n"}},
		{name: "malformed", input: Input{Address: "://%zz not a URL"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, present := Address(test.input)
			if got != test.input.Address || present != (test.input.Address != "") {
				t.Fatalf("Address = %q, %v; want %q, %v", got, present, test.input.Address, test.input.Address != "")
			}
		})
	}
}

// TestAddressRules checks [Address] through [keycheck.StringKey] operators.
func TestAddressRules(t *testing.T) {
	const address = "https://example.com/ready?state=ok#result"
	for _, test := range []struct {
		name    string
		address string
		op      keycheck.Operator
		right   string
		want    bool
	}{
		{"equal", address, keycheck.EqualTo, address, true},
		{"equal mismatch", address, keycheck.EqualTo, "https://example.com/failed", false},
		{"case sensitive", address, keycheck.EqualTo, "HTTPS://example.com/ready?state=ok#result", false},
		{"contains", address, keycheck.Contains, "?state=ok", true},
		{"contains mismatch", address, keycheck.Contains, "state=failed", false},
		{"prefix", address, keycheck.StartsWith, "https://example.com/", true},
		{"prefix mismatch", address, keycheck.StartsWith, "http://", false},
		{"suffix", address, keycheck.EndsWith, "#result", true},
		{"suffix mismatch", address, keycheck.EndsWith, "#failed", false},
		{"regex", address, keycheck.MatchesRegex, `^https://example\.com/ready\?state=ok#result$`, true},
		{"regex mismatch", address, keycheck.MatchesRegex, `/failed$`, false},
		{"exists", address, keycheck.Exists, "ignored", true},
		{"does not exist", address, keycheck.DoesNotExist, "ignored", false},
		{"absent exists", "", keycheck.Exists, "ignored", false},
		{"absent does not exist", "", keycheck.DoesNotExist, "ignored", true},
		{"malformed exists", "://%zz", keycheck.Exists, "ignored", true},
		{"absent equal", "", keycheck.EqualTo, "", false},
		{"not equal", address, keycheck.NotEqualTo, "other", true},
		{"absent not equal", "", keycheck.NotEqualTo, "other", false},
		{"does not contain", address, keycheck.DoesNotContain, "failed", true},
		{"absent does not contain", "", keycheck.DoesNotContain, "failed", false},
		{"does not start with", address, keycheck.DoesNotStartWith, "http://", true},
		{"absent does not start with", "", keycheck.DoesNotStartWith, "http://", false},
		{"does not end with", address, keycheck.DoesNotEndWith, "#failed", true},
		{"absent does not end with", "", keycheck.DoesNotEndWith, "#failed", false},
		{"does not match regex", address, keycheck.DoesNotMatchRegex, `/failed$`, true},
		{"absent does not match regex", "", keycheck.DoesNotMatchRegex, `/failed$`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			program, err := keycheck.Compile(keycheck.Chain[Input]{
				Status: keycheck.Success,
				Mode:   keycheck.And,
				Keys:   []keycheck.Key[Input]{keycheck.StringKey(Address, test.op, test.right)},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := program.Evaluate(Input{Address: test.address}, keycheck.None)
			if err != nil || result.Matched != test.want {
				t.Fatalf("Evaluate = %+v, %v; want matched %v", result, err, test.want)
			}
		})
	}
}

// TestBody checks borrowed bytes and length with independent presence semantics.
func TestBody(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    []byte
		present bool
	}{
		{name: "absent"},
		{name: "empty", body: []byte{}, present: true},
		{name: "bytes", body: []byte("ready"), present: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := Input{Body: test.body}
			got, present := Body(input)
			if present != test.present || !slices.Equal(got, test.body) {
				t.Fatalf("Body = %q, %v; want %q, %v", got, present, test.body, test.present)
			}
			if len(got) > 0 && &got[0] != &test.body[0] {
				t.Fatal("Body copied the supplied bytes")
			}
			length, present := BodyLength(input)
			if length != int64(len(test.body)) || present != test.present {
				t.Fatalf("BodyLength = %d, %v; want %d, %v", length, present, len(test.body), test.present)
			}
		})
	}
}

// TestStatusCode checks that only zero denotes absence, independently of other metadata.
func TestStatusCode(t *testing.T) {
	for _, code := range []int{0, http.StatusOK, http.StatusServiceUnavailable, -1} {
		input := Input{StatusCode: code, Header: map[string][]string{"X-Example": {"present"}}}
		got, present := StatusCode(input)
		if got != int64(code) || present != (code != 0) {
			t.Fatalf("StatusCode = %d, %v; want %d, %v", got, present, code, code != 0)
		}
	}
}

// TestHeaderAndTrailer checks canonical lookup and first-value versus map-entry presence.
func TestHeaderAndTrailer(t *testing.T) {
	for _, source := range []struct {
		name  string
		first keycheck.Selector[Input, string]
		all   keycheck.Selector[Input, []string]
	}{
		{"header", Header("x-example"), HeaderValues("X-EXAMPLE")},
		{"trailer", Trailer("x-example"), TrailerValues("X-EXAMPLE")},
	} {
		t.Run(source.name, func(t *testing.T) {
			for _, test := range []struct {
				name         string
				metadata     map[string][]string
				values       []string
				firstPresent bool
				allPresent   bool
			}{
				{name: "nil map"},
				{name: "empty map", metadata: map[string][]string{}},
				{name: "missing", metadata: map[string][]string{"Other": {"value"}}},
				{name: "nil values", metadata: map[string][]string{"X-Example": nil}, allPresent: true},
				{name: "empty values", metadata: map[string][]string{"X-Example": {}}, values: []string{}, allPresent: true},
				{name: "empty first", metadata: map[string][]string{"X-Example": {"", "second"}}, values: []string{"", "second"}, firstPresent: true, allPresent: true},
				{name: "multiple values", metadata: map[string][]string{"X-Example": {"first", "second"}}, values: []string{"first", "second"}, firstPresent: true, allPresent: true},
				{name: "noncanonical map key", metadata: map[string][]string{"x-example": {"value"}}},
			} {
				t.Run(test.name, func(t *testing.T) {
					unrelated := map[string][]string{"X-Example": {"wrong field"}}
					input := Input{Header: test.metadata, Trailer: unrelated}
					if source.name == "trailer" {
						input.Header, input.Trailer = unrelated, test.metadata
					}
					var wantFirst string
					if len(test.values) > 0 {
						wantFirst = test.values[0]
					}
					if got, present := source.first(input); got != wantFirst || present != test.firstPresent {
						t.Fatalf("first value = %q, %v; want %q, %v", got, present, wantFirst, test.firstPresent)
					}
					got, present := source.all(input)
					if !slices.Equal(got, test.values) || (got == nil) != (test.values == nil) || present != test.allPresent {
						t.Fatalf("all values = %#v, %v; want %#v, %v", got, present, test.values, test.allPresent)
					}
					if len(got) > 0 && &got[0] != &test.metadata["X-Example"][0] {
						t.Fatal("selector copied the supplied values")
					}
				})
			}
		})
	}
}

// TestInputNamedHeaderMaps checks direct assignment and borrowing of distinct named map types.
func TestInputNamedHeaderMaps(t *testing.T) {
	standard := http.Header{"X-Example": {"standard"}}
	fork := forkHeader{"X-Example": {"fork"}}
	input := Input{Header: standard, Trailer: fork}
	standard["X-Added"] = []string{"header"}
	fork["X-Added"] = []string{"trailer"}
	if got, present := Header("X-Added")(input); got != "header" || !present {
		t.Fatalf("Header = %q, %v; want borrowed named header map", got, present)
	}
	if got, present := Trailer("X-Added")(input); got != "trailer" || !present {
		t.Fatalf("Trailer = %q, %v; want borrowed named trailer map", got, present)
	}
	values, present := HeaderValues("X-Example")(input)
	if !present || &values[0] != &standard["X-Example"][0] {
		t.Fatal("HeaderValues did not borrow standard header values")
	}
	values, present = TrailerValues("X-Example")(input)
	if !present || &values[0] != &fork["X-Example"][0] {
		t.Fatal("TrailerValues did not borrow fork header values")
	}
}

// TestEvaluateLeavesResponseBodyUntouched checks field mapping, allocations, and shared immutable input.
func TestEvaluateLeavesResponseBodyUntouched(t *testing.T) {
	address := "https://example.com/ready"
	body := []byte(`{"ready":true}`)
	program, err := keycheck.Compile(keycheck.Chain[Input]{
		Status: keycheck.Success,
		Mode:   keycheck.And,
		Keys: []keycheck.Key[Input]{
			keycheck.StringKey(Address, keycheck.EqualTo, "https://example.com/ready"),
			keycheck.IntKey(StatusCode, keycheck.EqualTo, http.StatusOK),
			keycheck.StringKey(Header("content-type"), keycheck.Contains, "application/json"),
			keycheck.ListKey(HeaderValues("x-state"), keycheck.Contains, "ready"),
			keycheck.StringKey(Trailer("x-checksum"), keycheck.EqualTo, "verified"),
			keycheck.ListKey(TrailerValues("x-checksum"), keycheck.Contains, "verified"),
			keycheck.BytesKey(Body, keycheck.Contains, []byte(`"ready":true`)),
			keycheck.IntKey(BodyLength, keycheck.EqualTo, int64(len(body))),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody := &untouchedBody{}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": {"application/json"},
			"X-State":      {"pending", "ready"},
		},
		Trailer: http.Header{"X-Checksum": {"verified"}},
		Body:    responseBody,
	}
	input := Input{Address: address, StatusCode: response.StatusCode, Header: response.Header, Trailer: response.Trailer, Body: body}
	result, err := program.Evaluate(input, keycheck.None)
	if err != nil || !result.Matched || result.Status != keycheck.Success || result.Chain != 0 {
		t.Fatalf("Evaluate = %+v, %v", result, err)
	}
	if response.Body != responseBody {
		t.Fatal("Evaluate replaced the response body")
	}
	if got := testing.AllocsPerRun(100, func() {
		result, err := program.Evaluate(input, keycheck.None)
		if err != nil || !result.Matched || result.Status != keycheck.Success {
			t.Fatalf("Evaluate = %+v, %v", result, err)
		}
	}); got != 0 {
		t.Fatalf("Evaluate allocated %g times; want 0", got)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				result, err := program.Evaluate(input, keycheck.None)
				if err != nil || !result.Matched || result.Status != keycheck.Success {
					t.Errorf("concurrent Evaluate = %+v, %v", result, err)
					return
				}
			}
		})
	}
	workers.Wait()
}

// Example maps a supplied address, response fields, and an already available body into an input.
func Example() {
	program, err := keycheck.Compile(keycheck.Chain[Input]{
		Status: keycheck.Success,
		Mode:   keycheck.And,
		Keys: []keycheck.Key[Input]{
			keycheck.StringKey(Address, keycheck.EqualTo, "https://example.com/ready"),
			keycheck.IntKey(StatusCode, keycheck.EqualTo, http.StatusOK),
			keycheck.StringKey(Header("Content-Type"), keycheck.Contains, "application/json"),
			keycheck.BytesKey(Body, keycheck.Contains, []byte(`"ready":true`)),
		},
	})
	if err != nil {
		panic(err)
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
	}
	input := Input{
		Address:    "https://example.com/ready",
		StatusCode: response.StatusCode,
		Header:     response.Header,
		Trailer:    response.Trailer,
		Body:       []byte(`{"ready":true}`),
	}
	result, err := program.Evaluate(input, keycheck.None)
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Status, result.Matched)
}

// BenchmarkEvaluate measures selectors with shared immutable HTTP metadata and body bytes.
func BenchmarkEvaluate(b *testing.B) {
	chain := keycheck.Chain[Input]{
		Status: keycheck.Success,
		Mode:   keycheck.And,
		Keys: []keycheck.Key[Input]{
			keycheck.IntKey(StatusCode, keycheck.EqualTo, http.StatusOK),
			keycheck.StringKey(Header("Content-Type"), keycheck.Contains, "application/json"),
			keycheck.BytesKey(Body, keycheck.Contains, []byte(`"ready":true`)),
		},
	}
	program, err := keycheck.Compile(chain)
	if err != nil {
		b.Fatal(err)
	}
	chain.Keys = append(chain.Keys, keycheck.StringKey(Address, keycheck.EqualTo, "https://example.com/ready"))
	withAddress, err := keycheck.Compile(chain)
	if err != nil {
		b.Fatal(err)
	}
	input := Input{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       []byte(`{"ready":true}`),
	}
	addressInput := input
	addressInput.Address = "https://example.com/ready"
	for _, benchmark := range []struct {
		name     string
		program  *keycheck.Program[Input]
		input    Input
		parallel bool
	}{
		{"Serial", program, input, false},
		{"Parallel", program, input, true},
		{"WithAddressSerial", withAddress, addressInput, false},
		{"WithAddressParallel", withAddress, addressInput, true},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			if benchmark.parallel {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if result, err := benchmark.program.Evaluate(benchmark.input, keycheck.None); err != nil || !result.Matched {
							b.Errorf("Evaluate = %+v, %v", result, err)
							return
						}
					}
				})
				return
			}
			for b.Loop() {
				if result, err := benchmark.program.Evaluate(benchmark.input, keycheck.None); err != nil || !result.Matched {
					b.Fatalf("Evaluate = %+v, %v", result, err)
				}
			}
		})
	}
}
