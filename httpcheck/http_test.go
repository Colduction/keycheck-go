package httpcheck

import (
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"

	keycheck "github.com/colduction/keycheck-go"
)

type untouchedBody struct{}

func (untouchedBody) Read([]byte) (int, error) {
	panic("response body read")
}

func (untouchedBody) Close() error {
	panic("response body closed")
}

type forkHeader map[string][]string

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
	body := []byte("service ready")
	program, err := keycheck.Compile(keycheck.Chain[Input]{
		Status: keycheck.Success,
		Mode:   keycheck.And,
		Keys: []keycheck.Key[Input]{
			keycheck.IntKey(StatusCode, keycheck.EqualTo, http.StatusOK),
			keycheck.StringKey(Header("content-type"), keycheck.Contains, "text/plain"),
			keycheck.ListKey(HeaderValues("x-state"), keycheck.Contains, "ready"),
			keycheck.StringKey(Trailer("x-checksum"), keycheck.EqualTo, "verified"),
			keycheck.ListKey(TrailerValues("x-checksum"), keycheck.Contains, "verified"),
			keycheck.BytesKey(Body, keycheck.Contains, []byte("ready")),
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
			"Content-Type": {"text/plain; charset=utf-8"},
			"X-State":      {"pending", "ready"},
		},
		Trailer: http.Header{"X-Checksum": {"verified"}},
		Body:    responseBody,
	}
	input := Input{StatusCode: response.StatusCode, Header: response.Header, Trailer: response.Trailer, Body: body}
	result, err := program.Evaluate(input, keycheck.None)
	if err != nil || !result.Matched || result.Status != keycheck.Success || result.Chain != 0 {
		t.Fatalf("Evaluate = %+v, %v", result, err)
	}
	if response.Body != responseBody {
		t.Fatal("Evaluate replaced the response body")
	}
	if got := testing.AllocsPerRun(100, func() {
		result, err := program.Evaluate(input, keycheck.None)
		if err != nil || result.Status != keycheck.Success {
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

// Example maps response fields and an already available body into an input.
func Example() {
	program, err := keycheck.Compile(keycheck.Chain[Input]{
		Status: keycheck.Success,
		Mode:   keycheck.And,
		Keys: []keycheck.Key[Input]{
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
	// Output: SUCCESS true
}

// BenchmarkEvaluate measures selectors with shared immutable HTTP metadata and body bytes.
func BenchmarkEvaluate(b *testing.B) {
	program, err := keycheck.Compile(keycheck.Chain[Input]{
		Status: keycheck.Success,
		Mode:   keycheck.And,
		Keys: []keycheck.Key[Input]{
			keycheck.IntKey(StatusCode, keycheck.EqualTo, http.StatusOK),
			keycheck.StringKey(Header("Content-Type"), keycheck.Contains, "application/json"),
			keycheck.BytesKey(Body, keycheck.Contains, []byte(`"ready":true`)),
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	input := Input{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       []byte(`{"ready":true}`),
	}
	b.Run("Serial", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if result, err := program.Evaluate(input, keycheck.None); err != nil || !result.Matched {
				b.Fatalf("Evaluate = %+v, %v", result, err)
			}
		}
	})
	b.Run("Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if result, err := program.Evaluate(input, keycheck.None); err != nil || !result.Matched {
					b.Errorf("Evaluate = %+v, %v", result, err)
					return
				}
			}
		})
	})
}
