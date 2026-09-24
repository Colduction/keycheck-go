// Package httpcheck provides key selectors for borrowed HTTP metadata and caller-supplied bodies.
// It sends no requests and accepts no response body streams.
package httpcheck

import (
	"net/textproto"

	"github.com/colduction/keycheck-go"
)

// Input provides borrowed HTTP data for synchronous key evaluation.
// The zero value has no metadata or body.
// Named header map types with the same underlying type assign directly to Header and Trailer.
// Callers must keep the maps, their value slices, and body bytes unchanged during evaluation.
// An Input may be shared by concurrent evaluations while its data remains immutable.
type Input struct {
	// StatusCode supplies the HTTP status code; zero means absent.
	StatusCode int

	// Header supplies borrowed response headers independently of StatusCode.
	// Nil means no headers; keys must use canonical MIME header spelling.
	Header map[string][]string

	// Trailer supplies borrowed final response trailers independently of StatusCode.
	// Populate it only after the caller has consumed the response body.
	// Nil means no trailers; keys must use canonical MIME header spelling.
	Trailer map[string][]string

	// Body contains bytes already read by the caller and remains owned by the caller.
	// Nil means absent; a non-nil empty slice means a present, empty body.
	Body []byte
}

// Body returns the supplied body and reports whether it is present.
// The returned slice aliases [Input.Body] and is not retained by the selector.
func Body(input Input) ([]byte, bool) {
	return input.Body, input.Body != nil
}

// BodyLength returns the supplied body's byte length and reports whether it is present.
// A nil [Input.Body] returns zero and false; a non-nil empty body returns zero and true.
func BodyLength(input Input) (int64, bool) {
	return int64(len(input.Body)), input.Body != nil
}

// StatusCode returns the supplied status code and reports whether it is nonzero.
// A zero [Input.StatusCode] is absent regardless of other metadata.
func StatusCode(input Input) (int64, bool) {
	return int64(input.StatusCode), input.StatusCode != 0
}

// Header returns a selector for the first value of the named response header.
// A nil map, missing header, or header with no values is absent.
// An empty first value is present.
// The name is canonicalized once using [textproto.CanonicalMIMEHeaderKey].
// The selector reads [Input.Header], whose keys must already be canonical.
func Header(name string) keycheck.Selector[Input, string] {
	name = textproto.CanonicalMIMEHeaderKey(name)
	return func(input Input) (string, bool) {
		values := input.Header[name]
		if len(values) == 0 {
			return "", false
		}
		return values[0], true
	}
}

// HeaderValues returns a selector for all values of the named response header.
// A nil map or missing header is absent; an existing key is present even if its slice is nil or empty.
// Returned slices alias [Input.Header] and are not retained by the selector.
// The name is canonicalized once using [textproto.CanonicalMIMEHeaderKey].
// Map keys must already be canonical.
func HeaderValues(name string) keycheck.Selector[Input, []string] {
	name = textproto.CanonicalMIMEHeaderKey(name)
	return func(input Input) ([]string, bool) {
		values, ok := input.Header[name]
		return values, ok
	}
}

// Trailer returns a selector for the first value of the named final response trailer.
// It applies the canonicalization and presence rules of [Header] to [Input.Trailer].
// Callers must supply final trailers only after consuming the response body.
func Trailer(name string) keycheck.Selector[Input, string] {
	name = textproto.CanonicalMIMEHeaderKey(name)
	return func(input Input) (string, bool) {
		values := input.Trailer[name]
		if len(values) == 0 {
			return "", false
		}
		return values[0], true
	}
}

// TrailerValues returns a selector for all values of the named final response trailer.
// It applies the canonicalization and presence rules of [HeaderValues] to [Input.Trailer].
// Returned slices alias [Input.Trailer] and are not retained by the selector.
// Callers must supply final trailers only after consuming the response body.
func TrailerValues(name string) keycheck.Selector[Input, []string] {
	name = textproto.CanonicalMIMEHeaderKey(name)
	return func(input Input) ([]string, bool) {
		values, ok := input.Trailer[name]
		return values, ok
	}
}
