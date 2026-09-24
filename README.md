# keycheck-go

[![Go Reference](https://pkg.go.dev/badge/github.com/colduction/keycheck-go.svg)](https://pkg.go.dev/github.com/colduction/keycheck-go)
[![Go version](https://img.shields.io/github/go-mod/go-version/colduction/keycheck-go)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Compile ordered keychains once, then evaluate caller-owned values without I/O.
The model follows OpenBullet2's KeyCheck; comparisons and regex follow Go semantics.

- **Typed** – generic selectors over your own types, with no reflection or `map[string]any`.
- **Allocation-free** – warm built-in keys evaluate with 0 allocations when selectors don't allocate.
- **Fast text search** – rare-byte literal search, word-at-a-time case folding, and literal-aware regex plans.
- **Safe to share** – compiled programs are immutable and can be evaluated from many goroutines.
- **HTTP-ready** – the optional `httpcheck` package evaluates borrowed status, headers, trailers, and body.

## Install

```sh
go get github.com/colduction/keycheck-go@latest
```

## Quick start

```go
statusCode := func(code int64) (int64, bool) { return code, true }

program, err := keycheck.Compile(keycheck.Chain[int64]{
	Status: keycheck.Success,
	Mode:   keycheck.And,
	Keys: []keycheck.Key[int64]{
		keycheck.IntKey(statusCode, keycheck.GreaterThanOrEqualTo, 200),
		keycheck.IntKey(statusCode, keycheck.LessThan, 300),
	},
})
if err != nil {
	return err
}

result, err := program.Evaluate(204, keycheck.None)
// result.Status == keycheck.Success, result.Matched == true, result.Chain == 0
```

A **selector** is a `func(T) (V, bool)` that returns a value and reports whether it is present.
`T` can be any struct, pointer, scalar, slice, or map you already have.

## Evaluation

| Rule        | Behavior                                                                                           |
| ----------- | -------------------------------------------------------------------------------------------------- |
| Order       | Chains run in declaration order, and the first matching chain wins.                                |
| Modes       | `Or` (the zero value) needs any key, `And` needs every key; keys run left to right and stop early. |
| Empty chain | Never matches, even with `And`.                                                                    |
| Result      | `Result.Chain` is the matching chain's original index, or `-1` for no match or an error.           |
| Fallback    | Always explicit: pass `keycheck.Ban` for OpenBullet2's default, or the current status to keep it.  |
| Statuses    | `Status` is a string type, so you can define your own. Duplicate statuses are allowed.             |
| Programs    | A zero-value `Program` returns the fallback; a nil `*Program` returns `ErrNilProgram`.             |

| Method                              | Returns                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------ |
| `Evaluate(input, fallback)`         | The first matching chain, or the fallback.                                     |
| `AppendMatches(dst, input)`         | Every matching chain, appended to `dst` in order. No match leaves `dst` as is. |
| `AppendTrace(dst, input, fallback)` | The `Evaluate` decision, plus one `TraceEntry` per top-level key it reached.   |

`AppendMatches` and `AppendTrace` allocate nothing when `dst` has enough capacity.
Trace entries record chain index, key index, result, and error; they hold no selected values, though a `CustomKey` error may carry its own data.

### Limits

`keycheck.Compile` uses the default limits. A `Compiler` sets its own and compiles any input type:

```go
compiler := keycheck.Compiler{MaxDepth: 16, MaxKeys: 4096}
program, err := compiler.Compile(chains...)
```

| Field      | Default | Limits                                                                          |
| ---------- | ------: | ------------------------------------------------------------------------------- |
| `MaxDepth` |      64 | Nested key levels, counting the outer key and the deepest leaf.                 |
| `MaxKeys`  |  65,536 | Key occurrences across all chains; a shared group counts every time it appears. |

Zero selects the default and negative values return `ErrInvalidLimit`.
An unchanged `Compiler` is safe for concurrent use.

## Keys

| Constructor     | Selects                                 | Operators                                                                                       |
| --------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `StringKey`     | `string`                                | `EqualTo`, `Contains`, `StartsWith`, `EndsWith`, `MatchesRegex`, `Exists`, and their negations  |
| `BytesKey`      | `[]byte`                                | Same as `StringKey`, without copying the input                                                  |
| `IntKey`        | `int64`                                 | `EqualTo`, `NotEqualTo`, `LessThan`, `LessThanOrEqualTo`, `GreaterThan`, `GreaterThanOrEqualTo` |
| `FloatKey`      | `float64`                               | Same as `IntKey`                                                                                |
| `BoolKey`       | `bool`                                  | `Is`, `IsNot`                                                                                   |
| `ListKey`       | `[]string`                              | `Contains`, `DoesNotContain`, `Exists`, `DoesNotExist`                                          |
| `DictionaryKey` | `map[string]string`                     | `HasKey`, `HasValue`, `Exists`, and their negations                                             |
| `CompareKey`    | Two selectors of one `cmp.Ordered` type | Same as `IntKey`, with both operands chosen at run time                                         |
| `CustomKey`     | Your `T`                                | Your `func(T) (bool, error)`                                                                    |

Negations are `NotEqualTo` and the `DoesNot…` operators, such as `DoesNotContain` and `DoesNotMatchRegex`.

<details>
<summary><strong>Matching rules</strong></summary>

- A missing value matches only `DoesNotExist`; a negated operator does not turn absence into a match.
- A present empty value exists, including a nil slice or map that the selector reports as present.
- Existence operators ignore the right operand.
- List and dictionary comparisons are case-sensitive and compare whole elements. Dictionary existence refers to the map itself, not an entry.
- Regex uses Go `regexp` syntax and matches anywhere unless anchored. .NET-only constructs, such as backreferences and lookaround, fail at compile time.
- Float comparisons use Go operators, including NaN, infinity, and signed-zero behavior.
- `CompareKey` calls `left` once, then `right` only if `left` is present. A missing operand never matches.

</details>

### Case-insensitive text

Pass `keycheck.IgnoreCase` to `StringKey` or `BytesKey`:

```go
keycheck.StringKey(title, keycheck.Contains, "welcome back", keycheck.IgnoreCase)
```

- It uses Unicode simple case folding: `k` matches `K` and the Kelvin sign, but `ss` does not match `ß`, and nothing is normalized.
- Invalid UTF-8 bytes compare as the replacement character, U+FFFD.
- Regex patterns are parsed as if they began with `(?i)`, and inline flags such as `(?-i:…)` still apply.

### Errors

- `Compile` rejects empty statuses, invalid modes, zero-value keys, nil selectors or callbacks, unsupported operators, invalid options, invalid regex, out-of-range `AtLeast` or `Exactly` counts, and programs beyond `MaxDepth` or `MaxKeys`.
  Its `*CompileError` reports chain and key indices and works with `errors.Is` and `errors.As`.
- Built-in keys never fail during evaluation. A `CustomKey` error stops evaluation and arrives wrapped in `*EvalError`: `Evaluate` returns the fallback, and `AppendMatches` returns the matches found so far.
  Callback panics propagate.

## Groups

Groups are keys, so they nest inside chains and other groups.

| Group                 | Matches when                                                         |
| --------------------- | -------------------------------------------------------------------- |
| `All(keys...)`        | Every child matches. An empty group matches.                         |
| `Any(keys...)`        | Any child matches. An empty group does not.                          |
| `Not(key)`            | The child does not match, including because of a missing value.      |
| `AtLeast(n, keys...)` | At least `n` children match.                                         |
| `Exactly(n, keys...)` | Exactly `n` children match, so `Exactly(0, …)` matches when none do. |

```go
type Sample struct {
	Name        string
	Used, Limit uint64
}

name := func(s Sample) (string, bool) { return s.Name, true }
used := func(s Sample) (uint64, bool) { return s.Used, true }
limit := func(s Sample) (uint64, bool) { return s.Limit, true }

ready := keycheck.All(
	keycheck.Any(
		keycheck.StringKey(name, keycheck.StartsWith, "service-", keycheck.IgnoreCase),
		keycheck.StringKey(name, keycheck.EqualTo, "worker", keycheck.IgnoreCase),
	),
	keycheck.CompareKey(used, keycheck.LessThan, limit),
)
```

Group constructors copy their children.
Children run left to right and stop once the result is known, but compilation validates every child, including ones evaluation would skip.
`n` must be between zero and the number of children.
Errors pass through groups, including `Not`: `EvalError.Key` stays the top-level index, and the message names each nested child, as in `group key 1: group key 0: …`.

## HTTP

The `httpcheck` package evaluates response data your application has already read.

```go
program, err := keycheck.Compile(keycheck.Chain[httpcheck.Input]{
	Status: keycheck.Success,
	Mode:   keycheck.And,
	Keys: []keycheck.Key[httpcheck.Input]{
		keycheck.IntKey(httpcheck.StatusCode, keycheck.EqualTo, http.StatusOK),
		keycheck.StringKey(httpcheck.Header("Content-Type"), keycheck.Contains, "application/json"),
		keycheck.BytesKey(httpcheck.Body, keycheck.Contains, []byte(`"ready":true`)),
	},
})
if err != nil {
	return err
}

result, err := program.Evaluate(httpcheck.Input{
	StatusCode: response.StatusCode,
	Header:     response.Header,
	Trailer:    response.Trailer, // Final trailers, after the body is consumed.
	Body:       body,             // Already read and size-limited by the application.
}, keycheck.None)
```

| Selector                               | Selects                      | Absent when                            |
| -------------------------------------- | ---------------------------- | -------------------------------------- |
| `StatusCode`                           | Status code                  | It is zero                             |
| `Header(name)`                         | First header value           | The header is missing or has no values |
| `HeaderValues(name)`                   | All header values            | The header key is missing              |
| `Trailer(name)`, `TrailerValues(name)` | The same, for final trailers | The same rules                         |
| `Body`, `BodyLength`                   | Body bytes, or their length  | `Body` is nil                          |

> [!IMPORTANT]
> `httpcheck` never sends requests or touches body streams. Reading, size limits, decompression, and closing stay with your application.
> Header names are canonicalized once; header maps you fill in yourself must use canonical keys, as `http.Header.Get` requires.

`Input` borrows maps and bytes without copying. `http.Header` and forks with the same `map[string][]string` underlying type assign directly.
Byte keys match raw bytes and don't parse JSON, HTML, or cookies; parse once yourself and use typed selectors for structured checks.

## Concurrency and ownership

- Compiled programs are immutable. Share one across goroutines with read-only or separately owned inputs.
- Evaluation borrows input and never retains it. Don't modify a body, map, or slice while it is being evaluated.
- Compilation snapshots chain and key slices, and `BytesKey` copies its expected bytes when it is called.
- Selectors and custom predicates must be safe for concurrent use. Their allocations, blocking, and I/O are the caller's responsibility.
- Each selector runs once per operand that evaluation reaches.
- The package starts no goroutines and keeps no global caches or locks.
- To reload rules, compile a new program and publish it through an `atomic.Pointer[keycheck.Program[T]]`. A failed compilation leaves the current program in place.

## Performance

Text keys choose a search strategy at compile time, and results always equal those of `strings`, `strings.EqualFold`, and `regexp`:

- **Literals** start at the needle's rarest byte, then scan eight positions per word when that byte is common.
- **`IgnoreCase`** compares ASCII eight bytes at a time and anchors Unicode searches on rare case forms. It stays linear in the input length.
- **Regex** patterns that parse to a literal or to an alternation of plain literals skip `regexp`. Other patterns not anchored at the start first check for a literal every match must contain, when it is longer than `regexp`'s own literal prefix.

Measured on an AMD Ryzen 9 7950X with 4 KiB bodies and no match:

| Check                                                | keycheck | Standard library |
| ---------------------------------------------------- | -------: | ---------------: |
| `Contains "access_token"` on JSON                    |  43.7 ns |          1.53 µs |
| `Contains "<title>Dashboard</title>"` on HTML        |   484 ns |          1.57 µs |
| `MatchesRegex "Invalid password\|Account locked\|…"` |   158 ns |          84.9 µs |
| `MatchesRegex "[0-9]+ attempts? remaining"`          |   201 ns |          36.4 µs |

Warm built-in evaluation measures 0 B/op. Compilation allocates, and regex execution can allocate internal state on first use or under higher concurrency.
See [PERFORMANCE.md](PERFORMANCE.md) for the algorithms, sources, and full measurements.

## OpenBullet2 compatibility

Behavior follows [OpenBullet2 KeyCheck at `6b244ac7`](https://github.com/openbullet/OpenBullet2/blob/6b244ac7a58499dc00054d7aef1e1bb400ab2cd9/RuriLib/Models/Blocks/Custom/KeycheckBlockInstance.cs) and its [conditions](https://github.com/openbullet/OpenBullet2/blob/6b244ac7a58499dc00054d7aef1e1bb400ab2cd9/RuriLib/Functions/Conditions/Conditions.cs).
This package covers key families and ordered chain evaluation, not the OpenBullet2 scripting runtime: it does not import LoliCode or configs, coerce dynamic values, or apply runner and proxy BAN/RETRY policies.

Intentional differences are Go regex syntax, IEEE float equality, explicit missing-value rules, an explicit fallback, required chain statuses, and constant right operands: use `CompareKey` for values read at run time and `CustomKey` for other dynamic checks.

## License

[MIT](LICENSE)
