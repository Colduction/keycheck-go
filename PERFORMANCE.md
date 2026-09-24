# Design research and performance

The intended workload compiles rules once, evaluates them many times, and occasionally replaces a program.
The design optimizes that workload rather than adding a general-purpose cache.
Compilation does more analysis so that evaluation does less work.

## Cache policy

Programs retain immutable predicates, search tables, and compiled regex directly.
A temporary map deduplicates regex analysis during each `Compile` call.
Identical patterns, including string and byte keys and an `IgnoreCase` pattern matching an inline `(?i)` pattern, share one plan and one `*regexp.Regexp`.
Compiled closures retain what they need, and the map is discarded when compilation finishes.
No eviction, expiration, configuration-cache lookup, response cache, or mutable cache metadata exists in ordinary evaluation.
Live configuration controls retained memory. This is not a process-wide hard memory limit: applications must bound the number and size of programs they keep alive.
`Compiler.Compile[T]` configures depth and expanded-key limits using Go 1.27 generic methods.
These limits bound compiled node counts rather than the byte size of arbitrary operands or callback captures.

The alternatives reviewed were:

| Approach                | Relevant property                                                    | Decision for this workload                                                        |
| ----------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Program-owned artifacts | Reuse follows program lifetime and requires no evaluation lookup     | Implemented                                                                       |
| LRU                     | Hits update recency; capacity and synchronization need ownership     | No cross-program cache is needed for compile-once use                             |
| TinyLFU                 | Frequency-based admission helps resist one-off cache pollution       | No admission decision is needed when every compiled rule is deliberately retained |
| S3-FIFO                 | FIFO queues reduce promotion overhead in the studied cache workloads | No eviction queue is needed for program-owned artifacts                           |
| `sync.Map`              | Specialized concurrent map, without built-in eviction                | Does not solve cache lifetime or capacity                                         |
| `sync.Pool`             | Runtime may discard entries at any time                              | Not a correctness cache or a zero-allocation guarantee                            |

This is a workload-specific choice, not a claim that one cache policy wins universally.
If an application compiles arbitrary configurations repeatedly during operation, measure reuse distance, unique-pattern rate, compilation cost, retained heap, and contention before introducing a separately owned bounded cache.
Cached evaluation results would retain or hash caller data and require an invalidation contract; this package does not cache them.

Primary sources:

- [TinyLFU paper](https://arxiv.org/abs/1512.00727): admission policy and studied hit-rate tradeoffs.
- [S3-FIFO authors' research](https://s3fifo.com/): FIFO-based cache policy and its workload-dependent results.
- [HashiCorp LRU implementation](https://github.com/hashicorp/golang-lru/blob/main/lru.go): locking and recency maintenance.
- [Ristretto implementation and consistency caveats](https://github.com/dgraph-io/ristretto): buffered processing, admission, and potentially dropped insertions.
- [Go synchronization contracts](https://pkg.go.dev/sync): specialized `Map` use cases and discardable `Pool` contents.
- [Go memory model](https://go.dev/ref/mem): publication and synchronization requirements for shared values.

## Text search

HTTP bodies are the largest values most keychains inspect, so text keys dominate evaluation cost.
Each strategy below returns exactly the result of the equivalent standard-library operation.
Differential tests and fuzz targets compare them with `strings.Index`, `strings.EqualFold`, and `regexp`.

### Case-sensitive literals

`Contains` and `DoesNotContain` use a three-phase search compiled per key:

1. Vectorized `strings.IndexByte` jumps to the needle byte with the lowest background frequency rank, then checks the first, last, and all bytes.
   The ranks come from the memchr crate's [default byte ranks](https://github.com/BurntSushi/memchr/blob/master/src/arch/all/packedpair/default_rank.rs) (Unlicense or MIT), which its substring prefilters use.
2. When false candidates exceed one per 32 scanned bytes, eight candidate starts are tested per 64-bit word for the needle's first and last bytes.
   This is the portable form of the first/last-byte filter in Wojciech Muła's [SIMD-friendly substring search](http://0x80.pl/articles/simd-strfind.html), using the zero-byte test from [Bit Twiddling Hacks](https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord).
   That test can also flag a byte above a real zero byte; the full comparison rejects such candidates.
3. When first/last pairs are also dense, [`strings.Index`](https://go.dev/src/internal/stringslite/strings.go) finishes the search with its own adaptive fallbacks.

Go's `strings.Index` starts from the needle's first byte.
Structured bodies make that byte frequent: JSON needles often start with `"` and HTML needles with `<`.
Starting from a rare byte avoids those candidates, and the word phase avoids per-candidate function calls.
Every phase switch uses a work budget scaled by needle length, so long needles cannot make the prefilters quadratic.

The ranks are a prior, not knowledge of the input.
`BenchmarkEvaluateBody` places `-` near the end of an otherwise `x` body; for needles such as `absent-0`, `-` ranks rarer than `a`, which costs one extra short `IndexByte` call.
`EqualTo`, `StartsWith`, and `EndsWith` use direct string comparison.

### Case-insensitive literals

`IgnoreCase` literals are compiled into per-position sets of every rune in each Unicode simple case-folding orbit.
Orbits have at most four runes; a test checks every code point.
Matching compares a decoded rune against its set instead of calling `unicode.SimpleFold` for every input rune.

ASCII patterns use a word-at-a-time path:

- Comparison ORs 0x20 into letter positions and compares eight bytes at once, so no lowercase copy is built.
- Containment runs `IndexByte` on the ASCII case forms of the pattern byte whose forms have the lowest combined rank, often a single-form punctuation byte, then filters first/last pairs per word, then runs KMP.
- The Kelvin sign and long s are the only non-ASCII runes that fold to ASCII letters (k and s).
  When the ASCII search fails for a pattern containing k or s, a byte search for those two runes decides whether the Unicode path must run.

Other patterns anchor on up to three distinct runes ranked by the frequencies of their encoded case forms.
Each anchor is searched with the case-sensitive literal search above; candidates are verified forward and backward with UTF-8 decoding.
When an anchor produces too many false candidates, the next anchor resumes from the earliest unexamined match start, and KMP follows the last anchor.
Replacement characters are never anchors because invalid UTF-8 bytes also decode to them.
The prefilter phases have length-scaled work budgets, and KMP ([Knuth, Morris, and Pratt](https://epubs.siam.org/doi/10.1137/0206024)) is linear, so case-insensitive search stays linear in input length.

### Regular expressions

Go's [`regexp`](https://pkg.go.dev/regexp) guarantees linear-time matching but scans each input position with an automaton.
It skips ahead to a case-sensitive literal prefix; case-insensitive and unprefixed patterns scan every byte.
Compilation parses the pattern with [`regexp/syntax`](https://pkg.go.dev/regexp/syntax), simplifies it, and chooses one plan:

- A literal, optionally anchored with `^`, `$`, `\A`, or `\z`, becomes `Contains`, `StartsWith`, `EndsWith`, or `EqualTo`, with case folding when the literal is case-insensitive.
  `regexp` does not run.
- An unanchored alternation of literals, such as `success|welcome`, becomes a search for each literal.
  Go's parser first factors shared prefixes and merges single-character branches into classes, so `Invalid password|Invalid username` becomes `Invalid (?:password|username)`, `x|y|done` becomes `[xy]|done`, and both stay with `regexp`.
- Otherwise, the longest literal that every match must contain becomes a prefilter when it is longer than the regexp's own literal prefix and the pattern is not anchored at the start.
  Inputs without that literal are rejected before `regexp` runs.

Required literals are found with the syntax-tree analysis Russ Cox describes for [regular expression matching with a trigram index](https://swtch.com/~rsc/regexp/regexp4.html), reduced to single literals:
concatenations join adjacent literals, and `+`, captures, and required repetitions preserve them.
[Hyperscan](https://www.usenix.org/conference/nsdi19/presentation/wang-xiang) decomposes regex into literal prefilters in the same spirit.
Case-sensitive literals containing the replacement character, and any literal containing a surrogate, stay with `regexp`, because invalid UTF-8 input bytes decode to the replacement character.
Case-insensitive literals compare decoded runes, just as `regexp` does, so they keep their plans and prefilters.

`IgnoreCase` parses the pattern with the case-folding flag, which is equivalent to prefixing `(?i)`.
The pattern's own parentheses and `\Q…\E` quoting therefore keep their meaning, and an invalid pattern is rejected.

### Groups and byte keys

`All`, `Any`, and equivalent `AtLeast` groups use dedicated short-circuit loops.
String and byte keys share one generic implementation.
Byte keys view selected bytes as a string without copying for the duration of a predicate call; the package never retains the view.

## Allocation contract

Scalar, string, byte, list, and dictionary keys borrow input.
They do not construct temporary body strings, normalize whole inputs, allocate result slices, or box values through `any`.
Application selectors and custom predicates can allocate; those allocations are outside the built-in comparison contract.
Compilation, key construction, and diagnostic errors are cold paths and can allocate.

Case-insensitive search scans the input without allocating a lowercase copy; prefix and suffix checks decode only the necessary runes.
Folding follows [unicode.SimpleFold](https://pkg.go.dev/unicode#SimpleFold), [strings.EqualFold](https://pkg.go.dev/strings#EqualFold), and the standard [UTF-8 decoder](https://pkg.go.dev/unicode/utf8).

The regex plans above allocate nothing during evaluation.
Go's [`regexp` contract](https://pkg.go.dev/regexp) permits concurrent matching on a compiled expression.
The implementation uses boolean `MatchString`, avoiding capture result slices.
However, [execution machines](https://go.dev/src/regexp/exec.go) use [internal pooled storage](https://go.dev/src/regexp/regexp.go) and can allocate on cold use, after collection, or at greater concurrency.
Warm zero-allocation results do not imply that every regex evaluation allocates zero bytes.

[`testing.AllocsPerRun`](https://pkg.go.dev/testing#AllocsPerRun) performs a warm-up and sets `GOMAXPROCS` to one.
Allocation tests therefore complement parallel benchmarks and `BenchmarkEvaluateRegexAfterGC`, a post-GC diagnostic that shows regex execution state being rebuilt.
`RunParallel` nanoseconds per operation describe aggregate throughput, not individual request latency or p99.

## Correctness

- Differential tests and fuzz targets compare literal, case-insensitive, and regex keys with `strings.Index`, `strings.EqualFold`, and `regexp`, including invalid UTF-8, the Kelvin sign, long s, and Greek text.
- Deterministic randomized tests drive every search phase and fallback with dense inputs.
- A test checks canonical folding and orbit sizes for every Unicode code point.
- Race tests share compiled programs across goroutines.

## Reproduction

Run correctness checks before performance measurements. Do not run CPU-heavy checks concurrently with benchmarks.

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
staticcheck ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go test -run '^$' -fuzz '^FuzzEvaluateChains$' -fuzztime=30s -parallel=4 .
go test -run '^$' -fuzz '^FuzzStringAndBytesKeys$' -fuzztime=30s -parallel=4 .
go test -run '^$' -fuzz '^FuzzGroups$' -fuzztime=30s -parallel=4 .
go test -run '^$' -fuzz '^FuzzTextSearch$' -fuzztime=30s -parallel=4 .
go test -run '^$' -fuzz '^FuzzExactLiteral$' -fuzztime=30s -parallel=4 .
go test -run '^$' -fuzz '^FuzzRegexKeys$' -fuzztime=30s -parallel=4 .
```

The serial matrix samples 256 B, 4 KiB, and 64 KiB bodies; 1, 16, and 128 keys; and first, middle, last, and absent matches.
Structured-body benchmarks use generated JSON and HTML, dense adversarial inputs, and ASCII, Kelvin/long s, and Greek text.
Compilation benchmarks separate literal keys, repeated regex patterns, and unique patterns.
The HTTP benchmark uses supplied data and performs no network operations.

```sh
go test -run '^$' -bench '^(BenchmarkLiteralSearch|BenchmarkLiteralSearchAdversarial|BenchmarkIgnoreCaseContains|BenchmarkRegexPlans)$' -benchmem -benchtime=100ms -count=10 -cpu=1 .
go test -run '^$' -bench '^(BenchmarkEvaluateBody|BenchmarkEvaluateCallbacks|BenchmarkCompile|BenchmarkEvaluateRegex|BenchmarkComparable)$' -benchmem -benchtime=100ms -count=10 -cpu=1 .
go test -run '^$' -bench '^(BenchmarkEvaluateGroups|BenchmarkAppendMatches|BenchmarkAppendTrace|BenchmarkCompareKey)$' -benchmem -benchtime=100ms -count=10 -cpu=1 .
go test -run '^$' -bench '^BenchmarkEvaluateParallel$' -benchmem -benchtime=100ms -count=10 -cpu=1,4,16 .
go test -run '^$' -bench '^BenchmarkEvaluate$' -benchmem -benchtime=100ms -count=10 -cpu=1,4,16 ./httpcheck
go test -run '^$' -bench '^BenchmarkEvaluateRegexAfterGC$' -benchmem -benchtime=1x -count=10 -cpu=1 .
```

The post-GC diagnostic intentionally requires `-benchtime=1x` so ordinary benchmark calibration cannot trigger an unbounded number of full collections.
Two collections and setup are excluded from its reported match time and allocation statistics.
Compare matched output files using [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat).
Keep toolchain, CPU settings, host, inputs, and benchmark bodies identical when comparing measurements.

## Compatibility reference

The KeyCheck behavior reference is OpenBullet2 commit `6b244ac7a58499dc00054d7aef1e1bb400ab2cd9`:

- [Chain generation and ordering](https://github.com/openbullet/OpenBullet2/blob/6b244ac7a58499dc00054d7aef1e1bb400ab2cd9/RuriLib/Models/Blocks/Custom/KeycheckBlockInstance.cs).
- [Key comparison implementations](https://github.com/openbullet/OpenBullet2/blob/6b244ac7a58499dc00054d7aef1e1bb400ab2cd9/RuriLib/Functions/Conditions/Conditions.cs).
- [Default no-match behavior](https://github.com/openbullet/OpenBullet2/blob/6b244ac7a58499dc00054d7aef1e1bb400ab2cd9/RuriLib/Models/Blocks/Custom/KeycheckBlockDescriptor.cs).

The Go API preserves ordered first-match chains and all six key families while adding a direct byte path.
See the [README](README.md#openbullet2-compatibility) for intentional regex, float, missing-value, fallback, and scripting differences.

## Measurements

Measured with Go 1.27.1 on Windows/amd64 and an AMD Ryzen 9 7950X, using ten 100 ms samples per case at `-cpu=1`.
Tables show medians; raw samples are in [benchmarks/results.txt](benchmarks/results.txt).
The standard-library columns run the equivalent `strings` or `regexp` call on the same input.
These describe the benchmark inputs, not guarantees for arbitrary selectors or data.

`Contains` on generated 4 KiB bodies without a match:

| Body and needle                  | `StringKey` | With `IgnoreCase` | `strings.Contains` |
| -------------------------------- | ----------: | ----------------: | -----------------: |
| JSON, `"status":"success"`       |      684 ns |            846 ns |            1.54 µs |
| JSON, `access_token`             |     43.7 ns |            121 ns |            1.53 µs |
| HTML, `<title>Dashboard</title>` |      484 ns |            629 ns |            1.57 µs |
| HTML, `href="/logout"`           |      437 ns |            543 ns |             572 ns |

`IgnoreCase` `Contains` with the match at the end:

| Input                                      | `StringKey` | `regexp` with `(?i)` |
| ------------------------------------------ | ----------: | -------------------: |
| 4 KiB ASCII                                |     47.4 ns |              39.2 µs |
| 4 KiB Greek alpha, Kelvin sign and long s  |      151 ns |              34.9 µs |
| 4 KiB Greek text                           |      240 ns |              65.1 µs |
| 64 KiB ASCII                               |      609 ns |               841 µs |
| 64 KiB Greek alpha, Kelvin sign and long s |     1.83 µs |               630 µs |
| 64 KiB Greek text                          |     1.95 µs |              1.14 ms |

Worst-case near-misses on 64 KiB bodies.
The rarest needle byte, the first/last byte pairs, and every Unicode anchor occur densely, so each search reaches its final fallback: `strings.Index` for exact search and KMP for `IgnoreCase`.

| Body and needle                | `StringKey` | With `IgnoreCase` |
| ------------------------------ | ----------: | ----------------: |
| `aaab` repeated, `a`×7 + `b`   |     6.19 µs |            126 µs |
| `aaab` repeated, `a`×255 + `b` |     62.3 µs |            124 µs |
| `αααβ` repeated, `Α`×7 + `Β`   |           – |            120 µs |
| `αααβ` repeated, `Α`×255 + `Β` |           – |            116 µs |

Regex keys on a 4 KiB HTML body without a match:

| Pattern                                               | `StringKey` | `regexp` |
| ----------------------------------------------------- | ----------: | -------: |
| `Invalid password`                                    |     38.5 ns |   109 ns |
| `invalid password` with `IgnoreCase`                  |      626 ns |  41.2 µs |
| `[0-9]+ attempts? remaining`                          |      201 ns |  36.4 µs |
| `(?i)[0-9]+ attempts? remaining`                      |      579 ns |  36.6 µs |
| `class="item-[0-9]+"><a href="/logout"`               |      516 ns |  6.10 µs |
| `Invalid password\|Account locked\|Too many attempts` |      158 ns |  84.9 µs |
| The same alternation with `(?i)`                      |     1.89 µs |   128 µs |
| `^HTTP/1\.[01] 5[0-9]{2}`                             |     25.9 ns |  19.7 ns |

The anchored pattern stays with `regexp`, which stops at the first byte; the difference is key dispatch.
A nested `All(Any(...), ...)` group of sixteen conditions takes 49.9 ns, and the HTTP adapter's three-key check takes 26.4 ns.
Every warm serial evaluation benchmark in the raw samples reports 0 B/op and 0 allocs/op.

Compilation costs:

- Each unique regex that needs `regexp` is parsed twice, once for analysis and once inside `regexp`: 2.12 µs, 4.33 KiB, and 49 allocations for `present-[a-z]+-0$`.
  Literal and alternation plans skip `regexp` compilation, and repeated patterns reuse one plan.
- A single literal `StringKey` compiles in 79.3 ns.
