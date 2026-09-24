package keycheck

import (
	"cmp"
	"math/bits"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TextOption configures text comparisons for [StringKey] and [BytesKey].
// The zero value is invalid; omit options for case-sensitive comparison.
// [Compile] rejects unknown values with [ErrInvalidOption].
type TextOption uint8

// IgnoreCase enables Unicode simple case folding for literal comparisons and regular expressions.
// It matches single-rune case equivalents, such as K and the Kelvin sign, without locale rules or expansions.
// For example, the German sharp s does not equal ss.
// Literal comparisons interpret each invalid UTF-8 byte as the Unicode replacement character.
// Repeated [IgnoreCase] options have the same effect as one.
const IgnoreCase TextOption = iota + 1

func parseTextOptions(options []TextOption) (bool, error) {
	var ignoreCase bool
	for _, option := range options {
		if option != IgnoreCase {
			return false, ErrInvalidOption
		}
		ignoreCase = true
	}
	return ignoreCase, nil
}

type foldedLiteral struct {
	pattern []rune
	folds   [][4]rune
	failure []int
	lower   string
	mask    string
	wide    []exactLiteral
	narrow  foldAnchor
	anchors []foldAnchor
}

type foldAnchor struct {
	index int
	forms []exactLiteral
}

func compileFoldedLiteral(pattern string) foldedLiteral {
	matcher := foldedLiteral{pattern: []rune(pattern)}
	matcher.folds = make([][4]rune, len(matcher.pattern))
	ascii := len(matcher.pattern) > 0
	for i, r := range matcher.pattern {
		r = canonicalFold(r)
		matcher.pattern[i] = r
		ascii = ascii && r < utf8.RuneSelf
		matcher.folds[i] = [4]rune{r, -1, -1, -1}
		for j, next := 1, unicode.SimpleFold(r); next != r; j, next = j+1, unicode.SimpleFold(next) {
			matcher.folds[i][j] = next
		}
	}
	matcher.failure = make([]int, len(matcher.pattern))
	for i, matched := 1, 0; i < len(matcher.pattern); i++ {
		for matched > 0 && matcher.pattern[i] != matcher.pattern[matched] {
			matched = matcher.failure[matched-1]
		}
		if matcher.pattern[i] == matcher.pattern[matched] {
			matched++
		}
		matcher.failure[i] = matched
	}
	matcher.anchors = matcher.foldAnchors(false, 3)
	if !ascii {
		return matcher
	}

	lower := make([]byte, len(matcher.pattern))
	mask := make([]byte, len(matcher.pattern))
	for i, r := range matcher.pattern {
		lower[i] = byte(r)
		if 'A' <= r && r <= 'Z' {
			lower[i] |= 0x20
			mask[i] = 0x20
		}
	}
	matcher.lower, matcher.mask = string(lower), string(mask)
	matcher.narrow = matcher.foldAnchors(true, 1)[0]
	for _, wide := range [...]struct {
		letter byte
		form   string
	}{{'k', "K"}, {'s', "ſ"}} {
		if strings.IndexByte(matcher.lower, wide.letter) >= 0 {
			matcher.wide = append(matcher.wide, newExactLiteral(wide.form))
		}
	}
	return matcher
}

func (m *foldedLiteral) foldAnchors(ascii bool, limit int) []foldAnchor {
	type candidate struct {
		anchor foldAnchor
		cost   int
	}
	var candidates []candidate
	for i, r := range m.pattern {
		if r == utf8.RuneError || slices.Contains(m.pattern[:i], r) {
			continue
		}
		next := candidate{anchor: foldAnchor{index: i}}
		for _, form := range m.folds[i] {
			if form < 0 {
				continue
			}
			encoded := string(form)
			switch {
			case len(encoded) == 1:
				next.cost += int(byteRank[encoded[0]])
			case ascii:
				continue
			default:
				next.cost += 256 + int(byteRank[encoded[len(encoded)-1]])
			}
			next.anchor.forms = append(next.anchor.forms, newExactLiteral(encoded))
		}
		candidates = append(candidates, next)
	}
	slices.SortStableFunc(candidates, func(a, b candidate) int { return cmp.Compare(a.cost, b.cost) })
	anchors := make([]foldAnchor, min(limit, len(candidates)))
	for i := range anchors {
		anchors[i] = candidates[i].anchor
	}
	return anchors
}

func canonicalFold(r rune) rune {
	if r < utf8.RuneSelf {
		if r >= 'a' && r <= 'z' {
			return r - ('a' - 'A')
		}
		return r
	}
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}

func (m *foldedLiteral) foldEqual(i int, r rune) bool {
	folds := &m.folds[i]
	return r == folds[0] || r == folds[1] || r == folds[2] || r == folds[3]
}

func (m *foldedLiteral) equal(value string) bool {
	if m.lower != "" {
		if len(value) == len(m.lower) && equalFoldASCII(value, m.lower, m.mask) {
			return true
		}
		if len(m.wide) == 0 {
			return false
		}
	}
	for i := range m.pattern {
		if len(value) == 0 {
			return false
		}
		r, size := utf8.DecodeRuneInString(value)
		if !m.foldEqual(i, r) {
			return false
		}
		value = value[size:]
	}
	return len(value) == 0
}

func (m *foldedLiteral) hasPrefix(value string) bool {
	if n := len(m.lower); n > 0 {
		if len(value) >= n && equalFoldASCII(value[:n], m.lower, m.mask) {
			return true
		}
		if len(m.wide) == 0 {
			return false
		}
	}
	for i := range m.pattern {
		if len(value) == 0 {
			return false
		}
		r, size := utf8.DecodeRuneInString(value)
		if !m.foldEqual(i, r) {
			return false
		}
		value = value[size:]
	}
	return true
}

func (m *foldedLiteral) hasSuffix(value string) bool {
	if n := len(m.lower); n > 0 {
		if len(value) >= n && equalFoldASCII(value[len(value)-n:], m.lower, m.mask) {
			return true
		}
		if len(m.wide) == 0 {
			return false
		}
	}
	for i := range slices.Backward(m.pattern) {
		if len(value) == 0 {
			return false
		}
		r, size := utf8.DecodeLastRuneInString(value)
		if !m.foldEqual(i, r) {
			return false
		}
		value = value[:len(value)-size]
	}
	return true
}

func (m *foldedLiteral) contains(value string) bool {
	if len(m.pattern) == 0 {
		return true
	}
	if m.lower != "" {
		found, exhaustive := m.containsASCII(value)
		if found || exhaustive || !m.containsWide(value) {
			return found
		}
	}
	var start int
	for i, anchor := range m.anchors {
		found, restart, complete := m.containsAnchor(value, anchor, start, i == len(m.anchors)-1)
		if found || complete {
			return found
		}
		start = restart
	}
	return m.containsFrom(value, start)
}

func (m *foldedLiteral) containsWide(value string) bool {
	for _, wide := range m.wide {
		if wide.index(value) >= 0 {
			return true
		}
	}
	return false
}

func (m *foldedLiteral) containsASCII(value string) (found, exhaustive bool) {
	n := len(m.lower)
	last := len(value) - n
	if last < 0 {
		return false, true
	}
	anchor := m.narrow.index
	var next [4]int
	for i := range m.narrow.forms {
		next[i] = -1
	}
	position := anchor
	var fails int
	for {
		candidate := last + anchor + 1
		for i, form := range m.narrow.forms {
			if next[i] < position {
				next[i] = last + anchor + 1
				if offset := strings.IndexByte(value[position:last+anchor+1], form.needle[0]); offset >= 0 {
					next[i] = position + offset
				}
			}
			candidate = min(candidate, next[i])
		}
		if candidate > last+anchor {
			return false, false
		}
		start := candidate - anchor
		if equalFoldASCII(value[start:start+n], m.lower, m.mask) {
			return true, false
		}
		position = candidate + 1
		fails++
		if overBudget(fails, n, position, 5) {
			return m.containsASCIIWords(value, start+1)
		}
	}
}

func (m *foldedLiteral) containsASCIIWords(value string, start int) (found, exhaustive bool) {
	lower, mask := m.lower, m.mask
	n := len(lower)
	last := len(value) - n
	firsts, firstFolds := lowBits*uint64(lower[0]), lowBits*uint64(mask[0])
	finals, finalFolds := lowBits*uint64(lower[n-1]), lowBits*uint64(mask[n-1])
	tails := value[n-1:]
	begin := start
	var fails int
	for ; start+8 <= last+1; start += 8 {
		z := ((loadWord(value[start:start+8]) | firstFolds) ^ firsts) | ((loadWord(tails[start:start+8]) | finalFolds) ^ finals)
		flags := (z - lowBits) &^ z & highBits
		if flags == 0 {
			continue
		}
		for ; flags != 0; flags &= flags - 1 {
			candidate := start + bits.TrailingZeros64(flags)>>3
			if equalFoldASCII(value[candidate:candidate+n], lower, mask) {
				return true, false
			}
			fails++
		}
		if overBudget(fails, n, start-begin, 3) {
			return m.containsFrom(value, 0), true
		}
	}
	for ; start <= last; start++ {
		if equalFoldASCII(value[start:start+n], lower, mask) {
			return true, false
		}
	}
	return false, false
}

func (m *foldedLiteral) containsAnchor(value string, anchor foldAnchor, start int, final bool) (found bool, restart int, complete bool) {
	n := len(m.pattern)
	first, last := start+anchor.index, len(value)-(n-anchor.index)
	if last < first {
		return false, 0, true
	}
	var next [4]int
	for i := range anchor.forms {
		next[i] = -1
	}
	shift := 4
	if final {
		shift = 2
	}
	position := first
	var fails int
	for {
		candidate := last + 1
		for i, form := range anchor.forms {
			if next[i] < position {
				next[i] = last + 1
				if offset := form.index(value[position:min(last+len(form.needle), len(value))]); offset >= 0 {
					next[i] = position + offset
				}
			}
			candidate = min(candidate, next[i])
		}
		if candidate > last {
			return false, 0, true
		}
		if m.matchAt(value, candidate, anchor.index) {
			return true, 0, true
		}
		position = candidate + 1
		fails++
		if overBudget(fails, n, position-first, shift) {
			return false, m.backward(value, candidate, anchor.index), false
		}
	}
}

func (m *foldedLiteral) matchAt(value string, position, anchor int) bool {
	forward := position
	for i := anchor; i < len(m.pattern); i++ {
		if forward >= len(value) {
			return false
		}
		r, size := rune(value[forward]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRuneInString(value[forward:])
		}
		if !m.foldEqual(i, r) {
			return false
		}
		forward += size
	}
	for i := anchor - 1; i >= 0; i-- {
		if position == 0 {
			return false
		}
		r, size := utf8.DecodeLastRuneInString(value[:position])
		if !m.foldEqual(i, r) {
			return false
		}
		position -= size
	}
	return true
}

func (m *foldedLiteral) backward(value string, position, runes int) int {
	for range runes {
		_, size := utf8.DecodeLastRuneInString(value[:position])
		position -= size
	}
	return position
}

func (m *foldedLiteral) containsFrom(value string, position int) bool {
	var matched int
	for position < len(value) {
		r, size := rune(value[position]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRuneInString(value[position:])
		}
		position += size
		for matched > 0 && !m.foldEqual(matched, r) {
			matched = m.failure[matched-1]
		}
		if m.foldEqual(matched, r) {
			matched++
			if matched == len(m.pattern) {
				return true
			}
		}
	}
	return false
}

func equalFoldASCII(value, lower, mask string) bool {
	n := len(lower)
	if n < 8 {
		for i := range n {
			if value[i]|mask[i] != lower[i] {
				return false
			}
		}
		return true
	}
	for i := 0; i+8 <= n; i += 8 {
		if loadWord(value[i:i+8])|loadWord(mask[i:i+8]) != loadWord(lower[i:i+8]) {
			return false
		}
	}
	return loadWord(value[n-8:])|loadWord(mask[n-8:]) == loadWord(lower[n-8:])
}
