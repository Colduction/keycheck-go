package keycheck

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
)

type textKind uint8

const (
	textEqual textKind = iota
	textContains
	textPrefix
	textSuffix
	textContainsAny
	textRegex
)

type textTest struct {
	kind         textKind
	fold         bool
	literal      string
	alternatives []string
	regex        *regexMatcher
}

type regexMatcher struct {
	re     *regexp.Regexp
	exact  *exactLiteral
	folded *foldedLiteral
}

func (m *regexMatcher) match(value string) bool {
	if m.exact != nil && m.exact.index(value) < 0 || m.folded != nil && !m.folded.contains(value) {
		return false
	}
	return m.re.MatchString(value)
}

func (c *compiler) regexTest(pattern string, ignoreCase bool) (textTest, error) {
	flags, source := syntax.Perl, pattern
	if ignoreCase {
		flags, source = flags|syntax.FoldCase, "(?i)"+pattern
	}
	if test, ok := c.regexes[source]; ok {
		return test, nil
	}
	tree, err := syntax.Parse(pattern, flags)
	if err != nil {
		return textTest{}, fmt.Errorf("%w: %v", ErrInvalidPattern, err)
	}
	tree = tree.Simplify()
	test, ok := literalTest(tree)
	if !ok {
		re, err := regexp.Compile(source)
		if err != nil {
			return textTest{}, fmt.Errorf("%w: %v", ErrInvalidPattern, err)
		}
		matcher := &regexMatcher{re: re}
		prefix, _ := re.LiteralPrefix()
		if runes, fold := requiredLiteral(tree); runesSize(runes) > len(prefix) && !beginsText(tree) {
			if fold {
				folded := compileFoldedLiteral(string(runes))
				matcher.folded = &folded
			} else {
				exact := newExactLiteral(string(runes))
				matcher.exact = &exact
			}
		}
		test = textTest{kind: textRegex, regex: matcher}
	}
	if c.regexes == nil {
		c.regexes = make(map[string]textTest)
	}
	c.regexes[source] = test
	return test, nil
}

func literalTest(re *syntax.Regexp) (textTest, bool) {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op == syntax.OpAlternate {
		test := textTest{kind: textContainsAny}
		for i, branch := range re.Sub {
			literal, fold, ok := literalParts(concatParts(branch))
			if !ok || i > 0 && fold != test.fold {
				return textTest{}, false
			}
			if literal == "" {
				return textTest{kind: textContains}, true
			}
			test.alternatives, test.fold = append(test.alternatives, literal), fold
		}
		return test, true
	}
	parts := concatParts(re)
	var begin, end bool
	if len(parts) > 0 && parts[0].Op == syntax.OpBeginText {
		begin, parts = true, parts[1:]
	}
	if len(parts) > 0 && parts[len(parts)-1].Op == syntax.OpEndText {
		end, parts = true, parts[:len(parts)-1]
	}
	literal, fold, ok := literalParts(parts)
	if !ok {
		return textTest{}, false
	}
	test := textTest{kind: textContains, fold: fold, literal: literal}
	switch {
	case begin && end:
		test.kind = textEqual
	case begin:
		test.kind = textPrefix
	case end:
		test.kind = textSuffix
	}
	return test, true
}

func concatParts(re *syntax.Regexp) []*syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op == syntax.OpConcat {
		return re.Sub
	}
	return []*syntax.Regexp{re}
}

func literalParts(parts []*syntax.Regexp) (literal string, fold, ok bool) {
	var runes []rune
	for _, part := range parts {
		for part.Op == syntax.OpCapture {
			part = part.Sub[0]
		}
		switch part.Op {
		case syntax.OpEmptyMatch:
			continue
		case syntax.OpLiteral:
		default:
			return "", false, false
		}
		partFold := part.Flags&syntax.FoldCase != 0
		if len(runes) > 0 && partFold != fold || !literalRunes(part.Rune, partFold) {
			return "", false, false
		}
		runes, fold = append(runes, part.Rune...), partFold
	}
	return string(runes), fold, true
}

func literalRunes(runes []rune, fold bool) bool {
	for _, r := range runes {
		if !utf8.ValidRune(r) || r == utf8.RuneError && !fold {
			return false
		}
	}
	return true
}

func beginsText(re *syntax.Regexp) bool {
	for {
		switch re.Op {
		case syntax.OpBeginText:
			return true
		case syntax.OpCapture, syntax.OpConcat:
			re = re.Sub[0]
		default:
			return false
		}
	}
}

func requiredLiteral(re *syntax.Regexp) ([]rune, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		if literalRunes(re.Rune, fold) {
			return re.Rune, fold
		}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiteral(re.Sub[0])
	case syntax.OpConcat:
		var (
			best, run         []rune
			bestFold, runFold bool
		)
		for _, sub := range re.Sub {
			fold := sub.Flags&syntax.FoldCase != 0
			if sub.Op == syntax.OpLiteral && literalRunes(sub.Rune, fold) {
				if len(run) > 0 && fold != runFold {
					best, bestFold = betterLiteral(best, bestFold, run, runFold)
					run = nil
				}
				run, runFold = append(run, sub.Rune...), fold
				continue
			}
			best, bestFold = betterLiteral(best, bestFold, run, runFold)
			run = nil
			required, requiredFold := requiredLiteral(sub)
			best, bestFold = betterLiteral(best, bestFold, required, requiredFold)
		}
		return betterLiteral(best, bestFold, run, runFold)
	}
	return nil, false
}

func betterLiteral(current []rune, currentFold bool, candidate []rune, candidateFold bool) ([]rune, bool) {
	currentSize, candidateSize := runesSize(current), runesSize(candidate)
	if candidateSize > currentSize || candidateSize == currentSize && candidateSize > 0 && currentFold && !candidateFold {
		return candidate, candidateFold
	}
	return current, currentFold
}

func runesSize(runes []rune) int {
	var size int
	for _, r := range runes {
		size += utf8.RuneLen(r)
	}
	return size
}
