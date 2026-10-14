package keycheck

import (
	"cmp"
	"slices"
	"strings"
	"unsafe"
)

// StringKey compares the string selected by left with right.
// It accepts string types, including defined types.
// It supports [EqualTo], [NotEqualTo], [Contains], [DoesNotContain], [Exists],
// [DoesNotExist], [MatchesRegex], [DoesNotMatchRegex], [StartsWith],
// [DoesNotStartWith], [EndsWith], and [DoesNotEndWith].
// Comparisons are case-sensitive unless [IgnoreCase] is supplied.
// Regular expressions use Go's regular-expression syntax; [IgnoreCase] parses the pattern as if it began with (?i).
// Case-insensitive literal searches use Unicode simple folding with linear-time matching.
// A missing value matches only [DoesNotExist]; an empty present string exists.
// [Exists] and [DoesNotExist] ignore right and valid text options without retaining right.
// Options are copied into the key's configuration before returning.
// [Compile] reports a nil selector, unsupported operator, invalid option, or invalid pattern.
func StringKey[T any, V ~string](left Selector[T, V], op Operator, right V, options ...TextOption) Key[T] {
	return textKey(left, op, string(right), options)
}

// BytesKey compares the bytes selected by left with a private copy of right made before returning.
// It accepts byte slice types, including defined types.
// It supports the same operators, text options, and presence rules as [StringKey].
// [Exists] and [DoesNotExist] ignore right and valid text options without copying or retaining right.
// A nil slice reported as present is an empty present value.
// Evaluation borrows selected bytes only for the duration of the call.
// [Compile] reports a nil selector, unsupported operator, invalid option, or invalid pattern.
func BytesKey[T any, V ~[]byte](left Selector[T, V], op Operator, right V, options ...TextOption) Key[T] {
	var expected string
	if op != Exists && op != DoesNotExist {
		expected = string(right)
	}
	return textKey(left, op, expected, options)
}

func textKey[T any, V ~string | ~[]byte](left Selector[T, V], op Operator, right string, options []TextOption) Key[T] {
	ignoreCase, optionErr := parseTextOptions(options)
	if op == Exists || op == DoesNotExist {
		right = ""
	}
	return Key[T]{compile: func(c *compiler) (predicate[T], error) {
		if left == nil {
			return nil, ErrInvalidKey
		}
		if optionErr != nil {
			return nil, optionErr
		}
		want := true
		test := textTest{literal: right, fold: ignoreCase}
		switch op {
		case Exists, DoesNotExist:
			exists := op == Exists
			return func(input T) (bool, error) {
				_, present := left(input)
				return present == exists, nil
			}, nil
		case NotEqualTo:
			want = false
			fallthrough
		case EqualTo:
			test.kind = textEqual
		case DoesNotContain:
			want = false
			fallthrough
		case Contains:
			test.kind = textContains
		case DoesNotStartWith:
			want = false
			fallthrough
		case StartsWith:
			test.kind = textPrefix
		case DoesNotEndWith:
			want = false
			fallthrough
		case EndsWith:
			test.kind = textSuffix
		case DoesNotMatchRegex:
			want = false
			fallthrough
		case MatchesRegex:
			var err error
			if test, err = c.regexTest(right, ignoreCase); err != nil {
				return nil, err
			}
		default:
			return nil, ErrInvalidOperator
		}
		return textPredicate(left, test, want), nil
	}}
}

func textPredicate[T any, V ~string | ~[]byte](left Selector[T, V], test textTest, want bool) predicate[T] {
	right := test.literal
	if test.kind == textRegex {
		regex := test.regex
		return func(input T) (bool, error) {
			value, present := left(input)
			return present && regex.match(borrowString(value)) == want, nil
		}
	}
	if test.kind == textContainsAny {
		if test.fold {
			alternatives := make([]foldedLiteral, len(test.alternatives))
			for i, alternative := range test.alternatives {
				alternatives[i] = compileFoldedLiteral(alternative)
			}
			return func(input T) (bool, error) {
				value, present := left(input)
				if !present {
					return false, nil
				}
				for i := range alternatives {
					if alternatives[i].contains(borrowString(value)) {
						return want, nil
					}
				}
				return !want, nil
			}
		}
		alternatives := make([]exactLiteral, len(test.alternatives))
		for i, alternative := range test.alternatives {
			alternatives[i] = newExactLiteral(alternative)
		}
		return func(input T) (bool, error) {
			value, present := left(input)
			if !present {
				return false, nil
			}
			for _, alternative := range alternatives {
				if alternative.index(borrowString(value)) >= 0 {
					return want, nil
				}
			}
			return !want, nil
		}
	}
	if test.fold {
		folded := compileFoldedLiteral(right)
		switch test.kind {
		case textEqual:
			return func(input T) (bool, error) {
				value, present := left(input)
				return present && folded.equal(borrowString(value)) == want, nil
			}
		case textPrefix:
			return func(input T) (bool, error) {
				value, present := left(input)
				return present && folded.hasPrefix(borrowString(value)) == want, nil
			}
		case textSuffix:
			return func(input T) (bool, error) {
				value, present := left(input)
				return present && folded.hasSuffix(borrowString(value)) == want, nil
			}
		default:
			return func(input T) (bool, error) {
				value, present := left(input)
				return present && folded.contains(borrowString(value)) == want, nil
			}
		}
	}
	switch test.kind {
	case textEqual:
		return func(input T) (bool, error) {
			value, present := left(input)
			return present && (borrowString(value) == right) == want, nil
		}
	case textPrefix:
		return func(input T) (bool, error) {
			value, present := left(input)
			return present && strings.HasPrefix(borrowString(value), right) == want, nil
		}
	case textSuffix:
		return func(input T) (bool, error) {
			value, present := left(input)
			return present && strings.HasSuffix(borrowString(value), right) == want, nil
		}
	default:
		exact := newExactLiteral(right)
		return func(input T) (bool, error) {
			value, present := left(input)
			return present && (exact.index(borrowString(value)) >= 0) == want, nil
		}
	}
}

func borrowString[V ~string | ~[]byte](value V) string {
	return *(*string)(unsafe.Pointer(&value))
}

// IntKey compares the integer selected by left with right.
// It accepts all signed and unsigned integer types, including defined types and pointer-sized integers.
// It supports [EqualTo], [NotEqualTo], [LessThan], [LessThanOrEqualTo],
// [GreaterThan], and [GreaterThanOrEqualTo].
// Missing values do not match any operator.
// [Compile] reports a nil selector or unsupported operator.
func IntKey[T any, V ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr](left Selector[T, V], op Operator, right V) Key[T] {
	return orderedKey(left, op, right)
}

// FloatKey compares the floating-point value selected by left with right.
// It accepts both floating-point types, including defined types, without widening values.
// It supports the same operators and presence rules as [IntKey].
// Comparisons use Go's native operators, including their NaN and infinity behavior,
// rather than OpenBullet2's epsilon-based equality and inequality.
// [Compile] reports a nil selector or unsupported operator.
func FloatKey[T any, V ~float32 | ~float64](left Selector[T, V], op Operator, right V) Key[T] {
	return orderedKey(left, op, right)
}

func orderedKey[T any, V cmp.Ordered](left Selector[T, V], op Operator, right V) Key[T] {
	return Key[T]{compile: func(_ *compiler) (predicate[T], error) {
		if left == nil {
			return nil, ErrInvalidKey
		}
		switch op {
		case EqualTo:
			return func(input T) (bool, error) {
				value, present := left(input)
				return value == right && present, nil
			}, nil
		case NotEqualTo:
			return func(input T) (bool, error) {
				value, present := left(input)
				return value != right && present, nil
			}, nil
		case LessThan:
			return func(input T) (bool, error) {
				value, present := left(input)
				return value < right && present, nil
			}, nil
		case LessThanOrEqualTo:
			return func(input T) (bool, error) {
				value, present := left(input)
				return value <= right && present, nil
			}, nil
		case GreaterThan:
			return func(input T) (bool, error) {
				value, present := left(input)
				return value > right && present, nil
			}, nil
		case GreaterThanOrEqualTo:
			return func(input T) (bool, error) {
				value, present := left(input)
				return value >= right && present, nil
			}, nil
		default:
			return nil, ErrInvalidOperator
		}
	}}
}

// BoolKey compares the boolean selected by left with right using [Is] or [IsNot].
// It accepts boolean types, including defined types.
// Missing values do not match either operator.
// [Compile] reports a nil selector or unsupported operator.
func BoolKey[T any, V ~bool](left Selector[T, V], op Operator, right V) Key[T] {
	if op == IsNot {
		right = !right
	}
	return Key[T]{compile: func(_ *compiler) (predicate[T], error) {
		if left == nil {
			return nil, ErrInvalidKey
		}
		if op != Is && op != IsNot {
			return nil, ErrInvalidOperator
		}
		return func(input T) (bool, error) {
			value, present := left(input)
			return value == right && present, nil
		}, nil
	}}
}

// ListKey compares the list selected by left with right.
// It accepts slice types with comparable elements, including defined slice and element types.
// It supports [Contains], [DoesNotContain], [Exists], and [DoesNotExist].
// Membership uses Go equality; string comparisons are case-sensitive.
// Interface comparisons can panic when equal dynamic types are not comparable.
// A missing value matches only [DoesNotExist]; a nil slice reported as present exists.
// [Exists] and [DoesNotExist] ignore right and do not retain it.
// Evaluation borrows the selected list only for the duration of the call.
// [Compile] reports a nil selector or unsupported operator.
func ListKey[T any, S ~[]V, V comparable](left Selector[T, S], op Operator, right V) Key[T] {
	if op == Exists || op == DoesNotExist {
		var zero V
		right = zero
	}
	return Key[T]{compile: func(_ *compiler) (predicate[T], error) {
		if left == nil {
			return nil, ErrInvalidKey
		}
		switch op {
		case Exists, DoesNotExist:
			want := op == Exists
			return func(input T) (bool, error) {
				_, present := left(input)
				return present == want, nil
			}, nil
		case Contains, DoesNotContain:
			want := op == Contains
			return func(input T) (bool, error) {
				value, present := left(input)
				if !present {
					return false, nil
				}
				if slices.Contains(value, right) {
					return want, nil
				}
				return !want, nil
			}, nil
		default:
			return nil, ErrInvalidOperator
		}
	}}
}

// DictionaryKey compares the dictionary selected by left with right.
// It accepts map types whose keys and values share one comparable type, including defined types.
// It supports [HasKey], [DoesNotHaveKey], [HasValue], [DoesNotHaveValue],
// [Exists], and [DoesNotExist].
// Keys and values use Go equality; string comparisons are case-sensitive.
// Interface comparisons and map lookups can panic for non-comparable dynamic values.
// Existence checks concern the dictionary itself, not an entry named by right.
// A missing value matches only [DoesNotExist]; a nil map reported as present exists.
// [Exists] and [DoesNotExist] ignore right and do not retain it.
// Evaluation borrows the selected map only for the duration of the call.
// [Compile] reports a nil selector or unsupported operator.
func DictionaryKey[T any, M ~map[V]V, V comparable](left Selector[T, M], op Operator, right V) Key[T] {
	if op == Exists || op == DoesNotExist {
		var zero V
		right = zero
	}
	return Key[T]{compile: func(_ *compiler) (predicate[T], error) {
		if left == nil {
			return nil, ErrInvalidKey
		}
		switch op {
		case Exists, DoesNotExist:
			want := op == Exists
			return func(input T) (bool, error) {
				_, present := left(input)
				return present == want, nil
			}, nil
		case HasKey, DoesNotHaveKey:
			want := op == HasKey
			return func(input T) (bool, error) {
				value, present := left(input)
				if !present {
					return false, nil
				}
				_, found := value[right]
				return found == want, nil
			}, nil
		case HasValue, DoesNotHaveValue:
			want := op == HasValue
			return func(input T) (bool, error) {
				value, present := left(input)
				if !present {
					return false, nil
				}
				for _, item := range value {
					if item == right {
						return want, nil
					}
				}
				return !want, nil
			}, nil
		default:
			return nil, ErrInvalidOperator
		}
	}}
}
