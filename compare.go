package keycheck

import "cmp"

// CompareKey compares values selected from the same input by left and right.
// It accepts integer, floating-point, and string types, including defined types.
// It supports [EqualTo], [NotEqualTo], [LessThan], [LessThanOrEqualTo],
// [GreaterThan], and [GreaterThanOrEqualTo] using Go's native operators,
// including their NaN behavior and lexicographic string ordering.
// Evaluation calls left once, then right once only when left is present.
// A missing operand never matches, including with [NotEqualTo].
// Selected values are not retained after evaluation.
// [Compile] rejects nil selectors and unsupported operators.
// Use [BoolKey] for constant boolean comparisons and [CustomKey] for dynamic boolean or regex predicates.
func CompareKey[T any, V cmp.Ordered](left Selector[T, V], op Operator, right Selector[T, V]) Key[T] {
	return Key[T]{compile: func(*compiler) (predicate[T], error) {
		if left == nil || right == nil {
			return nil, ErrInvalidKey
		}
		switch op {
		case EqualTo, NotEqualTo, LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo:
		default:
			return nil, ErrInvalidOperator
		}
		return func(input T) (bool, error) {
			first, present := left(input)
			if !present {
				return false, nil
			}
			second, present := right(input)
			if !present {
				return false, nil
			}
			switch op {
			case EqualTo:
				return first == second, nil
			case NotEqualTo:
				return first != second, nil
			case LessThan:
				return first < second, nil
			case LessThanOrEqualTo:
				return first <= second, nil
			case GreaterThan:
				return first > second, nil
			default:
				return first >= second, nil
			}
		}, nil
	}}
}
