package keycheck

import (
	"fmt"
	"slices"
)

// All groups keys into a single key that matches when every child matches.
// An empty group matches.
// Keys are copied when All is called and evaluated from left to right,
// stopping at the first nonmatch or error.
// [Compile] validates every child, including children that evaluation would skip.
func All[T any](keys ...Key[T]) Key[T] {
	return AtLeast(len(keys), keys...)
}

// Any groups keys into a single key that matches when any child matches.
// An empty group does not match.
// Keys are copied when Any is called and evaluated from left to right,
// stopping at the first match or error.
// [Compile] validates every child, including children that evaluation would skip.
func Any[T any](keys ...Key[T]) Key[T] {
	if len(keys) == 0 {
		return Key[T]{compile: func(*compiler) (predicate[T], error) {
			return func(T) (bool, error) { return false, nil }, nil
		}}
	}
	return AtLeast(1, keys...)
}

// Not negates the result of key without suppressing its errors.
// It also negates nonmatches caused by missing selected values.
// [Compile] validates the child before the group can be evaluated.
func Not[T any](key Key[T]) Key[T] {
	return Key[T]{compile: func(c *compiler) (predicate[T], error) {
		match, err := c.key(key)
		if err != nil {
			return nil, fmt.Errorf("group key 0: %w", err)
		}
		return func(input T) (bool, error) {
			matched, err := match(input)
			if err != nil {
				return false, fmt.Errorf("group key 0: %w", err)
			}
			return !matched, nil
		}, nil
	}}
}

// AtLeast groups keys into a single key that matches when at least count children match.
// A zero count matches without evaluating children.
// Keys are copied when AtLeast is called and evaluated from left to right.
// Evaluation stops on an error or when the result is determined.
// [Compile] rejects negative counts or counts larger than the number of keys with [ErrInvalidThreshold]
// and validates every child, including children that evaluation would skip.
func AtLeast[T any](count int, keys ...Key[T]) Key[T] {
	return thresholdKey(count, false, keys)
}

// Exactly groups keys into a single key that matches when exactly count children match.
// A zero count matches only when no child matches; an empty group with zero count matches.
// Keys are copied when Exactly is called and evaluated from left to right.
// Evaluation stops on an error or when the result is determined.
// [Compile] rejects negative counts or counts larger than the number of keys with [ErrInvalidThreshold]
// and validates every child, including children that evaluation would skip.
func Exactly[T any](count int, keys ...Key[T]) Key[T] {
	return thresholdKey(count, true, keys)
}

func thresholdKey[T any](count int, exact bool, keys []Key[T]) Key[T] {
	keys = slices.Clone(keys)
	return Key[T]{compile: func(c *compiler) (predicate[T], error) {
		if count < 0 || count > len(keys) {
			return nil, ErrInvalidThreshold
		}
		if len(keys) > c.maxKeys-c.keys {
			return nil, ErrTooManyKeys
		}
		predicates := make([]predicate[T], len(keys))
		for i, key := range keys {
			match, err := c.key(key)
			if err != nil {
				return nil, fmt.Errorf("group key %d: %w", i, err)
			}
			predicates[i] = match
		}
		switch {
		case !exact && count == 0:
			return func(T) (bool, error) { return true, nil }, nil
		case !exact && count == len(predicates):
			return func(input T) (bool, error) {
				for i, match := range predicates {
					ok, err := match(input)
					if err != nil {
						return false, fmt.Errorf("group key %d: %w", i, err)
					}
					if !ok {
						return false, nil
					}
				}
				return true, nil
			}, nil
		case !exact && count == 1:
			return func(input T) (bool, error) {
				for i, match := range predicates {
					ok, err := match(input)
					if err != nil {
						return false, fmt.Errorf("group key %d: %w", i, err)
					}
					if ok {
						return true, nil
					}
				}
				return false, nil
			}, nil
		}
		return func(input T) (bool, error) {
			var matched int
			for i, match := range predicates {
				ok, err := match(input)
				if err != nil {
					return false, fmt.Errorf("group key %d: %w", i, err)
				}
				if ok {
					matched++
				}
				if exact {
					if matched > count {
						return false, nil
					}
				} else if matched >= count {
					return true, nil
				}
				if matched+(len(predicates)-i-1) < count {
					return false, nil
				}
			}
			return matched == count, nil
		}, nil
	}}
}
