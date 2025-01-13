package keycheck

import (
	"strconv"
	"strings"
)

type (
	bitwiseId uint8 // Bitwise Operator ID

	ID string
)

const (
	NOT bitwiseId = iota // Bitwise NOT
	AND                  // Bitwise AND
	OR                   // Bitwise OR
	XOR                  // Bitwise XOR (exclusive OR)

	SUCCESS ID = "SUCCESS"
	FAIL    ID = "FAIL"
	INVALID ID = "INVALID"
	CUSTOM  ID = "CUSTOM"
	RETRY   ID = "RETRY"
	BAN     ID = "BAN"
	NONE    ID = "NONE"
)

type validationError struct {
	err error
	msg string
}

func (m validationError) errorWithHeader(header string) string {
	var sb strings.Builder
	if header != "" {
		sb.WriteString(header)
		sb.WriteString(": ")
	}
	sb.WriteString(strconv.Quote(m.msg))
	if m.err != nil {
		sb.WriteString(": ")
		sb.WriteString(m.err.Error())
	}
	return sb.String()
}

func (m validationError) Error() string {
	return m.errorWithHeader("keycheck")
}

type KeyChain[T any] interface {
	DelValidator(label ID)
	GetValidator(label ID) func(a T) (bool, error)
	Reset()
	SetValidator(label ID, fn func(a T) (bool, error))
	Validate(data T, defaultLabel ID) (ID, bool, []error)
}

type keyChain[T any] struct {
	validators validatorsMap[T]
	condition  bitwiseId
}

func NewKeyChain[T any](condition bitwiseId) (KeyChain[T], error) {
	if condition > XOR {
		return nil, nil
	}
	return &keyChain[T]{
		validators: validatorsMap[T]{},
		condition:  condition,
	}, nil
}

func (kc *keyChain[T]) DelValidator(label ID) {
	if kc.validators == nil {
		return
	}
	kc.validators.Del(label)
}

func (kc *keyChain[T]) GetValidator(label ID) func(a T) (bool, error) {
	if kc.validators == nil {
		return nil
	}
	return kc.validators.Get(label)
}

func (kc *keyChain[T]) SetValidator(label ID, fn func(a T) (bool, error)) {
	if kc.validators == nil {
		kc.validators = validatorsMap[T]{}
	}
	kc.validators.Set(label, fn)
}

func (kc *keyChain[T]) Validate(data T, defaultLabel ID) (ID, bool, []error) {
	if kc.validators == nil {
		return defaultLabel, false, nil
	}
	var (
		ok   bool
		lbl  ID
		err  error
		errs []error
	)
	switch kc.condition {
	case NOT:
		for label, fn := range kc.validators {
			if fn == nil {
				continue
			}
			ok, err = fn(data)
			if !ok {
				lbl = label
				continue
			}
			errs = append(errs, validationError{nil, string(label)})
			return defaultLabel, false, errs
		}
		return lbl, true, nil
	case AND:
		for label, fn := range kc.validators {
			if fn == nil {
				continue
			}
			ok, err = fn(data)
			if !ok {
				return defaultLabel, false, append(errs, validationError{err, string(label)})
			}
			lbl = label
		}
		return lbl, ok, nil
	case OR:
		for label, fn := range kc.validators {
			if fn == nil {
				continue
			}
			ok, err = fn(data)
			if ok {
				return label, ok, nil
			}
			errs = append(errs, validationError{err, string(label)})
			lbl = label
		}
		return lbl, false, errs
	case XOR:
		var trueCount uint
		for label, fn := range kc.validators {
			if fn == nil {
				continue
			}
			ok, err = fn(data)
			if ok {
				trueCount++
				if trueCount > 1 {
					return defaultLabel, false, nil
				}
			} else {
				errs = append(errs, validationError{err, string(label)})
			}
			lbl = label
		}
		if trueCount == 1 {
			return lbl, true, nil
		}
		return defaultLabel, false, errs
	}
	return defaultLabel, false, nil
}

func (kc *keyChain[T]) Reset() {
	kc.condition = 0
	kc.validators = nil
}
