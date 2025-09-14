package keycheck

import (
	"slices"

	"github.com/colduction/errorwrapper/v1"
)

var errw = errorwrapper.New('.', "KeyChain")

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

type KeyChain[T any] interface {
	DelValidator(label ID) error
	GetValidator(label ID) (func(a T) (bool, error), error)
	Reset()
	SetValidator(label ID, fn func(a T) (bool, error)) error
	Validate(data T, defaultLabel ID) (ID, bool, []error)
}

type keyChain[T any] struct {
	validators validatorsMap[T]
	condition  bitwiseId
	order      []ID
}

func NewKeyChain[T any](condition bitwiseId) (KeyChain[T], error) {
	if condition > XOR {
		return nil, nil
	}
	return &keyChain[T]{
		validators: validatorsMap[T]{},
		condition:  condition,
		order:      []ID{},
	}, nil
}

func (kc *keyChain[T]) DelValidator(label ID) error {
	if kc == nil {
		return errw.NewErrorString("receiver is nil")
	}
	if kc.validators == nil {
		return errw.NewErrorString("no validator is exist")
	}
	if _, exists := kc.validators[label]; exists {
		kc.order = slices.DeleteFunc(kc.order, func(id ID) bool {
			return id == label
		})
	}
	kc.validators.Del(label)
	return nil
}

func (kc *keyChain[T]) GetValidator(label ID) (func(a T) (bool, error), error) {
	if kc == nil {
		return nil, errw.NewErrorString("receiver is nil")
	}
	if kc.validators == nil {
		return nil, errw.NewErrorString("no validator is exist")
	}
	return kc.validators.Get(label), nil
}

func (kc *keyChain[T]) SetValidator(label ID, fn func(a T) (bool, error)) error {
	if kc == nil {
		return errw.NewErrorString("receiver is nil")
	}
	if kc.validators == nil {
		kc.validators = validatorsMap[T]{}
	}
	if _, exists := kc.validators[label]; !exists {
		kc.order = append(kc.order, label)
	}
	kc.validators.Set(label, fn)
	return nil
}

func (kc *keyChain[T]) Validate(data T, defaultLabel ID) (ID, bool, []error) {
	if kc == nil {
		return "", false, []error{errw.NewErrorString("receiver is nil")}
	}
	if kc.validators == nil {
		return defaultLabel, false, nil
	}
	var (
		ok   bool
		lbl  ID
		err  error
		errs []error
		fn   func(a T) (bool, error)
	)
	switch kc.condition {
	case NOT:
		for _, label := range kc.order {
			if fn = kc.validators.Get(label); fn == nil {
				continue
			}
			if ok, err = fn(data); !ok {
				lbl = label
				continue
			}
			errs = append(errs, errw.NewError(nil, string(label)))
			return defaultLabel, false, errs
		}
		return lbl, true, nil
	case AND:
		for _, label := range kc.order {
			if fn = kc.validators.Get(label); fn == nil {
				continue
			}
			ok, err = fn(data)
			if !ok {
				return defaultLabel, false, append(errs, errw.NewError(err, string(label)))
			}
			lbl = label
		}
		return lbl, ok, nil
	case OR:
		for _, label := range kc.order {
			if fn = kc.validators.Get(label); fn == nil {
				continue
			}
			ok, err = fn(data)
			if ok {
				return label, ok, nil
			}
			errs = append(errs, errw.NewError(err, string(label)))
			lbl = label
		}
		return lbl, false, errs
	case XOR:
		var trueCount uint
		for _, label := range kc.order {
			if fn = kc.validators.Get(label); fn == nil {
				continue
			}
			ok, err = fn(data)
			if ok {
				trueCount++
				if trueCount > 1 {
					return defaultLabel, false, nil
				}
			} else {
				errs = append(errs, errw.NewError(err, string(label)))
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
	if kc == nil {
		return
	}
	kc.condition = 0
	kc.validators = nil
	kc.order = nil
}
