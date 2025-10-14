package keycheck

import (
	"slices"
	"strconv"

	"github.com/colduction/errorwrapper/v1"
)

var errw = errorwrapper.New('.', "KeyChain")

type (
	BitwiseID uint8 // Bitwise Operator ID
	ID        string
)

const (
	NOT BitwiseID = iota // Bitwise NOT
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

var bitwiseOps = [...]BitwiseID{
	NOT,
	AND,
	OR,
	XOR,
}

// IsValid checks if the BitwiseID is a defined operator.
func (bi BitwiseID) IsValid() bool {
	return int(bi) < len(bitwiseOps)
}

type KeyChain[T any] interface {
	DelValidator(label ID) error
	GetValidator(label ID) (func(a T) (bool, error), error)
	Reset()
	SetCondition(condition BitwiseID) error
	SetValidator(label ID, fn func(a T) (bool, error)) error
	Validate(data T, defaultLabel ID) (ID, bool, []error)
}

type keyChain[T any] struct {
	validators validatorsMap[T]
	condition  BitwiseID
	order      []ID
}

// NewKeyChain creates and returns a new KeyChain instance with a specified
// bitwise condition for validation logic. It returns an error if the
// condition is invalid.
func NewKeyChain[T any](condition BitwiseID) (KeyChain[T], error) {
	if !condition.IsValid() {
		return nil, errw.NewErrorString("invalid validator bitwise operator id", strconv.FormatUint(uint64(condition), 10))
	}
	return &keyChain[T]{
		validators: validatorsMap[T]{},
		condition:  condition,
		order:      []ID{},
	}, nil
}

// DelValidator removes a validator function, identified by its label,
// from the keychain.
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

// GetValidator retrieves a validator function by its label. It returns
// the function and a nil error if found, otherwise nil and an error.
func (kc *keyChain[T]) GetValidator(label ID) (func(a T) (bool, error), error) {
	if kc == nil {
		return nil, errw.NewErrorString("receiver is nil")
	}
	if kc.validators == nil {
		return nil, errw.NewErrorString("no validator is exist")
	}
	return kc.validators.Get(label), nil
}

// SetValidator adds or updates a validator function for a given label.
// It also maintains the order in which validators were added.
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

// SetCondition updates the bitwise condition (e.g., AND, OR) that
// governs the overall validation logic.
func (kc *keyChain[T]) SetCondition(condition BitwiseID) error {
	if kc == nil {
		return errw.NewErrorString("receiver is nil")
	}
	if !condition.IsValid() {
		return errw.NewErrorString("invalid validator bitwise operator id", strconv.FormatUint(uint64(condition), 10))
	}
	kc.condition = condition
	return nil
}

// Validate processes the given data against all registered validators according
// to the set bitwise condition (NOT, AND, OR, XOR). It returns the resulting
// ID label, a boolean indicating overall success, and a slice of any errors
// encountered.
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
			if ok, _ = fn(data); !ok {
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
		}
		return defaultLabel, false, errs
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

// Reset clears all validators, the validation order, and the bitwise
// condition, restoring the keychain to its initial empty state.
func (kc *keyChain[T]) Reset() {
	if kc == nil {
		return
	}
	kc.condition = 0
	kc.validators = nil
	kc.order = nil
}
