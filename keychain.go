package keycheck

import (
	"fmt"
	"slices"
)

type (
	ErrInvalidBitwiseID BitwiseID
	ErrNoValidatorExist struct{}
	ErrNilReceiver      struct{}
)

func (err ErrInvalidBitwiseID) Error() string {
	return fmt.Sprintf("keycheck: invalid bitwise operator ID %d", uint8(err))
}

func (err ErrNoValidatorExist) Error() string {
	return "keycheck: no validators registered"
}

func (err ErrNilReceiver) Error() string {
	return "keycheck: nil receiver"
}

type BitwiseID uint8 // Bitwise Operator ID

const (
	NOT BitwiseID = iota // Bitwise NOT
	AND                  // Bitwise AND
	OR                   // Bitwise OR
	XOR                  // Bitwise XOR (exclusive OR)
)

var bitwiseOps = [...]BitwiseID{
	NOT,
	AND,
	OR,
	XOR,
}

type (
	StatusGetter interface {
		Clone() Status
		GetDetails() string
		GetID() string
		Marshal(f func(v any) ([]byte, error)) ([]byte, error)
	}
	StatusSetter interface {
		SetDetails(details string)
		SetID(id string)
		Unmarshal(f func(data []byte, v any) error, b []byte) error
		Reset()
	}
	StatusGetSetter interface {
		StatusGetter
		StatusSetter
	}
)

type Status struct {
	ID      string `json:"id,omitempty"`
	Details string `json:"details,omitempty"`
}

func (s Status) Clone() Status {
	return Status{
		ID:      s.ID,
		Details: s.Details,
	}
}

func (s *Status) GetID() string {
	return s.ID
}

func (s *Status) SetID(id string) {
	s.ID = id
}

func (s *Status) GetDetails() string {
	return s.Details
}

func (s *Status) SetDetails(details string) {
	s.Details = details
}

func (s *Status) Marshal(f func(v any) ([]byte, error)) ([]byte, error) {
	return f(s)
}

func (s *Status) Unmarshal(f func(data []byte, v any) error, b []byte) error {
	return f(b, s)
}

func (s *Status) Reset() {
	if s == nil {
		return
	}
	s.Details = ""
	s.ID = ""
}

var (
	SUCCESS StatusGetter = &Status{ID: "SUCCESS"}
	FAIL    StatusGetter = &Status{ID: "FAIL"}
	INVALID StatusGetter = &Status{ID: "INVALID"}
	CUSTOM  StatusGetter = &Status{ID: "CUSTOM"}
	RETRY   StatusGetter = &Status{ID: "RETRY"}
	BAN     StatusGetter = &Status{ID: "BAN"}
	NONE    StatusGetter = &Status{ID: "NONE"}
)

// IsValid checks if the BitwiseID is a defined operator.
func (bid BitwiseID) IsValid() bool {
	return int(bid) < len(bitwiseOps)
}

type KeyChain[T any] interface {
	DelValidator(label string) error
	GetValidator(label string) (Status, func(a T) (bool, error), error)
	Reset()
	SetCondition(condition BitwiseID) error
	SetValidator(status Status, fn func(a T) (bool, error)) error
	Validate(data T, defaultStatus StatusGetter) (StatusGetter, bool, []error)
}

type keyChain[T any] struct {
	validators validatorsMap[T]
	condition  BitwiseID
	order      []string
}

// NewKeyChain creates and returns a new KeyChain instance with a specified
// bitwise condition for validation logic. It returns an error if the
// condition is invalid.
func NewKeyChain[T any](condition BitwiseID) (KeyChain[T], error) {
	if !condition.IsValid() {
		return nil, ErrInvalidBitwiseID(condition)
	}
	return &keyChain[T]{
		validators: validatorsMap[T]{},
		condition:  condition,
		order:      []string{},
	}, nil
}

// DelValidator removes a validator function, identified by its label,
// from the keychain.
func (kc *keyChain[T]) DelValidator(label string) error {
	if kc == nil {
		return ErrNilReceiver{}
	}
	if kc.validators == nil {
		return ErrNoValidatorExist{}
	}
	if _, exists := kc.validators[label]; exists {
		kc.order = slices.DeleteFunc(kc.order, func(id string) bool {
			return id == label
		})
	}
	kc.validators.Del(label)
	return nil
}

// GetValidator retrieves a validator function by its label. It returns
// the status, the function and a nil error if found, otherwise zero
// Status, nil function, and nil error (for compatibility with previous behaviour).
func (kc *keyChain[T]) GetValidator(id string) (Status, func(a T) (bool, error), error) {
	if kc == nil {
		return Status{}, nil, ErrNilReceiver{}
	}
	if kc.validators == nil {
		return Status{}, nil, ErrNoValidatorExist{}
	}
	status, fn := kc.validators.Get(id)
	return status, fn, nil
}

// SetValidator adds or updates a validator function for a given status.
// It also maintains the order in which validators were added.
func (kc *keyChain[T]) SetValidator(status Status, fn func(a T) (bool, error)) error {
	if kc == nil {
		return ErrNilReceiver{}
	}
	if kc.validators == nil {
		kc.validators = validatorsMap[T]{}
	}
	if _, exists := kc.validators[status.ID]; !exists {
		kc.order = append(kc.order, status.ID)
	}
	kc.validators.Set(status, fn)
	return nil
}

// SetCondition updates the bitwise condition (e.g., AND, OR) that
// governs the overall validation logic.
func (kc *keyChain[T]) SetCondition(condition BitwiseID) error {
	if kc == nil {
		return ErrNilReceiver{}
	}
	if !condition.IsValid() {
		return ErrInvalidBitwiseID(condition)
	}
	kc.condition = condition
	return nil
}

// Validate processes the given data against all registered validators according
// to the set bitwise condition (NOT, AND, OR, XOR). It returns the resulting
// Status, a boolean indicating overall success, and a slice of any errors
// encountered.
func (kc *keyChain[T]) Validate(data T, defaultStatus StatusGetter) (StatusGetter, bool, []error) {
	if kc == nil {
		return nil, false, []error{ErrNilReceiver{}}
	}
	if kc.validators == nil {
		return defaultStatus, false, nil
	}
	var (
		ok   bool
		lbl  Status
		err  error
		errs []error
	)
	switch kc.condition {
	case NOT:
		for _, id := range kc.order {
			status, fn := kc.validators.Get(id)
			if fn == nil {
				continue
			}
			if ok, _ = fn(data); !ok {
				lbl = status
				continue
			}
			return defaultStatus, false, errs
		}
		return &lbl, true, nil
	case AND:
		for _, id := range kc.order {
			status, fn := kc.validators.Get(id)
			if fn == nil {
				continue
			}
			ok, err = fn(data)
			if !ok {
				if err != nil {
					errs = append(errs, err)
				}
				return defaultStatus, false, errs
			}
			lbl = status
		}
		return &lbl, ok, nil
	case OR:
		for _, id := range kc.order {
			status, fn := kc.validators.Get(id)
			if fn == nil {
				continue
			}
			ok, err = fn(data)
			if ok {
				return &status, true, nil
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		return defaultStatus, false, errs
	case XOR:
		var trueCount uint
		for _, id := range kc.order {
			status, fn := kc.validators.Get(id)
			if fn == nil {
				continue
			}
			ok, err = fn(data)
			if ok {
				trueCount++
				if trueCount > 1 {
					return defaultStatus, false, nil
				}
				lbl = status
			} else if err != nil {
				errs = append(errs, err)
			}
		}
		if trueCount == 1 {
			return &lbl, true, nil
		}
		return defaultStatus, false, errs
	}
	return defaultStatus, false, nil
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
