package keycheck

type (
	validatorKey[T any] struct {
		status    Status
		validator func(a T) (bool, error)
	}
	validatorsMap[T any] map[string]validatorKey[T]
)

func (m validatorsMap[T]) Get(id string) (Status, func(a T) (bool, error)) {
	if d, ok := m[id]; ok {
		return d.status, d.validator
	}
	return Status{}, nil
}

func (m validatorsMap[T]) Set(id Status, fn func(a T) (bool, error)) {
	m[id.ID] = validatorKey[T]{
		status:    id,
		validator: fn,
	}
}

func (m validatorsMap[T]) Del(id string) {
	delete(m, id)
}
