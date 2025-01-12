package keycheck

type validatorsMap[T any] map[ID]func(a T) (bool, error)

func (m validatorsMap[T]) Get(name ID) func(a T) (bool, error) {
	return m[name]
}

func (m validatorsMap[T]) Set(name ID, fn func(a T) (bool, error)) {
	m[name] = fn
}

func (m validatorsMap[T]) Del(name ID) {
	delete(m, name)
}
