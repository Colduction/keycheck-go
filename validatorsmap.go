package keycheck

type (
	validatorEntry[T any] struct {
		id        string
		status    Status
		validator func(a T) (bool, error)
	}
	validatorsMap[T any] struct {
		entries []validatorEntry[T]
		index   map[string]int
	}
)

func (vm validatorsMap[T]) Get(id string) (Status, func(a T) (bool, error), bool) {
	if vm.index == nil {
		return Status{}, nil, false
	}
	i, ok := vm.index[id]
	if !ok {
		return Status{}, nil, false
	}
	d := vm.entries[i]
	return d.status, d.validator, true
}

func (vm *validatorsMap[T]) Set(status Status, fn func(a T) (bool, error)) {
	if vm.index == nil {
		vm.index = map[string]int{}
	}
	if i, ok := vm.index[status.ID]; ok {
		vm.entries[i].id = status.ID
		vm.entries[i].status = status
		vm.entries[i].validator = fn
		return
	}
	vm.entries = append(vm.entries, validatorEntry[T]{
		id:        status.ID,
		status:    status,
		validator: fn,
	})
	vm.index[status.ID] = len(vm.entries) - 1
}

func (vm *validatorsMap[T]) Del(id string) bool {
	if vm.index == nil {
		return false
	}
	i, ok := vm.index[id]
	if !ok {
		return false
	}
	delete(vm.index, id)
	last := len(vm.entries) - 1
	copy(vm.entries[i:], vm.entries[i+1:])
	vm.entries[last] = validatorEntry[T]{}
	vm.entries = vm.entries[:last]
	for j := i; j < len(vm.entries); j++ {
		vm.index[vm.entries[j].id] = j
	}
	return true
}
