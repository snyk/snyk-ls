package initialize

import "sync"

type Initializer interface {
	Init()
}

type DelegatingInitializer struct {
	initializer []Initializer
	mutex       sync.Mutex
}

func NewDelegatingInitializer(initializer ...Initializer) Initializer {
	return &DelegatingInitializer{initializer: initializer}
}

func (i *DelegatingInitializer) Init() {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	for _, initializer := range i.initializer {
		initializer.Init()
	}
}
