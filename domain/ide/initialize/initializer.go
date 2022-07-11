package initialize

type Initializer interface {
	Init()
}

type DelegatingInitializer struct {
	initializer []Initializer
}

func NewDelegatingInitializer(initializer ...Initializer) Initializer {
	return &DelegatingInitializer{initializer: initializer}
}

func (i *DelegatingInitializer) Init() {
	for _, initializer := range i.initializer {
		initializer.Init()
	}
}
