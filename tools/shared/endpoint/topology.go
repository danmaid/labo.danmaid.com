package endpoint

type Topology struct {
	name string
}

func NewTopology(name string) *Topology {
	return &Topology{name: name}
}

func (t *Topology) Name() string {
	return t.name
}

func (t *Topology) Attach(ctx Context) error {
	return nil
}

func (t *Topology) Close() error {
	return nil
}

func (t *Topology) Subscribe(cb func(Message)) {
}
