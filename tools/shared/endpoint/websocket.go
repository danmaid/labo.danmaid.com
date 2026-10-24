package endpoint

type Websocket struct {
	name string
}

func NewWebsocket(name string) *Websocket {
	return &Websocket{name: name}
}

func (w *Websocket) Name() string {
	return w.name
}

func (w *Websocket) Attach(ctx Context) error {
	return nil
}

func (w *Websocket) Close() error {
	return nil
}

func (w *Websocket) Subscribe(cb func(Message)) {
}
