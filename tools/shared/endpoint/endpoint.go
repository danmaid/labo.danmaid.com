package endpoint

type Context map[string]any

type Message struct {
	Data []byte
}

type Link struct {
	Source string
	Target string
}

type Endpoint interface {
	Name() string

	// Runtimeが接続する
	Attach(ctx Context) error

	// 終了
	Close() error

	// 受信購読
	Subscribe(func(Message))
}
