package endpoint

import (
	"time"
)

type Serial struct {
	name string
}

func NewSerial(name string) *Serial {
	return &Serial{name: name}
}

func (s *Serial) Name() string {
	return s.name
}

func (s *Serial) Attach(ctx Context) error {
	return nil
}

func (s *Serial) Close() error {
	return nil
}

func (s *Serial) Subscribe(cb func(Message)) {
	go func() {
		for {
			time.Sleep(5 * time.Second)

			cb(Message{
				Data: []byte("serial message"),
			})
		}
	}()
}
