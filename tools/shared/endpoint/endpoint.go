package endpoint

import (
	"context"
	"io"
)

type Params map[string]any

type ControlRequest struct {
	Method string
	Path   []string
	Params Params
}

type Endpoint interface {
	Resolve(context.Context, Params) (io.ReadWriteCloser, error)
	Control(context.Context, ControlRequest) (any, error)
}
