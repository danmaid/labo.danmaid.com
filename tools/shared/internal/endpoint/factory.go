package endpoint

import (
	"context"
	"fmt"
	"io"
	"strings"
)

type Builder func(ctx context.Context, params Params) (Endpoint, error)

type FactoryEndpoint struct {
	Name     string
	Registry *Registry
	Build    Builder
}

func (f *FactoryEndpoint) Resolve(ctx context.Context, p Params) (io.ReadWriteCloser, error) {
	id, _ := p[f.Name+"-id"].(string)
	if id == "" {
		id, _ = p["id"].(string)
	}
	if id == "" {
		ids := f.Registry.List(f.Name)
		if len(ids) > 0 {
			id = ids[len(ids)-1]
		} else {
			if f.Build == nil {
				return nil, fmt.Errorf("missing %s-id", f.Name)
			}
			ep, err := f.Build(ctx, p)
			if err != nil {
				return nil, err
			}
			id = f.Registry.Register(f.Name, ep)
		}
	}
	ep, ok := f.Registry.Get(f.Name, id)
	if !ok {
		return nil, fmt.Errorf("factory resource %s not found", id)
	}
	return ep.Resolve(ctx, p)
}

func (f *FactoryEndpoint) RegisterWithID(id string, ep Endpoint) {
	f.Registry.RegisterWithID(f.Name, id, ep)
}

func (f *FactoryEndpoint) Control(ctx context.Context, req ControlRequest) (any, error) {
	method := strings.ToUpper(req.Method)
	switch method {
	case "POST":
		if f.Build == nil {
			return nil, fmt.Errorf("factory endpoint %s does not support POST", f.Name)
		}
		ep, err := f.Build(ctx, req.Params)
		if err != nil {
			return nil, err
		}
		id := f.Registry.Register(f.Name, ep)
		return map[string]any{"id": id}, nil
	case "GET":
		if len(req.Path) == 0 {
			return map[string]any{"ids": f.Registry.List(f.Name)}, nil
		}
		id := req.Path[0]
		ep, ok := f.Registry.Get(f.Name, id)
		if !ok {
			return nil, fmt.Errorf("factory resource %s not found", id)
		}
		return ep.Control(ctx, ControlRequest{Method: "GET", Path: req.Path[1:], Params: req.Params})
	case "DELETE":
		if len(req.Path) < 1 {
			return nil, fmt.Errorf("missing id")
		}
		id := req.Path[0]
		ep, ok := f.Registry.Get(f.Name, id)
		if !ok {
			return nil, fmt.Errorf("factory resource %s not found", id)
		}
		if closer, ok := ep.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		if !f.Registry.Delete(f.Name, id) {
			return nil, fmt.Errorf("factory resource %s not found", id)
		}
		return map[string]any{"deleted": id}, nil
	default:
		return nil, fmt.Errorf("factory endpoint does not support method %s", req.Method)
	}
}
