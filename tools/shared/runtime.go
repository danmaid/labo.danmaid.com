package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/endpoint"
)

type Link struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
}

type Topology struct {
	Links  []Link         `yaml:"links"`
	Params map[string]any `yaml:"params"`
}

type Runtime struct {
	Endpoints  map[string]endpoint.Endpoint
	Topologies map[string]Topology
}

func (r *Runtime) Endpoint(name string) (endpoint.Endpoint, bool) {
	ep, ok := r.Endpoints[name]
	return ep, ok
}

func (r *Runtime) ControlTopology(ctx context.Context, method string, name string, params endpoint.Params) (any, error) {
	if !strings.EqualFold(method, "POST") {
		return nil, fmt.Errorf("topology %s only supports POST", name)
	}
	if _, ok := r.Topologies[name]; !ok {
		return nil, fmt.Errorf("topology %s not found", name)
	}
	if err := r.Connect(ctx, name, params); err != nil {
		return nil, err
	}
	return map[string]any{"started": name}, nil
}

func (r *Runtime) Connect(ctx context.Context, topologyName string, params endpoint.Params) error {
	t, ok := r.Topologies[topologyName]
	if !ok {
		return fmt.Errorf("topology %s not found", topologyName)
	}

	for _, link := range t.Links {
		src, ok := r.Endpoints[link.Source]
		if !ok {
			return fmt.Errorf("source endpoint %s not found", link.Source)
		}
		dst, ok := r.Endpoints[link.Destination]
		if !ok {
			return fmt.Errorf("destination endpoint %s not found", link.Destination)
		}

		srcRWC, err := src.Resolve(ctx, params)
		if err != nil {
			return err
		}
		dstRWC, err := dst.Resolve(ctx, params)
		if err != nil {
			_ = srcRWC.Close()
			return err
		}

		go func(s io.ReadWriteCloser, d io.ReadWriteCloser) {
			_, _ = io.Copy(d, s)
		}(srcRWC, dstRWC)
	}

	return nil
}
