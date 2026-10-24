package main

import (
	"fmt"

	endpoints "github.com/danmaid/labo.danmaid.com/tools/shared/endpoint"
)

type Runtime struct {
	cfg       *Config
	graph     *Graph
	endpoints map[string]endpoints.Endpoint
}

func NewRuntime(cfg *Config) (*Runtime, error) {

	r := &Runtime{
		cfg:       cfg,
		endpoints: map[string]endpoints.Endpoint{},
	}

	for name, ep := range cfg.Endpoint {

		switch ep.Type {

		case "serial":
			r.endpoints[name] =
				endpoints.NewSerial(name)

		case "websocket-listener":
			r.endpoints[name] =
				endpoints.NewWebsocket(name)

		case "topology":
			r.endpoints[name] =
				endpoints.NewTopology(name)

		default:
			return nil, fmt.Errorf(
				"unknown endpoint type %s",
				ep.Type,
			)
		}
	}

	r.graph = BuildGraph(cfg)

	return r, nil
}

func (r *Runtime) Start() error {

	for _, ep := range r.endpoints {

		err := ep.Attach(nil)
		if err != nil {
			return err
		}
	}

	return nil
}
