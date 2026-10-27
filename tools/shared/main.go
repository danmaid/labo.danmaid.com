package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/danmaid/labo.danmaid.com/tools/shared/endpoint"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/runtime"
)

func main() {
	configPath := flag.String("config", "examples/config.yaml", "path to config file")
	listenAddr := flag.String("listen", ":8080", "listen address")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	topologies := map[string]Topology{}

	for name, epCfg := range cfg.Endpoints {
		ep, err := buildEndpoint(name, epCfg, registry)
		if err != nil {
			log.Fatalf("build endpoint %s: %v", name, err)
		}
		rt.Endpoints[name] = ep
	}

	for name, tp := range cfg.Topologies {
		links := make([]runtime.Link, 0, len(tp.Links))
		for _, l := range tp.Links {
			links = append(links, runtime.Link{Source: l.Source, Destination: l.Destination})
		}
		rt.Topologies[name] = runtime.Topology{Links: links, Params: tp.Params}
	}

	srv := &httpadapter.Server{Runtime: rt}
	log.Printf("shared listening on %s", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func buildEndpoint(name string, cfg config.Endpoint, registry *endpoint.Registry) (endpoint.Endpoint, error) {
	switch cfg.Type {
	case "exec":
		return &endpoint.ExecEndpoint{Name: name, Line: cfg.Line}, nil
	case "serial":
		return &endpoint.SerialEndpoint{Name: name, Device: cfg.Device, Baudrate: cfg.Baudrate}, nil
	case "factory":
		if cfg.Template == nil {
			return nil, errors.New("factory endpoint requires template")
		}
		builder := buildFactoryBuilder(name, cfg)
		factory := &endpoint.FactoryEndpoint{Name: name, Registry: registry, Build: builder}
		return factory, nil
	default:
		return nil, fmt.Errorf("unsupported endpoint type %s", cfg.Type)
	}
}

func buildFactoryBuilder(name string, cfg config.Endpoint) endpoint.Builder {
	tpl := *cfg.Template
	if tpl.Type == "websocket" {
		return func(_ context.Context, params endpoint.Params) (endpoint.Endpoint, error) {
			id, _ := params["id"].(string)
			return endpoint.NewWebSocketEndpoint(name, id, "/api/v1/endpoint/"), nil
		}
	}
	return func(ctx context.Context, params endpoint.Params) (endpoint.Endpoint, error) {
		merged := mergeParams(cfg.Params, params)
		switch tpl.Type {
		case "exec":
			line := renderTemplate(tpl.Line, merged)
			return &endpoint.ExecEndpoint{Name: name, Line: line}, nil
		case "serial":
			device := tpl.Device
			if v, ok := merged["device"].(string); ok && v != "" {
				device = v
			}
			baud := tpl.Baudrate
			if v, ok := merged["baudrate"].(int); ok && v > 0 {
				baud = v
			}
			return &endpoint.SerialEndpoint{Name: name, Device: device, Baudrate: baud}, nil
		default:
			return nil, fmt.Errorf("unsupported template type %s", tpl.Type)
		}
	}
}

func mergeParams(base map[string]any, override endpoint.Params) endpoint.Params {
	out := endpoint.Params{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func renderTemplate(input string, params endpoint.Params) string {
	result := input
	for k, v := range params {
		result = strings.ReplaceAll(result, "${"+k+"}", fmt.Sprint(v))
	}
	return result
}
