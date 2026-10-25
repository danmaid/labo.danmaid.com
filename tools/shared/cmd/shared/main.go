package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/config"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/controlplane"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/endpoint"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/runtime"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/topology"
)

func main() {
	configPath := flag.String("config", "examples/config.yaml", "path to config file")
	listenAddr := flag.String("listen", ":8080", "listen address")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	registry := endpoint.NewRegistry()
	rt := &runtime.Runtime{
		Endpoints:  map[string]endpoint.Endpoint{},
		Topologies: map[string]topology.Topology{},
	}

	var websocketFactory *endpoint.FactoryEndpoint
	for name, epCfg := range cfg.Endpoints {
		ep, err := buildEndpoint(name, epCfg, registry)
		if err != nil {
			log.Fatalf("build endpoint %s: %v", name, err)
		}
		rt.Endpoints[name] = ep
		if f, ok := ep.(*endpoint.FactoryEndpoint); ok && epCfg.Template != nil && epCfg.Template.Type == "websocket" {
			websocketFactory = f
		}
	}

	for name, tp := range cfg.Topologies {
		links := make([]topology.Link, 0, len(tp.Links))
		for _, l := range tp.Links {
			links = append(links, topology.Link{Source: l.Source, Destination: l.Destination})
		}
		rt.Topologies[name] = topology.Topology{Links: links, Params: tp.Params}
	}

	srv := &controlplane.Server{Runtime: rt, WebSocketFactory: websocketFactory}
	log.Printf("shared listening on %s", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func loadConfig(path string) (config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config.Config{}, err
	}
	return config.ParseYAML(data)
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
		return &endpoint.FactoryEndpoint{Name: name, Registry: registry, Build: builder}, nil
	default:
		return nil, fmt.Errorf("unsupported endpoint type %s", cfg.Type)
	}
}

func buildFactoryBuilder(name string, cfg config.Endpoint) endpoint.Builder {
	tpl := *cfg.Template
	if tpl.Type == "websocket" {
		return func(context.Context, endpoint.Params) (endpoint.Endpoint, error) {
			return &discardEndpoint{}, nil
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

type discardEndpoint struct{}

func (d *discardEndpoint) Resolve(context.Context, endpoint.Params) (io.ReadWriteCloser, error) {
	return &discardRWC{}, nil
}

func (d *discardEndpoint) Control(context.Context, endpoint.ControlRequest) (any, error) {
	return map[string]any{"type": "discard"}, nil
}

type discardRWC struct{}

func (d *discardRWC) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (d *discardRWC) Write(p []byte) (int, error) {
	return len(p), nil
}

func (d *discardRWC) Close() error {
	return nil
}
