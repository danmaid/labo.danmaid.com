package main

import (
	"flag"
	"io"
	"log"
	"net/http"

	"github.com/danmaid/labo.danmaid.com/tools/shared/endpoints"
)

type Server struct {
	Config     *Config
	Topologies map[string]Topology
}

func main() {
	configPath := flag.String("config", "examples/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	srv := &Server{
		Config:     &cfg,
		Topologies: cfg.Topologies,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.BasePath+"/endpoints/{name}", srv.handleEndpoints)
	for name, topo := range srv.Topologies {
		mux.HandleFunc(cfg.BasePath+"/"+name, topo.httpHandler)
	}

	log.Printf("shared listening on %s", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		log.Fatal(err)
	}
}

func (t *Topology) httpHandler(w http.ResponseWriter, r *http.Request) {
	// Handle topology logic here
}

func (s *Server) Connect(t *Topology) error {
	for _, link := range t.Links {
		src := s.ResolveEndpoint(link.Source)
		dst := s.ResolveEndpoint(link.Destination)

		go func(s io.Reader, d io.Writer) {
			_, _ = io.Copy(d, s)
		}(src, dst)
	}

	return nil
}

func (s *Server) ResolveEndpoint(name string) endpoints.Endpoint {
	cfg, ok := s.Config.Endpoints[name]
	if !ok {
		return nil
	}
	ep, err := endpoints.Resolve(cfg.Type, cfg.Extra)
	if err != nil {
		log.Printf("resolve endpoint %s: %v", name, err)
		return nil
	}
	return ep
}
