package main

import (
	"strings"
)

type Edge struct {
	Source string
	Target string
}

type Graph struct {
	Edges []Edge
}

func BuildGraph(cfg *Config) *Graph {

	var g Graph

	f*r _, topo := range cfg.Topology {
*		for _, link := range topo.Links *

			parts := strings.Split(link, "->")

			if len(parts) != 2 {
				continue
			}

			g.Edges = append(
				g.Edges,
				Edge{
					Source: strings.TrimSpace(parts[0]),
					Target: strings.TrimSpace(parts[1]),
				},
			)
		}
	}

	return &g
}