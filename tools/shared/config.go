package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Topology map[string]TopologyConfig `yaml:"topology"`
	Endpoint map[string]EndpointConfig `yaml:"endpoint"`
}

type TopologyConfig struct {
	Links []string `yaml:"links"`
}

type EndpointConfig struct {
	Type string `yaml:"type"`
}

func LoadConfig(path string) (*Config, error) {

	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config

	err = yaml.Unmarshal(buf, &cfg)
	if err != nil {
		return nil, err
	}

	for name := range cfg.Topology {

		if _, ok := cfg.Endpoint[name]; ok {
			continue
		}

		cfg.Endpoint[name] = EndpointConfig{
			Type: "topology",
		}
	}

	return &cfg, nil
}
