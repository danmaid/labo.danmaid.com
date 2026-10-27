package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Endpoint struct {
	Type  string         `yaml:"type"`
	Extra map[string]any `yaml:",inline"`
}

type Config struct {
	Endpoints  map[string]Endpoint `yaml:"endpoints"`
	Topologies map[string]Topology `yaml:",inline"`
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseYAML(data)
}

func ParseYAML(data []byte) (Config, error) {
	cfg := Config{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
