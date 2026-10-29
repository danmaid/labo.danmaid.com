package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen     string              `yaml:"listen"`
	BasePath   string              `yaml:"basePath"`
	Topologies map[string]Topology `yaml:"topologies"`
	Endpoints  map[string]Endpoint `yaml:"endpoints"`
}

type Topology struct {
	Links  []Link         `yaml:"links"`
	Params map[string]any `yaml:"params"`
}
type Link struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
}
type Endpoint struct {
	Type  string         `yaml:"type"`
	Extra map[string]any `yaml:",inline"`
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err := ParseYAML(data)
	if err != nil {
		return Config{}, err
	}
	return setDefaults(cfg), nil
}

func ParseYAML(data []byte) (Config, error) {
	cfg := Config{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func setDefaults(cfg Config) Config {
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	return cfg
}
