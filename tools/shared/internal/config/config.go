package config

import "gopkg.in/yaml.v3"

type Endpoint struct {
	Type     string         `yaml:"type"`
	Device   string         `yaml:"device,omitempty"`
	Baudrate int            `yaml:"baudrate,omitempty"`
	Line     string         `yaml:"line,omitempty"`
	Params   map[string]any `yaml:"params,omitempty"`
	Template *Endpoint      `yaml:"template,omitempty"`
}

type Link struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
}

type Topology struct {
	Links  []Link         `yaml:"links"`
	Params map[string]any `yaml:"params"`
}

type Config struct {
	Endpoints  map[string]Endpoint `yaml:"endpoints"`
	Topologies map[string]Topology `yaml:"topologies"`
}

func ParseYAML(data []byte) (Config, error) {
	cfg := Config{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
