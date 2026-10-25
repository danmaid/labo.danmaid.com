package topology

type Link struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
}

type Topology struct {
	Links  []Link         `yaml:"links"`
	Params map[string]any `yaml:"params"`
}
