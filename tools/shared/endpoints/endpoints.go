package endpoints

import "io"

type Endpoint interface {
	io.ReadWriter
}

func Resolve(typ string, cfg map[string]any) (Endpoint, error) {
	if typ == "file" {
		return ResolveFileEndpoint(cfg)
	}
	return nil, nil
}
