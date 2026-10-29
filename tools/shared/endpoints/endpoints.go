package endpoints

import (
	"io"
)

type Endpoint interface {
	DataEndpoint
}
type DataEndpoint interface {
	io.ReadWriter
}

func Resolve(typ string, cfg map[string]any) (DataEndpoint, error) {
	if typ == "file" {
		return ResolveFileEndpoint(cfg)
	}
	return nil, nil
}
