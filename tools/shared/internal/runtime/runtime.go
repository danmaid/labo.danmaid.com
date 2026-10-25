package runtime

import (
	"context"
	"fmt"
	"io"

	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/endpoint"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/topology"
)

type Runtime struct {
	Endpoints  map[string]endpoint.Endpoint
	Topologies map[string]topology.Topology
}

func (r *Runtime) Connect(ctx context.Context, topologyName string, params endpoint.Params) error {
	t, ok := r.Topologies[topologyName]
	if !ok {
		return fmt.Errorf("topology %s not found", topologyName)
	}

	for _, link := range t.Links {
		src, ok := r.Endpoints[link.Source]
		if !ok {
			return fmt.Errorf("source endpoint %s not found", link.Source)
		}
		dst, ok := r.Endpoints[link.Destination]
		if !ok {
			return fmt.Errorf("destination endpoint %s not found", link.Destination)
		}

		srcRWC, err := src.Resolve(ctx, params)
		if err != nil {
			return err
		}
		dstRWC, err := dst.Resolve(ctx, params)
		if err != nil {
			_ = srcRWC.Close()
			return err
		}

		go func(s io.ReadWriteCloser, d io.ReadWriteCloser) {
			_, _ = io.Copy(d, s)
		}(srcRWC, dstRWC)
	}

	return nil
}
