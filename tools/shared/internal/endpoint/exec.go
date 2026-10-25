package endpoint

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type ExecEndpoint struct {
	Name string
	Line string
}

type rwc struct {
	io.Reader
	io.Writer
	closeFn func() error
}

func (r *rwc) Close() error {
	if r.closeFn != nil {
		return r.closeFn()
	}
	return nil
}

func (e *ExecEndpoint) Resolve(ctx context.Context, _ Params) (io.ReadWriteCloser, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", e.Line)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &rwc{
		Reader: out,
		Writer: in,
		closeFn: func() error {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			return cmd.Wait()
		},
	}, nil
}

func (e *ExecEndpoint) Control(_ context.Context, req ControlRequest) (any, error) {
	if strings.EqualFold(req.Method, "GET") {
		return map[string]any{"type": "exec", "name": e.Name, "line": e.Line}, nil
	}
	return nil, fmt.Errorf("exec endpoint does not support method %s", req.Method)
}
