package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type SerialEndpoint struct {
	Name     string
	Device   string
	Baudrate int
}

type serialDevice struct {
	Device  string `json:"device"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Path    string `json:"path"`
}

func (s *SerialEndpoint) Resolve(_ context.Context, _ Params) (io.ReadWriteCloser, error) {
	if s.Device == "" {
		return nil, fmt.Errorf("serial device is empty")
	}
	return os.OpenFile(s.Device, os.O_RDWR, 0)
}

func (s *SerialEndpoint) Control(_ context.Context, req ControlRequest) (any, error) {
	if strings.EqualFold(req.Method, "GET") {
		if len(req.Path) == 0 {
			return s.listDevices(), nil
		}
		return map[string]any{"type": "serial", "name": s.Name, "device": s.Device, "baudrate": s.Baudrate}, nil
	}
	return nil, fmt.Errorf("serial endpoint does not support method %s", req.Method)
}

func (s *SerialEndpoint) listDevices() []serialDevice {
	cmd := exec.Command("udevadm", "info", "--export-db")
	out, err := cmd.Output()
	if err != nil {
		return []serialDevice{{Device: s.Device, Vendor: "", Product: "", Path: ""}}
	}

	devices := make([]serialDevice, 0)
	blocks := strings.Split(string(out), "\n\n")
	for _, block := range blocks {
		if !strings.Contains(block, "/dev/tty") {
			continue
		}
		lines := strings.Split(block, "\n")
		entry := serialDevice{}
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			switch {
			case strings.HasPrefix(ln, "N: "):
				node := strings.TrimPrefix(ln, "N: ")
				if strings.HasPrefix(node, "tty") {
					entry.Device = "/dev/" + node
				}
			case strings.HasPrefix(ln, "E: ID_VENDOR="):
				entry.Vendor = strings.TrimPrefix(ln, "E: ID_VENDOR=")
			case strings.HasPrefix(ln, "E: ID_MODEL="):
				entry.Product = strings.TrimPrefix(ln, "E: ID_MODEL=")
			case strings.HasPrefix(ln, "P: "):
				entry.Path = strings.TrimPrefix(ln, "P: ")
			}
		}
		if entry.Device != "" {
			devices = append(devices, entry)
		}
	}
	if len(devices) == 0 && s.Device != "" {
		devices = append(devices, serialDevice{Device: s.Device})
	}
	return devices
}

func (s *SerialEndpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"type":     "serial",
		"name":     s.Name,
		"device":   s.Device,
		"baudrate": s.Baudrate,
	})
}
