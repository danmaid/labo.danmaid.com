package endpoints

import (
	"os"
	"sync"
)

type FileEndpoint struct {
	Config map[string]any
	Path   string
	File   *os.File
}

var mu sync.Mutex
var fileEndpoints = make(map[string]*FileEndpoint)

func ResolveFileEndpoint(cfg map[string]any) (*FileEndpoint, error) {
	path, _ := cfg["path"].(string)
	mu.Lock()
	defer mu.Unlock()
	if fe, ok := fileEndpoints[path]; ok {
		return fe, nil
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	fe := &FileEndpoint{Config: cfg, Path: path, File: file}
	fileEndpoints[path] = fe
	return fe, nil
}

func ReleaseFileEndpoints(cfg map[string]any) error {
	path, _ := cfg["path"].(string)
	mu.Lock()
	defer mu.Unlock()
	if fe, ok := fileEndpoints[path]; ok {
		err := fe.File.Close()
		delete(fileEndpoints, path)
		return err
	}
	return nil
}

func (f *FileEndpoint) Read(p []byte) (int, error) {
	return f.File.Read(p)
}

func (f *FileEndpoint) Write(p []byte) (int, error) {
	return f.File.Write(p)
}
