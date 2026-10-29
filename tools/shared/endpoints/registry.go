package endpoints

import (
	"fmt"
	"sort"
	"sync"
)

type Registry struct {
	mu     sync.RWMutex
	items  map[string]DataEndpoint
	names  map[string]string
	counts map[string]int
}

func NewRegistry() *Registry {
	return &Registry{
		items:  make(map[string]DataEndpoint),
		names:  make(map[string]string),
		counts: make(map[string]int),
	}
}

func (r *Registry) Register(name string, ep DataEndpoint) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.counts[name]++
	id := fmt.Sprintf("%s-%d", name, r.counts[name])
	r.items[id] = ep
	r.names[id] = name
	return id
}

func (r *Registry) ReserveID(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.counts[name]++
	return fmt.Sprintf("%s-%d", name, r.counts[name])
}

func (r *Registry) RegisterWithID(name, id string, ep DataEndpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[id] = ep
	r.names[id] = name
}

func (r *Registry) Get(name, id string) (DataEndpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ep, ok := r.items[id]
	if !ok {
		return nil, false
	}
	if r.names[id] != name {
		return nil, false
	}
	return ep, true
}

func (r *Registry) Delete(name, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[id]; !ok {
		return false
	}
	if r.names[id] != name {
		return false
	}
	delete(r.items, id)
	delete(r.names, id)
	return true
}

func (r *Registry) List(name string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0)
	for id, n := range r.names {
		if n == name {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
