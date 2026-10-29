package main

import (
	"encoding/json"
	"net/http"

	"github.com/danmaid/labo.danmaid.com/tools/shared/endpoints"
)

type httpPayload struct {
	req *http.Request
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	ep := s.ResolveEndpoint(name)
	if ep == nil {
		http.NotFound(w, r)
		return
	}

	if h, ok := ep.(endpoints.HTTPControlEndpoint); ok {
		h.ServeHTTP(w, r)
		return
	}

	ctx := endpoints.HTTPContext{Request: r, Response: w}
	params := endpoints.HTTPParams(r.URL.Query())

	var result any
	var err error

	switch r.Method {
	case http.MethodGet:
		h, ok := ep.(endpoints.Getter)
		if !ok {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}
		result, err = h.Get(params, ctx)
	case http.MethodPost:
		h, ok := ep.(endpoints.Poster)
		if !ok {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}
		payload := &httpPayload{req: r}
		result, err = h.Post(payload, params, ctx)
	case http.MethodPut:
		h, ok := ep.(endpoints.Putter)
		if !ok {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}
		payload := &httpPayload{req: r}
		result, err = h.Put(payload, params, ctx)
	case http.MethodDelete:
		h, ok := ep.(endpoints.Deleter)
		if !ok {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}
		result, err = h.Delete(params, ctx)
	default:
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if result == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *httpPayload) Json() (any, error) {
	var result any
	err := json.NewDecoder(h.req.Body).Decode(&result)
	return result, err
}
