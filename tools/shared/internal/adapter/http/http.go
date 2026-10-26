package httpadapter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/endpoint"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/runtime"
)

type Server struct {
	Runtime *runtime.Runtime
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/endpoint/", s.handleEndpoint)
	mux.HandleFunc("/api/v1/topology/", s.handleTopology)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path, "/api/v1/endpoint/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing endpoint name")
		return
	}
	name := parts[0]
	ep, ok := s.Runtime.Endpoint(name)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("endpoint %s not found", name))
		return
	}

	bodyParams := endpoint.Params{}
	if r.Body != nil {
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&bodyParams)
	}
	bodyParams["__http_request"] = r
	bodyParams["__http_response"] = w

	res, err := ep.Control(r.Context(), endpoint.ControlRequest{
		Method: r.Method,
		Path:   parts[1:],
		Params: bodyParams,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if handled, _ := bodyParams["__http_response_handled"].(bool); handled {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path, "/api/v1/topology/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing topology name")
		return
	}
	name := parts[0]
	bodyParams := endpoint.Params{}
	if r.Body != nil {
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&bodyParams)
	}
	bodyParams["__http_request"] = r
	bodyParams["__http_response"] = w

	res, err := s.Runtime.ControlTopology(r.Context(), r.Method, name, bodyParams)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func splitPath(path, prefix string) []string {
	trimmed := strings.TrimPrefix(path, prefix)
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
