package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/endpoint"
	"github.com/danmaid/labo.danmaid.com/tools/shared/internal/runtime"
)

type Server struct {
	Runtime          *runtime.Runtime
	WebSocketFactory *endpoint.FactoryEndpoint
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool { return true },
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/ws/", s.handleWebSocket)
	mux.HandleFunc("/api/v1/endpoint/", s.handleEndpoint)
	mux.HandleFunc("/api/v1/topology/", s.handleTopology)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.WebSocketFactory == nil {
		writeError(w, http.StatusBadRequest, "websocket endpoint is not configured")
		return
	}
	parts := splitPath(r.URL.Path, "/api/v1/ws/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing websocket id")
		return
	}
	id := parts[0]

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.WebSocketFactory.RegisterWithID(id, endpoint.NewWebSocketConnEndpoint(conn))
}

func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path, "/api/v1/endpoint/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing endpoint name")
		return
	}
	name := parts[0]
	ep, ok := s.Runtime.Endpoints[name]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("endpoint %s not found", name))
		return
	}

	bodyParams := endpoint.Params{}
	if r.Body != nil {
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&bodyParams)
	}

	res, err := ep.Control(r.Context(), endpoint.ControlRequest{
		Method: r.Method,
		Path:   parts[1:],
		Params: bodyParams,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	parts := splitPath(r.URL.Path, "/api/v1/topology/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing topology name")
		return
	}
	name := parts[0]
	params := endpoint.Params{}
	if r.Body != nil {
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&params)
	}
	if err := s.Runtime.Connect(context.Background(), name, params); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"started": name})
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
