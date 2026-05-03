package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Server struct {
	authStore     *AuthStore
	attachTokens  *AttachTokenStore
	sessions      *SessionManager
	sshAuth       SSHAuthenticator
	wsPublicBase  string
	wsUpgrader    websocket.Upgrader
	attachTokenTT time.Duration
}

type createSessionResponse struct {
	SessionID   string `json:"session_id"`
	WriterWSURL string `json:"writer_ws_url"`
}

type createAttachTokenRequest struct {
	Mode       string `json:"mode"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type createAttachTokenResponse struct {
	SessionID string `json:"session_id"`
	Mode      string `json:"mode"`
	WSURL     string `json:"ws_url"`
}

type resizeRequest struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/sessions", s.handleSessionsRoot)
	mux.HandleFunc("/sessions/", s.handleSessionActions)
	mux.HandleFunc("/ws/", s.handleWebSocketAttach)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSessionsRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	identity, ok := requireRESTIdentity(s.authStore, r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid auth token")
		return
	}

	var req SSHCreateParams
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	session, err := s.sessions.CreateSession(req, identity, s.sshAuth)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}

	attachToken, err := s.attachTokens.Issue(session.ID(), true, s.attachTokenTT)
	if err != nil {
		_ = s.sessions.Delete(session.ID())
		writeJSONError(w, http.StatusInternalServerError, "failed to issue attach token")
		return
	}

	writerURL := s.wsURL(session.ID(), attachToken)
	writeJSON(w, http.StatusCreated, createSessionResponse{
		SessionID:   session.ID(),
		WriterWSURL: writerURL,
	})
}

func (s *Server) handleSessionActions(w http.ResponseWriter, r *http.Request) {
	identity, ok := requireRESTIdentity(s.authStore, r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid auth token")
		return
	}

	sessionID, action, err := parseSessionActionPath(r.URL.Path)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	session, found := s.sessions.Get(sessionID)
	if !found {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	if session.Owner() != identity.Name {
		writeJSONError(w, http.StatusForbidden, "not allowed for this session")
		return
	}

	switch {
	case action == "" && r.Method == http.MethodDelete:
		s.handleDeleteSession(w, sessionID)
	case action == "attach-tokens" && r.Method == http.MethodPost:
		s.handleCreateAttachToken(w, r, sessionID)
	case action == "resize" && r.Method == http.MethodPost:
		s.handleResizeSession(w, r, session)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, sessionID string) {
	if err := s.sessions.Delete(sessionID); err != nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleCreateAttachToken(w http.ResponseWriter, r *http.Request, sessionID string) {
	var req createAttachTokenRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	writable := false
	switch mode {
	case "", "readonly":
		mode = "readonly"
	case "writer":
		mode = "writer"
		writable = true
	default:
		writeJSONError(w, http.StatusBadRequest, "mode must be readonly or writer")
		return
	}

	ttl := s.attachTokenTT
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl > 5*time.Minute {
			ttl = 5 * time.Minute
		}
	}

	token, err := s.attachTokens.Issue(sessionID, writable, ttl)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to issue attach token")
		return
	}

	writeJSON(w, http.StatusCreated, createAttachTokenResponse{
		SessionID: sessionID,
		Mode:      mode,
		WSURL:     s.wsURL(sessionID, token),
	})
}

func (s *Server) handleResizeSession(w http.ResponseWriter, r *http.Request, session *SSHSession) {
	var req resizeRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := session.Resize(req.Cols, req.Rows); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "resized"})
}

func (s *Server) handleWebSocketAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	sessionID, err := parseWebSocketPath(r.URL.Path)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	attachToken := strings.TrimSpace(r.URL.Query().Get("attach_token"))
	if attachToken == "" {
		writeJSONError(w, http.StatusUnauthorized, "attach_token is required")
		return
	}

	grant, err := s.attachTokens.Consume(attachToken, sessionID)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid attach token")
		return
	}

	session, found := s.sessions.Get(grant.SessionID)
	if !found {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}

	conn, err := s.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	client, err := session.RegisterClient(grant.Writable)
	if err != nil {
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "session closed"))
		return
	}
	defer session.UnregisterClient(client.ID)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case payload := <-client.Outbound:
				if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
					return
				}
			case <-session.Done():
				return
			}
		}
	}()

	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
			continue
		}
		if !client.Writable {
			continue
		}
		if err := session.WriteInput(payload); err != nil {
			break
		}
	}

	<-done
}

func (s *Server) wsURL(sessionID string, attachToken string) string {
	base := strings.TrimRight(s.wsPublicBase, "/")
	return fmt.Sprintf("%s/ws/%s?attach_token=%s", base, sessionID, attachToken)
}

func parseSessionActionPath(path string) (sessionID string, action string, err error) {
	rel := strings.TrimPrefix(path, "/sessions/")
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return "", "", errors.New("missing session id")
	}
	parts := strings.Split(rel, "/")
	if len(parts) > 2 {
		return "", "", errors.New("invalid path")
	}
	sessionID = parts[0]
	if sessionID == "" {
		return "", "", errors.New("invalid session id")
	}
	if len(parts) == 2 {
		action = parts[1]
	}
	return sessionID, action, nil
}

func parseWebSocketPath(path string) (string, error) {
	rel := strings.TrimPrefix(path, "/ws/")
	rel = strings.Trim(rel, "/")
	if rel == "" || strings.Contains(rel, "/") {
		return "", errors.New("invalid websocket path")
	}
	return rel, nil
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid json body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return errors.New("invalid json body: multiple JSON values")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write json response: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, map[string]string{"error": message})
}
