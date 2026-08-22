package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/aymanbagabas/go-pty"
	"github.com/gorilla/websocket"
)

func main() {
	mux := newMux()

	log.Printf("terminal-gateway listening on :6888")
	log.Fatal(http.ListenAndServe(":6888", withCORS(mux)))
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/sessions", createSessionHandler)
	mux.HandleFunc("/sessions/", sessionHandler)

	return mux
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		log.Printf("request origin=%s method=%s path=%s", origin, r.Method, r.URL.Path)
		if origin == "https://www.labo.danmaid.com" || origin == "http://127.0.0.1:5500" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func createSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req CreateSessionRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, err := NewSSHSession(req.Host, req.Port, req.User)
	if err != nil {
		log.Printf("NewSSHSession failed: %T %v", err, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id := registerSession(session)

	go func() {
		err := session.Wait()

		log.Printf(
			"session closed id=%s err=%v",
			id,
			err,
		)

		removeSession(id)

		_ = session.Close()
	}()

	writeJSON(w, map[string]string{
		"id": id,
	})
}

//
// Session Interfaces
//

type Session interface {
	io.ReadWriteCloser
}

type Resizable interface {
	Resize(cols, rows uint16) error
}

type Waitable interface {
	Wait() error
}

//
// SSH Session
//

type SSHSession struct {
	cmd    *pty.Cmd
	pty    pty.Pty
	cancel context.CancelFunc
}

func (s *SSHSession) Read(b []byte) (int, error) {
	return s.pty.Read(b)
}

func (s *SSHSession) Write(b []byte) (int, error) {
	return s.pty.Write(b)
}

func (s *SSHSession) Close() error {
	s.cancel()
	return s.pty.Close()
}

func NewSSHSession(host string, port uint16, user string) (*SSHSession, error) {
	ctx, cancel := context.WithCancel(context.Background())

	target := host

	if user != "" {
		target = user + "@" + host
	}

	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
	}

	if port > 0 {
		args = append(
			args,
			"-p",
			strconv.Itoa(int(port)),
		)
	}

	args = append(args, target)

	p, err := pty.New()
	if err != nil {
		return nil, err
	}

	cmd := p.CommandContext(ctx, "ssh", args...)
	log.Printf("cmd=%v", cmd.Args)
	if err := cmd.Start(); err != nil {
		p.Close()
		return nil, err
	}

	return &SSHSession{
		cmd:    cmd,
		pty:    p,
		cancel: cancel,
	}, nil
}

func (s *SSHSession) Resize(cols, rows uint16) error {
	return s.pty.Resize(
		int(cols),
		int(rows),
	)
}

func (s *SSHSession) Wait() error {
	return s.cmd.Wait()
}

//
// Session Registry
//

type SessionEntry struct {
	ID      string
	Session Session
}

var (
	sessionMu sync.RWMutex
	sessions  = map[string]*SessionEntry{}
)

func newSessionID() string {
	buf := make([]byte, 16)

	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	return hex.EncodeToString(buf)
}

func registerSession(session Session) string {
	id := newSessionID()

	sessionMu.Lock()
	defer sessionMu.Unlock()

	sessions[id] = &SessionEntry{
		ID:      id,
		Session: session,
	}

	return id
}

func getSession(id string) *SessionEntry {
	sessionMu.RLock()
	defer sessionMu.RUnlock()

	return sessions[id]
}

func removeSession(id string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	delete(sessions, id)
}

//
// HTTP Models
//

type CreateSessionRequest struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	User string `json:"user"`
}

type ResizeRequest struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

//
// WebSocket
//

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

//
// Helpers
//

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode error: %v", err)
	}
}

func sessionIDFromPath(path string) (string, string, bool) {
	path = strings.TrimPrefix(path, "/sessions/")

	if path == "" {
		return "", "", false
	}

	parts := strings.Split(path, "/")

	switch len(parts) {
	case 1:
		return parts[0], "", true

	case 2:
		return parts[0], parts[1], true

	default:
		return "", "", false
	}
}

//
// Handlers
//

func deleteSessionHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	entry := getSession(id)
	if entry == nil {
		http.NotFound(w, r)
		return
	}

	_ = entry.Session.Close()
	removeSession(id)

	w.WriteHeader(http.StatusNoContent)
}

func resizeSessionHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	entry := getSession(id)
	if entry == nil {
		http.NotFound(w, r)
		return
	}

	resizable, ok := entry.Session.(Resizable)
	if !ok {
		http.Error(
			w,
			"session is not resizable",
			http.StatusBadRequest,
		)
		return
	}

	var req ResizeRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := resizable.Resize(
		req.Cols,
		req.Rows,
	); err != nil {
		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func streamSessionHandler(w http.ResponseWriter, r *http.Request, id string) {
	entry := getSession(id)
	if entry == nil {
		http.NotFound(w, r)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	done := make(chan struct{})

	//
	// Session -> Browser
	//
	go func() {
		defer close(done)

		buf := make([]byte, 8192)

		for {
			n, err := entry.Session.Read(buf)
			if err != nil {
				return
			}

			if err := conn.WriteMessage(
				websocket.BinaryMessage,
				buf[:n],
			); err != nil {
				return
			}
		}
	}()

	//
	// Browser -> Session
	//
	for {
		select {
		case <-done:
			return

		default:
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}

			if _, err := entry.Session.Write(data); err != nil {
				return
			}
		}
	}
}

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	id, action, ok := sessionIDFromPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch action {
	case "":
		deleteSessionHandler(w, r, id)

	case "resize":
		resizeSessionHandler(w, r, id)

	case "stream":
		streamSessionHandler(w, r, id)

	default:
		http.NotFound(w, r)
	}
}
