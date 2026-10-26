package endpoint

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type websocketSession struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *websocketSession) Read(p []byte) (int, error) {
	for {
		msgType, msg, err := s.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
			continue
		}
		n := copy(p, msg)
		if n < len(msg) {
			return n, io.ErrShortBuffer
		}
		return n, nil
	}
}

func (s *websocketSession) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *websocketSession) Close() error {
	return s.conn.Close()
}

type WebSocketConnEndpoint struct {
	session *websocketSession
}

type WebSocketEndpoint struct {
	Name     string
	ID       string
	BasePath string
	session  *websocketSession
	upgrader websocket.Upgrader
}

func NewWebSocketEndpoint(name, id, basePath string) *WebSocketEndpoint {
	if basePath == "" {
		basePath = "/api/v1/endpoint/"
	}
	return &WebSocketEndpoint{
		Name:     name,
		ID:       id,
		BasePath: basePath,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool { return true },
		},
	}
}

func NewWebSocketConnEndpoint(conn *websocket.Conn) *WebSocketConnEndpoint {
	return &WebSocketConnEndpoint{session: &websocketSession{conn: conn}}
}

func (w *WebSocketConnEndpoint) Resolve(_ context.Context, _ Params) (io.ReadWriteCloser, error) {
	return w.session, nil
}

func (w *WebSocketConnEndpoint) Control(_ context.Context, _ ControlRequest) (any, error) {
	return map[string]any{"type": "websocket", "connected": true}, nil
}

func (w *WebSocketConnEndpoint) Close() error {
	return w.session.Close()
}

func (w *WebSocketEndpoint) Resolve(_ context.Context, _ Params) (io.ReadWriteCloser, error) {
	if w.session == nil {
		return nil, fmt.Errorf("websocket %s is not connected", w.ID)
	}
	return w.session, nil
}

func (w *WebSocketEndpoint) Control(_ context.Context, req ControlRequest) (any, error) {
	if len(req.Path) > 0 && req.Path[0] == "connect" {
		return w.handleConnect(req)
	}
	if req.Method == http.MethodGet && len(req.Path) == 0 {
		return map[string]any{"id": w.ID, "ws_url": w.buildConnectURL(), "connected": w.session != nil}, nil
	}
	return nil, fmt.Errorf("websocket endpoint does not support method %s", req.Method)
}

func (w *WebSocketEndpoint) handleConnect(req ControlRequest) (any, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("websocket connect only supports GET")
	}
	if len(req.Path) > 1 && req.Path[1] != w.ID {
		return nil, fmt.Errorf("websocket id mismatch")
	}
	httpReq, _ := req.Params["__http_request"].(*http.Request)
	httpRes, _ := req.Params["__http_response"].(http.ResponseWriter)
	if httpReq == nil || httpRes == nil {
		return nil, fmt.Errorf("websocket connect requires http context")
	}

	conn, err := w.upgrader.Upgrade(httpRes, httpReq, nil)
	if err != nil {
		return nil, err
	}
	w.session = &websocketSession{conn: conn}
	req.Params["__http_response_handled"] = true
	return map[string]any{"connected": w.ID}, nil
}

func (w *WebSocketEndpoint) buildConnectURL() string {
	base := strings.TrimRight(w.BasePath, "/")
	return fmt.Sprintf("%s/%s/%s/connect", base, w.Name, w.ID)
}
