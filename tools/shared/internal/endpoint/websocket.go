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

type WebSocketFactoryEndpoint struct {
	Name     string
	Factory  *FactoryEndpoint
	BasePath string
	upgrader websocket.Upgrader
}

func NewWebSocketFactoryEndpoint(name string, factory *FactoryEndpoint, basePath string) *WebSocketFactoryEndpoint {
	if basePath == "" {
		basePath = "/api/v1/endpoint/"
	}
	return &WebSocketFactoryEndpoint{
		Name:     name,
		Factory:  factory,
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

func (w *WebSocketFactoryEndpoint) Resolve(ctx context.Context, p Params) (io.ReadWriteCloser, error) {
	if w.Factory == nil {
		return nil, fmt.Errorf("websocket endpoint is not configured")
	}
	return w.Factory.Resolve(ctx, p)
}

func (w *WebSocketFactoryEndpoint) Control(ctx context.Context, req ControlRequest) (any, error) {
	if w.Factory == nil {
		return nil, fmt.Errorf("websocket endpoint is not configured")
	}
	if len(req.Path) > 0 && req.Path[0] == "connect" {
		return w.handleConnect(req)
	}
	if req.Method == http.MethodPost && len(req.Path) == 0 {
		res, err := w.Factory.Control(ctx, req)
		if err != nil {
			return nil, err
		}
		m, ok := res.(map[string]any)
		if !ok {
			return res, nil
		}
		id, _ := m["id"].(string)
		if id != "" {
			m["ws_url"] = w.buildConnectURL(id)
		}
		return m, nil
	}
	return w.Factory.Control(ctx, req)
}

func (w *WebSocketFactoryEndpoint) handleConnect(req ControlRequest) (any, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("websocket connect only supports GET")
	}
	if len(req.Path) < 2 || req.Path[1] == "" {
		return nil, fmt.Errorf("missing websocket id")
	}
	id := req.Path[1]
	httpReq, _ := req.Params["__http_request"].(*http.Request)
	httpRes, _ := req.Params["__http_response"].(http.ResponseWriter)
	if httpReq == nil || httpRes == nil {
		return nil, fmt.Errorf("websocket connect requires http context")
	}

	conn, err := w.upgrader.Upgrade(httpRes, httpReq, nil)
	if err != nil {
		return nil, err
	}
	w.Factory.RegisterWithID(id, NewWebSocketConnEndpoint(conn))
	req.Params["__http_response_handled"] = true
	return map[string]any{"connected": id}, nil
}

func (w *WebSocketFactoryEndpoint) buildConnectURL(id string) string {
	base := strings.TrimRight(w.BasePath, "/")
	return fmt.Sprintf("%s/%s/connect/%s", base, w.Name, id)
}
