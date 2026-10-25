package endpoint

import (
	"context"
	"io"
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
