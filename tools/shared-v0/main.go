package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/coder/websocket"
)

func main() {
	http.HandleFunc("GET /serial/{ttyFile}", func(w http.ResponseWriter, r *http.Request) {
		// WebSocket
		conn, err := websocket.Accept(w, r, nil)
		if err == nil {
			ctx := r.Context()
			netConn := websocket.NetConn(ctx, conn, websocket.MessageBinary)
			file, _ := os.OpenFile("/dev/"+r.PathValue("ttyFile"), os.O_RDWR, 0)
			go io.Copy(file, netConn)
			io.Copy(netConn, file)
			return
		}

		// normal
		scheme := "ws"
		if r.TLS != nil {
			scheme = "wss"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			URL string `json:"url"`
		}{
			URL: scheme + "://" + r.Host + r.URL.Path,
		})
	})
	http.ListenAndServe(":6901", nil)
}
