package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	var (
		listenAddr     string
		wsPublicBase   string
		defaultAuth    string
		attachTokenTTL time.Duration
	)

	flag.StringVar(&listenAddr, "listen", ":8080", "HTTP listen address")
	flag.StringVar(&wsPublicBase, "ws-public-base", "ws://localhost:8080", "Public base URL used to build websocket attach URLs")
	flag.StringVar(&defaultAuth, "auth-token", "dev-token", "Bootstrap REST auth token")
	flag.DurationVar(&attachTokenTTL, "attach-token-ttl", 90*time.Second, "Default attach token TTL")
	flag.Parse()

	authStore := NewAuthStore()
	authStore.AddToken(defaultAuth, Identity{Name: "bootstrap-user"})

	if extraToken := strings.TrimSpace(os.Getenv("SSHD_BOOTSTRAP_TOKEN")); extraToken != "" {
		authStore.AddToken(extraToken, Identity{Name: "env-user"})
	}

	server := &Server{
		authStore:     authStore,
		attachTokens:  NewAttachTokenStore(),
		sessions:      NewSessionManager(),
		sshAuth:       PasswordSSHAuthenticator{},
		wsPublicBase:  wsPublicBase,
		attachTokenTT: attachTokenTTL,
		wsUpgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				// In MVP we keep origin validation simple and leave hardening for later.
				return true
			},
		},
	}

	mux := http.NewServeMux()
	server.registerRoutes(mux)
	mux.Handle("/", http.FileServer(http.Dir(".")))

	log.Printf("listening on %s", listenAddr)
	log.Printf("bootstrap REST auth token: %s", defaultAuth)
	log.Fatal(http.ListenAndServe(listenAddr, logRequest(mux)))
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
