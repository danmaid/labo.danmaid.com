package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

func TestPTY(t *testing.T) {
	p, err := pty.New()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	cmd := p.Command("cmd.exe")

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
}

type createSessionResponse struct {
	ID string `json:"id"`
}

func TestSessionIDFromPath(t *testing.T) {
	id, action, ok := sessionIDFromPath(
		"/sessions/abc/resize",
	)

	if !ok {
		t.Fatal()
	}

	if id != "abc" {
		t.Fatal(id)
	}

	if action != "resize" {
		t.Fatal(action)
	}
}

func TestCreateSessionBadJSON(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	resp, err := http.Post(
		srv.URL+"/sessions",
		"application/json",
		strings.NewReader("{"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf(
			"status=%d",
			resp.StatusCode,
		)
	}
}

func TestSSHGatewayE2E(t *testing.T) {
	port := uint16(22222)
	startTestSSHServer(t, port)

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	body, err := json.Marshal(CreateSessionRequest{
		Host: "127.0.0.1",
		Port: port,
		User: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(srv.URL+"/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp.Status)

	var session createSessionResponse

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))

	if err := json.Unmarshal(raw, &session); err != nil {
		t.Fatal(err)
	}

	if session.ID == "" {
		t.Fatal("empty session id")
	}

	wsURL :=
		"ws" +
			strings.TrimPrefix(
				srv.URL,
				"http",
			) +
			"/sessions/" +
			session.ID +
			"/stream"

	conn, _, err :=
		websocket.DefaultDialer.Dial(
			wsURL,
			nil,
		)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(
		time.Now().Add(
			20 * time.Second,
		),
	)

	//
	// password
	//

	foundPassword := false

	for i := 0; i < 20; i++ {

		_, msg, err :=
			conn.ReadMessage()

		if err != nil {
			t.Fatal(err)
		}

		text := string(msg)

		if strings.Contains(
			strings.ToLower(text),
			"password",
		) {

			foundPassword = true

			err = conn.WriteMessage(
				websocket.BinaryMessage,
				[]byte("test\n"),
			)
			if err != nil {
				t.Fatal(err)
			}

			break
		}
	}

	if !foundPassword {
		t.Fatal(
			"password prompt not found",
		)
	}

	//
	// hello
	//

	err = conn.WriteMessage(
		websocket.BinaryMessage,
		[]byte("hello\n"),
	)
	if err != nil {
		t.Fatal(err)
	}

	foundHello := false

	for i := 0; i < 20; i++ {

		_, msg, err :=
			conn.ReadMessage()

		if err != nil {
			t.Fatal(err)
		}

		if strings.Contains(
			string(msg),
			"hello",
		) {

			foundHello = true
			break
		}
	}

	if !foundHello {
		t.Fatal(
			"hello not returned",
		)
	}

	//
	// resize
	//

	resp2, err := http.Post(
		srv.URL+
			"/sessions/"+
			session.ID+
			"/resize",
		"application/json",
		strings.NewReader(
			`{
				"cols":120,
				"rows":40
			}`,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp2.StatusCode !=
		http.StatusNoContent {

		t.Fatalf(
			"resize status=%d",
			resp2.StatusCode,
		)
	}

	//
	// delete
	//

	req, err := http.NewRequest(
		http.MethodDelete,
		srv.URL+
			"/sessions/"+
			session.ID,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	resp3, err :=
		http.DefaultClient.Do(req)

	if err != nil {
		t.Fatal(err)
	}

	if resp3.StatusCode !=
		http.StatusNoContent {

		t.Fatalf(
			"delete status=%d",
			resp3.StatusCode,
		)
	}
}

func startTestSSHServer(
	t *testing.T,
	port uint16,
) {

	t.Helper()

	key, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatal(err)
	}

	signer, err :=
		ssh.NewSignerFromKey(key)

	if err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(
			c ssh.ConnMetadata,
			pass []byte,
		) (
			*ssh.Permissions,
			error,
		) {

			if c.User() == "test" &&
				string(pass) == "test" {

				return nil, nil
			}

			return nil,
				fmt.Errorf(
					"bad credential",
				)
		},
	}

	cfg.AddHostKey(signer)

	addr := fmt.Sprintf(
		"127.0.0.1:%d",
		port,
	)

	ln, err := net.Listen(
		"tcp",
		addr,
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = ln.Close()
	})

	go func() {

		for {

			conn, err :=
				ln.Accept()

			if err != nil {
				return
			}

			go handleSSHConn(
				conn,
				cfg,
			)
		}
	}()

	time.Sleep(
		500 * time.Millisecond,
	)
}

func handleSSHConn(conn net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}

	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		log.Printf("channel type=%s", ch.ChannelType())

		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}

		channel, requests, err := ch.Accept()

		if err != nil {
			continue
		}

		go func() {
			for req := range requests {
				log.Printf("request type=%s", req.Type)

				switch req.Type {
				case "pty-req":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					_, _ = channel.Write([]byte("Welcome\r\n"))
				case "window-change":
					_ = req.Reply(true, nil)
				default:
					_ = req.Reply(true, nil)
				}
			}
		}()

		go func() {

			defer channel.Close()

			buf := make(
				[]byte,
				4096,
			)

			for {

				n, err :=
					channel.Read(
						buf,
					)

				if err != nil {
					return
				}

				_, err =
					channel.Write(
						buf[:n],
					)

				if err != nil {
					return
				}
			}
		}()
	}
}
