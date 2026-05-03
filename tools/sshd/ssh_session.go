package main

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHCreateParams struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	PTYCols  int    `json:"pty_cols"`
	PTYRows  int    `json:"pty_rows"`
}

type SSHAuthenticator interface {
	AuthMethod(params SSHCreateParams) (ssh.AuthMethod, error)
}

type PasswordSSHAuthenticator struct{}

func (PasswordSSHAuthenticator) AuthMethod(params SSHCreateParams) (ssh.AuthMethod, error) {
	if params.Password == "" {
		return nil, errors.New("password is required")
	}
	return ssh.Password(params.Password), nil
}

type AttachClient struct {
	ID       string
	Writable bool
	Outbound chan []byte
}

type SSHSession struct {
	id    string
	owner string

	client *ssh.Client
	shell  *ssh.Session
	stdin  io.WriteCloser

	done      chan struct{}
	closeOnce sync.Once

	mu      sync.RWMutex
	writeMu sync.Mutex
	closed  bool
	clients map[string]*AttachClient
}

func NewSSHSession(id string, owner string, params SSHCreateParams, auth SSHAuthenticator) (*SSHSession, error) {
	if params.Host == "" {
		return nil, errors.New("host is required")
	}
	if params.Username == "" {
		return nil, errors.New("username is required")
	}
	if params.Port == 0 {
		params.Port = 22
	}

	authMethod, err := auth.AuthMethod(params)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            params.Username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", params.Host, params.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("ssh dial failed: %w", err)
	}

	shell, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to create ssh shell session: %w", err)
	}

	stdin, err := shell.StdinPipe()
	if err != nil {
		_ = shell.Close()
		_ = client.Close()
		return nil, fmt.Errorf("failed to open stdin pipe: %w", err)
	}
	stdout, err := shell.StdoutPipe()
	if err != nil {
		_ = shell.Close()
		_ = client.Close()
		return nil, fmt.Errorf("failed to open stdout pipe: %w", err)
	}
	stderr, err := shell.StderrPipe()
	if err != nil {
		_ = shell.Close()
		_ = client.Close()
		return nil, fmt.Errorf("failed to open stderr pipe: %w", err)
	}

	rows := params.PTYRows
	cols := params.PTYCols
	if rows <= 0 {
		rows = 24
	}
	if cols <= 0 {
		cols = 80
	}

	if err := shell.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		_ = shell.Close()
		_ = client.Close()
		return nil, fmt.Errorf("failed to request pty: %w", err)
	}
	if err := shell.Shell(); err != nil {
		_ = shell.Close()
		_ = client.Close()
		return nil, fmt.Errorf("failed to start shell: %w", err)
	}

	s := &SSHSession{
		id:      id,
		owner:   owner,
		client:  client,
		shell:   shell,
		stdin:   stdin,
		done:    make(chan struct{}),
		clients: make(map[string]*AttachClient),
	}

	go s.pumpOutput(stdout)
	go s.pumpOutput(stderr)
	go s.waitForShellExit()

	return s, nil
}

func (s *SSHSession) ID() string {
	return s.id
}

func (s *SSHSession) Owner() string {
	return s.owner
}

func (s *SSHSession) Done() <-chan struct{} {
	return s.done
}

func (s *SSHSession) RegisterClient(writable bool) (*AttachClient, error) {
	clientID, err := randomHex(6)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("session is closed")
	}

	client := &AttachClient{
		ID:       clientID,
		Writable: writable,
		Outbound: make(chan []byte, 128),
	}
	s.clients[clientID] = client
	return client, nil
}

func (s *SSHSession) UnregisterClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, clientID)
}

func (s *SSHSession) WriteInput(data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return errors.New("session is closed")
	}

	_, err := s.stdin.Write(data)
	return err
}

func (s *SSHSession) Resize(cols int, rows int) error {
	if cols <= 0 || rows <= 0 {
		return errors.New("cols and rows must be > 0")
	}

	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return errors.New("session is closed")
	}

	return s.shell.WindowChange(rows, cols)
}

func (s *SSHSession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.clients = make(map[string]*AttachClient)
		s.mu.Unlock()

		close(s.done)

		if err := s.shell.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		if err := s.client.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (s *SSHSession) waitForShellExit() {
	_ = s.shell.Wait()
	_ = s.Close()
}

func (s *SSHSession) pumpOutput(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			s.broadcast(chunk)
		}
		if err != nil {
			return
		}
	}
}

func (s *SSHSession) broadcast(data []byte) {
	s.mu.RLock()
	clients := make([]*AttachClient, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.RUnlock()

	for _, client := range clients {
		select {
		case client.Outbound <- data:
		default:
			// Keep the session healthy if one client is too slow.
		}
	}
}
