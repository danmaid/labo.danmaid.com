package main

import (
	"errors"
	"sync"
)

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SSHSession
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SSHSession),
	}
}

func (m *SessionManager) CreateSession(params SSHCreateParams, owner Identity, auth SSHAuthenticator) (*SSHSession, error) {
	sessionID, err := randomHex(8)
	if err != nil {
		return nil, err
	}

	session, err := NewSSHSession(sessionID, owner.Name, params, auth)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sessionID] = session
	return session, nil
}

func (m *SessionManager) Get(sessionID string) (*SSHSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, ok := m.sessions[sessionID]
	return session, ok
}

func (m *SessionManager) Delete(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[sessionID]
	if !ok {
		return errors.New("session not found")
	}
	delete(m.sessions, sessionID)
	return session.Close()
}
