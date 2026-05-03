package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

var errInvalidAuthHeader = errors.New("invalid Authorization header")

type Identity struct {
	Name string `json:"name"`
}

type AuthStore struct {
	mu     sync.RWMutex
	tokens map[string]Identity
}

func NewAuthStore() *AuthStore {
	return &AuthStore{
		tokens: make(map[string]Identity),
	}
}

func (s *AuthStore) AddToken(token string, identity Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = identity
}

func (s *AuthStore) AuthenticateToken(token string) (Identity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	identity, ok := s.tokens[token]
	return identity, ok
}

func extractBearerToken(headerValue string) (string, error) {
	parts := strings.SplitN(headerValue, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errInvalidAuthHeader
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errInvalidAuthHeader
	}
	return token, nil
}

type AttachGrant struct {
	SessionID string
	Writable  bool
	ExpiresAt time.Time
}

type AttachTokenStore struct {
	mu     sync.Mutex
	grants map[string]AttachGrant
}

func NewAttachTokenStore() *AttachTokenStore {
	return &AttachTokenStore{
		grants: make(map[string]AttachGrant),
	}
}

func (s *AttachTokenStore) Issue(sessionID string, writable bool, ttl time.Duration) (string, error) {
	token, err := randomHex(24)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[token] = AttachGrant{
		SessionID: sessionID,
		Writable:  writable,
		ExpiresAt: time.Now().Add(ttl),
	}
	return token, nil
}

func (s *AttachTokenStore) Consume(token string, sessionID string) (AttachGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	grant, ok := s.grants[token]
	if !ok {
		return AttachGrant{}, errors.New("attach token not found")
	}
	if grant.SessionID != sessionID {
		delete(s.grants, token)
		return AttachGrant{}, errors.New("attach token does not match session")
	}
	if time.Now().After(grant.ExpiresAt) {
		delete(s.grants, token)
		return AttachGrant{}, errors.New("attach token expired")
	}

	delete(s.grants, token)
	return grant, nil
}

func requireRESTIdentity(authStore *AuthStore, r *http.Request) (Identity, bool) {
	token, err := extractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return Identity{}, false
	}
	identity, ok := authStore.AuthenticateToken(token)
	return identity, ok
}

func randomHex(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
