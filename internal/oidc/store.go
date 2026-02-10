package oidc

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrClientNotFound        = errors.New("client not found")
	ErrClientExists          = errors.New("client already exists")
	ErrInvalidClientSecret   = errors.New("invalid client secret")
	ErrClientInactive        = errors.New("client is inactive")
	ErrUnsupportedGrantType  = errors.New("client does not allow grant type")
	ErrConsentNotFound       = errors.New("consent not found")
	ErrAuthCodeNotFound      = errors.New("authorization code not found")
	ErrAuthCodeExpired       = errors.New("authorization code expired")
	ErrAuthCodeConsumed      = errors.New("authorization code already consumed")
	ErrRefreshTokenNotFound  = errors.New("refresh token not found")
	ErrRefreshTokenExpired   = errors.New("refresh token expired")
	ErrRefreshTokenRevoked   = errors.New("refresh token revoked")
	ErrRefreshTokenReplay    = errors.New("refresh token replay detected")
	ErrInvalidRedirectURI    = errors.New("invalid redirect uri")
	ErrInvalidRequestedScope = errors.New("invalid scope")
)

type Store interface {
	CreateClient(client OIDCClient, rawSecret string) (OIDCClient, string, error)
	GetClient(id string) (OIDCClient, error)
	ListClients() []OIDCClient
	UpdateClient(client OIDCClient) (OIDCClient, error)
	DeleteClient(id string) error
	ValidateClientSecret(clientID, rawSecret string) (OIDCClient, error)

	SaveAuthCode(record AuthCodeRecord) error
	ConsumeAuthCode(rawCode string, now time.Time) (AuthCodeRecord, error)

	SaveRefreshToken(record RefreshTokenRecord) error
	GetRefreshToken(rawToken string, now time.Time) (RefreshTokenRecord, error)
	RevokeRefreshToken(rawToken string, now time.Time) error
	RotateRefreshToken(oldRawToken string, newRecord RefreshTokenRecord, now time.Time) error

	SaveConsent(record ConsentRecord) error
	GetConsent(clientID, userID string) (ConsentRecord, error)
}

type InMemoryStore struct {
	mu            sync.RWMutex
	clients       map[string]OIDCClient
	authCodes     map[string]AuthCodeRecord
	refreshTokens map[string]RefreshTokenRecord
	consents      map[string]ConsentRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		clients:       make(map[string]OIDCClient),
		authCodes:     make(map[string]AuthCodeRecord),
		refreshTokens: make(map[string]RefreshTokenRecord),
		consents:      make(map[string]ConsentRecord),
	}
}

func (s *InMemoryStore) CreateClient(client OIDCClient, rawSecret string) (OIDCClient, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.clients[client.ID]; ok {
		return OIDCClient{}, "", ErrClientExists
	}
	now := time.Now().UTC()
	client.ID = strings.TrimSpace(client.ID)
	if client.ID == "" {
		randomID, err := randomURLSafe(24)
		if err != nil {
			return OIDCClient{}, "", err
		}
		client.ID = "cl_" + randomID
	}
	if rawSecret == "" {
		newSecret, err := randomURLSafe(32)
		if err != nil {
			return OIDCClient{}, "", err
		}
		rawSecret = newSecret
	}
	client.SecretHash = sha256Hex(rawSecret)
	client.Scopes = normalizeScopes(client.Scopes)
	client.RedirectURIs = normalizeScopes(client.RedirectURIs)
	client.GrantTypes = normalizeScopes(client.GrantTypes)
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = "client_secret_post"
	}
	if client.Status == "" {
		client.Status = "active"
	}
	client.CreatedAt = now
	client.UpdatedAt = now
	s.clients[client.ID] = client
	return client, rawSecret, nil
}

func (s *InMemoryStore) GetClient(id string) (OIDCClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[id]
	if !ok {
		return OIDCClient{}, ErrClientNotFound
	}
	return client, nil
}

func (s *InMemoryStore) ListClients() []OIDCClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]OIDCClient, 0, len(s.clients))
	for _, client := range s.clients {
		out = append(out, client)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *InMemoryStore) UpdateClient(client OIDCClient) (OIDCClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.clients[client.ID]
	if !ok {
		return OIDCClient{}, ErrClientNotFound
	}
	if client.Name != "" {
		current.Name = client.Name
	}
	if len(client.RedirectURIs) > 0 {
		current.RedirectURIs = normalizeScopes(client.RedirectURIs)
	}
	if len(client.Scopes) > 0 {
		current.Scopes = normalizeScopes(client.Scopes)
	}
	if len(client.GrantTypes) > 0 {
		current.GrantTypes = normalizeScopes(client.GrantTypes)
	}
	if client.TokenEndpointAuthMethod != "" {
		current.TokenEndpointAuthMethod = client.TokenEndpointAuthMethod
	}
	if client.Status != "" {
		current.Status = client.Status
	}
	current.FirstParty = client.FirstParty
	current.UpdatedAt = time.Now().UTC()
	s.clients[current.ID] = current
	return current, nil
}

func (s *InMemoryStore) DeleteClient(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		return ErrClientNotFound
	}
	delete(s.clients, id)
	return nil
}

func (s *InMemoryStore) ValidateClientSecret(clientID, rawSecret string) (OIDCClient, error) {
	client, err := s.GetClient(clientID)
	if err != nil {
		return OIDCClient{}, err
	}
	if !IsClientActive(client) {
		return OIDCClient{}, ErrClientInactive
	}
	if client.TokenEndpointAuthMethod == "none" {
		return client, nil
	}
	if rawSecret == "" {
		return OIDCClient{}, ErrInvalidClientSecret
	}
	if !constantTimeEquals(client.SecretHash, sha256Hex(rawSecret)) {
		return OIDCClient{}, ErrInvalidClientSecret
	}
	return client, nil
}

func (s *InMemoryStore) SaveAuthCode(record AuthCodeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[record.CodeHash] = record
	return nil
}

func (s *InMemoryStore) ConsumeAuthCode(rawCode string, now time.Time) (AuthCodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := sha256Hex(rawCode)
	record, ok := s.authCodes[hash]
	if !ok {
		return AuthCodeRecord{}, ErrAuthCodeNotFound
	}
	if record.ConsumedAt != nil {
		return AuthCodeRecord{}, ErrAuthCodeConsumed
	}
	if now.After(record.ExpiresAt) {
		return AuthCodeRecord{}, ErrAuthCodeExpired
	}
	consumed := now.UTC()
	record.ConsumedAt = &consumed
	s.authCodes[hash] = record
	return record, nil
}

func (s *InMemoryStore) SaveRefreshToken(record RefreshTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[record.TokenHash] = record
	return nil
}

func (s *InMemoryStore) GetRefreshToken(rawToken string, now time.Time) (RefreshTokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hash := sha256Hex(rawToken)
	record, ok := s.refreshTokens[hash]
	if !ok {
		return RefreshTokenRecord{}, ErrRefreshTokenNotFound
	}
	if record.RevokedAt != nil {
		return RefreshTokenRecord{}, ErrRefreshTokenRevoked
	}
	if now.After(record.ExpiresAt) {
		return RefreshTokenRecord{}, ErrRefreshTokenExpired
	}
	return record, nil
}

func (s *InMemoryStore) RevokeRefreshToken(rawToken string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := sha256Hex(rawToken)
	record, ok := s.refreshTokens[hash]
	if !ok {
		return nil
	}
	if record.RevokedAt != nil {
		return nil
	}
	revoked := now.UTC()
	record.RevokedAt = &revoked
	s.refreshTokens[hash] = record
	return nil
}

func (s *InMemoryStore) RotateRefreshToken(oldRawToken string, newRecord RefreshTokenRecord, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldHash := sha256Hex(oldRawToken)
	oldRecord, ok := s.refreshTokens[oldHash]
	if !ok {
		return ErrRefreshTokenNotFound
	}
	if oldRecord.RevokedAt != nil {
		return ErrRefreshTokenReplay
	}
	revoked := now.UTC()
	oldRecord.RevokedAt = &revoked
	s.refreshTokens[oldHash] = oldRecord
	s.refreshTokens[newRecord.TokenHash] = newRecord
	return nil
}

func (s *InMemoryStore) SaveConsent(record ConsentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if record.GrantedAt.IsZero() {
		record.GrantedAt = now
	}
	record.UpdatedAt = now
	record.Scope = normalizeScopes(record.Scope)
	key := consentMapKey(record.ClientID, record.UserID)
	s.consents[key] = record
	return nil
}

func (s *InMemoryStore) GetConsent(clientID, userID string) (ConsentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.consents[consentMapKey(clientID, userID)]
	if !ok {
		return ConsentRecord{}, ErrConsentNotFound
	}
	return record, nil
}

func ValidateRedirectURI(client OIDCClient, uri string) error {
	for _, allowed := range client.RedirectURIs {
		if constantTimeEquals(allowed, uri) {
			return nil
		}
	}
	return ErrInvalidRedirectURI
}

func ValidateScopes(client OIDCClient, requested []string) error {
	if len(requested) == 0 {
		return nil
	}
	allowedSet := make(map[string]struct{}, len(client.Scopes))
	for _, value := range client.Scopes {
		allowedSet[value] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowedSet[scope]; !ok {
			return ErrInvalidRequestedScope
		}
	}
	return nil
}

func IsClientActive(client OIDCClient) bool {
	status := strings.TrimSpace(strings.ToLower(client.Status))
	return status == "" || status == "active"
}

func ClientAllowsGrantType(client OIDCClient, grantType string) bool {
	target := strings.TrimSpace(grantType)
	if target == "" {
		return false
	}
	for _, value := range client.GrantTypes {
		if constantTimeEquals(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func consentMapKey(clientID, userID string) string {
	return clientID + "::" + userID
}
