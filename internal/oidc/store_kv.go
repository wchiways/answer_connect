package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	answerplugin "github.com/apache/answer/plugin"
)

const (
	kvGroupClients       = "oidc_clients"
	kvGroupAuthCodes     = "oidc_auth_codes"
	kvGroupRefreshTokens = "oidc_refresh_tokens"
	kvGroupConsents      = "oidc_consents"
	kvPageSize           = 200
)

type KVStore struct {
	operator *answerplugin.KVOperator
	mu       sync.Mutex
}

func NewKVStore(operator *answerplugin.KVOperator) *KVStore {
	return &KVStore{operator: operator}
}

func (s *KVStore) CreateClient(client OIDCClient, rawSecret string) (OIDCClient, string, error) {
	now := time.Now().UTC()
	client.ID = strings.TrimSpace(client.ID)
	if client.ID == "" {
		for {
			randomID, err := randomURLSafe(24)
			if err != nil {
				return OIDCClient{}, "", err
			}
			candidate := "cl_" + randomID
			_, err = s.GetClient(candidate)
			if err == nil {
				continue
			}
			if !errors.Is(err, ErrClientNotFound) {
				return OIDCClient{}, "", err
			}
			client.ID = candidate
			break
		}
	} else {
		if _, err := s.GetClient(client.ID); err == nil {
			return OIDCClient{}, "", ErrClientExists
		} else if !errors.Is(err, ErrClientNotFound) {
			return OIDCClient{}, "", err
		}
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

	if err := s.saveJSON(kvGroupClients, client.ID, client); err != nil {
		return OIDCClient{}, "", err
	}
	return client, rawSecret, nil
}

func (s *KVStore) GetClient(id string) (OIDCClient, error) {
	client := OIDCClient{}
	err := s.getJSON(kvGroupClients, id, &client)
	if err != nil {
		if errors.Is(err, answerplugin.ErrKVKeyNotFound) {
			return OIDCClient{}, ErrClientNotFound
		}
		return OIDCClient{}, err
	}
	return client, nil
}

func (s *KVStore) ListClients() []OIDCClient {
	rows, err := s.listJSON(kvGroupClients)
	if err != nil {
		return nil
	}
	out := make([]OIDCClient, 0, len(rows))
	for _, raw := range rows {
		client := OIDCClient{}
		if err = json.Unmarshal([]byte(raw), &client); err == nil {
			out = append(out, client)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *KVStore) UpdateClient(client OIDCClient) (OIDCClient, error) {
	current, err := s.GetClient(client.ID)
	if err != nil {
		return OIDCClient{}, err
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

	if err = s.saveJSON(kvGroupClients, current.ID, current); err != nil {
		return OIDCClient{}, err
	}
	return current, nil
}

func (s *KVStore) DeleteClient(id string) error {
	if _, err := s.GetClient(id); err != nil {
		return err
	}
	return s.operator.Del(context.Background(), answerplugin.KVParams{Group: kvGroupClients, Key: id})
}

func (s *KVStore) ValidateClientSecret(clientID, rawSecret string) (OIDCClient, error) {
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

func (s *KVStore) SaveAuthCode(record AuthCodeRecord) error {
	return s.saveJSON(kvGroupAuthCodes, record.CodeHash, record)
}

func (s *KVStore) ConsumeAuthCode(rawCode string, now time.Time) (AuthCodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	codeHash := sha256Hex(rawCode)
	record := AuthCodeRecord{}
	err := s.getJSON(kvGroupAuthCodes, codeHash, &record)
	if err != nil {
		if errors.Is(err, answerplugin.ErrKVKeyNotFound) {
			return AuthCodeRecord{}, ErrAuthCodeNotFound
		}
		return AuthCodeRecord{}, err
	}
	if record.ConsumedAt != nil {
		return AuthCodeRecord{}, ErrAuthCodeConsumed
	}
	if now.After(record.ExpiresAt) {
		return AuthCodeRecord{}, ErrAuthCodeExpired
	}
	consumed := now.UTC()
	record.ConsumedAt = &consumed
	if err = s.saveJSON(kvGroupAuthCodes, codeHash, record); err != nil {
		return AuthCodeRecord{}, err
	}
	return record, nil
}

func (s *KVStore) SaveRefreshToken(record RefreshTokenRecord) error {
	return s.saveJSON(kvGroupRefreshTokens, record.TokenHash, record)
}

func (s *KVStore) GetRefreshToken(rawToken string, now time.Time) (RefreshTokenRecord, error) {
	tokenHash := sha256Hex(rawToken)
	record := RefreshTokenRecord{}
	err := s.getJSON(kvGroupRefreshTokens, tokenHash, &record)
	if err != nil {
		if errors.Is(err, answerplugin.ErrKVKeyNotFound) {
			return RefreshTokenRecord{}, ErrRefreshTokenNotFound
		}
		return RefreshTokenRecord{}, err
	}
	if record.RevokedAt != nil {
		return RefreshTokenRecord{}, ErrRefreshTokenRevoked
	}
	if now.After(record.ExpiresAt) {
		return RefreshTokenRecord{}, ErrRefreshTokenExpired
	}
	return record, nil
}

func (s *KVStore) RevokeRefreshToken(rawToken string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokenHash := sha256Hex(rawToken)
	record := RefreshTokenRecord{}
	err := s.getJSON(kvGroupRefreshTokens, tokenHash, &record)
	if err != nil {
		if errors.Is(err, answerplugin.ErrKVKeyNotFound) {
			return nil
		}
		return err
	}
	if record.RevokedAt != nil {
		return nil
	}
	revoked := now.UTC()
	record.RevokedAt = &revoked
	return s.saveJSON(kvGroupRefreshTokens, tokenHash, record)
}

func (s *KVStore) RotateRefreshToken(oldRawToken string, newRecord RefreshTokenRecord, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldHash := sha256Hex(oldRawToken)
	oldRecord := RefreshTokenRecord{}
	err := s.getJSON(kvGroupRefreshTokens, oldHash, &oldRecord)
	if err != nil {
		if errors.Is(err, answerplugin.ErrKVKeyNotFound) {
			return ErrRefreshTokenNotFound
		}
		return err
	}
	if oldRecord.RevokedAt != nil {
		return ErrRefreshTokenReplay
	}
	revoked := now.UTC()
	oldRecord.RevokedAt = &revoked
	if err = s.saveJSON(kvGroupRefreshTokens, oldHash, oldRecord); err != nil {
		return err
	}
	return s.saveJSON(kvGroupRefreshTokens, newRecord.TokenHash, newRecord)
}

func (s *KVStore) SaveConsent(record ConsentRecord) error {
	now := time.Now().UTC()
	if record.GrantedAt.IsZero() {
		record.GrantedAt = now
	}
	record.UpdatedAt = now
	record.Scope = normalizeScopes(record.Scope)
	return s.saveJSON(kvGroupConsents, consentMapKey(record.ClientID, record.UserID), record)
}

func (s *KVStore) GetConsent(clientID, userID string) (ConsentRecord, error) {
	record := ConsentRecord{}
	err := s.getJSON(kvGroupConsents, consentMapKey(clientID, userID), &record)
	if err != nil {
		if errors.Is(err, answerplugin.ErrKVKeyNotFound) {
			return ConsentRecord{}, ErrConsentNotFound
		}
		return ConsentRecord{}, err
	}
	return record, nil
}

func (s *KVStore) saveJSON(group, key string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.operator.Set(context.Background(), answerplugin.KVParams{
		Group: group,
		Key:   key,
		Value: string(payload),
	})
}

func (s *KVStore) getJSON(group, key string, out any) error {
	raw, err := s.operator.Get(context.Background(), answerplugin.KVParams{Group: group, Key: key})
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), out)
}

func (s *KVStore) listJSON(group string) (map[string]string, error) {
	result := make(map[string]string)
	for page := 1; ; page++ {
		items, err := s.operator.GetByGroup(context.Background(), answerplugin.KVParams{
			Group:    group,
			Page:     page,
			PageSize: kvPageSize,
		})
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			break
		}
		for key, value := range items {
			result[key] = value
		}
		if len(items) < kvPageSize {
			break
		}
	}
	return result, nil
}
