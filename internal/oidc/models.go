package oidc

import "time"

type PluginInfo struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type OIDCClient struct {
	ID                      string    `json:"id"`
	Name                    string    `json:"name"`
	SecretHash              string    `json:"-"`
	RedirectURIs            []string  `json:"redirect_uris"`
	Scopes                  []string  `json:"scopes"`
	GrantTypes              []string  `json:"grant_types"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	FirstParty              bool      `json:"first_party"`
	Status                  string    `json:"status"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

type UserProfile struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

type AuthCodeRecord struct {
	CodeHash       string
	ClientID       string
	UserID         string
	RedirectURI    string
	Scope          []string
	CodeChallenge  string
	CodeMethod     string
	Nonce          string
	ExpiresAt      time.Time
	ConsumedAt     *time.Time
	CreatedAt      time.Time
	OriginalState  string
	SessionBinding string
}

type RefreshTokenRecord struct {
	TokenHash   string
	ClientID    string
	UserID      string
	Scope       []string
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
	RotatedFrom string
}

type ConsentRecord struct {
	ClientID   string
	UserID     string
	Scope      []string
	GrantedAt  time.Time
	UpdatedAt  time.Time
	RevokedAt  *time.Time
	FirstParty bool
}

type AccessTokenClaims struct {
	Issuer    string
	Audience  string
	Subject   string
	Scope     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	TokenUse  string
}

type IDTokenClaims struct {
	Issuer    string
	Audience  string
	Subject   string
	Nonce     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	AuthTime  time.Time
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	TraceID          string `json:"trace_id,omitempty"`
}
