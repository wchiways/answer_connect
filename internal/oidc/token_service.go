package oidc

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid token")

type TokenClaims map[string]any

type TokenService struct {
	issuer       string
	accessTTL    time.Duration
	idTTL        time.Duration
	refreshTTL   time.Duration
	keyService   *KeyService
	nowFn        func() time.Time
	defaultScope []string
}

func NewTokenService(config Config, keyService *KeyService) *TokenService {
	normalized := config.normalize()
	return &TokenService{
		issuer:       normalized.Issuer,
		accessTTL:    normalized.AccessTokenTTL,
		idTTL:        normalized.IDTokenTTL,
		refreshTTL:   normalized.RefreshTokenTTL,
		keyService:   keyService,
		nowFn:        func() time.Time { return time.Now().UTC() },
		defaultScope: append([]string(nil), normalized.DefaultScopes...),
	}
}

func (s *TokenService) IssueAccessToken(claims AccessTokenClaims) (string, int64, error) {
	now := s.nowFn()
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = now.Add(s.accessTTL)
	}
	if claims.Issuer == "" {
		claims.Issuer = s.issuer
	}
	if len(claims.Scope) == 0 {
		claims.Scope = append([]string(nil), s.defaultScope...)
	}

	jwtClaims := jwt.MapClaims{
		"iss":   claims.Issuer,
		"sub":   claims.Subject,
		"aud":   claims.Audience,
		"scope": strings.Join(claims.Scope, " "),
		"iat":   claims.IssuedAt.Unix(),
		"exp":   claims.ExpiresAt.Unix(),
		"typ":   "Bearer",
		"use":   "access_token",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = s.keyService.KID()
	signed, err := token.SignedString(s.keyService.PrivateKey())
	if err != nil {
		return "", 0, err
	}
	return signed, int64(claims.ExpiresAt.Sub(now).Seconds()), nil
}

func (s *TokenService) IssueIDToken(claims IDTokenClaims) (string, int64, error) {
	now := s.nowFn()
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = now.Add(s.idTTL)
	}
	if claims.Issuer == "" {
		claims.Issuer = s.issuer
	}
	if claims.AuthTime.IsZero() {
		claims.AuthTime = now
	}

	jwtClaims := jwt.MapClaims{
		"iss":       claims.Issuer,
		"sub":       claims.Subject,
		"aud":       claims.Audience,
		"nonce":     claims.Nonce,
		"iat":       claims.IssuedAt.Unix(),
		"exp":       claims.ExpiresAt.Unix(),
		"auth_time": claims.AuthTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = s.keyService.KID()
	signed, err := token.SignedString(s.keyService.PrivateKey())
	if err != nil {
		return "", 0, err
	}
	return signed, int64(claims.ExpiresAt.Sub(now).Seconds()), nil
}

func (s *TokenService) NewRefreshToken() (raw string, hash string, expiresAt time.Time, err error) {
	raw, err = randomURLSafe(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return raw, sha256Hex(raw), s.nowFn().Add(s.refreshTTL), nil
}

func (s *TokenService) ParseAndValidateAccessToken(raw string) (TokenClaims, error) {
	token, err := jwt.ParseWithClaims(raw, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, ErrInvalidToken
		}
		return s.keyService.PublicKey(), nil
	}, jwt.WithIssuer(s.issuer), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	if use, _ := claims["use"].(string); use != "access_token" {
		return nil, ErrInvalidToken
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil || time.Now().UTC().After(exp.Time) {
		return nil, ErrInvalidToken
	}
	result := make(TokenClaims, len(claims))
	for key, value := range claims {
		result[key] = value
	}
	return result, nil
}
