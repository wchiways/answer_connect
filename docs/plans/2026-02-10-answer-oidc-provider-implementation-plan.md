# Answer OIDC Provider Plugin Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an Apache Answer plugin that exposes OIDC endpoints (Authorization Code + PKCE) so other applications can use Answer accounts for login.

**Architecture:** Implement a Go plugin using Apache Answer `plugin.Agent` + `plugin.Config`. Public OIDC endpoints live in unauth routes, admin client-management APIs live in auth-admin routes. Use repository interfaces with an in-memory implementation first, so storage can later be swapped to DB/Redis for multi-instance deployments.

**Tech Stack:** Go 1.22, Apache Answer plugin SDK (`github.com/apache/answer/plugin`), Gin, JWT (`github.com/golang-jwt/jwt/v5`).

---

### Task 1: Bootstrap Plugin Module

**Files:**
- Create: `go.mod`
- Create: `plugin.go`
- Create: `config.go`
- Create: `models.go`
- Create: `README.md`

**Step 1: Write the failing compile check**

Run: `go test ./...`
Expected: FAIL with "no Go files" / module missing.

**Step 2: Add minimal plugin entry and config definitions**

- Define `OIDCProviderPlugin` struct and register with `plugin.Register` in `init()`.
- Implement `Info()` and `ConfigFields()` methods.

**Step 3: Re-run compile check**

Run: `go test ./...`
Expected: PASS compile for bootstrap package.

**Step 4: Commit**

Run:
```bash
git add go.mod plugin.go config.go models.go README.md
git commit -m "feat: bootstrap answer oidc provider plugin"
```

### Task 2: Add Key Service and Token Utilities

**Files:**
- Create: `key_service.go`
- Create: `token_service.go`
- Create: `crypto_util.go`
- Test: `token_service_test.go`

**Step 1: Write failing tests for JWT issue/verify**

- `TestIssueAndVerifyAccessToken`
- `TestIssueAndVerifyIDToken`
- `TestJWKSContainsActiveKey`

**Step 2: Run targeted tests**

Run: `go test ./... -run 'TestIssueAndVerify|TestJWKS' -v`
Expected: FAIL with missing implementation.

**Step 3: Implement minimal key + token services**

- Parse configured RSA private key or generate ephemeral key.
- Sign access token and id token with RS256 + `kid`.
- Expose JWKS document from active public key.

**Step 4: Re-run tests**

Run: `go test ./... -run 'TestIssueAndVerify|TestJWKS' -v`
Expected: PASS.

**Step 5: Commit**

Run:
```bash
git add key_service.go token_service.go crypto_util.go token_service_test.go
git commit -m "feat: add jwt and jwks services"
```

### Task 3: Implement Authorization Code + PKCE Flow

**Files:**
- Create: `store.go`
- Create: `handlers_authorize.go`
- Create: `handlers_token.go`
- Create: `pkce.go`
- Test: `handlers_oauth_flow_test.go`

**Step 1: Write failing flow tests**

- `TestAuthorizeReturnsCodeWhenPKCEValid`
- `TestTokenExchangeSucceedsWithVerifier`
- `TestTokenExchangeFailsOnCodeReplay`

**Step 2: Run targeted tests**

Run: `go test ./... -run 'TestAuthorize|TestTokenExchange' -v`
Expected: FAIL.

**Step 3: Implement authorize/token handlers**

- Validate client + redirect URI + scope.
- Require `code_challenge_method=S256`.
- Store one-time auth code hash with expiry and PKCE challenge.
- Exchange code for access/id/refresh tokens.

**Step 4: Re-run tests**

Run: `go test ./... -run 'TestAuthorize|TestTokenExchange' -v`
Expected: PASS.

**Step 5: Commit**

Run:
```bash
git add store.go handlers_authorize.go handlers_token.go pkce.go handlers_oauth_flow_test.go
git commit -m "feat: implement authorization code flow with pkce"
```

### Task 4: Add OIDC Metadata, UserInfo, and Revocation

**Files:**
- Create: `handlers_metadata.go`
- Create: `handlers_userinfo.go`
- Create: `handlers_revoke.go`
- Modify: `plugin.go`
- Test: `handlers_oidc_endpoints_test.go`

**Step 1: Write failing endpoint tests**

- `TestDiscoveryDocument`
- `TestUserInfoWithBearerToken`
- `TestRevokeRefreshToken`

**Step 2: Run targeted tests**

Run: `go test ./... -run 'TestDiscovery|TestUserInfo|TestRevoke' -v`
Expected: FAIL.

**Step 3: Implement handlers and route registration**

- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`
- `/userinfo`
- `/revoke`

**Step 4: Re-run tests**

Run: `go test ./... -run 'TestDiscovery|TestUserInfo|TestRevoke' -v`
Expected: PASS.

**Step 5: Commit**

Run:
```bash
git add handlers_metadata.go handlers_userinfo.go handlers_revoke.go plugin.go handlers_oidc_endpoints_test.go
git commit -m "feat: add oidc metadata userinfo and revoke endpoints"
```

### Task 5: Add Admin Client Management APIs

**Files:**
- Create: `handlers_admin_clients.go`
- Modify: `store.go`
- Modify: `plugin.go`
- Test: `handlers_admin_clients_test.go`

**Step 1: Write failing admin API tests**

- `TestCreateClient`
- `TestListClients`
- `TestUpdateClient`
- `TestDeleteClient`

**Step 2: Run targeted tests**

Run: `go test ./... -run 'TestCreateClient|TestListClients|TestUpdateClient|TestDeleteClient' -v`
Expected: FAIL.

**Step 3: Implement auth-admin handlers**

- CRUD client metadata (id/secret/redirect URIs/scopes/grants/status).
- Store hashed client secret only.
- Return generated secret only at creation time.

**Step 4: Re-run tests**

Run: `go test ./... -run 'TestCreateClient|TestListClients|TestUpdateClient|TestDeleteClient' -v`
Expected: PASS.

**Step 5: Commit**

Run:
```bash
git add handlers_admin_clients.go store.go plugin.go handlers_admin_clients_test.go
git commit -m "feat: add admin client management apis"
```

### Task 6: Final Validation and Docs

**Files:**
- Modify: `README.md`
- Create: `docs/oidc-endpoints.md`

**Step 1: Run full test suite**

Run: `go test ./... -v`
Expected: PASS.

**Step 2: Add operator docs**

- Configure issuer, key pair, token TTL.
- Explain endpoint URLs and sample client registration.
- Document current limitation (in-memory store; DB/Redis needed for true multi-instance).

**Step 3: Run formatting check**

Run: `gofmt -w *.go && go test ./...`
Expected: PASS.

**Step 4: Commit**

Run:
```bash
git add README.md docs/oidc-endpoints.md *.go
git commit -m "docs: add usage and endpoint references"
```
