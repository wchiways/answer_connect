# Answer OIDC Provider Plugin

Apache Answer plugin that exposes OAuth2/OIDC APIs so external applications can use Answer accounts for login.

## Highlights

- OAuth2 Authorization Code + PKCE (`S256`)
- OIDC discovery/JWKS/UserInfo/Revoke endpoints
- Admin APIs for OAuth client lifecycle (CRUD)
- RS256-signed access token and ID token
- Refresh token rotation + revoke support
- Consent persistence (in-memory and KV-backed)

## Apache Answer Integration

The plugin implements:

- `plugin.Base`
- `plugin.Config`
- `plugin.Agent`
- `plugin.KVStorage`

It is registered with `plugin.Register(...)` in `init()` and mounts routes through:

- `RegisterUnAuthRouter`
- `RegisterAuthUserRouter`
- `RegisterAuthAdminRouter`

## Storage Modes

- **Fallback mode:** `InMemoryStore` (single-process development)
- **Persistent mode:** `KVStore` via `plugin.KVOperator` (`plugin.KVStorage`), backed by Answer DB/cache

## Project Structure

```text
.
├── plugin.go                         # Answer plugin entrypoint (integration layer)
├── user_context.go                   # root-level compatibility wrapper
├── tests/                           # integration/external package tests
│   ├── plugin_integration_test.go
│   └── user_context_test.go
├── internal/
│   └── oidc/                         # core OAuth2/OIDC domain logic
│       ├── config.go
│       ├── models.go
│       ├── store.go
│       ├── store_kv.go
│       ├── handlers_*.go
│       ├── token_service.go
│       └── *_test.go
├── docs/
│   ├── README.md
│   ├── architecture/
│   │   └── data-model.md
│   ├── operations/
│   │   └── multi-instance.md
│   ├── reference/
│   │   └── oidc-endpoints.md
│   └── plans/
├── README.zh-CN.md
├── Makefile
├── go.mod
└── go.sum
```

## Documentation

- Docs index: `docs/README.md`
- Endpoint reference: `docs/reference/oidc-endpoints.md`
- Data model: `docs/architecture/data-model.md`
- Multi-instance deployment: `docs/operations/multi-instance.md`
- 中文副文档: `README.zh-CN.md`

## User Context Resolution

The plugin reads authenticated user context from Answer middleware key `ctxUuidKey` (reflection-based extraction to avoid importing Answer internal packages directly).

Expected fields in context user object:

- `UserID`
- `Username` or `DisplayName`
- `Mail`

## Quick Start

```bash
go mod tidy
go test ./...
```

Or run the project verification entrypoint:

```bash
make verify
```

## Dependency Sync

```bash
go get ./...
go mod tidy
```
