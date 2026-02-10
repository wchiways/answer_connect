# Data Model

This document describes the logical data model and persistence layout used by the plugin.

## Core Entities

### `OIDCClient`

Represents an OAuth client registered through admin APIs.

| Field | Type | Description |
|---|---|---|
| `ID` | string | Client identifier (`client_id`) |
| `Name` | string | Display name |
| `SecretHash` | string | SHA-256 hash of `client_secret` |
| `RedirectURIs` | []string | Allowed callback URIs |
| `Scopes` | []string | Allowed scopes for this client |
| `GrantTypes` | []string | Supported grants (`authorization_code`, `refresh_token`) |
| `TokenEndpointAuthMethod` | string | `client_secret_post` / `none` |
| `FirstParty` | bool | Trusted first-party client flag |
| `Status` | string | `active` / `disabled` |
| `CreatedAt` / `UpdatedAt` | time | Metadata timestamps |

### `AuthCodeRecord`

Represents one-time authorization code state.

| Field | Type | Description |
|---|---|---|
| `CodeHash` | string | SHA-256 hash of raw authorization code |
| `ClientID` | string | Issued-for client |
| `UserID` | string | Authorized user |
| `RedirectURI` | string | Redirect URI locked to the code |
| `Scope` | []string | Approved scopes |
| `CodeChallenge` / `CodeMethod` | string | PKCE challenge metadata (`S256`) |
| `Nonce` | string | OIDC nonce |
| `ExpiresAt` | time | Expiration time |
| `ConsumedAt` | *time | One-time consume marker |
| `CreatedAt` | time | Creation timestamp |
| `OriginalState` | string | Request state for traceability |

### `RefreshTokenRecord`

Represents refresh token chain and replay controls.

| Field | Type | Description |
|---|---|---|
| `TokenHash` | string | SHA-256 hash of raw refresh token |
| `ClientID` | string | Bound client |
| `UserID` | string | Subject user |
| `Scope` | []string | Token scope set |
| `ExpiresAt` | time | Expiration time |
| `RevokedAt` | *time | Revocation marker |
| `CreatedAt` | time | Issued timestamp |
| `RotatedFrom` | string | Previous token hash in rotation chain |

### `ConsentRecord`

Represents user grant consent against a client.

| Field | Type | Description |
|---|---|---|
| `ClientID` | string | Client key |
| `UserID` | string | User key |
| `Scope` | []string | Granted scope set |
| `GrantedAt` | time | First grant timestamp |
| `UpdatedAt` | time | Last scope merge/update timestamp |
| `RevokedAt` | *time | Optional revoke timestamp |
| `FirstParty` | bool | Whether consent is auto-granted for trusted clients |

## Storage Abstraction

The plugin uses the `Store` interface to decouple handlers from persistence details.

Required operation groups:

- Client CRUD + client secret validation
- Authorization code save/consume
- Refresh token save/get/revoke/rotate
- Consent save/get

## Physical Storage Mapping

### `InMemoryStore`

- Backed by process-local maps and mutex.
- Good for local development and tests.
- Not suitable for multi-instance production.

### `KVStore` (Answer-integrated)

Backed by Answer `plugin.KVOperator` with grouped keys:

| Group | Record Type | Key |
|---|---|---|
| `oidc_clients` | `OIDCClient` | `client_id` |
| `oidc_auth_codes` | `AuthCodeRecord` | `code_hash` |
| `oidc_refresh_tokens` | `RefreshTokenRecord` | `token_hash` |
| `oidc_consents` | `ConsentRecord` | `client_id::user_id` |

Records are JSON-serialized before persistence.

## Lifecycle Rules

- **Authorization code**: create once → consume once (`ConsumedAt` set) → reject reuse/replay.
- **Refresh token**: issue → rotate (old revoked, new created) → reject replay/expired/revoked tokens.
- **Consent**: first grant created → later grants merge scopes → optional revoke by policy.
- **Client**: created active by default → updatable metadata/status → soft disabling via status.

## Consistency and Concurrency

- Authorization code consume is guarded by lock + consumed marker write.
- Refresh token rotate is revoke-then-insert with replay detection.
- Consent updates are scope-merge based and timestamped.

For strict cross-node atomicity under high concurrency, add stronger distributed guarantees (DB transaction/CAS/distributed lock).
