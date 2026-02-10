# OIDC Endpoint Reference

The plugin exposes OIDC endpoints under `BasePath` (default: `/api/auth/oidc`) and mounts by Answer route groups:

- unAuth group: `RegisterUnAuthRouter`
- auth user group: `RegisterAuthUserRouter`
- admin group: `RegisterAuthAdminRouter`

In real Answer deployment, full URL is prefixed by Answer API base path (for example `/answer/api/v1`).

## Public Endpoints

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /authorize`
- `POST /token`
- `GET /userinfo`
- `POST /userinfo`
- `POST /revoke`

## Admin Endpoints

- `GET /admin/clients`
- `POST /admin/clients`
- `GET /admin/clients/:client_id`
- `PUT /admin/clients/:client_id`
- `DELETE /admin/clients/:client_id`

## Authorization Request Requirements

- `response_type=code`
- `client_id`
- `redirect_uri`
- `state`
- `code_challenge`
- `code_challenge_method=S256`

## Token Endpoint

Supported `grant_type`:

- `authorization_code`
- `refresh_token`

For `authorization_code`:

- `client_id`
- `client_secret` (if client auth method requires secret)
- `code`
- `redirect_uri`
- `code_verifier`

For `refresh_token`:

- `client_id`
- `client_secret` (if required)
- `refresh_token`

## Error Strategy

- OAuth2/OIDC compatible error codes are used, including:
  - `invalid_request`
  - `invalid_client`
  - `invalid_grant`
  - `invalid_scope`
  - `unsupported_grant_type`
  - `unauthorized_client`
- `trace_id` is included in error body for server-side troubleshooting.
