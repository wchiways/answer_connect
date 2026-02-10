# Multi-Instance Deployment Recommendations

This guide describes recommended production deployment for multi-instance Apache Answer clusters.

## Objectives

- Keep token/consent state consistent across nodes.
- Prevent auth code replay and refresh token replay.
- Keep discovery/JWKS behavior deterministic for all instances.

## Mandatory Baseline

- Use `KVStore` via Answer `plugin.KVOperator`.
- Do **not** use `InMemoryStore` in production multi-instance mode.
- Keep plugin config identical on all nodes:
  - `Issuer`
  - `BasePath`
  - token/code TTL values
  - `DefaultScopes`

## Shared Dependencies

- Shared Answer database storing plugin KV records.
- Shared cache (if enabled by Answer runtime).
- Stable NTP time synchronization across nodes.

## Key Management Strategy

### Single Active Key (minimum)

- Configure same `PrivateKeyPEM` on all nodes.
- Ensure all nodes expose same `kid` in JWKS.

### Rotation (recommended)

- Introduce new signing key on all nodes.
- Switch signer to new key.
- Keep old key in JWKS until all old access/id tokens expire.
- Remove old key after overlap window.

## Flow-Level Cross-Node Behavior

- **Authorization code**: issued on node A, redeemable on node B through shared `KVStore`.
- **Refresh token rotation**: rotate on any node; old token should be invalid cluster-wide immediately.
- **Consent**: granted on one node, visible to all nodes for subsequent authorizations.

## Concurrency and Race Hardening

Current logic provides lock + state-marker safeguards. For very high concurrency, evaluate:

- DB-transaction-backed compare-and-set for code consume/refresh rotate.
- Distributed lock for hot client/user combinations.
- Idempotent retry strategy in API gateway to reduce replay retries.

## Deployment Checklist

Before rollout:

- Verify all instances return identical discovery payload.
- Verify JWKS `kid` is identical on all instances.
- Verify auth-code flow works when authorize/token hit different nodes.
- Verify refresh rotation/replay behavior across nodes.
- Verify consent record visibility across nodes.

After rollout:

- Monitor `invalid_grant` rate and trend.
- Monitor token issuance latency and non-2xx ratio.
- Track admin client CRUD audit events.
- Keep emergency key rollback procedure documented.

## Recommended Next Enhancements

- Add consent revoke API and audit trail.
- Add scheduled cleanup for expired auth codes and refresh tokens.
- Add per-client rate limiting and abuse controls at edge/API gateway.
