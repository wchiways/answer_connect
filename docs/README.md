# Documentation Index

This folder contains technical documentation for the Answer OIDC Provider plugin.

## Structure

- `reference/` — protocol and API reference documents
- `architecture/` — internal architecture and data model design
- `operations/` — deployment and runtime operation guidance
- `plans/` — implementation planning and historical design records

## Key Documents

- OIDC endpoint reference: `reference/oidc-endpoints.md`
- Data model and storage layout: `architecture/data-model.md`
- Multi-instance deployment guidance: `operations/multi-instance.md`
- Implementation plan archive: `plans/2026-02-10-answer-oidc-provider-implementation-plan.md`

## Code Map

- Plugin integration layer: `plugin.go`
- OIDC core implementation: `internal/oidc/`
- External tests: `tests/`
- Chinese side-document: `README.zh-CN.md`

## Engineering Workflow

- Use `make fmt` to format Go files.
- Use `make test` to run tests with pinned local cache paths.
- Use `make verify` for end-to-end local verification.
