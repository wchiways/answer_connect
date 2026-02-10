# Answer OIDC Provider 插件（中文文档）

本项目是一个 **Apache Answer 插件**，用于将 Answer 作为 OAuth2/OIDC 登录提供方，对外提供统一登录能力。

## 功能概览

- 支持 OAuth2 授权码模式 + PKCE（`S256`）
- 支持 OIDC 端点：Discovery / JWKS / UserInfo / Revoke
- 支持客户端管理接口（Admin CRUD）
- Access Token / ID Token 使用 RS256 签名
- 支持 Refresh Token 轮换与吊销
- 支持 Consent（授权同意）持久化

## 与 Apache Answer 的集成方式

插件实现了以下官方接口：

- `plugin.Base`
- `plugin.Config`
- `plugin.Agent`
- `plugin.KVStorage`

并通过 `init()` 中的 `plugin.Register(...)` 完成注册。

路由挂载入口：

- `RegisterUnAuthRouter`
- `RegisterAuthUserRouter`
- `RegisterAuthAdminRouter`

## 存储模式

### 1) 内存模式（开发/测试）

- 使用 `InMemoryStore`
- 仅单进程有效
- 不适用于多实例生产环境

### 2) 持久化模式（推荐）

- 使用 `KVStore`
- 通过 Answer 的 `plugin.KVOperator` 写入共享存储（DB + Cache）
- 适合多实例部署

## 项目结构（已优化）

```text
.
├── plugin.go                         # 插件入口（仅保留 Answer 集成逻辑）
├── user_context.go                   # 根目录兼容封装
├── tests/                           # 外部包测试
│   ├── plugin_integration_test.go
│   └── user_context_test.go
├── internal/
│   └── oidc/                         # OIDC 核心实现
│       ├── config.go
│       ├── models.go
│       ├── store.go
│       ├── store_kv.go
│       ├── handlers_*.go
│       ├── token_service.go
│       └── *_test.go
├── docs/
│   ├── README.md
│   ├── architecture/data-model.md
│   ├── operations/multi-instance.md
│   ├── reference/oidc-endpoints.md
│   └── plans/
├── README.md
├── Makefile
├── go.mod
└── go.sum
```

## 用户上下文解析

插件会尝试从 Answer 中间件上下文键 `ctxUuidKey` 读取登录用户信息（采用反射读取，避免直接依赖 Answer internal 包）。

期望字段包括：

- `UserID`
- `Username` 或 `DisplayName`
- `Mail`

## 快速开始

```bash
go mod tidy
go test ./...
```

或使用统一校验入口：

```bash
make verify
```

## 文档导航

- 文档索引：`docs/README.md`
- OIDC 端点参考：`docs/reference/oidc-endpoints.md`
- 数据模型：`docs/architecture/data-model.md`
- 多实例部署建议：`docs/operations/multi-instance.md`
