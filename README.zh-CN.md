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
├── tests/                            # 外部包测试
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
├── info.yaml
├── i18n/
│   ├── translation.go
│   ├── en_US.yaml
│   └── zh_CN.yaml
├── README.md
├── Makefile
├── go.mod
└── go.sum
```

## 安装教程（集成到 Apache Answer）

### 官方文档

- Answer 安装文档：https://answer.apache.org/zh-CN/docs/installation/
- Answer 插件构建文档：https://answer.apache.org/zh-CN/docs/plugins/

### 1）先安装并启动 Apache Answer

官方推荐先用 Docker Compose 启动：

```bash
curl -fsSL https://raw.githubusercontent.com/apache/answer/main/docker-compose.yaml | docker compose -p answer -f - up
```

启动后访问 `http://localhost:9080/install`，完成初始化向导。

### 2）将本插件打包进 Answer

使用 Answer 官方插件构建命令，通过 `--with` 引入插件模块：

```bash
./answer build --with <你的插件模块路径> --output ./answer-with-plugins
```

示例：

```bash
./answer build --with github.com/wchiways/answer_connect --output ./answer-with-plugins
```

### 3）检查插件是否已打包

```bash
./answer-with-plugins plugin
```

### 4）启动打包后的 Answer

```bash
./answer-with-plugins run
```

启动后进入 Answer 管理后台配置插件参数并启用。

## 用户上下文解析

插件会尝试从 Answer 中间件上下文键 `ctxUuidKey` 读取登录用户信息（采用反射读取，避免直接依赖 Answer internal 包）。

期望字段包括：

- `UserID`
- `Username` 或 `DisplayName`
- `Mail`

## 本地开发快速开始

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

## License

本项目基于 MIT License，详见 `LICENSE`。
