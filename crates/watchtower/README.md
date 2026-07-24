# Watchtower

Watchtower 是 Steadholme 内网的**防篡改审计骨干（tamper-evident audit spine）+ 迷你 SIEM 仪表盘**，
用 Rust（axum 0.8）实现，与 keystone / keyward 同构。它把每一条安全相关事件写入一条**仅追加
（append-only）、哈希链（hash-chained）**的审计日志：任何对历史的修改 / 重排 / 插入 / 删除都会从
被篡改处起断链，可被 `GET /api/verify` 精确定位。

> Watchtower 自身**不做登录**。仪表盘位于网关（Sluice）的 `auth=sso` 路由之后，由 Sluice 完成 OIDC
> 浏览器登录并注入 `X-Auth-Email` / `X-Auth-Subject`；仪表盘只读取这些头部用于"已登录身份"展示与
> 管理操作授权。日志写入端点 `POST /events` 用 Bearer 令牌保护，由内网生产者（keystone / sluice）直接调用。

## 它是什么

- 默认监听 `0.0.0.0:8500`（内网端口，不对公网暴露）
- **仅追加 + 哈希链**：每条事件携带

  ```text
  hash(n) = SHA256( seq || ts || actor || action || target || severity || detail || source || prev_hash )
  prev_hash(1) = 32 个零字节（genesis）
  prev_hash(n) = hash(n-1)
  ```

  编码是**规范且无歧义**的：两个整数为定长 8 字节大端；每个字符串字段做长度前缀（8 字节大端长度 + UTF-8
  字节），因此相邻字段之间挪动字节不会产生碰撞原像；`prev_hash` 以其原始 32 字节并入。哈希以 hex 存储 / 返回。
- **单写者 / 串行追加**：`append` 由存储层串行化（内存实现靠 `Mutex`；Postgres 实现靠
  transaction-scoped advisory lock + 数据库事务），跨进程的"认领 key -> 读链头 -> 封链 -> 写入事件与
  key 映射"是同一个原子边界
- **无更新 / 删除代码路径**（由测试 `no_mutation` 机械校验）；生产环境另给审计库用户只授予 `INSERT/SELECT`
- **锚定（anchor）**：`/api/verify` 返回 `head_hash`（链头哈希），可被外部锚定（对象存储锚定为后续工作）

## 如何运行

```bash
# 构建
cargo build

# 运行（默认内存存储，无需数据库）
cargo run

# 测试（默认内存存储，无需数据库 —— 单元 + 契约 + 防篡改全绿）
cargo test
```

冒烟验证（服务运行后）：

```bash
curl -s http://127.0.0.1:8500/healthz                       # ok

# 写入一条事件（需 Bearer 令牌）
curl -s -X POST http://127.0.0.1:8500/events \
  -H "Authorization: Bearer $AUDIT_INGEST_TOKEN" \
  -H 'Idempotency-Key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  -H 'Content-Type: application/json' \
  -d '{"actor":"u_admin","action":"login.success","target":"keystone","severity":"info","detail":"password login","source":"keystone"}'

curl -s http://127.0.0.1:8500/api/verify                    # {"ok":true,"count":1,"head_hash":"..."}
curl -s 'http://127.0.0.1:8500/api/events?q=login'          # 过滤列表
```

## 配置（环境变量）

所有值在对应环境变量**未设置 / 为空时保留 dev 默认**，因此内存模式开箱即用。

| 变量 | 作用 | 默认值 |
|------|------|--------|
| `BIND_ADDR` | 监听地址 | `0.0.0.0:8500` |
| `WATCHTOWER_STORE` | 存储后端：`memory` \| `postgres` | `memory` |
| `DATABASE_URL` | Postgres DSN（仅 `postgres` 模式需要） | 无 |
| `AUDIT_INGEST_TOKEN` | 保护 `POST /events` 的 Bearer 令牌；**生产必须覆盖** | dev 默认串（须替换） |

## 端点

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/healthz` | 公开 | 存活探针 -> `200 ok` |
| POST | `/events` | **Bearer** | 追加一条事件；可选 `Idempotency-Key`；服务端赋予 `ts` / `seq` / `prev_hash` / `hash` |
| GET | `/api/verify` | 读 | 重算整条链 -> `{ ok, count, head_hash, first_broken_seq? }` |
| GET | `/api/events` | 读 | 过滤列表 `?actor=&action=&since=&q=`（最新在前） |
| GET | `/` | 网关 SSO | 服务端渲染的仪表盘（时间线 + 完整性徽章 + 计数） |

### `POST /events`

```json
{ "actor": "u_admin", "action": "login.success", "target": "keystone",
  "severity": "info", "detail": "password login from 10.0.0.4", "source": "keystone" }
```

所有字段均可缺省（默认空串）；`ts` / `seq` / `hash` **不接受**调用方传入，由服务端独占。返回封链后的完整事件：

```json
{ "seq": 1, "ts": 1700000000000, "actor": "u_admin", "action": "login.success", "...": "...",
  "prev_hash": "0000…0000", "hash": "8f3a…" }
```

#### `Idempotency-Key` 重试契约

- 不发送 header：保持原行为，每次请求都 append 一条新事件。
- 发送 header：值必须严格是 64 位小写 hex；这与 Murmur 的 stable key 输出一致。
- key 按请求体的 `source` 做 namespace；`murmur + key` 与 `sluice + key` 是两个独立操作。
- 同一 `source + key + payload` 的并发请求或 2xx response 丢失后的重试，返回第一次提交的完整
  `AuditEvent`（包括原 `ts` / `seq` / `hash`），不会追加第二条 event，也不会再次记录 alert match。
- 同一 `source + key` 若绑定到不同 payload，返回 `409 idempotency_conflict`，并且不写入任何新行。
- `payload` 指 `actor` / `action` / `target` / `severity` / `detail` / `source`；服务端生成的 `ts` 不参与比较。
- key 映射永久保留，调用方必须为每个逻辑操作生成稳定且唯一的 key。数据库只存储
  domain-separated SHA-256 摘要，不存储原始 key。

### `GET /api/verify`

```json
{ "ok": true, "count": 128, "head_hash": "8f3a…" }
```

链被篡改时 `ok=false` 且 `first_broken_seq` 给出**第一处断链的 seq**（链完好时该字段省略）。

### `GET /api/events`

- `actor` / `action`：精确匹配
- `since`：`ts >= since`（epoch 毫秒）
- `q`：对 `action` / `target` / `detail` 的**大小写不敏感** LIKE 子串搜索（语义检索为后续 FusionDB 接缝）
- 结果按 `seq` 倒序，最多 500 条

## 仪表盘（SSO）

`GET /` 渲染企业级 UI（与 Keystone 登录页同一套品牌设计令牌，CSS 经 `include_str!` 内联，无静态资源往返）：

- 顶部应用栏：Steadholme 盾徽 + 字标、页标题、右侧 `X-Auth-Email` 与指向 `/_gw/auth/logout` 的退出链接
- **完整性徽章**：调用 verify —— 绿色 `Verified · N events · head abcd…`，或红色 `TAMPERED at seq K`
- 严重度（severity）配色药丸 + 基本计数
- 过滤栏 + 审计时间线表格

> 由于 Sluice **不剥离**网关路由前缀，仪表盘以 axum `fallback` 注册：`auth=sso` 路由 `/watchtower`
> 转发到本服务后表现为 `GET /watchtower`，仍命中仪表盘；显式的 `/healthz` / `/events` / `/api/*` 路由优先匹配。
> 所有生产者文本在渲染时做 HTML 转义（针对存储型 XSS 的纵深防御）。

## 存储（Store）

`Store` trait 有内存与 PostgreSQL 两套实现，处理器只依赖 trait（与 keystone / keyward 同构的接缝）。
Postgres 数据模型与普通查询使用可移植 SQL（`TEXT/BIGINT`、`PRIMARY KEY/NOT NULL`、参数化查询、
`lower(..) LIKE ..`、普通索引），运行期查询无编译期宏，构建**不需要数据库**。跨进程 append authority 使用
PostgreSQL 的 `pg_advisory_xact_lock`；迁移到其他 pgwire 后端时必须提供等价的 transaction-scoped 全局写锁，
不能退回进程内 mutex。

```text
audit_events(
  seq BIGINT PRIMARY KEY, ts BIGINT, actor TEXT, action TEXT, target TEXT,
  severity TEXT, detail TEXT, source TEXT, prev_hash TEXT, hash TEXT NOT NULL
)
-- 索引：(ts), (actor), (action)

audit_idempotency_keys(
  key_hash TEXT PRIMARY KEY, request_hash TEXT NOT NULL,
  event_seq BIGINT NOT NULL UNIQUE, created_at BIGINT NOT NULL
)
```

> **仅追加**：没有任何 `UPDATE` / `DELETE` 代码路径（由 `tests/no_mutation.rs` 机械校验）。生产环境另给
> 审计库用户**只授予 `INSERT/SELECT`**，即使服务被攻陷也无法改写历史。

### Postgres 模式测试

默认 `cargo test` 走内存存储、无需数据库；Postgres 集成测试是显式 ignored gate：

```bash
docker run --rm -d --name wt-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=watchtower \
  -p 127.0.0.1:55442:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55442/watchtower \
  cargo test --test pg_store -- --ignored --nocapture
docker rm -f wt-testpg
```

该测试覆盖：迁移幂等、两个独立 `PgStore` 的跨进程等价并发、source namespace、payload conflict、
丢失 2xx 后重试、alert match 不重复、串行追加 + verify、LIKE / actor 过滤，以及**带外（raw DB）篡改某条
中间事件 detail 后 verify 精确报出 `first_broken_seq`**。

### 部署顺序

迁移是 additive，可先执行 `CREATE TABLE/INDEX IF NOT EXISTS`。但旧版本只持有进程内 append mutex，无法参与
新版本的数据库全局锁，因此不能让旧、新 Watchtower 实例同时接收 ingest：

1. 用 migration 权限执行 additive migration；
2. 在网关/生产者侧暂停或 drain `POST /events`，等待旧实例在途请求完成；
3. 停止所有旧 Watchtower 实例；
4. 启动新版本并确认 migration、`/healthz` 与 `/api/verify`；
5. 恢复 ingest 流量；此后可安全运行多个新版本实例。

运行期角色只需现有 `INSERT/SELECT` 权限及执行 `pg_advisory_xact_lock` 的权限；DDL 继续由 migration 角色负责。

## Docker

```bash
docker build -t steadholme/watchtower:dev .
docker run --rm -p 127.0.0.1:8500:8500 steadholme/watchtower:dev
curl -s http://127.0.0.1:8500/healthz   # ok
```

镜像为多阶段、非 root（uid 10001）、`EXPOSE 8500`，自带 `watchtower healthcheck` 探针（无需 curl）。

## 后续：生产者接线（仅说明，本步**不接线**）

Watchtower 已具备成为审计骨干的全部能力。下一步把内网生产者接到 `POST /events`（**不在本次范围内**）：

1. **keystone**：登录成功 / 失败、令牌签发等事件，以 `source=keystone` POST 到 `/events`
   （`action` 如 `login.success` / `login.failure` / `token.issue`）。
2. **sluice**：forward-auth 判定（放行 / 拒绝、SSO 会话建立 / 登出）以 `source=sluice` POST 到 `/events`。
3. 两者都持有 `AUDIT_INGEST_TOKEN`，直接走内网（`http://watchtower:8500/events`），不经公网网关。

> 注意：本服务此刻**不主动**向任何生产者发起调用，也未在 keystone / sluice 中加入任何写审计的代码 ——
> 上述接线是**下一步**，此处仅记录接缝。
