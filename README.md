# 内网 DNS 区域认证副本备份（dns-zone-backup）

内网 DNS 运维场景：留存**经过 TSIG 认证**的权威区域副本，供故障后恢复解析。
首页提供备份入口，按**启动配置**中固定的服务器、区域名与 TSIG 密钥发起
AXFR；只有传输完整且末报文验签通过的副本才会落库，任何失败都保留旧版。

## 安全与完整性规则

### 传输（`app/axfr_client.py`）

- 使用 **dnspython 手工驱动 TCP**（RFC 5936）执行 AXFR，不走 UDP。
- TSIG 固定 **HMAC-SHA256**，按 **RFC 8945 5.3.1** 核验多报文 MAC 链：
  首报文对请求 MAC 验签，中间报文可以不带 TSIG（运行中的 HMAC 上下文仍覆盖
  其 wire 字节），**末报文必须带 TSIG 且验签通过**。
- 仅接受 **SOA、NS、A** 三类记录；出现其他类型立即中止整次传输。
- 单区**最多 1000 条**记录，超出即放弃。
- **首尾 SOA 必须完全一致**，且收尾 SOA 必须出现在最后一个报文。
- 全程一个 **5 秒墙钟总时限**，覆盖连接、发送与每次 recv；超时、断流、
  连接拒绝、RCODE 错误、验签失败全部转成带中文原因的 `TransferError`。
- 未完整通过前不向调用方返回任何数据，杜绝半成品/未认证副本入库。

### 提交（`app/storage.py` + `app/serial.py`）

- 网络传输**全程不持有数据库写锁**；仅在完整副本已在内存中后，开启一个
  短事务完成序列号判定与整版替换。
- 按 **RFC 1982** 序列号算术与最新已存序列号比较：
  - **无副本**：直接保存首版；
  - **较新**：整版替换（zone 文件先写临时文件 fsync 再 rename，与元数据
    在同一事务内提交，下载不可能混版）；
  - **相同**：不改动；
  - **较旧**：拒绝覆盖，保留已存新版；
  - 序列号之差恰为 **2³1**：RFC 1982 未定义先后，拒绝写入。
- 验签失败、断流、超时、进程中断均不触碰已存版本；SQLite 为 WAL 模式，
  两个 Web 进程共享同一数据库文件，**重启后副本保留**。
- 每次尝试（含失败原因、观测到的序列号）写入 `attempts` 审计表。

### 页面（`app/main.py` + `templates/`）

- 展示每个区域的 **SOA 序列号、记录数、AXFR 报文数、更新时间**。
- 任务表展示运行/成功/失败状态与**失败原因**。
- 每个已存副本提供 **zone 文件下载**（标准 RFC 1035 master 格式，
  `Cache-Control: no-store`），可直接用于恢复。
- 备份目标只来自启动配置，浏览器无法指定任意服务器或密钥。

## 快速开始（Docker Compose）

```bash
docker compose up --build -d
# 浏览器入口（仅绑定回环地址）
open http://127.0.0.1:8080/        # Linux 可改用 xdg-open
```

Compose 包含两个服务：

| 服务 | 作用 |
| --- | --- |
| `auth-dns` | 本地权威源，TCP 5301–5305 五个监听，分别对应五个演示场景 |
| `web` | 备份控制台，uvicorn **两个 worker 进程**，数据写入持久卷 `backup-data` |

停止与清卷：

```bash
docker compose down            # 保留备份数据
docker compose down -v         # 同时删除备份卷
```

## 演示剧本（首页按钮一一对应）

1. **多报文完整传输（multi, 5301）**：区域含 66 条记录，AXFR 被拆成 4 个
   TCP 报文，TSIG 多报文链逐报文核验；成功后显示序列号、记录数与报文数，
   可下载 zone 文件。
2. **末报文签名损坏（badsig, 5302）**：末报文 MAC 被篡改，验签失败并显示
   「第 N 个报文 HMAC-SHA256 签名不匹配」，旧版保持不变。
3. **传输中断流（truncated, 5303）**：服务器发出首报文后关闭连接，缺少
   收尾 SOA 与末签名，判定断流并保留旧版。
4. **服务器超时（timeout, 5305）**：只收不发，客户端 5 秒总时限到期报超时。
5. **旧版本延迟完成（stale, 5304）**：先备份 multi 得到新版；再备份 stale，
   传输本身完整但延迟约 2.5 秒，提交时按 RFC 1982 判定序列号较旧而拒绝，
   已存新版不动（页面会同时显示「观测到的旧序列号」与拒绝原因）。

## 启动配置

| 环境变量 | 说明 | 默认 |
| --- | --- | --- |
| `BACKUP_DB` | SQLite 路径 | `/data/backup.db` |
| `BACKUP_FILES_DIR` | zone 文件目录 | `/data/zones` |
| `BACKUP_ZONE` | 区域名 | `backup.test.` |
| `BACKUP_SERVER_HOST` | 权威服务器主机 | `auth-dns` |
| `BACKUP_TSIG_KEY_NAME` | TSIG 密钥名 | `backup-key.backup.test.` |
| `BACKUP_TSIG_KEY_SECRET` | base64 编码的 HMAC-SHA256 密钥 | 内置演示密钥 |
| `BACKUP_TARGETS` | 自定义目标列表（见下） | 五个内置场景 |

`BACKUP_TARGETS` 为换行或逗号分隔的条目，格式：

```
id|显示名|主机|端口|区域|密钥名|base64密钥
```

后两个密钥字段可省略，回退到 `BACKUP_TSIG_KEY_NAME/SECRET`。

## 本地直接运行（不用 Docker）

```bash
pip install -r requirements.txt

# 1) 本地权威源（五个场景端口 5301..5305，可用 --port-base 改基址）
python3 -m app.auth_server --host 127.0.0.1

# 2) Web 控制台（两个进程）
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 2
```

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 备份控制台页面 |
| GET | `/healthz` | 健康检查 |
| GET | `/api/targets` | 启动配置中的备份目标（不含密钥） |
| GET | `/api/zones` | 已存副本的序列号/记录数/报文数 |
| POST | `/api/backups/{id}` | 异步触发备份（202，网络等待在后台线程） |
| POST | `/api/backups/{id}/sync` | 同步触发（旧版延迟演示与测试使用） |
| GET | `/api/jobs` / `/api/jobs/{job_id}` | 任务状态与失败原因 |
| GET | `/api/attempts` | 历次尝试审计（含失败原因） |
| GET | `/api/zones/{name}/download` | 下载该版本 zone 文件 |

## 测试

```bash
pip install -r requirements.txt
python3 -m pytest -q
```

覆盖：RFC 1982 边界（含 2³1 歧义与序列号回绕）、多报文 TSIG 成功链、坏末签名、
断流、5 秒超时、不支持记录类型、1000 条上限、错误密钥、整版替换与不混版、
旧版/歧义拒绝、无副本直存、重启持久化、并发备份一致性、Web/API 端到端。

## 目录结构

```
app/
  axfr_client.py    # TCP AXFR + 5 秒总时限 + RFC 8945 多报文 TSIG 核验
  serial.py         # RFC 1982 三态比较（newer/equal/older/ambiguous）
  storage.py        # SQLite(WAL)、短事务、原子整版替换、审计表
  service.py        # 编排：先传输后提交，失败保留旧版
  config.py         # 启动配置（目标、区域、TSIG 密钥）
  auth_server.py    # 本地权威源：multi/badsig/truncated/stale/timeout
  main.py           # FastAPI 路由、页面与下载
  templates/ static/
tests/
Dockerfile  docker-compose.yml  requirements.txt
```
