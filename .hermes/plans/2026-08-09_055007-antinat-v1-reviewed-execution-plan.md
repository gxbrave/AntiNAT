# AntiNAT v1 Reviewed Implementation Plan（v0.8 审查修订执行版）

> **For Hermes:** This is the execution authority for AntiNAT v1. Follow milestone gates strictly. Before implementing any Work Package, create a separate 2–5 minute Story/TDD plan under `.hermes/plans/`; do not hand a whole Work Package, protocol adapter, platform port, installer, or release program to one coding agent.

**Goal:** 从零实现一个 Go 编写、轻量、高并发的 Controller（管理面板）+ Agent（节点）系统。Agent 主动连接预先可达的 Controller，在条件允许的 IPv4 网络拓扑上建立 TCP/UDP 公网入口并转发至目标服务；Controller 仅承担管理、版本化 desired state、状态展示和受限 WAN probe 协调，不承载用户业务流量。

**Architecture:** 控制面和数据面严格分离。Controller 在一个可配置逻辑 TCP 端口（默认 `3111`）上提供 UI、API、SSE 和 Agent WebSocket，支持 IPv4/IPv6 控制连接；v1 的 Forward ingress 与 target 仅支持 IPv4。Agent 使用 per-Forward actor、Agent-global socket-owning PortRegistry、正交运行状态、per-Forward applied state、显式删除 tombstone 和 durable control inbox/outbox。PCP、NAT-PMP、UPnP 与 STUN 作为可组合 layer，而不是互斥“打洞模式”。公网端点只能被描述为“从指定独立 vantage 验证可达”，不能承诺任意 NAT 或任意互联网来源均可直连。

**Tech Stack:** Go（现有计划暂定 `go 1.26.0` + `toolchain go1.26.5`，M0 必须重新核验官方版本、checksum 和 CI image 后冻结）、`net/http`、Go templates + 原生 HTML/CSS/JS、SQLite（Controller）、bbolt（Agent）+ 独立 terminal marker、WebSocket、Ed25519、STUN RFC 8489、PCP RFC 6887、NAT-PMP RFC 6886、UPnP IGD、systemd、OpenRC、Windows Service、GitHub Actions。Natter 仅作为原理参考；Apache-2.0 项目不得复制或改写其 GPL-3.0 源码。

---

## 0. 文档地位与开工判定

### 0.1 文档地位

- 原计划保留：`.hermes/plans/2026-08-07_115401-antinat-v1-implementation-plan.md`。
- 本文件是三路专项审查后生成的 **v0.8 执行版**，后续实施以本文件为准；原 v0.7 仅作为详细设计背景，不得用其中与本文件冲突的旧语义通过验收。
- 原始需求仍是 `antinat.txt`，但所有可行性缩减必须先固化到版本化 requirements traceability 和 ADR。
- 本次未修改任何业务代码；当前仓库仍只有需求和计划。

### 0.2 审查结论

项目在明确边界内 **可行**，但当前只能判定为：

```text
ARCHITECTURE: FEASIBLE
START_TASK_0_AND_M0_PREPARATION: GO
START_M1_PRODUCT_CODE: CONDITIONAL NO-GO
START_FULL_UI/INSTALLER/WINDOWS_GA/PERFORMANCE_CLAIMS: NO-GO
```

解除 M1 的条件：M0 所有阻断 spike、机器可读协议契约、状态/恢复契约和资源清单通过；每项结果必须为 `PASS` 或被明确降级为 `SUPPORTED_WITH_LIMITS/UNSUPPORTED`。不得用 TODO、仅交叉编译或仅 fake server 掩盖 NO-GO。

### 0.3 可立即开始与不可立即开始

可以立即开始：

1. Task M0-01：scope、requirements traceability、LICENSE、module path、支持矩阵；
2. Task M0-02：Git、toolchain、最小 CI、证据 schema；
3. 预约真实 Windows、独立 WAN vantage、真实路由器/协议 daemon、arm64/OpenRC 和性能实验室资源；
4. 为 M0 spike 编写单独 Story/TDD 计划。

M0 通过前禁止开始：完整 UI、全量 SQLite schema、完整 installer、所有 traversal adapter 并行开发、Windows GA 宣传、JS runner 发布、2 Gbps/`<1 ms`/zero-copy 宣传。

---

## 1. v1 范围与需求差异基线

| 原始目标 | v1 执行基线 | 原因 |
|---|---|---|
| 任意 NAT 都可打洞直连 | 仅在 NAT/filter/firewall/显式 mapping 允许时直连；失败是正常 capability 结果 | STUN 映射不等于入站开放；对称 NAT、严格 CGNAT 可能必须 Relay |
| Controller + Agent | 保留；Agent 主动连接用户预先提供的 Controller endpoint | 控制入口不依赖 AntiNAT 自己的打洞 |
| Controller 不转发业务 | 强制保留 | 独立控制/数据故障域；未来 Relay 只能是独立公网 Agent 角色 |
| 完整 IPv4/IPv6 双栈 | v1 控制面双栈；Forward ingress/target IPv4-only；IPv6 数据面进入 v2 | NAT66、IPv6 firewall pinhole、PCP IPv6 是独立工程 |
| 添加/修改/删除都不断连 | 添加和普通 target/显示修改不影响其他 Forward；target 修改仅影响新 session；删除是立即中断例外 | 删除若保留连接，不满足“删除即停” |
| 修改限速/详细统计立即生效且不断连 | v1 固定为 `NEW_SESSIONS_ONLY`；可选 `disconnect_existing=true` 强制立即生效 | 已在 `io.Copy` 中运行的连接无法无损插入 limiter/counter |
| 尽可能零拷贝 | Linux TCP、无限速、详细统计关闭时为 `splice-eligible`；是否实际 splice 由实验室证据证明 | 标准库不提供逐 activation 的精确 splice/fallback 计数 |
| UDP 零拷贝 | 不承诺；单 ingress socket + bounded buffers/session table | UDP 路径和业务语义不适合宣传严格零拷贝 |
| JavaScript/脚本 DDNS | v1 为 webhook + 强隔离 JS runner；任意 local shell/local executable 不进入 v1 | 避免 RCE、OOM 和跨 Forward 故障 |
| HTTPS 开关 | 仅控制发布链接 scheme，不签发/托管 TLS | `https://` 文本不等于目标拥有合法证书 |
| 自动用 ip.sb 拼 Controller 地址 | 只显示“未验证候选公网 IP”；部署命令使用管理员显式确认的 `controller_endpoint` | 公网 IP 不证明端口可达，也不代表反代/tunnel URL |
| 一键部署命令包含 token | 安装命令与 token 分离：一个安装命令 + TTY 隐藏输入；非交互只接受 FD/0600 文件 | token literal 进入命令会泄露到 shell/PowerShell history |
| 用户内容中英双语 | 系统 UI 文案中英双语、默认中文；v1 用户自定义名称/简介保存单值 | 消除原计划单值与双语字段冲突 |
| Linux/Windows/Docker | Linux amd64/arm64 为目标；Windows amd64 仅在实机门禁通过后 GA；Docker 为 Linux host-network Beta，必须有完整 OCI 交付链 | cross-build 或一条 docker 命令不等于平台支持 |

v1 非目标：任意 NAT 保证直连、Controller 业务 Relay、IPv6 数据面、macOS、Windows container、RBAC/HA、自动无人值守升级、任意 shell、内置 DDNS provider、内核态 nft 快速路径。

---

## 2. 网络成功语义：必须拆成正交事实

### 2.1 禁止单一 `ACTIVE` 承载所有事实

每个 Forward 持有稳定 `forward_id`；每个 activation 持有独立 `activation_id`、generation、spec revision。持久状态至少分为：

```text
control_state:
  ONLINE | OFFLINE

listener_state:
  STOPPED | STARTING | READY | ERROR

mapping_state:
  NOT_REQUIRED | ACQUIRING | FIRST_HOP_MAPPED |
  PUBLIC_CANDIDATE | LOST | ERROR

keepalive_state:
  NOT_REQUIRED | HEALTHY | DEGRADED | LOST

wan_reachability_state:
  NOT_TESTED | PROBING | OPEN_FROM_VANTAGE |
  REJECTED | TIMEOUT | NO_INDEPENDENT_VANTAGE |
  PROBE_INFRA_UNAVAILABLE | UNKNOWN

return_path_state:
  NOT_TESTED | VERIFIED | FAILED | UNKNOWN

target_health_state:
  PASS | FAIL | SKIPPED | UNSUPPORTED | UNKNOWN

publication_state:
  NONE | PUBLISHED_VERIFIED | PUBLISHED_UNVERIFIED |
  STALE | UNPUBLISHED

data_plane_state:
  STOPPED | READY | DEGRADED | ERROR
```

UI 可以计算聚合状态，但聚合值不是协议事实，不能覆盖上述字段。

### 2.2 “打洞成功”与“业务端到端成功”分开

- `PUBLIC_CANDIDATE`：STUN/explicit mapping/manual 配置得到候选 global IPv4 endpoint。
- `OPEN_FROM_VANTAGE`：某个指定 probe vantage 能到达 exact endpoint，并完成认证往返。
- `PUBLISHED_VERIFIED`：listener ready、候选端点未过期、独立 vantage 认证往返通过。
- `target_health=PASS`：Agent 本地能连接/请求目标。
- `application_e2e=PASS`：独立 WAN client 的真实业务请求通过 Agent 到 target 并验证特征响应；仅适用于配置了 HTTP/echo 等可验证 fixture 的协议。

Probe frame 被 Agent 消费时只证明 WAN ingress/return path，不证明 backend application。未知协议可显示 `target_health=SKIPPED`，不得冒充应用 E2E。

### 2.3 旧端点撤销

一旦本地证据表明 lease 失效、STUN TCP 断开、observed endpoint 改变、route/interface 改变或 Agent 从 suspend 恢复：

1. 先把旧 publication 原子改为 `STALE/UNPUBLISHED`；
2. 本地持久排队 `EndpointDeactivated`；
3. 再尝试 remap/reprobe；
4. Controller 离线时也不得继续显示旧 endpoint 为 verified；
5. force publish 使用 `PUBLISHED_UNVERIFIED` 和独立 `UnverifiedEndpointPublished` 审计事件，不产生普通 `EndpointActivated/Changed`。

---

## 3. IPv4 traversal 设计

### 3.1 Strategy 是 pipeline，不是互斥模式

```text
direct-v4
manual-static-v4:
  expected_public_endpoint
explicit-gateway:
  mapping_layer: pcp | nat-pmp | upnp-igd
  upstream_discovery: none | stun
  keepalive: protocol-specific
stun-only:
  keepalive: protocol-specific
auto:
  ordered strategies[]
```

`direct-v4` 的成功前提是选定 source interface 本身持有 global IPv4；candidate endpoint 为该 global source IPv4 + actual bound port，再由 WAN probe 验证。若 source 仅为 RFC1918/CGNAT/link-local/reserved，`direct-v4` 返回 `NO_GLOBAL_V4_SOURCE`，不得借助 ip.sb 猜测公网端点。云 1:1 NAT、人工 DNAT、安全组或路由器静态映射归入 `manual-static-v4`，由管理员提供 expected endpoint。

统一步骤：

1. 选定 route/interface/source IPv4；无 IPv4 source/default route 时返回 `V4_SOURCE_UNAVAILABLE` 或 `V4_DEFAULT_ROUTE_UNAVAILABLE`，但 Agent 控制连接仍可 ONLINE。
2. PortRegistry 原子创建并持有实际 socket；不得“试 bind→close→rebind”。
3. 可选获取 explicit mapping layer。
4. 保存每层 control server、internal/assigned endpoint、scope、lease、epoch、ownership strength 和 parent layer。
5. non-global gateway endpoint 只能是 `FIRST_HOP_MAPPED`。
6. strategy 指定时，从同一 source tuple 执行 transport-correct STUN/keepalive。
7. 得到 global candidate 后执行 WAN probe。
8. 仅 `OPEN_FROM_VANTAGE` 可产生 verified publication。

v1 限制为“最多一个 explicit mapping layer + 一个 observed STUN layer”。遇到多 explicit NAT control layer 返回 `UNSUPPORTED_MULTIPLE_EXPLICIT_NAT_LAYERS`，不得错误合并。

### 3.2 Node capability detection

首次上线自动 detection 只运行可自动执行的项目：direct、PCP、NAT-PMP、UPnP、STUN 和组合 pipeline。

`manual-static-v4` **不参与自动 detection**；它始终作为 `USER_CONFIGURED_UNTESTED` 可选项，只有管理员填写 expected public endpoint 后，才对具体 Forward 做 listener + WAN verification。

Detection 默认 sequential；parallel 必须 bounded，每个 attempt 使用不同临时 tuple、operation ID 和清理路径。临时 detection 只能说明 capability，不证明任何正式 Forward endpoint；每条 Forward 必须独立 acquire、keepalive、probe。

### 3.3 每层端口能力，而非一个含糊 `port_policy`

```text
PortControlCapability
  mechanism
  can_request_exact
  can_accept_assigned
  can_retry_candidate
  final_endpoint_constraint
```

- direct：public port 与实际 bound local port 相同，仅由 probe 验证；
- manual：只验证管理员给定 expected endpoint；
- PCP：支持 suggested port 与 `PREFER_FAILURE`；
- NAT-PMP：requested 只是 suggestion，response 才是 assigned；
- UPnP IGDv2 `AddAnyPortMapping`：可返回 reserved port；
- UPnP IGDv1 `AddPortMapping`：不返回 assigned port；`accept_any` 只能做有界随机候选重试，禁止线性扫描全部端口；
- STUN-only：只能观察端口；`strict` 是最终结果约束，不得无界轮换 local port。

layered strategy 分开保存 `gateway_port_policy` 与 `final_endpoint_constraint`。第一跳端口满足 strict，但 CGNAT/STUN 改写最终端口时，必须按 final constraint 决定失败或接受。

### 3.4 Mapping ownership 诚实分级

- PCP nonce：`STRONG_PROTOCOL_OWNERSHIP`；
- NAT-PMP：`WEAK_LEASE_OWNERSHIP`。默认依赖短 lease 过期；仅同一 Agent instance 持续拥有 exact internal tuple 且未 handoff 时主动 delete。v1 的 delete API必须拒绝 `internal_port=0`，绝不提供 delete-all；
- UPnP：`BEST_EFFORT_QUERY_THEN_DELETE`。delete 前重新核对 external port/protocol/internal client/internal port/description；仍需承认 query/delete TOCTOU；
- 第三方或不匹配条目只告警，不删除；
- permanent-only UPnP 默认 unsupported，显式 override 必须显示 crash residue 风险。

Mapping journal 保存 ownership strength，不得把所有机制都宣传为 crash-safe strong ownership。

### 3.5 Provisional renewal/keepalive contract

M0 必须用真实网络验证并冻结默认值；在冻结前采用以下 provisional 值：

- PCP/NAT-PMP/UPnP：请求 3600s lease；在 50% lifetime 附近加入 ±10% jitter 续租；到 expiry safety margin 或确证 epoch/reboot 时立即使 publication stale；
- UDP STUN keepalive：默认 20s、±20% jitter，可配置 10–120s；transaction/source 不匹配不算成功；
- TCP STUN keepalive：默认 60s、±20% jitter，可配置 15–300s；TCP 断开立即使该 mapping candidate 失效并重建；
- 三次连续 keepalive/renewal 失败只进入 `DEGRADED`；到安全余量、明确连接断开、mapping changed 或 lease expired 才进入 `LOST`；
- suspend/resume、默认路由变化和 source IP 变化不沿用旧验证，直接 stale + revalidate；
- 所有 deadline 用 monotonic clock；墙钟仅用于日志。

若公共 STUN server 的可接受频率低于默认值，应由 endpoint health/cooldown 调整，不得持续高频重试。

---

## 4. Socket ownership 与数据面

### 4.1 Agent-global PortRegistry

PortRegistry key：`(family, protocol, concrete source address, local port)`，并检查 wildcard/specific overlap。

强制规则：

1. `Acquire` 在 registry 临界区内创建并 bind/listen 实际 socket；port 0 由 OS 原子分配后读取 actual port；
2. registry entry 持有实际 FD/handle、owner ID、generation 和 SocketSet；actor 不能自行 close 非自己持有的 socket；
3. 一个 tuple 只有一个 listener/ingress owner；普通 listener 不用 reuse 绕过冲突；
4. stale release 必须携带 owner generation，不能关闭新 owner；
5. Agent 进程使用 OS 级单实例锁；升级默认 stop-old-before-start-new，除非后续有经实测的 FD/handle handoff ADR；
6. Controller partial unique index 只用于提前报错，Agent 持有 OS socket 才是最终所有权；
7. M0 必须测试另一个同 UID 进程、旧 Agent 迟退、崩溃重启和 installer 并发启动。

### 4.2 TCP shared-port

- 每个 tuple 永远只有一个 listener owner；
- production keepalive 默认只有一个 primary connected TCP STUN connection；
- capability detection 若要比较两个 STUN destination，第一条连接保持 ESTABLISHED，再从同一 local tuple 建第二条 remote 4-tuple；只有 Linux/真实 Windows spike 证明 listener + 多 connected sockets 分流确定，才记录 `EIM_OBSERVED_CONCURRENT`；
- 平台不支持并存时，顺序结果只能记录 `PORT_REUSE_OBSERVED/MAPPED_UNVERIFIED`，不得宣称 EIM；
- shared-port spike 不通过，只禁用 `stun-tcp-shared-port`；manual/direct/explicit gateway TCP 不应被连带禁用；
- TCP forwarding 必须正确处理 half-close。

### 4.3 UDP single-socket

一个未连接 ingress `UDPConn` 同时处理 STUN、keepalive、probe 和业务数据：

- STUN 只按 outstanding transaction ID + exact server tuple + class + deadline 消费；
- probe 只按 provider signature/source + probe ID + activation + endpoint + challenge 消费；
- 来源端点本身永远不能决定一包是 keepalive；keepalive 使用可严格匹配的 STUN transaction/明确 control frame；
- 其他 payload 全部进入 bounded UDP session table；
- target 回复必须通过原 ingress socket发回，保证 published source port；
- 使用 truncation-aware read 和受限 65,507-byte buffer pool；截断包丢弃并计数；
- 限制全局、per-source sessions、FD/handle、buffer bytes、ephemeral ports 和 churn；
- Windows 专项测试 `WSAECONNRESET/SIO_UDP_CONNRESET`；UDP `REJECTED` 只能来自能关联 quoted original tuple/transaction 的 ICMP 证据。

### 4.4 TCP data path 与可观测性

默认 Linux unlimited/stats-off 使用裸 `*net.TCPConn` + `io.Copy`，但 UI/API 只能报告：

```text
data_path = go_tcp_copy_splice_eligible
zero_copy_evidence = eligible | lab_verified | runtime_observed | not_applicable
```

在没有自定义可观测 splice ADR 前：

- 不报告 `zero_copy_active=true`；
- 不报告逐 activation 精确 `splice_bytes/buffered_fallback_bytes`；
- `strace/eBPF` 证据只进入 lab/release evidence；
- 对每个 eligible 连接仍按标准库可能 fallback 的最坏情况预留内存预算；不能假设 hidden fallback buffer 自动受 `sync.Pool` 控制。

若以后需要运行时精确 splice/fallback byte accounting，必须先通过 ADR 和 benchmark 再实现自定义 fast path。

### 4.5 限速/详细统计更新语义

v1 固定：

```text
rate_or_stats_update_effect = NEW_SESSIONS_ONLY
```

启用或修改后：

- 新连接/新 UDP session 使用新 limiter/statistics path；
- 既有连接继续原 path；
- API 返回 `legacy_connection_count`、`fully_effective=false`；
- 所有旧 session 结束后才为 `fully_effective=true`；
- 管理员若选择 `disconnect_existing=true`，可以立即生效，但 UI 必须明确会断连。

---

## 5. WAN probe：无裸 accept、无预共享 challenge、无扫描 oracle

### 5.1 Vantage 语义

- `controller-local` 默认 `NO_INDEPENDENT_VANTAGE`；只有管理员显式登记 topology、固定 egress 和证据后才可作为一个 named vantage；
- 自动比较公网 IP/traceroute 只能提供诊断，不能自动升级为 independent；
- provider egress IP 必须与该 tuple 用过的 STUN/keepalive destination IP 不同；Agent 不得从被测 tuple 向 provider 预热；
- 成功状态命名为 `OPEN_FROM_VANTAGE`，不是“全球开放”；
- GA 至少使用一个额外普通 WAN client，与 provider/STUN server 均不同，执行真实应用交叉验证；
- `antinat-probe` 是“无持久业务状态”，但必须保留 TTL nonce replay cache、rate bucket、concurrency state 和审计摘要。

### 5.2 两阶段 arm + provider-hidden challenge

1. Controller 创建 `probe_operation`，向 Agent 发送 `probe_arm`：只包含 probe ID、provider ID/public key、expected source policy、activation、exact endpoint 和 TTL；**不包含 provider challenge**。
2. Agent 验证 activation/endpoint 后持久化 outstanding operation，以本地 monotonic deadline 计时，返回 durable `probe_armed`。
3. Controller 只有收到并持久化 `probe_armed` 后才请求 provider；避免 provider 报文早于 Agent gate。
4. Controller 给 provider 的签名请求绑定 node public-key hash、probe ID、activation、exact endpoint 和 provider policy；Provider 生成随机 challenge，签名完整 WAN frame，再连接/发送 exact global IPv4 literal。
5. Agent 只有从实际 ingress 收到并验证 provider frame 后才能知道 challenge。
6. TCP：Agent 在同一 TCP connection 返回 Agent-signed authenticated ACK；UDP：Agent 通过原 ingress socket 从 exact published IPv4:port 返回 Agent-signed/MAC ACK，响应不得大于请求。Provider 用 Controller 请求中绑定的 node public key 验证响应。
7. Agent 同时通过已签名 control channel 发送 `probe_ingress_receipt = Sign(node_key, challenge_hash + probe_id + activation + endpoint + provider)`。
8. Provider 验证 same-path ACK 并把 signed result 返回 Controller。
9. Controller 只有 join 到同一 operation 的 provider result + Agent control receipt，且 endpoint/activation/challenge/TTL 全部匹配，才记录 `OPEN_FROM_VANTAGE` 和 `RETURN_PATH_VERIFIED`。

禁止：裸 TCP accept、仅 TCP connect、仅 `sendto()`、仅 Agent control ACK、未认证 nonce成为 OPEN。

TCP 初次 activation 使用 verification-only gate，普通业务连接在发布前可被明确拒绝。ACTIVE endpoint 的重验证不得让所有业务连接进入前缀嗅探：只有 remote source IP 命中已 armed、稳定且预先声明的 provider egress policy 时，listener 才在有界 deadline 内解析 probe frame；其他来源直接进入正常业务转发。provider source 不稳定或不可预知时，使用 shadow public port（若 strategy 支持）或返回 `REVALIDATION_UNSUPPORTED_WITHOUT_TRAFFIC_RISK`，不得静默破坏 server-first/slow-client 协议。

### 5.3 Anti-scan

- provider 是 operator-owned/pinned 服务，不提供公共匿名多租户接口；
- 请求只接受 Controller key 签名、已登记 provider tenancy、global IPv4 literal、fixed frame；拒绝 DNS、private、CGNAT、loopback、link-local、multicast、reserved 和 metadata；
- 未经管理员授权的 manual endpoint 不 probe；automatic candidate 只能走固定 bounded probe 流程；
- 对 Agent 返回统一结果，不能泄露 victim 的 RST/TIMEOUT/timing 细节；详细 provider diagnostics 只供授权管理员审计；
- per-controller/node/endpoint rate、并发、payload、timeout 和每日预算均需硬限制；
- 即使 Agent 恶意，也无法提前知道 challenge 并伪造 control receipt；它只能在真实收到 ingress frame 后回答。

### 5.4 Probe expiry

- control command 使用 `ttl_ms` + opaque `expiry_bytes`；
- Agent 收到合法 arm 后以 monotonic clock建立 deadline，不用墙钟解释 absolute expiry；
- WAN frame必须原样匹配 opaque expiry；
- provider/Controller用自己的可信时钟验证 absolute expiry；
- Controller只在 operation deadline 内聚合双边结果。

---

## 6. Control protocol、Enrollment 与 durable delivery

### 6.1 Normative wire frame

`docs/protocol.md` 和 golden fixtures 必须冻结：

```text
magic
wire_version
protected_header_length
payload_length
protected_header_bytes
raw_payload_bytes
signature
```

protected header 至少包含：

```text
protocol_domain = "AntiNAT-Control-v1"
controller_instance_id
node_id
controller_key_id
agent_credential_version
connection_epoch
session_id
direction
sequence
message_id
message_type
schema_version
payload_length
payload_sha256
```

- header 使用固定二进制编码或冻结的 canonical CBOR/protobuf；不得依赖普通 JSON map serialization；
- Ed25519 签名 `domain || protected_header || payload_hash`；
- 先验证 framing、长度、hash、key ID、credential version、signature，再严格解析 payload；
- JSON payload 若保留，必须拒绝 duplicate key、unknown field、过深嵌套、越界数字和 oversize；
- 同 message ID + 同 type/hash 返回缓存结果；同 ID + 不同 type/hash 关闭 session 并审计；
- outbox 保存 semantic payload，不保存旧 session 的完整签名 frame；重连使用同 operation/message ID 重新 envelope/sign。

消息至少包含：desired、desired result、forward delete command/ack、node decommission command/ack、message receipt、operation complete、probe arm/armed/ingress receipt/result、controller/agent key rotation prepare/ack/commit、restore reconcile request/result、heartbeat/status/traffic。

### 6.2 Enrollment transcript

1. Controller 返回 pinned-key signed `EnrollChallenge`：controller instance/key ID、node ID、server nonce、protocol versions、expiry；
2. Agent 生成 Ed25519 key，发送包含 challenge hash、Agent nonce、public key、token、capability hash 的 `EnrollRequest`，并用新 Agent key做 domain-separated signature 证明 possession；
3. token consume、credential bind、enrollment result ID 同一 SQLite 事务；
4. Controller 返回 signing-key signed `EnrollResult`，绑定 node、Agent key hash、credential version、Controller key ID；
5. response 丢失后，同 node + 同 key + possession proof 可返回原 binding result/直接 connect；不同 key 统一失败并审计；
6. 已注册节点不能用普通 enrollment token重绑 key，只能走 credential rotation/recovery；
7. token 默认不出现在生成命令、shell history、argv、env、service、config 或日志。安装命令后由 TTY hidden prompt 输入；noninteractive 只接受 FD/0600 file 并在 consume 后删除。

### 6.3 双向 connection epoch fencing

Controller 和 Agent 都必须持久化 epoch：

- Controller：`current_connection_epoch/current_session_id`；
- Agent bbolt：`controller_instance_id/max_accepted_connection_epoch/current_session_id`；
- Agent 收到更高 epoch handshake final 后，先 fsync/persist，再启用新 socket并关闭低 epoch socket；
- 所有 command 在进入 inbox 前检查 current epoch/session；
- Controller inbound DB mutation 和 outbound claim 都带 epoch/session CAS 条件；
- stale goroutine 即使没退出也不能写状态、消费 outbox或执行 side effect；
- v1 禁止从同一 Controller state/backup 同时启动两个实例；clone/split-brain fail closed。

### 6.4 Durable inbox/outbox 与 side-effect FSM

```text
Controller/Agent Outbox:
  PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED -> GC

Inbox/Operation:
  RECEIVED -> INTENT_PERSISTED -> APPLYING -> APPLIED | NACKED
```

- `SENT` 只表示 socket write；
- receiving side 持久化 semantic result 后发送 ACK；发送 side持久化 ACK 后返回 `message_receipt/operation_complete`；原 side 收到 durable receipt 后才 GC；
- operation ID 负责跨 message delivery 的语义幂等，message ID 负责一次连接内 delivery 去重；
- delete/decommission/rotation/restore 需要 phase journal，外部 side effect 前先持久 intent；
- 旧 epoch ACK 被拒后，新 session以同 semantic result重新签名发送，不重复 side effect；
- hello 交换 desired high-water、pending operation results、Forward tombstone digest/list、credential/key generations、outbox cursors；
- 全量 snapshot 中“缺失 Forward”绝不自动删除；删除必须携带显式 `desired_presence=ABSENT + deletion_operation_id`。

---

## 7. Agent LKG、删除与恢复

### 7.1 AppliedForwardState

`last_applied_spec` 扩展为：

```text
AppliedForwardState
  forward_id
  spec + spec_revision + desired_revision
  actual bind/local tuple
  assigned gateway/public port(s)
  strategy/layer version
  activation recovery descriptor
  mapping journal references
  hook definition/secret versions
  applied_at
```

不持久化可直接恢复为真的 `healthy/WAN_VERIFIED`。正常进程重启后可以恢复 listener/mapping，但状态先为 `RECOVERING/UNVERIFIED_AFTER_RESTART`；重新 independent probe 前不发布、不触发 Activated/Changed。

### 7.2 Forward delete

Controller 同一事务：

1. `desired_presence=ABSENT`；
2. increment desired revision；
3. create `forward_deletion_operation`；
4. write control outbox。

Agent：

1. durable inbox + operation intent；
2. bbolt 事务写 `forward_delete_tombstone`；
3. stop listener、active TCP、UDP sessions；
4. best-effort release mapping；
5. 删除 received/applied state；
6. durable result + ACK；
7. 只有 Controller durable receipt/high-water 足够后才 GC tombstone。

Agent 离线时 UI 显示 `DELETE_PENDING_OFFLINE`；Controller 不得声称远端已停。

### 7.3 Node decommission

- terminal marker 与 reconcile 使用同一排他 latch；marker 开始写入后，并发 desired apply 不得启动新 actor；
- Agent 先 fsync+rename+parent fsync 写 `DECOMMISSIONING`，再停止全部 Forward；
- 清理 LKG、hook secrets、jobs 后写 `DECOMMISSIONED`；
- ACK 丢失时保留最小 node private identity、operation result 和 ACK outbox，直到 Controller durable receipt；不保留 Forward LKG/secret；
- cleanup tombstone 保存 rotation overlap 中所有允许的 Agent key hashes/credential versions；
- normal delete 等 ACK；force delete 立即从常规 UI 移除但 `remote_cleanup_confirmed=false`，旧 Agent只允许 cleanup-only session。

Hook 语义：Forward delete 的 durable event 可以继续 at-least-once；Node decommission/uninstall 为有界 best-effort，deadline 后必须清 secret并标 `DROPPED_DUE_TO_DECOMMISSION`，不能承诺永久 at-least-once。

### 7.4 Backup/restore anti-rollback

备份 manifest 包含 backup/controller instance ID、schema/protocol version、desired/deletion/tombstone high-water、current key IDs、每个文件 hash/权限、Agent marker/outbox high-water。备份与 migration/key rotation 使用 barrier。

Restore：

1. 解到新 state dir；
2. 校验 manifest/hash/ACL、SQLite `quick_check/integrity_check/foreign_key_check`、keys 和 bbolt；
3. 全部成功后原子切换；
4. Controller 进入 `RESTORE_RECONCILIATION`：失效 web sessions、unused enroll tokens、probe operations；节点 quarantine，不自动下发 desired/delete/rotation；
5. Agent hello 上报 high-water/tombstones/results/key generations；Controller把新 revision提升到 Agent high-water以上并合并删除事实；无法确定的节点需管理员显式 reauthorize；
6. Agent 从备份恢复进入 `RECOVERY_QUARANTINE`，不自动恢复 LKG listener；必须获得 Controller recovery authorization；当前磁盘 terminal/uninstall marker永远不能被旧备份覆盖。

必须在 threat model 明示：如果攻击者掌握旧 Controller signing private key 和完整备份，纯软件 Agent 无法完美区分合法灾难恢复与恶意 rollback；强 anti-rollback 需外部 WORM/TPM/HSM 或人工 out-of-band approval。

---

## 8. Hook sandbox 与密钥生命周期

### 8.1 v1 Hook 边界

v1 schema/UI 只允许 webhook 和 isolated JavaScript；删除原 v0.7 Forward 表单中的 `local script hook`。

Linux runner 最低门：专用 UID、sanitized env、无继承 FD、`NoNewPrivileges`、独立 net namespace、空/只读 mount namespace、seccomp 禁止 socket/connect/execve/ptrace/mount，可用时 Landlock。

Windows runner 最低门：restricted token 或 AppContainer、无 network capability、Job Object、不可写目录 ACL、无继承 handle。只有 Job Object 不算通过。

任一平台达不到最低门，JS capability 为 `UNSUPPORTED`，v1 退化为 webhook-only。

### 8.2 Broker

- runner 不直接访问 network/files/process/secret；
- `secret.sign` 不能对任意 bytes 做 HMAC；broker只对已校验、规范化的最终请求签名，capability绑定 hook ID、secret ID、algorithm、scheme/host/port/path/action/max calls；
- 默认 HTTPS、TLS verification on、redirect off；启用 redirect时逐跳 allowlist/DNS重验，跨 origin 删除 Authorization/signature；
- 忽略 proxy env；校验全部 A/AAAA，任一受限地址即拒绝；pin实际 IP并保留 SNI/Host；
- 拒绝 userinfo、zone、混合编码 IP、危险 IDNA/尾点歧义、CRLF 和 Host/Content-Length/Transfer-Encoding/Connection 等 header；
- 限制压缩前后 response bytes，防 gzip bomb；
- queue 满时按 versioned policy coalesce/drop/DLQ并审计，不静默丢失。

### 8.3 Keyring rotation

Controller signing key、Agent key、Controller master encryption key、Agent hook encryption key和 probe pinned key都使用持久 operation FSM：

```text
PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED
```

Controller key rotation certificate由 old key签名，绑定 old/new key ID、公钥、generation、not-before、overlap deadline。Agent fsync新 pin set后ACK，并持久最高 generation 防 downgrade。离线未ACK节点阻止正常 retire；force retire 后需人工 repin/re-enroll。

ciphertext 保存 `key_id`；master/hook key rotation先新写用新 key，再后台 rewrap，所有记录校验且备份含新 key后才 retire old。rotation 与 backup/decommission/force-delete必须互斥或由 operation journal协调。

---

## 9. 数据模型与 API 契约

### 9.1 Controller SQLite 最小完整表集

必须补上 v0.7 缺失项：

```text
controller_instances
users
web_sessions
api_idempotency_keys
admin_events                 # durable SSE Last-Event-ID
admin_audit_logs
global_settings
nodes
node_enrollment_tokens
node_credentials
node_traversal_profiles
node_traversal_results
node_deployment_profiles
node_deletion_operations
node_cleanup_tombstones
forwards                     # stable parent + current_activation_id
forward_specs
forward_activations
forward_runtime_status
forward_deletion_operations
forward_endpoint_events
control_outbox
control_inbox
probe_providers
probe_operations
probe_results
navigation_categories
navigation_items
hook_definitions
hook_secrets
hook_deliveries
traffic_ingest_cursors
traffic_rollups
key_rotation_operations
restore_operations
schema_migrations
```

关键规则：

- `forwards.current_activation_id` 和 `nodes.current_connection_epoch/session_id` 用事务 CAS；
- deletion/cleanup rows 不被 node/forward cascade误删；
- idempotency row 保存 route、principal、key、request hash、response/status、expiry；同 key不同 request返回 conflict；
- SSE 使用 durable monotonically ordered `admin_events`，不是内存广播代替 Last-Event-ID；
- exact tuple partial unique index只做预检；wildcard overlap和OS ownership由Agent验证；
- stop/delete/decommission在低磁盘策略中优先；
- SQLite backup只能用 Backup API/`VACUUM INTO`，不能只复制WAL主文件。

### 9.2 Agent bbolt buckets

```text
meta/schema
controller_pins
connection_epochs
control_inbox
control_outbox
received_desired
applied_forwards
forward_delete_tombstones
activation_recovery
mapping_journal
hook_queue
keyring
operation_results
```

terminal marker独立于bbolt并优先加载。bbolt schema需要version/migration/rollback测试。

### 9.3 Normative API

`§11 管理 API` 不再是“建议”；M0必须创建 `api/openapi.yaml` 和 `docs/error-codes.md`，冻结 pagination/filter/sort、ETag、Idempotency-Key和错误码。

至少包含：

```text
GET  /healthz
GET  /readyz
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me

GET/POST/PATCH nodes
POST nodes/{id}/enrollment-token
POST nodes/{id}/traversal-detection
PUT  nodes/{id}/traversal-defaults
POST nodes/{id}/delete
GET  node-deletions/{operation_id}

GET/POST/PATCH forwards
DELETE forwards/{id}
GET  forward-deletions/{operation_id}
POST forwards/{id}/retry
POST forwards/{id}/force-publish
POST forwards/{id}/force-cutover

CRUD navigation categories/items + order
CRUD hook definitions/secrets
GET/POST hook deliveries/{id}/retry
GET audit/traffic/events(SSE)
GET/PUT settings
```

所有资源修改使用 ETag/`If-Match`；缺失为 428，revision mismatch为412，端口/状态冲突为409。创建使用持久 Idempotency-Key。

### 9.4 Normative UI/UX 产品契约

整体采用 **Operate** 模式，不做营销式大屏。白色/近白画布、安静的结构层级、紧凑但不拥挤的数据布局；M4 写代码前先创建 `docs/ui-design-direction.md`，冻结 4–7 个语义色 token、中文/英文字体栈、type scale、spacing/radius/elevation/motion token，并通过 design critique 后才实现。AntiNAT 的单一视觉签名是有真实含义的“证据链轨道”：在 Forward 详情中以 `Control → Listener → Gateway/Mapping → STUN/Keepalive → WAN Vantage → Target` 展示正交证据和断点；不得把它退化为装饰性步骤条，也不得到处添加渐变、假指标或无意义动画。

公共首页 `/`：白色、简约、扁平卡片式网址导航；桌面端左侧分类，移动端改为可横向滚动分类；卡片显示单值名称、简介、协议、状态和跳转按钮；右上角设置入口进入 `/admin`。关联 Forward 只有 `PUBLISHED_VERIFIED` 时默认可点击；`PUBLISHED_UNVERIFIED` 必须持续显示风险；offline/stale/failed 卡片置灰、红灯并显示最后已知地址与时间，最后地址只能经显式风险确认复制。全局 private-site 开启时，首页也要求登录。

管理页固定四个主 Tab：

1. **首页设置**：分类和卡片 CRUD、拖拽排序、关联已有 Forward、实时预览；用户内容字段 v1 为单值，系统 UI 文案中英双语；
2. **转发设置**：全部/按节点分组；卡片至少显示 name、正交状态、current/last endpoint、target、published URL、strategy layers、gateway/public scope、requested/assigned ports、lease、probe vantage/result、target health、data path、legacy connection count、限速/统计状态和编辑入口；
3. **节点**：名称、OS/arch、control peer、在线状态/心跳、IPv4 data-plane capability、network fingerprint、TCP/UDP strategy results/defaults、测试时间/stale 原因、重新探测、部署、编辑、normal/force delete；
4. **全局设置**：显式 `controller_endpoint`、只读展示 process listen address/port（修改需配置+重启）、trusted proxies、private-site、管理员密码、语言、TCP/UDP STUN 列表、probe provider pin/vantage、默认 detection scheduler、retention、更新策略。

Forward 表单字段：node、单值 name、protocol、IPv4 target host/port、strategy/layers、source interface/IPv4、requested local/public port、per-layer port constraints、manual expected endpoint、rate limit、detailed stats、publish scheme、published host、custom URI template、health check、webhook/isolated-JS hook。UDP/非 Web 服务默认不生成 HTTP URL；`https` 仅改变 scheme，并明确不会创建证书。表单按 Agent OS/capability 禁用不支持项；删除按钮必须写明会立即关闭 listener/连接/session，Agent offline 时不能保证立即执行。

节点创建/部署流程：名称可空，由后端生成；请求防重复并检查 HTTP/业务状态；成功后直接进入部署弹窗。部署 profile 保存结构化 JSON，不保存拼接后的命令；字段只保留 AntiNAT 相关项：platform、controller endpoint、bind interface、initial detection scheduler、GitHub proxy、install dir、service name、log level、auto-update policy。展示 Linux、Windows 和 Linux host-network Docker；每个平台使用独立安全 quoting。部署弹窗给出不含 token 的安装命令，并单独一次性显示 token；复制由明确用户操作触发，Clipboard 失败有降级。安装成功、Agent online 后展示 detection 进度，再分别选择 TCP/UDP default strategy；全部失败仍允许保存。

浏览器验收至少覆盖：公开/私有首页、四 Tab、分类拖拽、创建节点→部署→上线→detection、创建/编辑/删除 Forward、ETag 冲突、normal/force node delete、offline/stale 风险、中文/English 长文案、键盘、移动端、loading button 宽度稳定和 clipboard fallback。

生产质量门槛：状态必须同时使用文本+图标/形状，不得只依赖红绿；`UNKNOWN`、`FAILED`、`OFFLINE`、`STALE`、`DELETE_PENDING_OFFLINE` 必须视觉和文案均不同。端口、速率、计数、时间使用 tabular figures。桌面高密度控件 hit area 至少 40×40px，触屏优先 44×44px；支持 semantic HTML、visible focus、dialog focus trap/return、WCAG 2.2 AA、reduced motion、无布局跳动 loading、empty/error recovery、长中英文和窄屏 overflow。normal node delete、force node delete、Forward immediate delete 使用三套后果准确的确认文案，不复用泛化“确定吗”。高级 NAT layers/ownership/evidence 用 progressive disclosure；主列表优先展示当前任务和可恢复错误。动效只用于低频状态切换，必须可中断、≤150ms 或遵循 reduced-motion，且绝不是唯一反馈。

---

## 10. 仓库结构补全

在 v0.7 结构基础上补充：

```text
api/openapi.yaml
cmd/antinatctl/main.go
internal/controller/app.go
internal/agent/app.go
internal/protocol/testdata/control-envelope/
internal/protocol/testdata/probe-frame/
internal/protocol/testdata/enrollment/
internal/install/contract/
test/fixtures/compat/n-minus-1/
test/fixtures/installer-contract/
test/evidence/schema.json
test/e2e/walking_skeleton_test.go
test/e2e/harness/
test/realnet/
scripts/run-release-gates.sh
scripts/verify-evidence.go
.github/workflows/ci.yml
.github/workflows/release.yml
CHANGELOG.md
docs/release-policy.md
docs/recovery.md
docs/error-codes.md
docs/support-matrix.md
docs/requirements-traceability.md
```

必须有 App Composition Story，负责 main→config→keys/store/migrations/hub/router/reconciler装配、signals、readiness、graceful shutdown、startup rollback和进程级 integration；包级测试通过不等于产品可启动。

Docker 若保留 v1 Beta，必须增加 Controller/Agent Dockerfile、OCI labels、non-root runtime、state volumes、Linux `--network host` E2E、image SBOM/signature和release image；否则不得在UI中显示为正式支持。

---

## 11. 里程碑依赖图与 Work Packages

### 11.1 全局规则

- 每个 WP 开工前生成独立 Story/TDD plan；一个 Story只覆盖一个可观察行为；
- 每个 Story写清 blocked-by、exact files、RED command、expected failure、GREEN、focused/full verify、CI lane、timeout、evidence path、cleanup和commit；
- 真实资源失败不靠无限重跑；基础设施重试最多一次，随后保留 logs/pcap/state dump；
- 每个协议 adapter、每个平台和每个 installer 分开 gate；
- spike源码、README、environment manifest和result summary长期保留；大pcap作为带checksum artifact，不在结论后删除。

### 11.2 M0 — 范围、toolchain、feasibility、contract freeze

#### M0-01 Scope/ADR/License

**Files:** `LICENSE`, `README.md`, `docs/requirements-traceability.md`, `docs/v1-scope-contract.md`, `docs/support-matrix.md`, `docs/adr/0001..0004-*.md`。

**Steps:**

1. 初始化Git；不添加remote；
2. 填写最终Go module path/托管owner；未填写不得执行`go mod init`；
3. 固化本Plan第1节差异、删除语义、IPv6边界、Natter clean-room/Apache-2.0、probe语义；
4. 为支持矩阵定义`ga|beta|experimental|build-only|unsupported`；
5. 写变更批准人、日期和以后scope变更流程；
6. `git diff --check`。

#### M0-02 Toolchain/CI/Evidence bootstrap

**Files:** `go.mod`, `Makefile`, `.gitignore`, `.github/workflows/ci.yml`, `test/evidence/schema.json`, `scripts/verify-evidence.go`。

**Gate:** 重新从官方来源核验Go版本、checksum、镜像和Actions SHA pin；现有`go1.26.5`只作为待确认pin。CI至少包含`pr-fast`、`pr-integration`、`windows-pr` job skeleton，固定timeout、runner、artifact retention、concurrency。fork PR不得运行privileged/secret jobs。

#### M0-03 Feasibility spikes（必须分Story/commit）

| Spike | 必须证明 | NO-GO后的降级 |
|---|---|---|
| TCP shared-port Linux/Windows | unique listener + primary/multiple remote connected sockets不随机分流；half-open/restart | 对应平台禁用STUN TCP shared-port |
| Atomic PortRegistry/process | bind/listen原子持有、port 0、第二进程、旧进程迟退 | 禁止同端口热升级；无法保证则阻断Agent |
| UDP single socket/probe ACK | STUN/probe/data严格demux；provider收到exact-source ACK；Windows ICMP不杀loop | UDP capability unsupported |
| Layered NAT | 至少一个真实gateway protocol + upstream STUN；FIRST_HOP不误报 | 只保留实测单层strategy |
| Probe hidden challenge | arm/armed、provider challenge不进control、恶意Agent无扫描oracle | 禁止自动verified publish |
| State crash recovery | SQLite+bbolt+terminal marker、partial apply、old epoch、ACK丢失 | 阻断M1 |
| SQLite driver | static/cross-build、WAL、Backup API、license | 选择通过driver或缩平台 |
| Data path baseline | Linux splice-eligible、pessimistic buffer budget、Windows buffered | 删除zero-copy宣传/缩SLO |
| Hook isolation | Linux namespaces/seccomp + Windows restricted token/AppContainer | v1 webhook-only |
| Windows identity/Defender | service SID/DPAPI或ACL、managed/manual firewall | Windows对应capability beta/unsupported |
| UPnP/NAT-PMP ownership | IGDv1/v2端口行为、NAT-PMP port-0拒绝、weak cleanup | adapter experimental/unsupported |

每个spike必须提供exact command、timeout、OS/build/router、assertions、evidence JSON/path、负责人、批准人和scope fallback。

#### M0-04 Contract freeze

**Files:** `docs/protocol.md`, `docs/state-model.md`, `docs/installer-contract.md`, `docs/test-strategy.md`, `api/openapi.yaml`, protocol/installer/compat fixtures。

冻结：control/enrollment/probe bytes、error registry、Agent bbolt schema、Controller core schema、installer CLI/exit codes/path/service/token input、N/N-1 fixture、release evidence schema。M0-03先于M0-04；spike结果必须改变contract，而不是反过来假定结论。

**M0 exit:** 所有阻断spike PASS或已写入scope降级；fixtures可由空骨架测试解析；module path、真实测试资源和支持下限已登记。

### 11.3 M1 — Linux TCP direct-v4 CLI Walking Skeleton

M1严格CLI-only，明确排除：正式UI/SSE、manual、STUN、PCP/NAT-PMP/UPnP、UDP、Windows、key rotation、force node delete、hooks、limit/stats、Docker。

执行DAG：

```text
M1-01 protocol core
 -> M1-02 controller core DB
 -> M1-03 agent localstate foundation
 -> M1-04 enrollment
 -> M1-05 signed control + durable receipt
 -> M1-06 Linux route + atomic PortRegistry direct listener
 -> M1-07 TCP proxy/half-close/backend snapshot
 -> M1-08 TCP WAN probe hidden-challenge path
 -> M1-09 activation/CAS/publication/online Forward delete
 -> M1-10 minimal admin auth/API + antinatctl
 -> M1-11 app composition
 -> M1-12 walking-skeleton E2E
```

M1 core DB只实现walking skeleton必需表；完整schema在后续expand migration加入，避免一次实现全部表拖垮M1。最小admin API必须有认证，不能为了CLI暴露无认证管理接口。

**M1 E2E exact behavior:** 从空state启动Controller→初始化管理员→CLI创建node→Agent hidden token输入enroll→创建一个Linux direct-v4 TCP Forward→独立provider认证往返→外部client获得target echo特征响应→target热改时旧连接留在旧target、新连接进入新target→重启Agent恢复listener但先UNVERIFIED→reprobe后重新发布→在线DELETE立即断开并ACK→重启不复活。

**Primary command:**

```bash
go test ./test/e2e -run TestLinuxDirectV4WalkingSkeleton -count=1 -v
```

Expected: PASS；失败必须保存Controller/Agent/probe logs、SQLite/bbolt state summary和socket dump。

### 11.4 M2 — Linux TCP traversal Beta

Work Packages：

1. TCP STUN RFC8489 codec/client + golden/fuzz；
2. PCP adapter；
3. NAT-PMP adapter；
4. UPnP IGDv1/v2 adapter与SSDP安全；
5. gateway+same-source-STUN composition；
6. sequential/bounded parallel Node detection（不含manual）；
7. per-Forward manual-static verification；
8. strategy/profile/fingerprint/stale；
9. activation replacement capability与cutover；
10. `22A` Linux netns + real gateway TCP lab。

STUN补齐：CSPRNG transaction、TCP framing/deadline无STUN层重传、UDP retransmit、ERROR-CODE/300、unknown comprehension-required、FINGERPRINT/MESSAGE-INTEGRITY支持边界、persistent keepalive、server cooldown；`stun+tcp://`/`stun+udp://`明确为AntiNAT配置格式。

UPnP补齐：SSDP绑定选定interface、多IGD稳定选择、USN/fingerprint、LOCATION/control URL scope、redirect/response/XML/SOAP size、timeout、设备重启；任意SSDP响应不能把Agent变成通用HTTP client。

每个GA adapter都需要：golden corpus + deterministic fake server faults + 独立真实daemon/reference implementation + 至少一个实际CPE/router/运营商环境。缺实际CPE证据只能beta/experimental。

### 11.5 M3 — UDP + lifecycle Beta

Work Packages：

1. UDP STUN + single ingress mux；
2. UDP sessions/limits/ICMP/MTU；
3. UDP hidden-challenge probe；
4. Forward offline delete完整FSM；
5. normal/force node decommission；
6. Agent-only uninstall notice/receipt；
7. `22B` UDP/deletion/crash lab。

**Exit:** 旧snapshot不复活；decommission marker-before-stop；ACK丢失可重发；UDP target response保持published source；session/FD/buffer/ephemeral exhaustion有界。

### 11.6 M4 — Product/Security feature complete

Work Packages：

1. 完整admin auth/API/OpenAPI/SSE；
2. 白色简约导航首页与管理面板；
3. rate limit + detailed stats（NEW_SESSIONS_ONLY）；
4. webhook；
5. isolated JS runner（只在平台sandbox gate通过时）；
6. hook secret/keyring/rotation；
7. deployment profile + safe command generation；
8. browser/a11y/i18n/security tests。

UI开始前必须按顺序加载并实际使用：`design-critique`、`frontend-design`、safe local `impeccable`、`make-interfaces-feel-better`。系统文案双语；用户内容单值。浏览器测试框架必须在M0冻结，不得写“Playwright或等价”后临时决定。

### 11.7 M5 — Platform/Installer/Operations

Work Packages：

1. installer reference parser；
2. Linux systemd installer；
3. Alpine/OpenRC原生环境；
4. Linux arm64原生；
5. Windows Service/DPAPI-or-ACL/Defender/route/socket；
6. upgrade N/N-1 + expand/contract + rollback；
7. safe purge/manifest handle-relative deletion；
8. Linux host-network OCI Beta；
9. dual-stack control platform matrix；
10. `22C` platform/router/service matrix；
11. release hardening audit。

Linux删除优先使用dirfd/`openat2`/`O_NOFOLLOW`一类handle-relative操作；Windows使用打开handle、reparse检查和file ID，不只做字符串canonicalize。

管理员初始化契约必须包括username、password hidden stdin/file、空值随机生成、`controller init-admin`和recovery。安装结束一次显示随机密码；不写日志。

### 11.8 M6 — Performance/RC/GA

1. pilot决定paired round数量，默认20、不得少于10；按round/block bootstrap；
2. 明确per-client jitter聚合、HTTP payload/方向/keepalive/backpressure、UDP datagram/pps/session模型；
3. M0 baseline后冻结CPU/RSS/FD/handle/每连接内存pass/fail阈值，“只报告”不等于“轻量验收”；
4. Linux/Windows各自direct baseline；未通过平台只影响该平台SLO宣称；
5. 真实WAN只做部署/稳定性，实验室做因果性能；
6. 24h soak、真实NAT矩阵、fresh install/upgrade/purge；
7. tested digest原样晋级release，不允许测试后rebuild；
8. 发布binary/OCI、SBOM、checksums、signature、support matrix和evidence bundle。

---

## 12. CI 与证据门禁

| Lane | 内容 | 关键限制 |
|---|---|---|
| `pr-fast` | gofmt、unit、golden、store、vet/static analysis、cross-build、license | `<10m`目标；无privilege/secret |
| `pr-integration` | enroll/control/LKG/direct TCP、delete、race subset | 固定timeout；失败上传state/log |
| `windows-pr` | Winsock、DPAPI/ACL、Service parser、Defender logic、UDP ICMP | native Windows，不以cross-build替代 |
| `nightly-privileged` | netns、fuzz、installer VM、fault injection | self-hosted隔离；fork PR禁止 |
| `weekly-dedicated` | real router、arm64/OpenRC、Windows service、short perf | 环境manifest + raw evidence |
| `release` | real WAN/NAT、full perf、24h soak、artifact install/purge | 手工批准、不可重建digest |

必需commands（对应功能存在后）：

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
go test ./internal/protocol -run 'Test(ControlEnvelope|Enrollment|Probe)Golden' -count=1
go test ./test/e2e -run TestLinuxDirectV4WalkingSkeleton -count=1 -v
sudo -E go test -tags=netns ./test/integration/... -count=1 -v
GOOS=windows GOARCH=amd64 go build ./cmd/...
./scripts/run-release-gates.sh --evidence-dir ./artifacts/evidence
```

每个evidence JSON至少包含：commit SHA、artifact digest、OS/kernel/build、arch、hardware/router/firmware、command、start/end monotonic duration、result、assertions、logs/pcap hashes、approver、capability promotion。

---

## 13. 性能验收定义

### 13.1 Linux TCP data path

- `go_tcp_copy_splice_eligible`只是代码路径资格；
- release evidence用strace/eBPF和payload hash证明lab运行是否splice；
- 运行时普通UI不虚报精确splice bytes；
- buffered和eligible连接都必须纳入pessimistic memory/connection budget。

### 13.2 Minecraft-like jitter

- 同一client monotonic clock：`e_i = abs((r_i-r_{i-1})-(s_i-s_{i-1}))`；
- 每个client独立计算p99，不用pooled histogram淹没差client；
- primary aggregate及CI方法在M0 pilot后预注册；至少报告p50/p95/max client的p99；
- paired direct/proxy随机顺序，默认20 rounds、至少10；
- `<1 ms`只表述为专用lab中的paired incremental目标；真实Minecraft另做1h smoke，不称认证。

### 13.3 Web throughput

固定协议/payload size matrix、request/response方向、连接复用、100并发、至少两台load generator、backpressure。要求direct payload baseline有足够headroom；原目标保留为proxy平均`>=2.0 Gbps`且`>=80%` paired direct，无payload hash错误，报告1s窗口和最长stall。每个2Gbps×10min run约150GB，完整矩阵必须预先预算网络/存储/时间。

### 13.4 UDP

M0后冻结datagram size matrix、pps、loss、p99、session churn和资源阈值。只报告pps而无pass/fail标准不能称UDP性能验收。

---

## 14. Installer、升级、卸载与发布

### 14.1 安全部署流程

UI生成：

1. 不含secret的安装命令；
2. 单独显示一次enrollment token；
3. installer在TTY隐藏读取token；
4. noninteractive仅接受`--token-fd`或严格ACL的`--token-file`；
5. token消费后安全删除；
6. 测试shell/PowerShell history、`ps`、service、env、config、日志均无token literal。

一行命令内嵌token的“便利模式”不进入默认v1，不得声称无泄露风险。

### 14.2 Artifact trust

冻结release manifest、签名工具、公钥分发、asset URL、checksum和失败exit code。bootstrap下载固定版本manifest+artifact并验签；不能以同一不受信URL中的checksum作为唯一信任根。

### 14.3 Upgrade/rollback

- N/N-1 control和store compatibility；
- expand/contract，destructive contract延后一版本；
- upgrade时冻结状态修改/关键command acceptance，创建一致SQLite/bbolt/keys/config/binary snapshot；
- migration/health失败恢复整个集合，不只binary；
- restore后运行DB integrity、admin login、Agent reconnect和real Forward smoke。

### 14.4 Purge

- Agent在线时发送signed uninstall notice并等待bounded receipt；离线时Controller不能自动认为已卸载；
- Controller purge先normal decommission远端node；离线node需警告/export/explicit force；
- ownership manifest root/SYSTEM ACL + HMAC + installation ID；
- 缺损manifest只删compile-time allowlisted专属资源；
- handle-relative防symlink/reparse TOCTOU；
- offline purge必须定义Controller无法启动、DB损坏、管理员凭据丢失的export/force语义；
- 二次运行报告无残留，不能误删用户反代/TLS/外部文件。

---

## 15. 最终验收标准

### 15.1 网络与功能

- Controller同一逻辑端口在IPv4/IPv6可访问；Agent可经A/AAAA/Happy Eyeballs连接；无IPv4 data path时控制仍online并明确返回V4 capability error；
- Node detection不自动运行manual-static；每条正式Forward独立acquire/probe；
- FIRST_HOP_MAPPED不冒充公网成功；
- TCP/UDP probe均要求same-path authenticated ACK + Agent control receipt；
- successful result是`OPEN_FROM_VANTAGE`，不是任意来源开放保证；
- PortRegistry原子持有socket，第二进程/旧generation不能加入错误reuse组；
- NAT-PMP/UPnP按weak/best-effort ownership报告；绝不发送NAT-PMP internal port 0 delete；
- endpoint loss立即撤销旧publication；
- target热改保持旧connection/session，删除立即中断；
- rate/stats更新明确NEW_SESSIONS_ONLY或显式断连；
- UDP control/data不误分流，response source port正确；
- Linux data path只报告可证实的evidence level。

### 15.2 Control/state/security

- enrollment transcript、同key response-loss recovery、不同key拒绝通过；
- byte-level golden在Linux/Windows/N/N-1一致；duplicate JSON/key、oversize、bit flip在payload解析前拒绝；
- Controller和Agent双向epoch fencing；
- outbox每个crash point最终一次语义生效并可durable receipt/GC；
- snapshot缺失不删除；显式operation+tombstone优先；
- AppliedForwardState恢复actual assigned tuple，但不恢复verified；
- node decommission ACK丢失仍可cleanup-only重发，业务/LKG/secret不恢复；
- probe challenge不出现在control command；恶意Agent不能得到victim端口oracle；
- runner无法socket/file/exec/read env/inherited FD；secret broker不是任意HMAC oracle；
- key rotation、backup restore、force delete并发有phase journal；
- restore进入quarantine/reconciliation，不自动复活备份后的已删资源。

### 15.3 平台与发布

- Linux amd64/arm64、Alpine/OpenRC和Windows amd64只按真实原生证据晋级；
- Windows Defender managed/manual rule、Service identity和router行为通过后才GA；
- Docker只有完整OCI构建、SBOM/sign、host-network E2E后才Beta；
- release artifact digest与测试digest一致；
- fresh install、N/N-1 upgrade、rollback、complete purge和残留扫描通过；
- 2Gbps、jitter、zero-copy、NAT/platform支持只写入README中已对应evidence的项目。

---

## 16. 审查问题关闭台账

| ID | 原问题 | 本版处理 |
|---|---|---|
| NET-01 | TCP/UDP probe成功条件不完整 | 第5节定义arm/hidden challenge/same-path ACK/control receipt |
| NET-02 | controller-local无法自动证明independent | 默认NO_INDEPENDENT；named vantage +额外WAN client |
| NET-03 | one TCP STUN socket与两目的地EIM冲突 | detection临时多connected socket，仅spike通过才EIM |
| NET-04 | PortRegistry bind TOCTOU/第二进程 | socket-owning Acquire +单实例锁+进程测试 |
| NET-05 | 全局port_policy不符合各协议 | 第3.3节per-layer capability/final constraint |
| NET-06 | NAT-PMP/UPnP强ownership夸大 | strong/weak/best-effort分级 |
| NET-07 | 单一ACTIVE混合正交事实 | 第2节正交状态和publication撤销 |
| NET-08 | 标准库无法精确报告splice bytes | eligibility/evidence level，删除虚假runtime counters |
| NET-09 | 限速/统计无法无损热插入 | NEW_SESSIONS_ONLY/显式disconnect |
| SEC-01 | enrollment transcript/response loss缺失 | 第6.2节 |
| SEC-02 | envelope字段/encoding不统一 | 第6.1节normative frame |
| SEC-03 | Agent端epoch fencing缺失 | 第6.3节双向持久fencing |
| SEC-04 | inbox/outbox无durable receipt/phase | 第6.4节FSM |
| SEC-05 | LKG不含actual applied tuple | AppliedForwardState |
| SEC-06 | probe可成为扫描oracle | challenge不下发Agent，统一结果和配额 |
| SEC-07 | runner只有资源限制 | namespaces/seccomp/restricted token/AppContainer |
| SEC-08 | key rotation/restore anti-rollback不完整 | 第7.4、8.3节 |
| ENG-01 | M1与CLI-only v0.1冲突 | M1严格CLI-only，正式UI延后 |
| ENG-02 | Task6/7、9/10、11/12等循环 | 第11节无环DAG并拆包 |
| ENG-03 | 缺forwards/idempotency/SSE表 | 第9节补表 |
| ENG-04 | 缺OpenAPI/error/fixtures | M0-04强制机器契约 |
| ENG-05 | 缺app composition和CLI | 第10节、M1-10/11 |
| ENG-06 | CI/installer/release只描述不可执行 | 证据schema、release workflow、verify脚本和digest promotion |
| ENG-07 | Docker只有命令无OCI交付 | M5完整OCI Beta，否则不展示支持 |
| ENG-08 | UI含local script/i18n冲突 | 删除local script；系统双语、用户内容单值 |

---

## 17. 开工前仍需人工提供/确认的输入

1. 最终Go module path和代码托管owner；
2. 哪台机器/服务作为独立remote probe vantage；若没有，本机模式只能UNKNOWN/force-published；
3. 真实Windows + router、Linux arm64、Alpine/OpenRC、实际CPE/协议daemon和10GbE实验室资源；
4. v1目标OS最低版本，M0 provisional候选需在支持矩阵冻结；
5. release signing key的离线保管方式和release approver；
6. Docker保持Linux host-network Beta，或降为experimental example。

这些输入不阻止Task M0-01写文档和准备资源，但阻止对应capability晋级GA。

---

## 18. 第一阶段执行入口

实施不要从Task 2/完整UI开始。正确顺序：

```text
M0-01 scope/ADR/module path
  -> M0-02 toolchain/CI/evidence
  -> 为每个M0-03 spike生成Story plan并逐个执行
  -> 根据真实结果修改support matrix
  -> M0-04 freeze machine-readable contracts
  -> M0 review: spec compliance + security + evidence audit
  -> 仅全部通过后进入M1-01
```

M0完成后的第一个用户可运行artifact必须是M1 Linux direct-v4 CLI Walking Skeleton，而不是半完成的全功能面板。
