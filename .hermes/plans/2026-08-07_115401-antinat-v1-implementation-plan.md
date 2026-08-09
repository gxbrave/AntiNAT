# AntiNAT v1 Implementation Plan（v0.7 最终复盘版）

> **For Hermes:** Follow the milestone gates. Before implementing any Work Package, generate a separate bite-sized TDD sub-plan; do not hand an entire WP to one coding agent.

**Goal:** 从零实现一个 Go 编写的轻量 Controller（面板/主控）+ Agent（节点）系统；Agent 主动连接可达的 Controller，并在 IPv4 数据面上完成 TCP/UDP 节点能力探测、打洞/显式映射、转发、可选限速、可选详细统计、映射变更通知与热维护。Controller 只承担控制、管理、状态和轻量 WAN 探测，不承载用户业务流量，也不通过打洞为 Agent 提供控制入口。

**Architecture:** Controller 在双栈地址上使用一个逻辑 TCP 监听端口（默认 `3111`、安装时可改）提供导航首页、管理 API、SSE 和 Agent 控制 WebSocket；`listen_addr/listen_port` 与对外 `controller_endpoint` 分离。TLS 可由用户现有证书、反向代理或隧道提供，AntiNAT 不签发或托管 TLS。节点首次上线自动执行一次 IPv4 traversal capability detection，可顺序或分组并行探测；结果按 TCP/UDP 保存为节点默认 strategy/layers，用户确认后用于新建 Forward，且每条 Forward 仍可覆盖。Agent 保存每条 Forward 的 last-known-good applied state 并为每条转发运行隔离 actor；Linux 无限制 TCP 优先让 Go 标准库 `io.Copy` 命中 `splice(2)`，Windows 和启用限速/详细统计的路径明确显示为 buffered/overhead mode。

**Tech Stack:** Go 1.26.5（已于 2026-08-07 通过 `go.dev/VERSION` 复核）、Linux amd64/arm64、Windows amd64（arm64 仅 cross-build，实机通过前不列 GA）、`net/http`、Go templates + 原生 HTML/CSS/JS、SQLite（Controller；驱动须经 pure-Go/cross-build spike 决定）、bbolt（Agent 事务状态）+ 独立原子 terminal marker、HTTP(S)/WebSocket + 一次性注册 token + 双向签名控制消息、STUN RFC 8489、PCP RFC 6887、NAT-PMP RFC 6886、UPnP IGD、systemd/OpenRC/Windows Service、GitHub Actions。Docker v1 仅支持 Linux host-network 部署。

---

## 1. 文档状态

- 计划版本：v0.7（2026-08-07 最终复盘；完成 scope/support contract、M0–M6 Walking Skeleton 路线、28 个 WP 的 Story/TDD 拆分规则、CI evidence lanes 与 installer contract 闭环）
- 初始生成时间：2026-08-07；最近修订：2026-08-07。
- 当前仓库状态：只有需求文件和本 Plan，尚未初始化 Git，也没有业务代码；当前主机尚未安装 `go` 命令。
- 第 18 节产品 P0 已确认；技术 P0（layered traversal、PortRegistry/shared-port、双向控制认证、independent probe+wire frame、Agent 部分应用/删除状态、hook 隔离、Windows Defender 策略、mapping ownership、性能 lab）必须在对应里程碑前通过 spike/ADR。
- 本阶段只写计划，不写业务代码。

### 1.1 本轮复盘结论（必须先修正）

原 Plan 对 NAT 边界、Forward/Node 删除、UDP 单 socket、IPv6 版本边界和真实性能验证的理解总体正确，但仍有以下会导致返工或安全问题的缺口：

1. **25 个 Task 实际是工作包，不是可直接交给单个实现 Agent 的 2–5 分钟任务。** 第 14 节改为“里程碑 + 工作包”；每个工作包开工前必须再生成一份 bite-sized TDD 子计划，不得一次性实现整个工作包。
2. **先做高风险 spike，再做面板。** Linux/Windows TCP 同端口复用、UDP 单 socket 分流、独立 WAN probe、SQLite 静态交叉构建和 JS runner 资源隔离均设置 Go/No-Go 闸门。
3. **原控制认证只充分证明 Agent 身份，没有完整证明 Controller→Agent 命令。** Controller 必须有持久 Ed25519 signing key；Agent 安装时 pin 指纹；双向控制消息都要签名并绑定 session/direction/sequence/payload hash。
4. **“全局 LKG snapshot”无法正确表达部分 Forward apply 失败。** Agent 必须分别保存 `received desired` 与 per-Forward `last_applied_spec`；失败项不能覆盖其旧 LKG，ACK 必须返回逐资源结果。
5. **Forward 离线删除缺少持久 operation 表。** 增加 `forward_deletion_operations`，重连时删除命令优先于普通 desired state，ACK 前不得把“远端已停”显示为完成。
6. **Controller 不天然等于独立 WAN 视角。** Controller 与 Agent 同主机/同 NAT、或 Controller 只经 tunnel 可达时，probe 必须返回 `UNKNOWN/NO_INDEPENDENT_VANTAGE`，不能用 hairpin 结果激活公网链接。
7. **TCP probe 不能长期在普通连接上嗅探首包。** 仅对尚未发布的新 generation 在 `VERIFYING_WAN` 阶段读取一次 nonce；激活后 listener 直接转发，重验通过新 generation 完成。
8. **“安全 JavaScript 沙箱”不能只靠进程内超时。** v1 使用独立 `antinat-hook-runner` 子进程和 Agent HTTP broker；runner 无网络/文件/进程 API，Linux/Windows 分别施加进程级时间/内存限制。任意 local shell 延后到 v1.1。
9. **不要先写自定义 splice。** 先用两端保持为裸 `*net.TCPConn` 的 `io.Copy`，用 `strace` 证明 Go 1.26.5 标准库实际命中 `splice(2)`；只有基准证明不足时才加自定义 fast path。
10. **原需求的“默认 3111、可修改”与旧 Plan 的“固定 3111”冲突。** 本修订采用一个逻辑端口、默认 3111、安装时可改；所有 UI/API/SSE/WebSocket 共享该端口。
11. **一键部署 token 不能成为长期 argv/service 参数。** token 短 TTL、一次消费；安装器只通过 0600 临时文件或 stdin 交给首次 enrollment，随后立即删除，绝不写入服务定义、Agent 配置、日志或长期进程参数。
12. **Docker 不能笼统承诺跨平台 host networking。** v1 Docker 仅支持 Linux host；Windows container 不在范围，Docker Desktop 仅作为明确标注限制的开发体验。
13. **原始需求与修订边界必须可追踪。** 删除立即中断、IPv4-only 数据面和可配置单端口写入正式差异表/ADR，验收不再混用冲突文案。
14. **Forward 聚合状态不能代替多 generation 状态。** 每个 activation 独立状态机，Forward 只 CAS `current_activation_id`；strategy/layer 明确 shadow/overlap/cutover 能力。
15. **删除 operation 还需要 Agent 本地 tombstone。** tombstone 必须先于 stop 落盘，并永久阻止旧 snapshot 复活，直到高水位和 operation complete 允许 GC。
16. **控制重连需要 fencing 和 durable inbox/outbox。** 新 `connection_epoch` 拒绝旧 socket 迟到 ACK；delete/decommission/rotation 与 ACK 跨重启幂等重放。
17. **Hook 明确 at-least-once 和 deactivation 事件。** SSRF 防护必须覆盖全部 A/AAAA、CGNAT/ULA/IPv4-mapped、redirect 和 proxy env；JS 只拿 secret signing handle。
18. **升级/卸载不能只管本机 happy path。** N/N-1+expand/contract、SQLite consistent backup、远端 decommission、manifest HMAC 和 symlink/reparse 防护都进入验收。
19. **网关 mapping 与 STUN 必须可组合。** 家庭 CPE + 上游 CGNAT 需要 `gateway-map + same-port STUN/keepalive + independent probe` pipeline；第一跳私网地址只能 FIRST_HOP_MAPPED。
20. **端口是 Agent 全局资源。** PortRegistry 保证一个 tuple 一个 listener owner；reuse 只允许 connected TCP STUN socket + 唯一 listener，不能让双 Forward/双 generation 随机分流。
21. **Probe 需要正式 wire protocol。** provider connect 与 Agent signed token ACK 同时成立，frame 绑定 exact endpoint/activation；scanner、timeout 和 infra failure 不能误激活。
22. **Windows 防火墙不能依赖交互弹窗。** 安装时明确 managed-range/manual policy，真实 Windows+router 通过后才标 capability。
23. **Mapping cleanup 需要 crash-safe ownership journal。** 创建/删除前核对远端条目；permanent-only UPnP 默认拒绝，绝不覆盖或删除第三方 mapping。
24. **性能 SLO 必须可判定。** 专用 lab、明确 jitter 公式/paired CI、direct baseline 和 150GB/run 级数据预算；普通 CI/真实 WAN 不承担 2Gbps/<1ms 因果声明。

### 1.2 本轮关闭的推荐默认值

- 首次 detection 默认 `sequential`，管理员可切换 bounded `parallel`。
- 离线 endpoint 不可点击；显示 stale 标签并允许用户主动复制，复制不视为发布成功。
- `port_policy` 默认 `accept_any`；Forward 可选 `prefer_requested` 或 `strict`，始终展示 requested/assigned port。
- WAN probe 为 `UNKNOWN` 时只允许管理员 force publish，并要求二次确认、醒目标记和审计。
- 用户自定义导航名称/简介 v1 使用单值；系统文案中英双语、默认中文。
- 自动更新默认关闭，仅提示已签名 release；升级由管理员显式执行。

### 1.3 已确认的产品原则

- Agent 打洞失败不影响其连接 Controller、接收配置或继续运行 last-known-good 转发。
- Controller 必须由用户预先提供 Agent 可直接到达的 URL；不使用打洞解决 Controller 控制入口。
- V1 打洞/转发公网入口只实现 IPv4；IPv6 仅用于 Controller 双栈访问和 Agent→Controller 连接，并预留后续 NAT66/IPv6 firewall pinhole 接口。
- 节点首次上线自动探测一次打洞能力，用户选择该节点 TCP/UDP 默认 traversal strategy；全部失败仍允许保存配置。
- Linux TCP 零拷贝是目标而不是无条件承诺；限速、详细统计、Windows 和 UDP 的开销必须在 UI/文档中显示。
- V1 同时支持 Linux、Windows Controller+Agent；macOS 延后。
- Forward 限速按每条 Forward 聚合；限速和详细流量统计默认关闭。
- Forward 删除立即停止 listener、活跃 TCP 连接和 UDP session，并 best-effort 释放 mapping；不执行 drain，网关不可达不影响本地业务立即停止。
- 普通删除节点必须先让 Agent 停止全部 Forward、清空本地 LKG 并 ACK；强制删除不等待 ACK，但必须保留最小 cleanup tombstone 并明确远端未确认风险。
- 卸载必须完整清除 AntiNAT 自身二进制、服务、配置、状态、数据库、日志和所创建的规则/任务。
- UI 中英文双语，默认中文；离线 Forward 置灰、红灯、显示最后已知地址。
- README 明确致谢 Natter 为原理参考，但实现不得复制 Natter 代码。

### 1.4 原始需求差异与验收基线

`antinat.txt` 是需求来源，但以下条目已被本 Plan 的可行性边界明确修订。Task 0 必须把本表固化到 `docs/requirements-traceability.md` 和 ADR，后续测试/验收只引用该基线，不能同时引用互相冲突的旧文案。

| 原始需求 | v1 验收基线 | 处理理由 |
|---|---|---|
| 添加、修改或删除均不可影响已有连接 | 添加和普通 target/显示修改不影响其他 Forward；删除是用户确认的立即中断例外 | 删除若继续连接就不满足“删除即停” |
| 完全支持 IPv4/IPv6 双栈 | v1 控制面双栈，Forward ingress/target 为 IPv4-only；IPv6 数据面进入 v2 | NAT66/IPv6 firewall pinhole 是独立工程，不能虚假承诺 |
| Controller 默认监听 3111 且可修改 | 使用一个逻辑端口，默认 3111，安装时可配置 | 保留原始安装体验，同时让 UI/API/SSE/WS 共端口 |
| 安装完成后用 ip.sb 自动组成访问地址 | 只显示为“未验证候选地址”；部署命令使用管理员确认的 `controller_endpoint` | 公网 IP 不等于端口可达，且可能存在反代/tunnel |
| JavaScript/脚本更新 DDNS | v1 为 webhook + 隔离 JS runner；任意 shell 延后 | 防止一个 hook 拖垮整个 Agent 或形成命令执行入口 |

上述基线由产品验收人确认后写入 ADR；若以后恢复 IPv6 数据面、graceful delete 或任意 shell，应新建版本化变更，不修改历史验收记录。

## 2. 可行性结论

### 2.1 总结

项目总体可行，但“任何 NAT 都能直连打洞”“所有修改均绝对零断连”“限速、实时统计、完全零拷贝同时成立”三个目标不能作为无条件承诺。

核心条件如下：

1. Natter 式方案依赖 NAT 的映射与过滤行为。获得稳定公网映射不等于任意公网客户端可访问；必须单独验证 Endpoint-Independent Mapping 与实际入站过滤结果。
2. 对称 NAT、地址端口相关映射、严格 CGNAT 防火墙等拓扑，在没有 PCP/UPnP/人工端口映射时，无法保证由任意公网客户端直接访问。若产品要“总能连通”，必须增加独立 Relay，Relay 可以由“公网 Agent 角色”承担，但不能由主控承载用户流量。
3. V1 不实现 IPv6 数据面打洞。V1 的 IPv6 范围是 Controller 双栈监听与 Agent 通过 A/AAAA/IPv4/IPv6 连接 Controller；NAT66、IPv6 防火墙 pinhole 和 IPv6 公网 listener 只定义扩展接口与测试桩，不进入 V1 运行路径。
4. Linux TCP 的无解析、无限速、无详细统计路径可用 `splice(2)` 降低用户态拷贝；Windows、UDP、限速和详细统计路径不能承诺真正零拷贝。产品必须显示当前实际 data-path 及退化原因。
5. 普通目标地址/限速/显示配置可以热更新；协议、绑定网卡、本地监听端口、映射方式变更可能需要新旧 generation 并行。若 OS/NAT 不允许同端口重叠，无法做到严格零切换；删除 Forward 是用户确认的例外，必须立即中断。

### 2.2 功能可行性矩阵

| 需求 | 结论 | 约束/修正 |
|---|---|---|
| Controller + Agent | 高度可行 | Agent 主动连接预先可达的 Controller；打洞失败和控制断线均不停止 last-known-good 数据面 |
| 节点首次自动能力探测 | 可行 | 结果按 TCP/UDP strategy/layers 分开保存；节点默认 strategy 只是建议值，Forward 可覆盖，网络变化/超期后标 stale |
| TCP/UDP IPv4 打洞 | 条件可行 | 仅对兼容 NAT/防火墙或显式映射机制有效；失败允许保存节点与配置 |
| 对称 NAT 保证直连 | 不可保证且非 V1 目标 | V1 准确报告失败，不实现 Controller Relay |
| V1 控制面 IPv4/IPv6 双栈 | 可行 | Controller 在同一配置端口（默认 3111）上接受 IPv4/IPv6；Agent endpoint 使用 Happy Eyeballs |
| V1 IPv6 数据面打洞 | 不实现 | 预留 family/strategy 接口和 unsupported capability，后续扩展 NAT66/pinhole |
| Go 轻量高并发 | 可行 | goroutine + OS poller；Linux/Windows 分别设置 FD/handle、内存和会话上限并实测 |
| TCP 尽可能零拷贝 | Linux 条件可行 | unlimited + detailed stats off 才优先 `splice`；Windows/限速/详细统计显示 buffered |
| UDP 零拷贝 | 只能尽量优化 | 使用单 socket、批量收发、buffer pool；不宣传为严格零拷贝 |
| 热添加 | 可行 | 新 actor 独立创建，不触碰其他转发 |
| 热修改目标/限速 | 可行 | 现有 TCP 连接保留旧 backend，新连接使用新 backend；限速开关改变 data-path 时要显示开销 |
| 修改协议/网卡仍绝对无损 | 不能保证 | 新旧 generation 重叠；冲突时 UI 明确提示 cutover |
| 删除 Forward | 可行但有意中断 | 立即停止 listener/活跃连接/session；mapping 释放 best-effort，不 drain |
| 隔离 JavaScript 调 DNS API | 条件可行 | 独立 runner + Agent broker 暴露 HTTPS request、HMAC/哈希/Base64/URL 编码和 secret 引用；平台资源限制 spike 必须通过 |
| Controller 仅一个逻辑监听端口 | 可行 | UI/API/SSE/Agent WebSocket 共用一个可配置 TCP 端口（默认 3111）；不自建 STUN |
| Linux 支持 | 可行 | 静态 Go 二进制；systemd + OpenRC |
| Windows Controller+Agent | 可行，中等平台风险 | 用户态转发和 Controller 容易；共享端口 socket、Windows Service、防火墙与 2 Gbps 需专项实测；无 `splice` |
| 后续 macOS | 中等难度 | 核心 Go 逻辑可复用；主要新增 launchd、socket reuse/pf 行为、安装器和真实网络验证，不应重写整体架构 |

## 3. 对原需求的关键修正

### 3.1 “打洞成功”的定义

不能以“STUN 返回公网 IP:端口”作为成功。正式状态必须同时满足：

1. 目标服务可达；
2. 本地转发 listener 可达；
3. 映射保持稳定；
4. Controller 或独立 probe 从 WAN 连接公网端点成功；
5. 对 HTTP(S) 类型可选做应用层响应校验；其他协议至少完成 TCP accept 或 UDP nonce 往返。

`UNKNOWN`、探测超时和 probe 不可用不能错误显示为 `FAILED`；应显示 `待确认/探测不可用`，且默认不发布链接。

### 3.2 不使用旧的“Full Cone/NAT 1”作为唯一判定

内部状态使用行为与机制名称：

- `direct-v4`
- `direct-v6`（仅保留为 future capability，V1 返回 `UNSUPPORTED_IN_V1`）
- `pcp`
- `nat-pmp`
- `upnp-igd`
- `stun-eim`（仅表示观测到映射复用）
- `verified-open`
- `suspected-filtering`（仅诊断推断，不能作为已证明事实）
- `relay-required`

稳定端口只能说明映射可能为 endpoint-independent，不能证明过滤允许任意外部来源。

### 3.3 V1 的 IPv6 边界与后续预留

V1 只实现控制面双栈：

- Controller 在同一个配置端口（默认 `3111`）上接受 IPv4 与 IPv6；实现可使用一个真正 dual-stack listener，或在平台需要时以 `tcp4`/`tcp6` 两个 socket 监听同一数值端口。
- Agent 连接 Controller endpoint 时使用系统 DNS 和 Happy Eyeballs，可经 IPv4、IPv6、内网地址、反向代理、CDN tunnel 或内网穿透域名连接。
- V1 的公网映射、打洞 listener 与 Forward ingress 都是 IPv4；不得在 UI 中显示未实现的 `v6/dual` 数据面选项。
- traversal 核心接口仍保留 `AddressFamily`、strategy capability 和 family-specific socket factory；V1 的 IPv6 strategy 返回明确 `UNSUPPORTED_IN_V1`，避免以后改数据库/API/actor 主结构。
- 后续版本再实现 global IPv6 direct、NAT66 识别、PCP IPv6、UPnP IPv6FirewallControl、主机/路由器防火墙 pinhole 和 IPv6 WAN probe。

### 3.4 “HTTPS 开关”的文案必须修正

开关只能决定生成链接使用 `http://` 还是 `https://`，不会自动提供 TLS。目标服务必须自行持有与自定义域名匹配的证书，否则浏览器仍会报证书错误。UI 文案建议改为“发布链接协议”，并增加：

- `http`
- `https`
- `tcp`
- `udp`
- `custom URI template`

UDP 或非 Web 服务默认不生成 HTTP 导航链接。

### 3.5 自定义域名不等于 DDNS 已更新

`published_host` 只替换显示/导航链接中的主机名。若公网 IPv4/端口改变，AntiNAT 只发送已验证的 MappingChanged event；用户可用 webhook/沙箱 JavaScript 更新 A、SRV 或其他外部系统。V1 不内置 DDNS provider，也不能在 WAN 验证前触发变更事件。

### 3.6 从 Komari 参考需求中删除无关项目

下列选项属于主机监控或 Web SSH，不应机械加入 AntiNAT v1：

- 禁用 Web SSH
- 监测可用内存/包含 cache
- GPU 监控
- 指定挂载点
- 采集硬件指标
- 每月监控流量重置日（可改造成 AntiNAT 自身统计周期，但不是安装参数）

AntiNAT 节点部署参数只保留：`endpoint`、一次性 enroll token、平台、安装目录、服务名、GitHub 代理、绑定网卡、首次探测调度、日志级别、自动更新策略；TLS/反代证书由用户部署环境管理。

### 3.7 Controller 地址必须由用户提供并已可达

Agent 控制入口不依赖 AntiNAT 打洞。安装 Controller 时必须配置或确认一个 Agent 可直接连接的 `controller_endpoint`，它可以是：

- 内网 IP/域名；
- 公网 IP/域名；
- 已由反向代理、CDN tunnel 或其他内网穿透产品转发到 Controller 配置端口的域名。

`ip.sb` 只可用于显示本机候选公网 IP，不自动组成或保存 Controller endpoint，也不作为可达性证明。安装完成可把它显示为“未验证候选地址”，同时必须单独输出用户确认的 `controller_endpoint`。节点部署命令始终使用用户确认的 endpoint。本机 Controller+Agent 可以使用 loopback endpoint，但不得自动创建“打洞暴露 Controller”的系统 Forward。

### 3.8 Natter 参考与许可证边界

调研到的 Natter v2.2.1 使用 GPL-3.0。AntiNAT 不复制、改写或移植 Natter 源码，只参考其项目展示出的打洞思路，并依据 RFC 与独立设计重新实现。`README.md` 应在“致谢/设计参考”中明确链接 `https://github.com/MikeWang000000/Natter/`，同时声明 AntiNAT 不是 Natter fork，Natter 作者不为 AntiNAT 提供背书。AntiNAT 已确定采用 Apache-2.0，因此必须持续维护独立实现与来源记录。

### 3.9 监听地址、对外地址与反向代理必须分离

- 进程配置：`listen_address`（默认 `::`/平台双栈策略）与 `listen_port`（默认 `3111`）。变更通常需要重启服务。
- 产品配置：`controller_endpoint` 是 Agent 实际连接的完整 `http(s)://host[:port][/base]` URL，不从监听地址、`Host`、`X-Forwarded-*` 或 `ip.sb` 静默推导。
- 反向代理场景必须配置 `trusted_proxies`；仅信任这些源发送的 forwarded headers。Cookie `Secure`、Origin/CSRF 与 URL 生成以显式 external URL 为准，不能信任任意客户端头。
- 修改 `controller_endpoint` 只影响新部署命令和已在线 Agent 可接收的候选 endpoint 更新；已经离线且只知道旧地址的 Agent 无法被魔法迁移，UI/文档必须要求手工更新。
- “一个逻辑端口”是指 UI/API/SSE/Agent WebSocket 共用同一个数值端口；实现可按平台使用 `tcp4`/`tcp6` 两个 socket。

## 4. 建议范围

### 4.1 v1（必须完成）

- 单管理员 Controller；SQLite WAL；在 IPv4/IPv6 上使用一个逻辑 TCP 端口（默认 3111、可配置）；HTTP/HTTPS 由部署环境决定，AntiNAT 不管理证书。
- 导航首页、公有/私有模式、管理登录；中文/英文，默认中文。
- 节点创建、一次性注册 token、Linux/Windows 一键部署命令，以及 Linux host-network Docker 命令。
- Agent/Controller 双向签名控制消息、断线重连、per-Forward last-known-good applied state；打洞失败不影响控制连接。
- Linux amd64/arm64：Debian/Ubuntu/systemd、Alpine/OpenRC；Windows Controller+Agent 与 Windows Service。
- 节点首次上线自动 IPv4 capability detection；顺序或分组并行；按 TCP/UDP 记录 strategy/layer 结果和用户选择的默认 strategy；全失败允许保存。
- TCP/UDP IPv4 数据面；direct/manual/gateway-map+optional-STUN/stun-only 可组合 strategy pipeline；不实现 IPv6 数据面。
- Controller 外部可达性 probe；状态机；映射变化处理。
- 可选 stateless `antinat-probe` reference helper，为 Controller+Agent 同网场景提供独立 signed WAN vantage；它不是 Relay，不承载业务流量。
- Go 用户态转发；Linux TCP splice fast path；Windows buffered path；限速和详细统计为每 Forward 可选且默认关闭。
- 热添加、target 热修改、限速开关热修改；删除 Forward 立即停止全部实际转发。
- 通用 webhook + 独立进程 JavaScript hook runner；提供经 Agent broker 审核的 HTTPS 请求、签名/编码和 secret 引用，可由用户实现 AliDNS 等 API，不内置特定 DDNS provider。
- 首页分类、导航卡片、关联 Forward、拖拽排序；离线置灰、红灯、显示最后已知地址。
- Linux/Windows 安装、升级、完全卸载、备份、日志和基础审计。

### 4.2 v1.1（推荐）

- 可选 nftables 特权辅助进程与 Linux 内核转发快速路径。
- 多管理员/RBAC。
- 流量历史与告警增强。
- arm/v7（若真实设备需求确认）。
- 更完整的探测调度、网络 fingerprint 自动失效和多 probe vantage。
- 管理员预安装、绝对路径 allowlist、`shell=false` 的 local executable hook；v1 不提供任意 shell。

### 4.3 v2（条件需求）

- IPv6 数据面：global IPv6 direct、NAT66、PCP IPv6、UPnP IPv6FirewallControl、主机/路由器 pinhole 和 IPv6 WAN probe。
- 公网 Agent 作为可选 Relay fallback；Controller 仍不传输用户流量。
- macOS Agent/Controller 与 launchd 安装器。
- Controller HA/PostgreSQL。
- 多 Controller 联邦或 Agent-to-Agent 控制。

### 4.4 交付层级与明确非目标

为避免“所有模块都完成后才第一次端到端运行”，v1 按可运行层级交付：

1. **v0.1 Core Vertical Slice（Linux TCP direct-v4）**：CLI 方式创建一个 Forward，Agent enrollment/双向签名、per-Forward LKG、Controller probe、重启恢复和立即删除闭环；无正式 UI、无 STUN/UPnP、无性能宣传。
2. **v0.2 Linux Traversal Beta**：direct/manual/gateway+optional-STUN/stun-only TCP pipeline、PortRegistry、节点 detection、基础管理 API、真实 WAN 验证。
3. **v0.3 UDP + Lifecycle Beta**：UDP 单 socket、热切换、Forward 离线删除 operation、Node normal/force decommission 全状态机。
4. **v0.4 Product Beta**：正式 UI、hook runner、Linux 安装/升级/卸载、审计与安全门禁。
5. **v1.0 GA**：Windows amd64 真实测试、跨平台 installer、NAT 实网矩阵、24h soak、release artifact 重装与按平台性能报告通过。

以下不属于 v1：任意 NAT 保证直连、Controller 业务 Relay、IPv6 数据面/NAT66、macOS、Windows containers、RBAC/HA、内核态 nft 转发、自动无人值守升级、任意 shell、内置 DDNS provider。Windows 某个 traversal strategy/layer 若共享端口 spike 不通过，可按 capability 标记为 `UNSUPPORTED`；不因此伪造“全模式支持”。

Windows amd64 按 capability matrix 发布：direct/gateway TCP、UDP single-socket、STUN shared-port TCP、managed Defender rule 分别需要真实 Winsock+Service+router 测试。某一项失败只把该项标 `UNSUPPORTED_ON_PLATFORM`；例如 STUN TCP 不通过时，Windows 仍可支持 direct/manual/显式 gateway mapping，但 README 不能写“全打洞模式支持”。

## 5. 总体架构

```text
Browser / Agent
  └─ HTTP(S) TCP :<listen_port=3111> over IPv4 or IPv6 ──> Controller
       ├─ Home/Admin HTML + JSON API + SSE
       ├─ SQLite (desired state, users, navigation, audit, optional rollups)
       ├─ Agent Hub (WebSocket + bidirectionally signed control envelopes)
       └─ Reachability Probe (outbound only, never forwards user traffic)

Agent (always outbound control connection to a user-provided reachable URL)
  ├─ Enrollment token -> persistent node key/credential
  ├─ Received Desired State + per-Forward Last-Applied State
  ├─ Node Traversal Profile (TCP/UDP strategies/layers + user-selected defaults)
  ├─ Reconciler
  │    └─ one isolated Forward Actor per forward ID
  │         ├─ IPv4 traversal strategy pipeline
  │         ├─ keepalive + WAN verification
  │         ├─ TCP/UDP forwarder
  │         ├─ optional limiter/detailed counters
  │         └─ hook broker -> isolated antinat-hook-runner
  └─ platform data path
       ├─ Linux: splice fast path or buffered path
       └─ Windows: IOCP-backed Go networking + buffered path

Internet client
  └─ IPv4 public mapping ──> Agent IPv4 listener ──> target service
                                         (Controller is never in this path)
```

### 5.1 Controller 职责边界

Controller 可以：

- 保存 desired state；
- 向 Agent 下发版本化配置；
- 接收状态和统计；
- 以临时出站连接做 WAN probe；
- 生成部署命令、显示导航链接。

Controller 不可以：

- 代理业务 TCP/UDP；
- 通过打洞暴露自身作为 Agent 控制入口；
- 自建或要求用户部署 AntiNAT STUN；
- 签发、续期或托管站点 TLS 证书；
- 在 Agent 离线时伪造在线/成功状态；
- 保存明文注册 token、节点私钥或管理员密码。

### 5.2 Agent 进程模型

- 一个 Agent 进程管理多个 Forward Actor；打洞模块失败不得终止 Agent 控制连接。
- 首次成功注册并上线后自动创建一次 Node Traversal Detection job；结果保存后提示用户分别选择 TCP 与 UDP 默认 strategy。
- 每个 actor 只操作自己的 socket、mapping、计数器与 hook；panic/error 不能终止其他转发。
- Controller 断开时通常不停止数据面；但 Agent 一旦收到节点删除的 terminal command，必须先持久化 `DECOMMISSIONING` 标记，再停止全部 Forward、best-effort 释放 mapping、清空 LKG/secret/pending job，之后进入不可自动恢复的 `DECOMMISSIONED` 状态。
- Agent 重启时先检查 terminal marker：`DECOMMISSIONING/DECOMMISSIONED` 时禁止恢复任何 LKG；否则标成 `RECOVERING` 并从完整 last-known-good 恢复，不沿用陈旧 `healthy=true`。
- 所有资源都带 `forward_id + generation`，旧事件不得覆盖新 generation 状态。

## 6. IPv4 Traversal 策略与节点能力探测

### 6.1 节点首次探测与默认 strategy

节点完成 enrollment 并建立控制连接后，Controller 自动要求 Agent 探测一次。探测使用独立临时端口，完成后清理所有临时 listener、lease 与 UPnP mapping，不能影响实际 Forward。

探测支持两种调度方式：

- `sequential`：逐项探测，日志清楚、路由器副作用最小，作为默认。
- `parallel`：缩短等待，但不是把所有机制无约束同时运行。先并行执行只读/低副作用检查，再以独立端口并行 PCP、NAT-PMP、UPnP、STUN；每项有 timeout、唯一 lease description 和统一 cleanup。

节点结果必须按协议分开，因为 TCP 和 UDP 的 STUN、filtering 和 socket 行为可能不同：

```text
NodeTraversalProfile
  network_fingerprint
  tested_at
  scheduler: sequential | parallel
  tcp: strategies[] + selected_default
  udp: strategies[] + selected_default
  stale: bool + stale_reason
```

- UI 显示每条 strategy pipeline 的 layers、`SUCCESS/FAILED/UNKNOWN/FIRST_HOP_MAPPED`、耗时、gateway/public endpoint、endpoint scope、失败原因和测试时间。
- 探测结束后提示用户选择 TCP 与 UDP 默认 strategy；成功 strategy 优先展示，但允许选择失败/未验证 strategy 或在全部失败时保存。
- 添加 Forward 时默认继承 node 对应协议的 selected strategy，并允许 Forward 单独覆盖。
- 默认路由、选定网卡、LAN/public 地址、route metric、gateway identity hash、strategy config version 变化时标记 `STALE`；默认 7 天超期为 `STALE_BY_AGE`。无法读取 gateway identity 不阻塞，但 evidence 标 unknown；旧结果不应静默视为永久有效。
- 每 transport 的 STUN endpoint 记录解析 IP、success rate、RTT、last error、last success 和 cooldown；服务不可用与 NAT 不兼容分开报告，选择时避免连续命中同一解析地址。
- 探测失败只更新 capability profile，不改变 Agent online 状态，不停止控制通道，也不阻止下发 Forward。
- Node detection 使用临时 tuple，只提供 strategy capability/推荐顺序，不证明未来任意端口可达；每条实际 Forward 都必须在自己的 PortRegistry tuple 上重新 acquire mapping、keepalive 和 independent WAN probe。

### 6.2 V1 IPv4 traversal strategy pipeline

PCP、NAT-PMP、UPnP 和 STUN 不是永远互斥的“模式”。在家庭 CPE + 上游 CGNAT 中，gateway mapping 可能只打开第一跳，还必须从 **同一内部 IP/端口** 执行 STUN/keepalive 才能发现并维持上游映射。因此节点探测和 Forward 使用可组合 `TraversalStrategy`：

```text
direct-v4
manual-static-v4:
  expected_public_endpoint
explicit-gateway:
  gateway_method: pcp | nat-pmp | upnp-igd
  upstream_discovery: none | stun
  keepalive: protocol-specific
stun-only:
  keepalive: protocol-specific
auto:
  ordered strategies[]
```

统一 pipeline：

1. 由 Agent 全局 PortRegistry 预留具体 `(family, protocol, source IPv4, local port)` 并建立唯一 listener/ingress socket。
2. 可选申请 PCP/NAT-PMP/UPnP 第一跳 mapping，记录 gateway endpoint、lease 和 ownership journal。
3. 分类 gateway endpoint scope：`global/cgnat/private/reserved`。非 global 只能标记 `FIRST_HOP_MAPPED`，不得当最终 SUCCESS 或直接发布。
4. strategy 指定 `upstream_discovery=stun` 时，从同一 source IP/port 完成 transport-correct STUN 和 keepalive，得到 observed public endpoint。
5. 只有 global IPv4 endpoint 经独立 WAN probe 成功后才成为 `VERIFIED_OPEN`。
6. `manual-static-v4` 不操作 gateway lease；用户提供预期公网 endpoint，Agent 只建立 listener、验证 endpoint 并维护状态，适用于云 1:1 NAT、安全组或人工 DNAT。

`StrategyResult` 至少包含：

```text
layers[]
gateway_method
gateway_external_endpoint
observed_public_endpoint
endpoint_scope: global | cgnat | private | reserved
mapping_status
wan_probe_status
lease_expiry
ownership_operation_id
evidence[]
```

用户选择固定 strategy 时不静默改成另一条 pipeline；`auto` 才按有界顺序 fallback。端口策略独立为 `port_policy: strict | prefer_requested | accept_any`，默认 `accept_any`：PCP strict 使用 `PREFER_FAILURE`；NAT-PMP/UPnP 按返回/冲突执行策略，禁止覆盖第三方 mapping 或无界扫描。始终记录 requested/assigned port。

TCP/UDP STUN 服务器列表分开，使用显式 transport URL（`stun+tcp://`、`stun+udp://`）。至少两个真实完成对应 transport exchange、解析到不同远端 IP 的 endpoint 才可比较 mapping；单一观测为 `MAPPED_UNVERIFIED`，不得宣称 EIM/full-cone。

每条 strategy 返回结构化 `code/retryable/layers/endpoint_scope/evidence[]`。direct-v4 或显式 mapping probe 失败时，诊断区分 listener、host firewall suspicion、gateway mapping、probe infrastructure 和 timeout；`suspected_filtering` 只能是带 inference 标记的诊断，不是已证明事实。Agent 默认不自动修改 Linux 防火墙。

Mapping ownership 使用 crash-safe bbolt journal，记录 mechanism、gateway、internal/external tuple、protocol、nonce/description、operation ID、created_at 和 lease。PCP 用 nonce；UPnP 创建前查询现有条目，默认不覆盖，删除前重新核对 internal client/port/protocol/description；NAT-PMP 只释放本 operation 记录的 source/internal port/protocol。UPnP 若仅支持永久 lease，默认返回 `UNSUPPORTED_PERMANENT_ONLY`；管理员显式允许时持续显示 crash 残留风险。不得因端口相同删除不属于 AntiNAT 的规则。

### 6.3 TCP socket 设计

Natter 的核心做法是让 STUN/keepalive socket 与入站 listener 共享本地 IP/端口。实现必须通过 platform socket factory 在 `bind` 前设置所需复用选项，不得依赖事后修改其他进程 FD。

- Linux：通过 `net.Dialer.Control` / `net.ListenConfig.Control` 设置并测试 `SO_REUSEADDR`/`SO_REUSEPORT`。
- Windows：单独实现 `socket_windows.go`，验证 Winsock `SO_REUSEADDR`、listener/connected 4-tuple 分流、接口选择和 Windows Defender Firewall 行为；不得假设 Linux 选项语义相同。若某种模式无法可靠共享端口，capability detection 必须将其标为 unsupported，而不是让数据随机落到错误 socket。
- Agent 级 `PortRegistry/SocketRegistry` 对 `(family, protocol, bind IPv4, local port)` 做唯一所有权；同时检查 wildcard 与 specific-address 冲突。普通 TCP/UDP listener 禁止用 `SO_REUSEPORT` 绕过冲突，一个 tuple 同时只有一个 listener/ingress owner。
- reuse 只允许同一 registry owner 管理的“connected TCP STUN/keepalive socket + 唯一 listener”组合。两条 Forward 请求同端口必须 NACK；旧 actor 的迟到 close 必须带 owner generation，不能关闭新 owner。
- 同 local port remap/revalidation 复用稳定 listener，只替换 mapping/keepalive activation；不得让新旧 generation 各建一个 reuseport listener。只有 local port 改变时才允许双 listener 并行。UDP 永远一个 tuple 一个 ingress socket。
- traversal socket 必须绑定 route lookup 选出的具体 source IPv4，禁止 wildcard bind。Linux 不依赖可能需要 capability 的 `SO_BINDTODEVICE`；Windows 通过 source address/interface route 实测。

流程：

1. route lookup 并锁定 source interface/IPv4，由 PortRegistry 原子预留 tuple；
2. 创建唯一 listener SocketSet；STUN TCP strategy 在同 owner 下创建带受控 reuse 的 connected keepalive socket，验证不会抢 listener 流量；
3. 按 strategy pipeline 获取第一跳/上游映射并建立保活；
4. 启动 verification-only forwarder；
5. 请求独立 ProbeProvider 验证；
6. 仅在 probe frame/token 成功后 CAS activation 为 ACTIVE；
7. lease renewal、gateway epoch 变化、keepalive 失败、Agent resume、route/interface 变化或 host-firewall 配置提示时重新验证，并做带 jitter 的低频复查；
8. Controller 离线时发现新 endpoint，状态为 `UNVERIFIED_NEW_ENDPOINT`，不发布、不触发 Activated/Changed hook，重连后再验证。

不能把 TCP simultaneous-open 当作任意客户端接入方案，因为普通公网客户端不会配合 simultaneous-open。

### 6.4 UDP socket 设计

禁止用“一个 connected keepalive socket + 一个 SO_REUSEPORT listener”竞争同一 UDP 端口。UDP 使用单个未连接 `UDPConn`：

- 同一 socket 发送/接收 STUN、keepalive、probe 和用户流量；
- 按 STUN magic cookie/transaction ID、outstanding signed probe frame/token、keepalive 来源端点做协议分流；
- 普通数据按客户端地址进入 UDP session table；
- 每个客户端 session 使用 connected outbound UDP socket 与目标通信；
- session 表分片、有限额、idle timeout，并对源地址做基本滥用防护。
- ingress 使用可检测 datagram truncation 的平台 API 和足以容纳 IPv4 最大 UDP payload（65,507 bytes）的受限 buffer pool；截断包丢弃并计数，不能转发残缺数据。测试 IPv4 fragment/reassembly、MTU 和 oversize。
- target response 最终必须经同一个 ingress socket 发回，公网客户端看到的 source port 始终是 published port。Windows 专项处理/测试 `WSAECONNRESET` 与 `SIO_UDP_CONNRESET`，ICMP 错误不能杀死整个 ingress loop。
- 达到 session、outbound ephemeral port 或 buffer budget 上限时按策略丢弃并计数，不能无限创建 socket；测试大包、ICMP、session churn、单 IP flood 和端口耗尽。

### 6.5 WAN probe 协议

- Probe service 先判断自己是否为独立视角：记录 `vantage_id/source_ip/path_class`。Controller 与 Agent 同主机、同 LAN/NAT、只通过反向 tunnel 到达、或无法确认路径独立时，结果为 `UNKNOWN/NO_INDEPENDENT_VANTAGE`；hairpin 成功不能作为公网成功。
- V1 定义 `ProbeProvider` 接口并支持两种 provider：`controller-local`（Controller 自身确属独立公网视角）和管理员配置的 `remote-signed` probe endpoint。参考 `antinat-probe` 是可选、无状态、只做短时 TCP/UDP 出站探测的辅助程序，不保存 desired state、不接触 hook secrets、绝不转发用户业务；请求/结果都带 provider key 签名、nonce、endpoint 和 expiry。
- Controller+Agent 本机模式若未配置独立 remote probe，只能得到 UNKNOWN；允许管理员 force publish，但不得把该路径显示为 verified。部署 remote probe 不是 Agent 控制连接的前置条件。
- Controller 创建 outstanding probe 后，通过签名控制消息下发 provider、protocol、activation、完整 endpoint、expiry 和 256-bit token。TCP/UDP wire frame 都包含 `magic/version/node_id_hash/forward_id/activation_id/endpoint/expiry/token/provider_id/MAC-or-signature`，有严格长度上限；结果必须同时满足 provider connect/send 成功和 Agent token-match ACK。
- TCP 初次 activation 处于 verification-only gate：invalid/扫描连接不会激活，只有完整合法 frame 得到 ACK 后才切业务。已 ACTIVE listener 只在短时 outstanding probe window 启用可回放前缀分类：backend 可并行 dial，server→client 不等待；magic 首次不匹配、短包或分类超时都把已读字节原样写给 backend，完整匹配才关闭预连 backend 并只回 probe ACK。其余时间不读取业务首包，保持 splice path。
- TCP frame 使用长随机 magic 并绑定 exact endpoint/activation；测试 scanner race、slowloris、magic-prefix collision、短包、server-first 协议、普通连接与 probe 并发和周期复查。Controller connect 成功但 Agent token 不匹配不能算 OPEN。
- UDP frame 的 MAC key/token 来自已签名控制命令，只匹配 outstanding provider/source/endpoint/activation/transaction；回包长度不得超过请求，探测包不进入 target，防反射放大。
- ProbeProvider 只允许 Controller 已绑定到该 node/activation 的 **全球可路由 IPv4 literal**；拒绝 DNS、private、CGNAT、loopback、link-local、multicast/reserved。每 node/endpoint 有速率、并发、payload 和 timeout 限制并审计，不能把 probe 变成 TCP/UDP 扫描器。
- Probe outcome 使用 `OPEN`、`REJECTED`（明确 RST/ICMP 等）、`TIMEOUT`、`NO_INDEPENDENT_VANTAGE`、`PROBE_INFRA_UNAVAILABLE`、`UNKNOWN`；timeout 不能证明 NAT filtering，`suspected_filtering` 只能作为 inference diagnostic。只有 independent OPEN 可生成 `WAN_VERIFIED_INDEPENDENT`；其他结果默认不发布，force publish 必须二次确认和审计。
- Target health 与 traversal 分开：节点 capability detection 使用 Agent 内置临时 echo responder；实际 TCP connect/HTTP(S) check 可配置，结果为 `PASS/FAIL/SKIPPED/UNSUPPORTED`。未知协议 UDP target 不发送任意 nonce，也不能因 health `SKIPPED` 把 NAT 判失败。

### 6.6 映射状态机

```text
DISABLED
  -> RESOLVING_TARGET
  -> DISCOVERING_NETWORK
  -> ACQUIRING_MAPPING
  -> STARTING_FORWARDER
  -> VERIFYING_LOCAL
  -> VERIFYING_WAN
  -> ACTIVE
       -> DEGRADED -> REMAPPING -> VERIFYING_WAN -> ACTIVE
       -> REPLACING -> ACTIVE（新 generation）+ DRAINING（仅旧 generation）
       -> STOPPING_IMMEDIATE -> STOPPED（删除 Forward）
任何阶段 -> FAILED（结构化 reason，可重试；Agent 本身仍 ONLINE）
```

上述枚举是 **单个 activation/generation 的状态机**，不是整个 Forward 的唯一状态。每条 Forward 保存稳定 `forward_id`、`spec_revision` 和原子 `current_activation_id`；每个 activation 另存 `activation_id`（UUID/128-bit）、generation number、strategy/layers、endpoint 和独立 state。替换时允许旧 activation=`ACTIVE/DRAINING` 与新 activation=`VERIFYING_WAN` 同时存在，不能用一个 `REPLACING` 值覆盖两者。

只有通过 WAN gate 的新 activation 才能用 CAS 将 `current_activation_id: old -> new`；旧 activation 的迟到事件、probe、hook 或 ACK 永远不能修改 current endpoint。映射 endpoint 只能在 activation 成为 current ACTIVE 后写入发布状态并触发 hook。Agent 启动、控制断线、映射续租失败、默认路由变化、接口地址变化都必须产生明确 transition。

每种 strategy/layer 还必须声明 replacement capability：`SHADOW_PORT`（新端口验证后发布）、`SAME_PORT_OVERLAP`、`CUTOVER_REQUIRED` 或 `NO_REPLACE`，并实现 `Prepare/Commit/Abort/Release`。PCP/NAT-PMP/UPnP 申请同一外部端口可能覆盖旧 lease，OS 也可能不允许双 generation 同端口监听；这种情况 UI 必须提示短 cutover，不能笼统承诺无损。

## 7. 转发数据面

### 7.1 TCP

- 每个入站连接解析当前原子 backend snapshot，连接建立后固定使用该 snapshot；后续 target 变化不迁移已有连接。
- 双向转发支持 TCP half-close：一个方向 EOF 后对另一端 `CloseWrite`，不能立即关闭双方。
- `fast-splice`：仅 Linux、无限速、详细统计关闭、两端保持为裸 `*net.TCPConn` 时启用。第一实现使用双向 `io.Copy`，依靠 Go 1.26.5 `TCPConn.ReadFrom/WriteTo` 的 Linux splice path；用 syscall trace 和 benchmark 证明实际命中 `splice(2)`。只有标准库路径未达标且独立 benchmark 证明收益时，才建立 ADR 并增加自定义 splice 代码。
- `buffered`：Windows、限速开启、详细统计开启、包装器破坏 fast path 或 splice 不可用时启用；使用 `sync.Pool` 管理 32–64 KiB buffer。
- `sync.Pool` 只负责复用，不是容量限制。全局 `buffer_budget_bytes` 用 weighted semaphore 硬限制，默认 `min(256 MiB, 10% detected RAM)`，每个双向 buffered TCP 连接按实际两方向 buffer 预留；预算不足时拒绝新连接并报告 `buffer_budget_exhausted`，不让 10k 连接隐式消耗 0.6–1.2 GiB 以上内存。各平台默认连接上限由该预算、FD/handle 和 benchmark 共同决定。
- 无论模式都保留低成本 health、active connection 和错误计数；“详细统计关闭”不等于没有运行状态。
- UI/API 暴露 `data_path`、`zero_copy_active`、`overhead_reasons[]`，例如 `rate_limit_enabled`、`detailed_stats_enabled`、`windows_no_splice`。
- Linux 每 activation 记录 `splice_bytes/buffered_fallback_bytes/fallback_reason`；`strace` 只证明 syscall 出现，不能单独证明整条连接一直 fast path。测试 deadline、wrapper、half-close 和错误恢复不会隐藏回退或虚报 zero-copy。
- 做连接数硬上限和 accept backoff，避免 FD/handle/内存耗尽；Windows 与 Linux 分别压测。

### 7.2 UDP

- UDP 永远标记 `zero_copy_active=false`，使用单 ingress socket、buffer pool 和有界 session table。
- session key 至少包含 ingress client address + forward generation。
- target 改变后：旧 session 继续走旧 target，新的 client/session 使用新 target；idle 后回收。
- 限制最大 session 数；满载时丢弃并保留低成本错误计数，不让 map 无限增长。
- Linux/Windows 可分别评估 batch API，但只有基准证明收益才保留平台特化。

### 7.3 限速

V1 只实现每条 Forward、每个方向的聚合字节率；不做 per-connection/per-source 限速。字段：

- `rate_limit_enabled`（默认 `false`）
- `ingress_bytes_per_second`
- `egress_bytes_per_second`
- `burst_bytes`

开启限速会切换或保持在可精确计量的 data-path，并在 UI 明确提示可能增加 CPU、拷贝与抖动；关闭后新连接可回到 fast-splice，已有连接不强制迁移。

### 7.4 统计

每条 Forward 有两个层级：

- **基础运行计数（始终开启）**：状态、当前 endpoint、active connections/sessions、启动/失败/重试次数、最近错误、mapping uptime。
- **详细流量统计（默认关闭）**：ingress/egress bytes/packets、accepted/rejected、session churn、probe latency、copy errors，以及 Controller rollup。

字段 `detailed_traffic_stats_enabled=false`。开启后 Agent 每 10 秒发送带 seq 的 delta；Controller 幂等去重并按保留策略 rollup。关闭时不创建流量历史，不运行高频 per-chunk 上报。切换开关必须更新 `data_path/overhead_reasons`，文档列出 Linux splice、Windows buffered、UDP、限速、统计各自成本。

## 8. 热维护一致性模型

### 8.1 配置版本

- Controller 对每个 node 保存单调递增 `desired_revision`。
- 每条 forward 有稳定 UUID、`spec_revision` 和运行 `generation`。
- Agent 使用 bbolt 事务区分三类状态：`received_desired`（已验签并完成 schema 校验）、per-Forward `last_applied_spec`（真实可恢复 LKG）和 runtime/outbox。一个 Forward apply 失败时，只更新 received desired 与失败状态，绝不能用失败 spec 覆盖它原来的 `last_applied_spec`。
- `desired_state_ack` 分 `RECEIVED`、`VALIDATED`、`APPLIED/PARTIAL/NACK`；最终 ACK 含每个 `forward_id/spec_revision` 的 apply result。Controller 不以“WebSocket 写成功”或“snapshot 已接收”代替实际生效。
- Agent 重启先读取独立于 bbolt 的 fsync+rename terminal marker；存在 `DECOMMISSIONING/DECOMMISSIONED` 时 fail closed，只继续清理。bbolt 损坏或无法校验时也必须 fail closed，不能猜测恢复旧转发。
- Agent 持久化 `max_accepted_desired_revision`。全量 desired snapshot 中缺失的 Forward 只有在存在更高 revision 或匹配的持久 deletion operation 时才视为删除；删除 operation 在重连 reconcile 中优先于添加/修改。
- Agent 收到 Forward 删除时，必须在关闭 listener 前用 bbolt 事务写入 `forward_delete_tombstone(forward_id, deletion_revision, operation_id)`；该 tombstone 阻止任何旧 desired/spec revision 复活 Forward。收到 Controller operation-complete 且持久 high-water revision 已覆盖删除 revision 后才能 GC tombstone。
- 不支持的字段或 schema version 必须 NACK，不能部分静默忽略。

### 8.2 变更分类

| 变更 | 行为 |
|---|---|
| 名称、链接、hook、限速、统计开关、超时 | 原位热更新；新连接采用所需 data-path |
| target host/port | 原子 backend 切换；旧 TCP/UDP session 保持 |
| 添加 Forward | 启动独立 actor，成功或失败状态均可保存 |
| 删除 Forward | 立即停止 accept、关闭 listener/全部活跃 TCP/UDP session、删除本地 desired spec，并 best-effort 释放 mapping |
| protocol/interface/mode/local port | 新 generation 并行建立；验证后切换；若端口冲突则提示短 cutover |
| 普通删除 node | 锁定节点为 `DELETING`，禁止新配置；下发 terminal `stop_all_and_forget`；等待 Agent 清空全部 Forward/LKG 并 ACK 后，才删除 Controller node 记录 |
| 强制删除 node | 勾选明确风险选项后，best-effort 下发同一 terminal command，立即从主控节点列表删除且不等 ACK；保留不含配置的最小 cleanup tombstone，旧 Agent 重连时只能进入受限清理会话 |

### 8.3 失败回滚

新配置失败时保留该 Forward 旧 `last_applied_spec` 和旧 ACTIVE generation，并向 Controller 回报 `APPLY_FAILED` 与具体原因；其他 Forward 可独立成功，整体结果为 `PARTIAL`。删除 Forward 不回滚；它是带 operation ID 的立即停止命令。Controller 必须持久化 `forward_deletion_operations`，只有 Agent ACK `local_forwarding_stopped=true` 后才把远端停止标为完成；离线时保持 `DELETE_PENDING_OFFLINE`。

### 8.4 节点删除状态机

普通删除：

1. Controller 事务创建 operation，节点进入 `DELETING`，冻结 Forward/config 变更。
2. 在线时发送 `node_decommission_command(operation_id)`；离线时保持 `WAITING_AGENT`，等重连后优先发送。
3. Agent 收到后先把独立 terminal marker 原子写为 `DECOMMISSIONING`；从这一刻起即使崩溃重启，也不得加载 LKG。
4. Agent 停止全部 Forward、关闭活跃连接/session，best-effort 释放 mapping/lease，并清空 LKG、hook secret、pending job 与本地 runtime state。网关不可达时不能阻止本地终止，释放错误写入 cleanup warnings，残留 lease 等待自然过期。
5. Agent 写 `DECOMMISSIONED` 并返回带 operation ID、`local_forwarding_stopped=true` 和 cleanup warnings 的 ACK。
6. Controller 核对 ACK 后删除 node、Forward 管理记录和 credential binding，写审计记录。

强制删除：

1. UI 必须由用户主动勾选“强制删除”并二次确认。
2. Controller 创建 operation；若控制连接存在则 best-effort 写入同一 command，随后不等 ACK，立即从常规节点/Forward 管理表和 UI 删除。
3. Controller 保留最小 cleanup tombstone；旧 Agent key 后续只能进入 cleanup-only session，重复接收同一 operation 的 terminal command，不能收到普通配置或 secret。
4. 收到迟到 ACK 后标记 cleanup 完成并清理 tombstone/credential material，只保留普通审计记录。
5. 若 Agent 离线且永不重连，主控无法证明它已停止。强制删除只代表“主控记录立即删除”，不代表“远端业务已确认停止”。

## 9. 安全设计

### 9.1 管理员与 Web

- 管理密码使用 Argon2id + 每用户随机 salt；参数启动时可迁移。
- 服务端 session ID 使用 `crypto/rand`，数据库只存 hash；cookie 为 `HttpOnly`、`SameSite=Lax/Strict`、TLS 时 `Secure`。
- 所有状态修改 API 做 CSRF 校验、Origin 检查、body size 限制。
- 登录限速、统一错误信息、审计登录成功/失败但不记录密码。
- CSP、`X-Content-Type-Options`、frame 限制；模板自动转义；前端避免 `innerHTML` 拼接不可信字段。

### 9.2 Agent 身份与传输边界

AntiNAT 不签发或管理 TLS 证书，也不依赖 mTLS，以兼容反向代理/CDN tunnel：

1. Controller 首次启动生成持久 Ed25519 signing key，私钥仅存 Controller 0600 state；公钥指纹显示在管理页并嵌入部署命令。Agent 必须 pin 指纹，不能静默 TOFU 到任意新 Controller key。Controller key 轮换采用 old-key 签名的 overlap rotation；丢失旧 key 需要管理员显式重新 enrollment。
2. 创建 node 时生成 256-bit 一次性 enrollment token；Controller 只保存 token hash、node ID、到期时间和 used 状态。token 只在创建/轮换时显示一次，不允许 API 再次读取明文。
3. Agent 本地生成 Ed25519 节点密钥；enroll 时提交 public key，私钥永不离开 Agent。Controller 消费 token 后绑定 node ID 与 public key；同一 token 并发只能有一个事务成功。
4. WebSocket 建连时双方用随机 challenge 证明持有各自私钥。之后每条控制 envelope 都包含 `schema_version/session_id/direction/sequence/message_id/type/payload_hash`，发送方对精确 envelope bytes 签名；每个 session 的 sequence 从 1 开始且严格单调，方向隔离。签名通过后才解析 payload，避免 JSON 重编码/规范化歧义。
5. Agent 只接受 pinned Controller key 签名的 desired/deletion/probe/credential-rotation 命令；Controller 只接受已绑定 Agent key 签名的 heartbeat/status/ACK/traffic。反向代理/CDN 只能转发，不能伪造端到端命令。
6. 普通删除只在 Agent 返回 `node_decommission_ack` 后删除 key binding；强制删除立即移除完整 node 记录，但保留 `node_id + public_key_hash + delete_operation_id` 的最小 cleanup tombstone。旧 Agent 在 handshake 中重新提交 public key，Controller 先比对 hash 再验签，只允许 cleanup-only session。
7. `http/ws` 只适合用户显式确认的可信内网，且必须持续显示明文警告；跨互联网 enrollment/control 必须使用用户已有的 `https/wss`、反向代理或安全隧道。应用层签名提供身份和完整性，但不提供机密性，也不能防止明文 token 被旁路窃听。
8. 非 TLS transport 禁止下发或缓存 hook secrets；安装器默认拒绝对非 loopback/RFC1918 endpoint 做明文 enrollment，只有显式 `--allow-insecure-enrollment` 才能继续并写审计。
9. Agent 私钥在 Linux 由专用 service user 以 0600 文件持有；Windows 优先使用 service identity 绑定的 DPAPI，无法使用时必须严格 service SID ACL。Agent key rotation 是 crash-safe 两阶段：旧 key 对 `new_public_key + Controller nonce + credential_version` 签名，Controller overlap 接受 old/new，Agent fsync 新 key 并用新 key ACK 后才撤销旧 key；cleanup tombstone 保存 credential version，处理轮换与强删并发。

### 9.3 Hook

V1 不内置 Cloudflare/AliDNS/DNSPod provider adapter。Mapping hook 在 Agent 侧运行，因此 Controller 断线但映射发生变化时仍可执行；提供通用 webhook 和独立进程 JavaScript runner：

- 只读输入：`event`、`forward`、`old_endpoint`、`new_endpoint`、`published_url`、`timestamp`；通过 stdin 传一份有大小上限的 JSON，不挂载或暴露真实文件系统。
- `antinat-hook-runner` 每次事件启动独立短命子进程；JS runtime 不注册网络、文件、进程、反射或任意 Go bridge。Linux 用 rlimit/cgroup 能力（可用时），Windows 用 Job Object；Agent 必须有 wall-clock timeout、kill 和并发上限。若平台无法施加最低资源限制，JS capability 报 `UNSUPPORTED`，不能退回不受限进程内执行。
- runner 只产生受限 `http.request`/`secret.sign` 描述，由 Agent broker 真正发请求或 HMAC。SHA256、Base64、RFC3986 URL 编码、随机 nonce 和 RFC3339 时间可在 runner 内作为纯函数提供；HMAC-SHA1/SHA256 默认由 broker 使用 secret handle 完成，JS 不获得明文 secret。每个 hook 明确 destination allowlist 和可引用 secret 列表。
- HTTP broker 默认只允许 HTTPS 公网目标并忽略 `HTTP_PROXY/HTTPS_PROXY/NO_PROXY` 环境变量。每次请求和每次 redirect 都解析并校验全部 A/AAAA；任一地址属于 loopback、RFC1918、CGNAT、ULA、link-local、multicast、unspecified、metadata 或 IPv4-mapped IPv6 受限地址时整体拒绝。实际 Dial 固定到已校验 IP，同时保留原 hostname 做 SNI/Host，防 DNS rebinding/TOCTOU。
- 限制请求 method、port、header、body、响应大小、redirect、总时长、连接数、并发和重试。Hook delivery 明确为 **at-least-once**：Agent bbolt 持久化 bounded queue，stable event ID 进入 header/body，指数退避后进入 dead-letter，UI 显示 pending/failed；目标/API 必须幂等，不宣称 exactly-once。
- Hook 事件至少包含 `EndpointActivated`、`EndpointChanged`、`EndpointDeactivated`、`ForwardDeleted`。删除/decommission 先本地立即停止，再 best-effort 投递 deactivation/delete event；hook 失败绝不能恢复 Forward。只有 WAN verified activation 可产生 Activated/Changed，force-published 状态必须带 unverified 标记。
- Controller master key 与 Agent hook key 分别保存为 DB 外 0600 文件；secret 在 SQLite/bbolt 中只存密文，runner 只拿签名句柄，日志自动脱敏。备份/恢复必须包含对应 key；若整个 state directory 被攻破，不宣传“磁盘加密可抵御 root”。
- 任意 local shell/local executable hook 不进入 v1；如 v1.1 增加，只能由机器管理员预安装绝对路径 allowlist 并使用 `shell=false`，不能从面板上传可执行文件。

### 9.4 进程权限

- Controller 与 Agent 默认使用普通用户权限；V1 用户态高端口转发不要求 root/Administrator。
- Linux systemd/OpenRC 与 Windows Service 安装动作需要一次管理员权限，但运行账户应降权。
- Windows Service 不能依赖交互式“首次监听”弹窗。安装时选择 `firewall_policy=managed-range|manual`：默认 managed-range 为精确 Agent binary 创建 TCP/UDP inbound rule，端口范围默认 `10240-65535`、profile 由用户确认，并记录 rule GUID/owner tag；manual 不创建规则且 capability 显示 `HOST_FIREWALL_RULE_REQUIRED`。低权限 Agent 不动态改 Defender，范围外端口需要管理员 repair 命令或判 unsupported。
- v1.1 若加入 nftables，使用最小化 `antinat-netd` helper，不让完整 Agent 长期持有 `CAP_NET_ADMIN`。
- systemd 至少评估并启用 `NoNewPrivileges`、`ProtectSystem=strict`、`PrivateTmp`、`ProtectHome`、最小 `ReadWritePaths` 与合理 `LimitNOFILE`；Windows 使用独立 service SID、目录 ACL 和 Job limits。所有平台保留与动态 listener/session 上限一致的资源预算。
- Controller 的 UI/API、Agent WebSocket、SSE 和 probe 虽共享端口，但使用独立连接数、速率、body、队列和 goroutine 配额，防止 Agent/探测洪泛拖死管理 UI。
- ownership manifest 必须 root/SYSTEM 所有、严格 ACL，并用安装实例 key 做 HMAC。卸载时 canonicalize path，拒绝 allowlist 外路径、`..`、symlink/reparse-point 穿越、挂载点/系统目录和未知 resource type；核对 service name、firewall GUID/owner tag 和 installation ID 后才删除。
- Agent 卸载先写本地 uninstall/terminal marker，关闭 listener/活跃连接/session，best-effort 释放 mapping，确认不再恢复 LKG 后再删服务与 state。
- Controller “完全卸载”前列出全部远端节点，默认批量执行普通 decommission 并等待 ACK；离线节点明确显示未确认。用户强制继续时导出 operation/节点清单和警告，不能声称远端已停止，然后才允许删除 Controller DB/key。

## 10. 数据模型

SQLite migration 初始表：

- `users`
- `web_sessions`
- `global_settings`
- `nodes`
- `node_enrollment_tokens`
- `node_credentials`
- `node_deletion_operations`
- `node_cleanup_tombstones`
- `node_traversal_profiles`
- `node_traversal_strategy_results`
- `node_deployment_profiles`
- `control_outbox`
- `control_inbox`
- `forward_specs`
- `forward_deletion_operations`
- `forward_activations`
- `forward_runtime_status`
- `forward_endpoint_events`
- `probe_providers`
- `probe_results`
- `traffic_ingest_cursors`
- `traffic_rollups`
- `navigation_categories`
- `navigation_items`
- `hook_definitions`
- `hook_secrets`
- `hook_deliveries`
- `audit_logs`
- `schema_migrations`

关键约束：

- 所有 ID 使用 UUID；显示顺序使用可重排的 `sort_key`。
- node/forward revision 单调递增。
- 关键唯一键至少包含：`(node_id, desired_revision)`、`(forward_id, spec_revision)`、`(forward_id, activation_id)`、`(node_id, agent_instance_id, stream_id, seq)`、`(forward_id, activation_id, endpoint_event_id)`、`(hook_id, event_id, attempt_no)`。
- `nodes.current_connection_epoch` 与 `forwards.current_activation_id` 都以事务/CAS 更新；旧 epoch/activation 事件不能覆盖 current。
- control outbox/inbox、deletion operation 和 cleanup tombstone 用逻辑 UUID 关联；需要在 node/forward 主行删除后继续存在的记录不得使用会被级联删除的 FK。
- traversal profile 唯一键包含 node、network fingerprint、protocol、strategy 与 layer signature；selected default 分 TCP/UDP。
- `forward_specs` 对 desired-present 的 exact `(node_id,family,protocol,bind_ipv4,local_port)` 建 partial unique index；wildcard/specific overlap 由 API validator + Agent PortRegistry 二次拒绝，数据库约束不能替代运行时 ownership。
- endpoint/runtime status 唯一键包含 `activation_id`；旧 activation 更新不能覆盖 `current_activation_id` 对应发布状态。
- token/secret/password 只存 hash 或密文；节点只保存 public key/credential hash，不保存 Agent 私钥。
- SQLite 开启 WAL、foreign keys、busy timeout；所有多表变更使用事务。
- SQLite 初始运维默认值：`busy_timeout=5s`；约 1000 pages passive checkpoint，WAL 超过 64 MiB 时在非关键路径触发 checkpoint，备份窗口可 `TRUNCATE`；启动/备份前做 `quick_check`，恢复/迁移失败后做 `integrity_check`。这些值可配置并由 benchmark 调整。
- 磁盘剩余低于 10% 或 512 MiB 时告警并暂停非关键 traffic rollup/hook debug 写入；低于 128 MiB 时拒绝新配置但仍允许 stop/delete/decommission、安全审计和必要 ACK，避免磁盘满阻止远端停止。
- 默认 retention：traffic rollup 30 天、endpoint event 90 天、audit 180 天、已完成 operation/hook delivery 30 天；未 ACK deletion/tombstone 不因保留期自动删除。管理员可配置更长并看到预计磁盘占用。
- `forward_deletion_operations` 独立持久化 operation ID、node/forward ID、requested revision、状态、Agent ACK、warnings 与时间；ACK 前不能因删掉 `forward_specs` 而失去重连 stop 指令。
- `probe_results` 保存 `vantage_id/path_class/source_ip/result/nonce_hash/expires_at/generation`；nonce 明文不长期落库，过期结果不能激活 endpoint。
- Controller signing private key、Controller master encryption key 不放 SQLite；仅保存 key ID/公钥/轮换元数据。备份若缺少外部 key，恢复程序必须 fail closed 并给出可操作错误。
- 删除 Forward 的 Controller 事务必须立即把资源改为 `desired_presence=ABSENT`、递增 desired revision、创建 deletion operation 并写 control outbox；此后任何新 snapshot 都不得再包含可激活 spec。管理/审计行可保留到 Agent ACK，但不能以 active desired 形式保留。在线 ACK 后才显示远端停止完成；离线为 `DELETE_PENDING_OFFLINE`。
- 普通 node deletion operation 是可恢复状态机：`PREPARING -> COMMAND_SENT -> WAITING_ACK -> ACKED -> CONTROLLER_REMOVED`。只有 ACK 证明 Agent 已停止所有本地 Forward、关闭 listener/连接并清空 LKG/secret/job 后，才级联删除 node/forward 管理记录；网关 mapping 释放失败作为 warning，不阻塞本地终止。
- 强制删除使用相同 command，但在 `COMMAND_SENT_BEST_EFFORT` 后立即删除完整 node 记录；cleanup tombstone 不设指向 node 表的级联外键，只保存 node ID、public-key hash、operation ID、创建时间和 cleanup 状态，不保留 Forward 配置或 secret。
- 强制删除时若 Agent 离线或消息尚未执行，远端可能继续旧 LKG；UI 必须明确“仅主控已删除，远端停止未确认”。旧 Agent 后续连接只允许执行 `stop_all_and_forget` 并返回 cleanup ACK。

## 11. API 与控制协议

### 11.1 管理 API（建议）

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me

GET    /api/v1/admin/settings
PUT    /api/v1/admin/settings
PUT    /api/v1/admin/password

GET    /api/v1/admin/nodes
POST   /api/v1/admin/nodes
GET    /api/v1/admin/nodes/{id}
PATCH  /api/v1/admin/nodes/{id}
POST   /api/v1/admin/nodes/{id}/delete   ({"force": false|true})
GET    /api/v1/admin/node-deletions/{operation_id}
POST   /api/v1/admin/nodes/{id}/enrollment-token
GET    /api/v1/admin/nodes/{id}/traversal-profile
POST   /api/v1/admin/nodes/{id}/traversal-detection
PUT    /api/v1/admin/nodes/{id}/traversal-defaults
GET    /api/v1/admin/nodes/{id}/deployment-profile
PUT    /api/v1/admin/nodes/{id}/deployment-profile

GET    /api/v1/admin/forwards
POST   /api/v1/admin/forwards
GET    /api/v1/admin/forwards/{id}
PATCH  /api/v1/admin/forwards/{id}
DELETE /api/v1/admin/forwards/{id}
GET    /api/v1/admin/forward-deletions/{operation_id}
POST   /api/v1/admin/forwards/{id}/retry
POST   /api/v1/admin/forwards/{id}/force-cutover

GET    /api/v1/admin/navigation/categories
POST   /api/v1/admin/navigation/categories
PATCH  /api/v1/admin/navigation/categories/{id}
DELETE /api/v1/admin/navigation/categories/{id}
GET    /api/v1/admin/navigation/items
POST   /api/v1/admin/navigation/items
PATCH  /api/v1/admin/navigation/items/{id}
DELETE /api/v1/admin/navigation/items/{id}
PUT    /api/v1/admin/navigation/order

GET    /api/v1/admin/events          (SSE)
GET    /api/v1/admin/audit
GET    /api/v1/admin/traffic
```

所有修改/删除已有资源的写请求使用标准 ETag/`If-Match` 做 optimistic concurrency：缺少前置条件返回 `428 Precondition Required`，revision 不匹配返回 `412 Precondition Failed` 并附当前 ETag；`409 Conflict` 只用于端口占用、状态机不允许等语义冲突。创建操作使用 idempotency key，避免浏览器重试产生重复节点/Forward。

节点删除请求返回 deletion operation：普通模式为 `202 Accepted` 并在 ACK 后从节点列表消失；强制模式同样先创建 operation/best-effort 发送 command，但立即从节点列表移除，并返回 `remote_cleanup_confirmed=false`。强制删除不是远端停止成功的证明。

Forward `DELETE` 也返回 `202 Accepted + operation_id`。在线 Agent ACK 前状态为 `DELETE_PENDING_AGENT`，离线为 `DELETE_PENDING_OFFLINE`；只有 `forward-deletions/{operation_id}` 进入 `ACKED` 才表示远端 listener/连接/session 已停止。重复 DELETE 使用同一未完成 operation，不能创建互相竞争的删除任务。

### 11.2 Enrollment 与 Agent 通道

```text
POST /api/v1/agent/enroll
GET  /api/v1/agent/connect   (WebSocket upgrade + signed challenge)
```

消息类型：

- `hello`
- `desired_state`
- `desired_state_ack` / `desired_state_nack`
- `heartbeat`
- `runtime_transition`
- `endpoint_changed`
- `traffic_delta`
- `node_decommission_command`
- `node_decommission_ack`
- `traversal_detect_request`
- `traversal_detect_progress`
- `traversal_detect_result`
- `probe_request`
- `probe_result`
- `credential_rotate`
- `server_notice`

每条消息使用第 9.2 节签名 envelope，并包含对应 revision/generation。时间戳只作观测，安全过期以 Controller deadline/session nonce 为准，允许报告 clock skew，不能依赖 Agent 墙钟决定 token/probe 是否有效。消息大小有限制；未知 type 拒绝或按版本协商处理。

每次认证成功由 Controller 事务分配持久、单调递增的 `connection_epoch` 和随机 `session_id`；所有消息绑定 node/session/epoch/direction。新连接成为 current 后，旧 WebSocket 即使签名正确，其迟到 ACK/status 也因 epoch fencing 被拒绝。sequence 只在当前 session 内按方向独立单调，跨重连幂等依赖 operation/message ID 与持久状态，不能依赖内存计数器。

关键命令使用 durable inbox/outbox：Controller 在同一 SQLite 事务中写 desired/delete/decommission/credential operation 与 `control_outbox`；Agent 在 bbolt 中持久 inbox、operation result 和待发 ACK。重连后按 operation 状态重发，直到幂等 ACK；heartbeat 和可丢 telemetry 可不进入 durable outbox。

### 11.3 创建节点响应修正

创建节点响应可一次返回 deployment token，但该 token 之后不可再次读取：

```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "name": "node-xxxx",
    "enrollment_token": "only-shown-once",
    "expires_at": "RFC3339"
  }
}
```

## 12. UI/UX 信息架构

### 12.1 公共首页 `/`

- 白色、简约、扁平卡片布局。
- 左侧分类；移动端改为横向可滚动分类条。
- 卡片显示名称、简介、协议/状态和跳转按钮。
- 关联 Forward 为 ACTIVE 时显示可点击地址；离线/失败时卡片置灰、红色状态灯，并显示“最后已知地址 + 更新时间 + 可能已失效”文本。
- 最后已知地址不可点击，避免把用户导向陈旧端点；提供显式“复制陈旧地址”按钮，按钮/Toast 必须再次提示可能失效，复制不改变发布状态。
- 私有站点模式下首页重定向登录；公开模式下只读，无管理信息泄漏。
- 右上设置按钮进入 `/admin`。
- 提供中文/English 切换，默认中文；选择持久化到用户/session。

### 12.2 管理页 `/admin`

四个主 tab：

1. 首页设置：分类、卡片、拖拽、关联 Forward、中英文内容、实时预览。
2. 转发设置：按节点筛选/分组；卡片显示名称、状态、当前/最后 endpoint、target、published host、strategy layers、gateway/public endpoint scope、requested/assigned port、lease、probe vantage/last result、host-firewall suspicion、基础计数、可选流量、data-path/zero-copy 和编辑入口。
3. 节点：名称、控制连接地址、在线状态、最近心跳、network fingerprint、TCP/UDP strategy/layer 结果、选定默认 strategy、重新探测、部署、编辑、删除。
4. 全局设置：`controller_endpoint`、只读展示当前 `listen_address/listen_port`（修改需服务配置+重启）、`trusted_proxies`、可选 remote-signed probe endpoint + pinned key、首页是否私有、用户名/密码、分开的 TCP/UDP STUN 列表、默认探测调度、语言和可选统计保留。

节点探测完成时弹出模式选择；若全部失败仍显示“保存所选模式”按钮，不把失败结果当作表单校验错误。

### 12.3 Forward 编辑表单

字段：

- node
- name（中英文显示名可按 i18n 模型处理）
- protocol (`tcp`/`udp`)
- target host + port（V1 域名解析结果只选择 IPv4；纯 IPv6 target 返回 `UNSUPPORTED_IN_V1`）
- traversal strategy（默认继承 node 对应协议 selected default；可覆盖 `direct-v4`、`manual-static-v4`、`explicit-gateway{pcp|nat-pmp|upnp, upstream none|stun}`、`stun-only`、`auto`）
- requested public port + `port_policy: strict|prefer_requested|accept_any`（默认 accept_any）
- bind interface/IPv4
- requested local port（可选；必须通过 PortRegistry 唯一所有权检查）
- manual-static-v4 expected public endpoint（仅该 strategy 显示）
- rate limit enable + ingress/egress rate + burst（默认关闭）
- detailed traffic stats enable（默认关闭）
- publish scheme、published host、custom URI template
- webhook/JavaScript/local script hook
- health check

表单根据 Agent OS/capabilities 和 node traversal profile 禁用不支持项。data-path 预览实时显示：Linux splice、buffered-limited、buffered-stats、Windows buffered 或 UDP；启用高开销功能前明确说明影响。删除按钮明确写明“立即停止并断开所有活动连接”，Agent 离线时显示无法保证立即执行。

### 12.4 节点创建/部署弹窗

v1 展示 Linux、Windows 和 Docker：

- 创建名称可空；后端生成默认名。
- 请求中按钮宽度稳定并防重复提交。
- 成功后进入部署步骤；Agent 首次上线后自动进入探测进度，再进入 TCP/UDP 默认 strategy 选择。
- enrollment token 只显示一次并明确到期。
- Linux 命令使用 POSIX shell 安全转义；Windows 使用 PowerShell 专用转义；Docker 移除安装脚本专用参数。
- GitHub proxy 使用独立 enable 开关与 URL normalize。
- 复制命令必须由用户点击触发，Clipboard 失败有降级。

### 12.5 节点删除交互

- 删除对话框先列出该节点全部 Forward 数量、在线状态和后果。
- 默认按钮为“停止全部 Forward 并删除节点”：节点进入 `DELETING`，UI 显示每条 Forward 停止进度；收到 `node_decommission_ack` 后节点才从列表移除。
- 增加未默认勾选的“强制删除”复选框。勾选后必须二次显示：主控会立即移除节点，不等待 Agent 确认；Agent 离线或命令未执行时，远端可能继续运行旧配置。
- 强制删除后从常规节点列表移除，但审计日志显示 operation ID、command 是否已发送和 `remote_cleanup_confirmed`；不把 cleanup tombstone 当作可管理节点展示。
- 普通删除期间禁止新增/修改 Forward；允许取消只限 command 尚未发送前。Agent 一旦进入 `DECOMMISSIONING`，删除不可回滚，重新使用该主机必须重新 enrollment。

### 12.6 前端技能门禁

已安装并验证以下技能，UI 工作开始前必须全部加载：

- `design-critique`：Anthropic 主文件，经人工核验后处理安全扫描误报；
- `frontend-design`：Anthropic trusted source，SAFE；
- `impeccable`：完整上游包因包含持久化 hooks/浏览器注入被 Hermes 判为 DANGEROUS，已改为本地 safe standalone methodology，不运行脚本或修改 AGENTS；
- `make-interfaces-feel-better`：原作者完整资源，SAFE。

实际 UI 流程：先 critique 和信息架构，再定视觉方向，以 safe `impeccable` 做 Operate 模式质量门槛，最后用 `make-interfaces-feel-better` 检查字体、表面、图标、动效和性能。最终报告列出四个技能的实际使用证据。

## 13. 建议仓库结构

```text
/root/AntiNAT/
├── .github/workflows/ci.yml
├── .hermes/plans/
├── cmd/
│   ├── antinat-controller/main.go
│   ├── antinat-agent/main.go
│   ├── antinat-probe/main.go              # v1 可选无状态 WAN probe
│   ├── antinat-hook-runner/main.go        # v1 独立 JS runner
│   └── antinat-netd/main.go              # v1.1 可选
├── internal/
│   ├── buildinfo/
│   ├── config/
│   ├── controller/
│   │   ├── app.go
│   │   ├── auth/
│   │   ├── agenthub/
│   │   ├── api/
│   │   ├── probe/
│   │   ├── store/
│   │   └── web/
│   ├── agent/
│   │   ├── app.go
│   │   ├── control/
│   │   ├── localstate/
│   │   └── reconcile/
│   ├── traversal/
│   │   ├── strategy.go
│   │   ├── portregistry.go
│   │   ├── mapping_journal.go
│   │   ├── manager.go
│   │   ├── state.go
│   │   ├── direct/
│   │   ├── manual/
│   │   ├── stun/
│   │   ├── pcp/
│   │   ├── natpmp/
│   │   └── upnp/
│   ├── forward/
│   │   ├── backend.go
│   │   ├── runtime.go
│   │   ├── tcp/
│   │   └── udp/
│   ├── hook/
│   ├── metrics/
│   ├── protocol/
│   └── security/
├── migrations/
├── web/
│   ├── templates/
│   └── static/{css,js,icons}/
├── scripts/
│   ├── install.sh
│   ├── install.ps1
│   ├── uninstall.sh
│   ├── uninstall.ps1
│   └── libinstall.sh
├── deploy/
│   ├── systemd/
│   ├── openrc/
│   ├── windows/
│   └── docker/
├── test/
│   ├── integration/
│   ├── netns/
│   ├── e2e/
│   └── benchmark/
├── spike/                                  # M0 可行性代码；结论固化后可删除
│   ├── tcp-reuse/
│   ├── udp-single-socket/
│   ├── sqlite-crossbuild/
│   └── hook-runner-limits/
├── docs/
│   ├── architecture.md
│   ├── nat-support.md
│   ├── security.md
│   ├── operations.md
│   └── adr/
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── LICENSE
└── SECURITY.md
```

### 13.1 运行时路径与 ownership 边界

- Linux binaries：`/usr/local/bin/antinat-{controller,agent,probe,hook-runner}`；配置：`/etc/antinat/{controller,agent}.yaml`；状态：`/var/lib/antinat/{controller,agent}/`。systemd 默认写 journal，OpenRC 若写文件则由专属 logrotate 管理。
- Windows binaries：`%ProgramFiles%\AntiNAT\`；配置/状态：`%ProgramData%\AntiNAT\{Controller,Agent}\`；服务、Event Log source、Firewall rule 使用带稳定 product ID 的精确名称。
- Docker：只支持 Linux host；Controller/Agent 分别挂载独立 state volume，token 不写 image layer/compose 文件。容器内目标地址语义在 host-network 下按 host namespace 解释。
- 每个安装实例生成 ownership manifest 和 installation ID；卸载只删除相同 ID 或编译时专属路径下的资源。Controller 与 Agent 共机时各自拥有独立 state，卸载单角色不得误删另一角色，只有“完全卸载”才清两者。

## 14. 里程碑与工作包实施计划

本节共有 **28 个 Work Package**：Task 0、1、1A、1B、2–25。它们规模从数小时到数周，是 Epic/WP 而不是可一次实现的 TDD Task；不得把整个 WP 一次性交给单个编码 Agent。每个 WP 开工前必须在 `.hermes/plans/` 生成独立 milestone/story 子计划，把每个 Story 限定为一个可观察行为，再拆成 2–5 分钟动作（精确失败测试、运行确认 RED、最小 GREEN、focused/full 回归、refactor、commit）。下面的 Expected 只表示真实执行后应达到的结果，不得伪造输出。

### 14.0 执行顺序与退出闸门

| 里程碑 | 工作包 | 必须证明的退出条件 | 失败时处理 |
|---|---|---|---|
| M0 范围/合同/可行性 | Task 0、1、1A、1B | Git/module/CI；scope/support matrix；依赖/许可证；Linux+Windows unique-listener/Defender；layered CPE→CGN；probe frame；SQLite；hook runner；控制/LKG/installer contracts 冻结 | 不继续产品层；缩 capability 或延期 |
| M1 Linux TCP Walking Skeleton | Task 2、3、5、6、7、8、11、12、17/18 的 direct/manual 最小切片 | 从空 DB/UI 创建 node→enroll→创建 direct/manual TCP Forward→独立 probe→外部请求到 target→显示状态→target 热改→重启 LKG→在线删除，全链 E2E | 修正协议/状态模型，不扩 traversal |
| M2 Linux TCP Traversal Beta | Task 9、10、11、14、22 的 TCP 子集 | sequential direct/manual/gateway+STUN/stun-only；组合 NAT lab+至少一类真实 NAT；lease/socket/journal 无残留；非 independent OPEN 不发布 | 每个 layer 单独 unsupported，不一次合入全部 adapter |
| M3 UDP + Lifecycle Beta | Task 13、14、22 的 UDP/删除子集 | UDP 单 socket/demux/limits/ICMP；Forward offline delete；normal/force node decommission crash/reconnect E2E | 隐藏未完成的 UDP/删除入口，不发布半语义 |
| M4 Product/Security Feature Complete | Task 4、15、16、17、18、19、24 的随功能测试 | 管理 auth、完整 API/UI、rate/stats、hook runner、token bootstrap、浏览器与安全/故障回归；高成本开关默认关闭 | 高风险功能 feature-gate、降级 webhook-only 或延期 |
| M5 Deployment/Platform | Task 20、21、22、24 的平台/运维子集 | Debian/systemd fresh install/upgrade/purge；Alpine/OpenRC 原生；Linux arm64；Windows amd64 Service/Defender/router；dual-stack 控制 | 未实测平台只标 beta/build-only，不列 GA |
| M6 Performance/RC/GA | Task 23、25 | 专用 lab SLO、独立 WAN、真实 NAT 矩阵、24h soak、SBOM/签名、release artifact fresh install/upgrade/uninstall | 只发布 beta 或移除未通过的平台/strategy/SLO 宣传 |

强制规则：

1. M0 未通过前，不开始完整 UI、installer 或全量数据库表实现。
2. 每个里程碑产生可运行 artifact；M1 必须是第一个用户可操作的 Walking Skeleton，不能等 Task 17/18 全量完成才第一次端到端。
3. Windows strategy/layer 使用 `supported/beta/experimental/build-only/unsupported` 矩阵；cross-build 不等于支持。
4. 节点删除入口只有 Task 14 的 crash/offline/cleanup-only E2E 完整后才在 UI 启用；此前返回 feature-disabled，而不是提供半成品。
5. 手工 real-WAN/2Gbps/24h 不放普通 PR CI；支持声明只来自对应 evidence lane。
6. 每个 WP 完成后单独 commit；里程碑结束做 spec compliance + security/code review，再进入下一阶段。

### 14.1 Story/TDD 子计划模板

每个 WP 开工前的子计划必须为每个 Story 写明：

```text
Story ID / parent WP / milestone
One observable behavior and explicit non-goals
Prerequisites + blocked-by
Files to create/modify
CI lane + time budget + required failure artifacts
RED: exact focused test command + expected failure reason
GREEN: minimal implementation only
VERIFY: focused test -> affected package -> integration/E2E -> static checks
REFACTOR: constraints that must remain true
Commit message
Rollback/cleanup for privileged or external resources
```

Story 不能同时跨两个协议 adapter、两个平台实现或“API+完整 UI+installer”。确定性失败不得靠重跑变绿；只允许基础设施失败最多自动重试一次，并保存 logs/pcap/goroutine/handle dump。Flaky test 必须隔离、建 issue 并阻断对应 release evidence。

### 14.2 CI lanes 与证据

| Lane | 预算/触发 | 内容 | 必须保留的失败证据 |
|---|---|---|---|
| `PR-fast` | 每 PR，目标 <10 min | gofmt、unit、protocol golden、store、vet、cross-build、license | test JSON、compile error、dependency diff |
| `PR-integration` | 每 PR，目标 <20 min | enroll/control/LKG/direct TCP Walking Skeleton、target hot-update/delete、targeted race | Controller/Agent structured logs、state dump |
| `windows-pr` | Windows runner，相关 PR | Winsock/PortRegistry、DPAPI、Service unit/Defender parser、UDP ICMP | ETW/Event Log、handle dump、firewall export |
| `nightly-privileged` | nightly，隔离 runner | netns、真实/fake gateway、bounded fuzz/race、installer containers/VM、failure injection | pcap、namespace/rule dump、goroutine dump |
| `weekly-dedicated` | 固定硬件 | Windows router、Linux arm64/OpenRC、性能短基线、资源泄漏 | hardware manifest、raw histogram、RSS/FD/handle series |
| `release` | RC 手工批准 | 专用性能、真实 WAN/NAT、24h soak、SBOM/signature、fresh install/upgrade/purge | 完整 evidence bundle 与支持矩阵 |

每个 Story 必须标注进入哪个 lane；功能的安全/故障测试随 Story 同时进入 CI，Task 24 只做发布级复核，不是第一次测试重放、SSRF、磁盘满或网络变化。

### 14.3 大型 WP 的强制 Story 边界

- Task 5：token issuance/hash → Agent key storage → enrollment bind → bidirectional challenge/frame signing → rotation/revoke → cleanup-only identity。
- Task 10：strategy contract/PortRegistry → direct/manual → PCP → NAT-PMP → UPnP → STUN-only → gateway+STUN composition → scheduler/profile/journal；每个 adapter 独立 Go/No-Go。
- Task 14：per-activation transition/CAS → target replacement → Forward tombstone/delete → normal node decommission → force cleanup-only。
- Task 16：event/outbox → webhook broker → SSRF transport → secret handles → Linux runner limits → Windows runner limits；runner gate 失败时停在 webhook-only。
- Task 18：最小 node/Forward status UI 先进入 M1；导航拖拽/i18n/a11y/mobile/高级诊断分别成 Story。
- Task 20：installer CLI contract fixture → Linux systemd → OpenRC → Windows Service/Defender → upgrade/rollback → purge/manifest/path attack；不得三平台一次合入。
- Task 23–25：是 release programs，必须进一步按平台、场景和 evidence run 拆分，不能作为一次 RED→GREEN Task。

### Task 0: 固化已确认产品决策并写 ADR

**Objective:** 将已关闭的 P0 决策固化为 ADR、Apache-2.0 LICENSE 和 README 边界。

**Files:**
- Create: `docs/adr/0001-v1-scope.md`
- Create: `docs/adr/0002-traversal-and-relay-boundary.md`
- Create: `docs/adr/0003-security-and-agent-identity.md`
- Create: `docs/requirements-traceability.md`
- Create: `docs/v1-scope-contract.md`
- Create: `docs/support-matrix.md`
- Create: `README.md`
- Create: `LICENSE`

**Steps:**
1. 运行 `git init -b main`，确认只初始化当前 `/root/AntiNAT`，不添加远端。
2. 将第 1.4 节差异和第 18 节决策写入 scope contract/traceability/ADR；support matrix 使用 `supported/beta/experimental/build-only/unsupported`，禁止 cross-build 冒充支持。
3. 在 scope contract 记录最终 Go module path/代码托管 owner；这是 Task 1 的唯一人工启动输入，未填写时停止，不先用临时 module path 产生大量 import。
4. 在 `README.md` 写 Natter 致谢与“无代码复制”声明。
5. 为普通删除、强制删除、cleanup tombstone 和 Agent 本地 terminal marker 单独写删除语义 ADR；明确强制删除不等于远端已停止。
6. 运行 `git diff --check`；Expected: 无空白错误。
7. Commit: `docs: record AntiNAT v1 architecture decisions`。

### Task 1: 初始化 Go monorepo 与质量门禁

**Objective:** 建立可重复构建、测试和交叉编译骨架。

**Files:**
- Create: `go.mod`, `Makefile`, `.gitignore`
- Create: `cmd/antinat-controller/main.go`
- Create: `cmd/antinat-agent/main.go`
- Create: `internal/buildinfo/buildinfo.go`
- Create: `.github/workflows/ci.yml`

**Steps:**
1. 写失败测试 `internal/buildinfo/buildinfo_test.go`，验证版本/commit/date 字段可注入。
2. 使用 Task 0 scope contract 中已填写的最终 module path 初始化 module；设置 `go 1.26.0` language version 与 `toolchain go1.26.5`，安装来源、checksum 和 CI image 固定。
3. 实现两个 `version` 子命令，不启动网络。
4. CI 运行 `go test ./...`、`go vet ./...`、Linux race tests，以及 Linux/Windows amd64/arm64 cross-build；Windows-only socket/service tests 在 Windows runner 执行。
5. Run: `go test ./...`; Expected: PASS。
6. Run: Linux amd64/arm64 和 Windows amd64/arm64 `go build ./cmd/...`；Expected: 四个目标成功或在 ADR 明确移除未验证架构。
7. Commit: `chore: initialize Go workspace and CI`。

### Task 1A: 高风险可行性 spikes（M0 Go/No-Go）

**Objective:** 在业务架构被大量代码锁定前，用最小程序验证最可能推翻设计的假设。

**Files:**
- Create: `spike/tcp-reuse/{linux,windows}/`
- Create: `spike/udp-single-socket/`
- Create: `spike/layered-nat-pipeline/`
- Create: `spike/probe-frame/`
- Create: `spike/data-path-baseline/`
- Create: `spike/sqlite-crossbuild/`
- Create: `spike/hook-runner-limits/`
- Create: `docs/adr/0004-feasibility-gates.md`

**Steps:**
1. Linux 与真实 Windows 分别验证固定 local IP:port 的 TCP outbound STUN/keepalive socket 与唯一 listener 共存、连接归属确定、PortRegistry 冲突、关闭/重建无随机分流；Windows 同时验证 managed-range/manual Defender policy，记录 OS/build/NAT/防火墙。
2. 验证单个未连接 UDP socket 可同时处理 STUN transaction、signed probe frame、keepalive 和普通 payload，普通 payload 不误吞，Windows ICMP 不杀 loop。
3. 用最小 CPE→CGN netns 验证 gateway mapping 后从同一 source tuple 做 upstream STUN/keepalive 的组合 pipeline，第一跳 private/CGN endpoint 不误报 SUCCESS。
4. 验证 bounded TCP probe frame 在 verification-only 和 ACTIVE 短窗口下处理 scanner、slowloris、magic collision、短包/server-first 并回放业务前缀，不误激活/破坏连接。
5. 做短时 data-path baseline：Linux `io.Copy` 是否实际 splice、buffered fallback CPU/alloc；Windows buffered CPU/RSS/handle 和 global buffer budget。只作架构 Go/No-Go，不声称 2 Gbps；无实测收益不引入自定义 splice。
6. 选 1–2 个 SQLite driver 候选，验证 Linux/Windows amd64/arm64 build、无意外 CGO、WAL/backup/迁移、许可证和最小性能。
7. 验证 JS runner 的 timeout、kill、stdout/stderr cap、Linux memory/rlimit 和 Windows Job Object；恶意无限循环/大分配不能杀死 Agent fixture。
8. 用 Controller 与 Agent 同 LAN/同主机案例证明 hairpin 不能算独立 WAN；定义 `NO_INDEPENDENT_VANTAGE`，验证 remote-signed provider request 不可被滥用于 private scan。
9. 把结果写 ADR：`PASS`、`SUPPORTED_WITH_LIMITS` 或 `NO-GO`。NO-GO 必须同步缩减 capability/scope，不能用 TODO 掩盖。
10. Commit: `spike: validate AntiNAT platform feasibility gates`。

### Task 1B: 冻结控制协议、状态语义与依赖清单

**Objective:** 在实现 Controller/Agent 前固定双向身份、partial apply、删除 operation 和依赖许可证边界。

**Files:**
- Create: `docs/protocol.md`
- Create: `docs/state-model.md`
- Create: `docs/dependencies.md`
- Create: `docs/provenance.md`
- Create: `docs/test-strategy.md`
- Create: `docs/milestones.md`
- Create: `docs/installer-contract.md`
- Create: `docs/adr/0005-control-envelope-and-state.md`

**Steps:**
1. 写签名 envelope byte-level test vectors（Controller→Agent 与 Agent→Controller），明确 session/direction/sequence/payload hash、connection epoch fencing、N/N-1 和 Controller/Agent 两阶段 key rotation。
2. 写 desired/received/per-Forward applied/partial ACK、local Forward delete tombstone、durable inbox/outbox、Node terminal decommission 的时序图和 crash points。
3. 写 ProbeProvider/vantage、TCP/UDP bounded signed frame、outstanding token、ACTIVE replayable-prefix classifier 和 anti-scan 的 byte-level test vectors。
4. 决定 SQLite driver、WebSocket、bbolt、Argon2、STUN/UPnP/JS runtime 等依赖，记录版本、许可证、用途和替代方案；定义 per-activation state 与 strategy/layer replacement capability；CI 加 license/SBOM gate。
5. 冻结 installer CLI/exit-code/service/path/ownership contract：Linux/PowerShell/Docker 参数、token stdin/file 语义、noninteractive 行为、repair/upgrade/purge 和 smoke fixture；Task 19 命令生成与 Task 20 installer 必须消费同一 contract fixture。
6. 将第 14.0–14.3 节固化到 `docs/milestones.md`/`docs/test-strategy.md`，每个后续 Story 声明 CI lane、预算、失败 artifacts 和 cleanup。
7. `docs/provenance.md` 记录 RFC/标准和参考来源；实现任务仅依赖 RFC、测试向量和本设计，不复制 Natter GPL 源码。
8. Commit: `docs: freeze AntiNAT control state installer and test contracts`。

### Task 2: 定义领域模型与严格配置解析

**Objective:** 让 Controller 和 Agent 共享版本化、可验证的 desired state。

**Files:**
- Create: `internal/protocol/schema.go`
- Create: `internal/protocol/validate.go`
- Create: `internal/protocol/schema_test.go`
- Create: `internal/config/controller.go`
- Create: `internal/config/agent.go`

**Steps:**
1. 测试 Controller endpoint 的 IPv4/IPv6 URL、Forward IPv4 local/requested public port、`port_policy`、TraversalStrategy/layers、rate/stats、protocol enum 和未知字段拒绝。
2. 定义 `ForwardSpec`、`DesiredState`、`DesiredApplyResult`、`ForwardDeletionOperation`、`ForwardActivation`、`RuntimeStatus`、`TrafficDelta`、`DeploymentProfile`、`NodeTraversalProfile`、`TraversalStrategy/StrategyResult`、`ProbeProvider` 和签名 `ControlEnvelope`；包括 layers、endpoint scope、port policy、connection epoch、operation ID 与 replacement capability。
3. `AddressFamily` 保留 `v4/v6`，但 V1 Forward ingress validator 对 v6 返回稳定错误 `UNSUPPORTED_IN_V1`。
4. JSON decoder 使用 `DisallowUnknownFields`，限制大小并校验 schema version。
5. 用 `netip.AddrPort` 表示 endpoint；域名与端口分字段保存，避免以后加入 IPv6 时迁移字符串格式。
6. Fuzz endpoint 与 desired-state decoder 不 panic。
7. Run: `go test ./internal/protocol ./internal/config`; Expected: PASS。
8. Commit: `feat: define versioned control-plane schema`。

### Task 3: Controller SQLite 与迁移

**Objective:** 建立事务化持久层与 revision 约束。

**Files:**
- Create: `migrations/0001_initial.sql`
- Create: `internal/controller/store/sqlite.go`
- Create: `internal/controller/store/migrations.go`
- Create: `internal/controller/store/*_test.go`

**Steps:**
1. 先写临时数据库测试：迁移幂等、foreign key、WAL、revision conflict、Forward deletion operation 离线/重连/ACK、node deletion operation 恢复、强制删除后 cleanup tombstone 不被级联清除、probe 过期结果不能激活。
2. 实现 schema；token/session 使用 hash 字段，禁止明文列。
3. 所有多表更新通过事务；测试 busy timeout、WAL checkpoint/size、retention、traffic/audit cursor 去重和低磁盘降级，stop/delete/decommission 在低磁盘策略中保持优先。
4. 用 SQLite Backup API 或 `VACUUM INTO` 测一致备份，禁止只复制处于 WAL 模式的主 `.db` 文件；测试 `quick_check/integrity_check`、损坏/磁盘满/迁移失败不覆盖旧 DB。
5. Run: `go test ./internal/controller/store -count=1`; Expected: PASS。
6. Commit: `feat: add transactional controller storage`。

### Task 4: 管理认证和 Web 安全中间件

**Objective:** 安全实现单管理员登录、session 和 CSRF。

**Files:**
- Create: `internal/controller/auth/password.go`
- Create: `internal/controller/auth/session.go`
- Create: `internal/controller/web/middleware.go`
- Create: `internal/controller/auth/*_test.go`

**Steps:**
1. 测试 Argon2id hash/verify、随机密码长度、session 过期/撤销、CSRF/Origin、cookie flags。
2. 实现统一 JSON 错误，不区分用户名/密码哪项错误。
3. 加登录速率限制、body 上限、request ID 和脱敏日志。
4. 测试密码、cookie、token 不出现在日志捕获器。
5. Run: `go test ./internal/controller/auth ./internal/controller/web`; Expected: PASS。
6. Commit: `feat: secure controller authentication`。

### Task 5: Node 创建、一次性 enrollment 与应用层身份

**Objective:** 在不管理 TLS 证书的前提下建立不可重放的 Agent 身份。

**Files:**
- Create: `internal/security/nodekey.go`
- Create: `internal/security/challenge.go`
- Create: `internal/controller/api/nodes.go`
- Create: `internal/controller/agenthub/enroll.go`
- Create: `internal/agent/control/enroll.go`
- Test: corresponding `*_test.go`

**Steps:**
1. 测试 token 使用 `crypto/rand`、只存 hash、TTL、一次消费、并发只能成功一次。
2. Controller 生成 signing key；Agent 生成 Ed25519 私钥/public key；部署命令 pin Controller fingerprint，Controller 消费 token 后绑定 Agent public key。
3. 实现双向 challenge 和逐消息签名 envelope；测试 direction/session/sequence/payload hash、错误 Controller key、错误 Agent key、过期和重放拒绝；私钥不离开各自进程。
4. 实现 node deletion operation：普通删除在 ACK 后移除 key binding；强制删除移除完整 node 后保留 cleanup tombstone，并允许旧 key 进入只能接收 decommission command 的受限会话。
5. 测试 unknown/revoked key 不能恢复普通控制；cleanup key 不能读取 desired state、secret、管理命令，只能 ACK terminal cleanup。
6. 测试非 TLS transport 下秘密字段被拒绝；公网明文 enrollment 默认拒绝；wss/受信 transport 才允许下发 hook secret。
7. 测 Agent two-phase key rotation 在生成新 key、fsync、Controller overlap、ACK、撤销旧 key 各 crash point 可恢复；Windows DPAPI/service ACL 和 Linux 0600 权限测试通过，轮换与 force-delete 并发不绕过 cleanup tombstone。
8. Run: `go test ./internal/security ./internal/controller/agenthub ./internal/agent/control`; Expected: PASS。
9. Commit: `feat: add one-time enrollment and signed node identity`。

### Task 6: Agent WebSocket 控制通道

**Objective:** 实现 IPv4/IPv6 可连接、版本化、可重连、幂等的双向控制通道。

**Files:**
- Create: `internal/controller/agenthub/hub.go`
- Create: `internal/controller/web/dualstack.go`
- Create: `internal/agent/control/client.go`
- Create: `internal/protocol/message.go`
- Test: `internal/*/control*_test.go`

**Steps:**
1. 用 `httptest` 和平台 integration 写双向 signed challenge、逐消息签名、错误 Controller/Agent key、direction/sequence 重放、重复 node 连接、消息大小测试。
2. Controller 在配置端口（默认 3111）同时接受 IPv4/IPv6；Agent URL 测 A-only、AAAA-only、dual-stack 与 fallback。
3. 实现 hello/capability/version 协商；打洞 capability 不是控制连接成功的前置条件。
4. 实现 ping/heartbeat、指数退避+抖动、单 node 新连接替换旧连接；认证事务递增 `connection_epoch`，测试旧 socket 的迟到 ACK 即使签名正确也被 fencing。
5. 每条消息验签后再按 operation/message ID、connection epoch、session sequence 去重；关键命令/ACK 用 SQLite+bbolt durable outbox/inbox，重启重连可重放。旧 revision/activation 被忽略并记录 debug；墙钟偏差只上报，不用于替代 session deadline。
6. Run: Linux + Windows control tests；Expected: PASS。
7. Commit: `feat: establish resilient dual-stack agent control channel`。

### Task 7: Agent last-known-good 与 Reconciler

**Objective:** Controller 离线或错误配置时，现有转发继续工作。

**Files:**
- Create: `internal/agent/localstate/store.go`
- Create: `internal/agent/reconcile/reconciler.go`
- Create: `internal/agent/reconcile/actor.go`
- Test: corresponding tests

**Steps:**
1. 使用 bbolt 测试事务提交/回滚、文件锁、损坏 fail-closed；terminal marker 使用独立临时写+fsync+rename，并 fsync 父目录。
2. 测试 `max_accepted_desired_revision`、`received_desired`、per-Forward `last_applied_spec`、durable inbox/outbox、新/重复/旧 revision、逐资源 ACK 和部分 actor 失败隔离。
3. actor interface 暴露 `Prepare/Activate/Update/Drain/Stop/Status`。
4. 新 desired state 全量验签/校验后写 `received_desired`；每个 Forward 仅在 apply 成功后更新自己的 `last_applied_spec`。失败项保留旧 ACTIVE/LKG，其他项可成功并返回 `PARTIAL`。
5. Forward delete 先事务写 local tombstone 再 stop；测试崩溃/旧 snapshot/Controller rollback 不复活，operation complete + revision high-water 后安全 GC。
6. 实现独立于 LKG 的 durable terminal marker；收到 node decommission 时必须先原子写 `DECOMMISSIONING`，再停止/清空，最后写 `DECOMMISSIONED`。两个状态下进程重启均不得恢复 Forward。
7. 测 crash points：写 Forward/Node marker 后、停止一半 Forward 后、清空 LKG 后、ACK 前；Expected: 重启继续清理而不是恢复业务。
8. Run: `go test ./internal/agent/localstate ./internal/agent/reconcile -race`; Expected: PASS。
9. Commit: `feat: add crash-safe agent reconciliation and decommissioning`。

### Task 8: 网络接口、路由、fingerprint 与目标解析

**Objective:** 正确识别 V1 IPv4 打洞网络，生成 profile 失效 fingerprint，并保持 Controller dual-stack 连接能力。

**Files:**
- Create: `internal/traversal/network.go`
- Create: `internal/traversal/fingerprint.go`
- Create: `internal/forward/resolver.go`
- Test: corresponding Linux/Windows tests

**Steps:**
1. 测试 RFC1918、CGNAT `100.64.0.0/10`、loopback、link-local、公网 IPv4，以及 Controller endpoint 的 global IPv6/zone URL。
2. Linux 读取 netlink/default route；Windows 读取系统 interface/route API；generic fallback 使用 stdlib。
3. fingerprint 至少包含 OS、选定网卡 stable ID、default gateway、route metric、LAN IPv4、观察公网 IPv4、可得时的 gateway MAC/network profile ID hash 和 strategy config version；变化或默认 7 天 max-age 后 profile 标 `STALE/STALE_BY_AGE`。
4. Controller dial 使用 Happy Eyeballs；V1 Forward target 解析后只接受 IPv4，IPv6 target 返回 `UNSUPPORTED_IN_V1`，但 resolver/strategy 接口保留 family 参数。
5. Forward target 域名使用有界后台刷新（默认 60 秒+jitter，可配置），原子保存最近成功的 IPv4 列表并为新 session 轮转；DNS 临时失败不清空 last-known-good 地址、不切断已有连接。v1 不声称遵循 DNS TTL，除非后续明确引入可返回 TTL 的 resolver。
6. Run: Linux/Windows network tests；Expected: PASS。
7. Commit: `feat: fingerprint traversal networks and resolve targets`。

### Task 9: STUN 编解码与同端口 socket

**Objective:** 基于 RFC 8489 从指定本地端口获取 TCP/UDP mapped address。

**Files:**
- Create: `internal/traversal/stun/message.go`
- Create: `internal/traversal/stun/client.go`
- Create: `internal/traversal/stun/socket_linux.go`
- Create: `internal/traversal/stun/socket_windows.go`
- Create: `internal/traversal/stun/socket_generic.go`
- Test: unit + fake STUN server

**Steps:**
1. 写 V1 IPv4 XOR-MAPPED-ADDRESS、message class/server tuple/transaction mismatch、malformed/oversize length、TCP header+body partial read/framing/deadline 和 UDP retransmit/backoff 测试；保留 IPv6 codec 单测但不接入 V1 strategy。
2. 使用可靠 codec（可用 pion/stun 只做消息编解码），socket 生命周期由 AntiNAT 控制。
3. Linux/Windows 分别在 bind 前设置平台选项并通过 PortRegistry 管理；验证 connected TCP keepalive 与唯一 listener 同端口共存、两个 Forward/两个 listener/wildcard-specific 冲突被 NACK、stale owner close 不影响新 owner。
4. UDP 复用同一 `PacketConn`，不启动竞争 listener。
5. TCP/UDP STUN URL 列表分开预检；响应必须匹配配置 server IP/port、transaction、class 和 transport。`ALTERNATE-SERVER` 默认不自动跟随，显式允许时也要做全球地址/transport/循环/次数校验。至少两个不同解析 IP 的成功 exchange 才比较 mapping；记录每 transport endpoint 的 success rate/RTT/error/DNS/cooldown，服务不可用与 NAT 不兼容分开；不武断命名 full-cone。
6. Fuzz malformed STUN；Expected: 不 panic、不越界。
7. Commit: `feat: implement cross-platform reusable-port STUN mapping`。

### Task 10: IPv4 strategy pipeline 与 Node Traversal Detection

**Objective:** 实现 direct/manual/gateway+optional-STUN/stun-only 可组合 pipeline、顺序/分组并行探测和节点 TCP/UDP 默认 strategy。

**Files:**
- Create: `internal/traversal/strategy.go`
- Create: `internal/traversal/portregistry.go`
- Create: `internal/traversal/mapping_journal.go`
- Create: `internal/traversal/detection.go`
- Create: `internal/traversal/profile.go`
- Create: `internal/traversal/direct/direct.go`
- Create: `internal/traversal/manual/manual.go`
- Create: `internal/traversal/pcp/client.go`
- Create: `internal/traversal/natpmp/client.go`
- Create: `internal/traversal/upnp/client.go`
- Test: fake gateway + scheduler + cleanup tests

**Steps:**
1. 表驱动测试 direct、manual-static、PCP、NAT-PMP、UPnP、stun-only，以及 `gateway_method + upstream_discovery=stun` 组合 pipeline；第一跳 non-global 只能 FIRST_HOP_MAPPED，最终 global+independent probe 才 VERIFIED。
2. PCP 实现 MAP 所需子集：server discovery、protocol/internal port、96-bit nonce、result/lifetime、epoch 倒退/重启、lifetime=0 delete、重试/退避和 strict `PREFER_FAILURE`。
3. NAT-PMP 实现 public-address 与 TCP/UDP mapping opcode、epoch wrap/reboot、替代端口和删除；按 `strict/prefer_requested/accept_any` 处理 assigned port。
4. UPnP 支持 IGDv1/v2、WANIPConnection/WANPPPConnection、AddPortMapping/AddAnyPortMapping capability、冲突、permanent-only 和 bounded discovery；创建前查询、不覆盖第三方，删除前 journal+远端条目双重核验。
5. PortRegistry 测两个 Forward 同 tuple、wildcard/specific、same-port activation overlap、快速重启/TIME_WAIT、reuseport 防回归和 stale actor close；UDP 始终唯一 ingress。
6. mapping journal 在 Agent crash/restart 后恢复 renewal/安全 cleanup；测试端口被其他设备占用、条目外部修改、永久 lease only 和 gateway 不可达。
7. sequential 逐 pipeline；parallel 为 strategy 分配独立临时 tuple/operation，bounded concurrency，统一 cleanup。组合正向覆盖 CPE UPnP + CGN STUN/EIM/可达，失败覆盖第一跳成功但上游 TIMEOUT。
8. 结果按 TCP/UDP、strategy/layers、network fingerprint 持久化；全部失败仍可保存默认。Forward 继承 selected strategy，fixed strategy 不 silent fallback，`auto` 才执行 ordered strategies。
9. 模拟网卡/网关/公网 IP、gateway epoch、Agent resume 和 profile age 变化；profile stale 但 Agent 仍 online，新 endpoint 未验证不发布。
10. Run: `go test ./internal/traversal/... -race`; Expected: PASS，无残留临时 mapping、journal 或 PortRegistry owner。
11. Commit: `feat: detect and persist layered traversal strategies`。

### Task 11: Controller WAN probe

**Objective:** 把“发现映射”与“外部可达”分离。

**Files:**
- Create: `internal/controller/probe/service.go`
- Create: `internal/controller/probe/provider.go`
- Create: `cmd/antinat-probe/main.go`
- Create: `internal/agent/reconcile/probe.go`
- Create: `internal/protocol/probe.go`
- Test: TCP/UDP spoof/replay/timeout/activation tests

**Steps:**
1. 定义 `controller-local` 与 `remote-signed` ProbeProvider；生成一次性 token，绑定 node/forward/activation/endpoint/expiry/vantage。先判断 Controller probe 路径是否独立，不独立且无 remote provider 时返回 `NO_INDEPENDENT_VANTAGE`。
2. 实现固定上限 TCP/UDP probe frame 与 outstanding table。TCP 初次 verification-only gate 和 ACTIVE 短窗口 replayable-prefix 分类都要测试 server-first、短包、magic collision、scanner/slowloris；UDP 必须精确匹配 provider/source/activation/transaction 且不放大。
3. 旧 activation、重复 token、错误 endpoint/provider/source、过期 frame 不得激活 Forward；provider connect 与 Agent token ACK 必须同时成功。
4. remote probe 仅接受已绑定 activation 的全球 IPv4 literal，并做每 node/endpoint rate/concurrency/payload/timeout 限制。区分 `OPEN/REJECTED/TIMEOUT/NO_INDEPENDENT_VANTAGE/PROBE_INFRA_UNAVAILABLE/UNKNOWN`；timeout 不归因 filtering，非 OPEN force publish 走单独审计路径。
5. Run: `go test ./internal/controller/probe ./internal/agent/reconcile -race`; Expected: PASS。
6. Commit: `feat: verify mappings from controller WAN vantage`。

### Task 12: TCP 转发器与 half-close

**Objective:** 构建正确、可热切换 target 的高性能 TCP proxy。

**Files:**
- Create: `internal/forward/tcp/listener.go`
- Create: `internal/forward/tcp/proxy.go`
- Create only if benchmark justifies: `internal/forward/tcp/splice_linux.go`
- Create: `internal/forward/tcp/copy_windows.go`
- Create: `internal/forward/tcp/copy_generic.go`
- Test: echo, half-close, backend switch, immediate stop, leak tests

**Steps:**
1. 先写长连接、半关闭、target connect failure、accept backoff、target hot switch、immediate delete 测试。
2. 实现 atomic backend snapshot；已有连接保持旧 backend，新连接使用新 backend；删除命令关闭全部连接。
3. Linux fast mode 先用裸 `*net.TCPConn` + 双向 `io.Copy` 实现并验证标准库 splice；Windows/limited/detailed-stats 使用 buffer pool。自定义 splice 文件只在 ADR+benchmark 证明标准库路径不足后创建。
4. 连接计数和 global buffer budget 使用 semaphore；测试 32/64 KiB 两方向 accounting、预算耗尽、Windows handle/Linux FD 上限和拒绝 reason，`sync.Pool` 不得绕过预算。
5. API 状态准确报告 data-path、overhead reasons、splice/fallback bytes 和 fallback reason；wrapper/deadline/half-close 测试不能虚报 zero-copy。
6. Run: Linux/Windows `go test ./internal/forward/tcp`; Expected: PASS。
7. Linux 用 `strace -f -e splice` + 传输字节核对；Expected: 合格 fast path 的 splice bytes 覆盖预期 payload，fallback 有明确 bytes/reason，其他模式不虚报。
8. Commit: `feat: add cross-platform hot-swappable TCP forwarding`。

### Task 13: UDP 单 socket 与 session 转发

**Objective:** 在不与 keepalive 竞争端口的情况下代理 UDP。

**Files:**
- Create: `internal/forward/udp/mux.go`
- Create: `internal/forward/udp/sessions.go`
- Create: `internal/forward/udp/proxy.go`
- Test: STUN/probe/data demux, session switch/expiry/limits

**Steps:**
1. 构造普通 payload 看起来接近 STUN/probe 的测试，确保严格按 outstanding transaction/source/provider/activation 验证；普通 payload 不误吞，probe 不放大。
2. 分片 session map，connected outbound socket，idle wheel/定时回收。
3. target 变化不迁移旧 session；新 session 使用新 backend activation。
4. 使用 truncation-aware read 与有界 65,507-byte buffer pool；截断包丢弃计数，target response 由 ingress socket/发布源端口发回。
5. 达到全局/每 IP session、buffer、FD/handle 或 outbound ephemeral port 上限时安全丢弃并计数；覆盖大包、fragment、MTU、ICMP、source churn、Windows `WSAECONNRESET/SIO_UDP_CONNRESET` 和端口耗尽。
6. Run: `go test ./internal/forward/udp -race`; Expected: PASS，无 data race/泄漏，返回 source port 正确。
7. Commit: `feat: add single-socket UDP forwarding`。

### Task 14: Forward 与节点终止状态机

**Objective:** 串联 mapping、forwarder、probe、generation 切换、Forward 立即删除，以及 node decommission 的普通/强制语义。

**Files:**
- Modify: `internal/agent/reconcile/actor.go`
- Create: `internal/agent/reconcile/state_machine.go`
- Create: `internal/agent/reconcile/node_decommission.go`
- Create: `internal/agent/reconcile/state_machine_test.go`
- Create: `internal/agent/reconcile/node_decommission_test.go`

**Steps:**
1. 表驱动测试每个 activation 的合法/非法 transition；Forward 聚合只存 `current_activation_id`，允许旧 ACTIVE/DRAINING 与新 VERIFYING 并存；Forward FAILED 不影响 Agent ONLINE。
2. 新 activation 在 WAN verified 前不可 CAS 替换 current endpoint；旧 activation 的迟到 status/probe/hook 不得改 current，新 activation 失败保留旧 ACTIVE。
3. 为 direct/manual/stun-only/gateway+optional-STUN strategy 测 `SHADOW_PORT/SAME_PORT_OVERLAP/CUTOVER_REQUIRED/NO_REPLACE` 和 Prepare/Commit/Abort。相同 local tuple 必须复用唯一 listener，只替换 mapping activation；成功 cutover 只 drain 旧 backend/mapping，不能 overlap 时 UI 明示短 cutover。target 热切换保持已有连接。
4. 删除 Forward 进入 `STOPPING_IMMEDIATE`；Agent 先事务写 `forward_delete_tombstone`，再关闭 listener/TCP/UDP、删除 received/applied spec、best-effort 释放 mapping，并用 operation ID ACK；不得 drain。旧 snapshot/spec revision 在 tombstone 存在时不能复活该 Forward。
5. Controller 持久化 `forward_deletion_operations`；Agent 离线时标记 `DELETE_PENDING_OFFLINE`，重连后先 stop 再处理普通 desired，ACK 丢失/重复 DELETE/Controller 重启均幂等。
6. node decommission command 带 operation ID；Agent 先 durable marker，再并发停止全部 actor，关闭本地资源，best-effort 释放网关 mapping，清空 LKG/secret/job，最后 ACK 并携带 cleanup warnings。重复 command/重连必须幂等。
7. 普通 node delete 等 ACK；强制 node delete 不等 ACK，但 cleanup-only reconnect 使用相同 operation ID，不能重新获得 desired state。
8. 测 crash/restart、部分 Forward stop 失败、ACK 丢失、重复 ACK、强制删除后旧 Agent 重连；Expected: 业务最终停止且不恢复。
9. Run: `go test ./internal/agent/reconcile -race -count=10`; Expected: PASS。
10. Commit: `feat: reconcile forwarding and terminal node deletion safely`。

### Task 15: 限速与流量统计

**Objective:** 提供明确语义、热更新、可补发的 metrics。

**Files:**
- Create: `internal/forward/limiter.go`
- Create: `internal/metrics/counters.go`
- Create: `internal/metrics/delta.go`
- Create: `internal/controller/store/traffic.go`
- Test: fake clock + duplicate delta tests

**Steps:**
1. 用 fake clock 测每 Forward 聚合 rate/burst/方向/热修改，不使用脆弱 sleep 测试。
2. 默认 `rate_limit_enabled=false`、`detailed_traffic_stats_enabled=false`；基础 health/active/error 计数始终存在。
3. 测开关导致的 data-path 转换和 `overhead_reasons`；关闭后仅新连接回 fast path。
4. 详细统计开启时 delta 带单调 seq，Controller 幂等去重；关闭时不写 traffic rollup。
5. 断线 buffer 有磁盘/条目上限，溢出聚合。
6. Run: `go test ./internal/metrics ./internal/forward ./internal/controller/store -race`; Expected: PASS。
7. Commit: `feat: add opt-in forward limits and detailed statistics`。

### Task 16: Mapping change automation hook

**Objective:** 仅在已验证 endpoint 变化时安全调用用户自定义 HTTP/JavaScript 自动化。

**Files:**
- Create: `internal/hook/event.go`
- Create: `internal/hook/webhook.go`
- Create: `internal/hook/javascript.go`
- Create: `internal/hook/broker.go`
- Create: `cmd/antinat-hook-runner/main.go`
- Create: `internal/hook/runner_test.go`

**Steps:**
1. 测 `Activated/Changed/Deactivated/ForwardDeleted`、stable event ID、at-least-once 重试、dead-letter、timeout、redaction；只有 verified activation 可触发 Activated/Changed，删除 hook 失败不回滚本地 stop。
2. webhook 支持 method/headers/query/body template、secret reference、HMAC。
3. JS 在短命 runner 子进程中执行；仅暴露纯 encoding/time、只读 context 和 `secret.sign` handle。`http.request`/HMAC 生成 broker request，由 Agent 校验 destination/secret allowlist 后执行；runner 无 socket/shell/真实文件系统或明文 secret。
4. 用 AliDNS 风格签名请求 fixture 证明无需 shell/内置 provider 即可生成正确 API 请求；测试 secret 不进入脚本日志。
5. 实施 SSRF 默认阻断、忽略 proxy env、全部 A/AAAA 任一受限即拒绝、IPv4-mapped IPv6/CGNAT/ULA 拒绝、DNS 解析后 pin IP、每次 redirect 重验、HTTPS 默认策略、host/port allowlist 和响应大小限制。
6. 测试无限循环/大分配被 OS 资源限制和 Agent timeout 终止，runner 崩溃/OOM 不影响 Forward actor；不能访问 net/os/file/exec。
7. Run: `go test ./internal/hook -race`; Expected: PASS。
8. Commit: `feat: expose safe programmable mapping hooks`。

### Task 17: Controller REST API 和 SSE

**Objective:** 完成管理、并发控制、实时状态 API。

**Files:**
- Create/Modify: `internal/controller/api/*.go`
- Create: `internal/controller/web/router.go`
- Test: `internal/controller/api/*_test.go`

**Steps:**
1. 为 auth、nodes、node/forward deletion operations、forwards、navigation、settings、traffic 写成功/校验/权限、428/412/409 和 idempotency 测试。
2. 统一 response envelope、request ID、错误 code。
3. 所有 PATCH/DELETE 使用 ETag/`If-Match`；创建使用 idempotency key。Forward 创建/修改验证 TraversalStrategy/layers、endpoint scope、`port_policy`、manual expected endpoint、PortRegistry tuple conflict 和平台/Defender capability；但历史探测失败本身仍允许用户保存为待重试。
4. 测普通删除等待 ACK、离线等待、强制删除立即隐藏、cleanup tombstone restricted reconnect、重复请求幂等和审计字段。
5. SSE 做断线重连和 last-event-id，不泄露 token/secret。
6. Run: `go test ./internal/controller/api ./internal/controller/web -race`; Expected: PASS。
7. Commit: `feat: expose revision-safe controller API`。

### Task 18: 首页与管理面板

**Objective:** 实现白色简约、无 Node 构建依赖的响应式 UI。

**Prerequisite:** 加载 `design-critique`、`frontend-design`、safe local `impeccable`、`make-interfaces-feel-better`，按第 12.6 节顺序执行。

**Files:**
- Create: `web/templates/*.html`
- Create: `web/static/css/*.css`
- Create: `web/static/js/{api,i18n,home,admin,nodes,forwards,navigation}.js`
- Create: `web/i18n/{zh-CN,en-US}.json`
- Create: `internal/controller/web/assets.go`
- Test: handler/template/Playwright 或等价浏览器测试

**Steps:**
1. 先用 design-critique 评估任务流，再用 frontend-design 形成白色简约 Operate 方向与 token；safe impeccable 做状态/i18n/a11y floor，最后细节技能复核。
2. 用 `go:embed` 嵌入模板、双语文案和静态资源；输出带 hash/cache policy。
3. 首页实现分类、卡片、ACTIVE 链接、离线置灰/红灯/最后地址与 stale 文案。
4. 节点页实现首次 detection 进度、TCP/UDP strategy layers/endpoint scope/lease/probe vantage 结果、全部失败仍可保存默认 strategy。
5. Forward UI 显示 strategy layers、endpoint scope、gateway/lease、requested/assigned port、probe vantage/last success、firewall suspicion、data-path/zero-copy/splice-fallback、current activation/cutover capability、hook pending/failed/DLQ；删除对话框说明立即断开、deactivation hook 为 best-effort 以及离线 Agent 限制。
6. 管理页实现四 tab、drag reorder、SSE 更新、稳定 loading button、中文/English 切换。
7. 所有动态文本使用 `textContent` 或模板转义；不拼接不可信 HTML。
8. 浏览器测试双语长文案、键盘、移动端、登录、节点探测、普通节点删除等待进度、强制删除二次警告、创建/编辑/删除 Forward、旧 revision 冲突和私有首页。
9. Run: Go + browser tests；Expected: PASS。
10. Commit: `feat: add bilingual accessible navigation and admin UI`。

### Task 19: 部署配置与命令生成

**Objective:** 安全生成 Linux、Windows 和 Docker 安装命令。

**Files:**
- Create: `internal/controller/deployment/profile.go`
- Create: `web/static/js/install-command.js`
- Modify: `docs/installer-contract.md`
- Create: `test/fixtures/installer-contract/*.json`
- Create: JS/Go POSIX shell + PowerShell quote tests

**Steps:**
1. 先加载 Task 1B 冻结的 installer contract fixture；Linux/PowerShell/Docker 生成器与 Task 20 installer parser 对同一参数/exit-code/service/path contract 做双向 smoke，contract 未实现不得展示命令。
2. 测 POSIX shell 与 PowerShell quoting、URL normalize、空值、引号、换行、恶意代理/路径。
3. deployment profile 保存结构化字段，不保存最终命令。
4. 强制要求明确的 `controller_endpoint`；不根据 `ip.sb` 自动创建 endpoint，也不创建 Controller 打洞 Forward。
5. Docker v1 仅生成 Linux host `--network host` 命令；Windows containers 明确拒绝，Docker Desktop 显示 host-network/L4/Enhanced Container Isolation 限制。Windows 原生命令支持 Controller、Agent、Controller+Agent 和 Windows Service。
6. 部署命令包含 Controller signing key 指纹；token 只在创建/轮换时进入页面状态，关闭弹窗后不从普通 API 重新获取。
7. 生成命令不得把 token 作为 Agent 服务长期 argv/env；安装器通过 stdin 或 0600 临时文件消费 token，enroll 后删除。测试 service definition、日志、配置和运行进程参数均无 token。
8. Run: Go + JS + installer-contract fixture tests；Expected: 命令可被对应 installer dry-run parser 接受，所有 injection corpus 被正确转义/拒绝。
9. Commit: `feat: generate contract-tested cross-platform deployment commands`。

### Task 20: Linux/Windows 安装、服务、升级与完全卸载

**Objective:** 支持 Controller、Controller+本机 Agent、Agent-only 和完整卸载，并保证无 AntiNAT 残留。

**Files:**
- Create: `scripts/install.sh`, `scripts/libinstall.sh`, `scripts/uninstall.sh`
- Create: `scripts/install.ps1`, `scripts/uninstall.ps1`
- Create: `deploy/systemd/*.service`, `deploy/openrc/*`, `deploy/windows/*`
- Create: `internal/install/manifest.go`
- Test: container/VM/Windows runner smoke scripts

**Steps:**
1. 实现 Task 1B installer contract 的 dry-run parser，并让 Task 19 的全部 fixture 在 shell/PowerShell/Windows runner 通过；再测 OS/arch/init/proxy/监听端口冲突（默认 3111）、controller endpoint、exit code、普通用户运行和管理员安装边界。
2. 菜单：Controller；Controller+本机 Agent；Agent-only；完全卸载。Controller+本机 Agent 必须先健康启动 Controller，再事务创建本机 node，以 loopback `controller_endpoint` 和一次性 0600 token file 完成 enrollment；失败时回滚 Agent 服务和未消费节点记录。安装结束只向终端显示一次生成的管理员密码，并区分“已确认 endpoint”与“ip.sb 未验证候选地址”。
3. 禁止裸 `curl | sudo bash` 作为唯一安全路径：下载版本固定的 installer/release artifact，校验签名/校验和后再执行；说明 bootstrap trust 来源。
4. 升级协议至少保证 Controller/Agent `N` 与 `N-1` 互通；DB 使用 expand/contract migration，破坏性 contract 至少延后一主版本。协议/状态格式先新增兼容字段，再迁移读写，最后移除旧字段。
5. 升级前用 SQLite Backup API/`VACUUM INTO` 生成一致 DB snapshot；关闭或稳定读取 bbolt 后备份 Agent state，并连同旧 binary、配置、signing/encryption keys 记录 manifest。禁止只复制 WAL 主文件。
6. migration 或健康检查失败时停止新进程、原子恢复旧 binary+DB+bbolt+keys/config，随后运行 `integrity_check`、实际管理员登录和 Agent reconnect。不可逆 migration 必须有 ADR，不能只回滚 binary。
7. CI/VM 测试旧 DB→新版本、N/N-1 Controller-Agent 组合、迁移后旧二进制回滚、升级中断和磁盘满。
8. Linux 使用 systemd/OpenRC；Windows 注册独立低权限 Windows Service。实现/测试 `managed-range|manual` Defender policy：managed-range 创建精确 binary + TCP/UDP + 配置高端口范围的 GUID rule，manual 显示 `HOST_FIREWALL_RULE_REQUIRED`；范围外端口用管理员 repair。Linux 防火墙只诊断/给指引，v1 不静默改规则。
9. 安装时写 root/SYSTEM ACL + HMAC 的 ownership manifest，记录 installation ID、AntiNAT 创建的文件 identity、目录、服务、firewall GUID/owner tag、scheduled task 和 registry entry；不记录用户外部反代/TLS 配置。
10. 完全卸载：交互式要求明确数据丢失确认，非交互要求 `--purge --yes`；Agent 先写 terminal marker 并本地 cleanup；Controller 先批量 normal decommission，离线节点需强制确认并导出未确认清单。随后才删除 manifest 中全部 AntiNAT 二进制、配置、LKG、Controller DB、keys、日志、缓存、备份、rules/tasks/registry 和空目录。
11. 卸载器 canonicalize 并拒绝 allowlist 外、symlink/reparse、`..`、挂载点、系统目录、未知 resource type 或 identity 不匹配；manifest 缺失/损坏时只清理编译时 allowlist 的 AntiNAT 专属路径和精确命名资源。卸载幂等，二次执行报告“无残留”。
12. Run: Debian/Ubuntu/Alpine VM/container + Windows runner/VM smoke；Expected: install、restart、N/N-1、upgrade rollback、complete uninstall 均通过。
13. Commit: `feat: add transactional cross-platform installation and purge`。

### Task 21: Controller 控制面双栈与 IPv6 扩展边界测试

**Objective:** 证明 V1 的双栈仅用于 Controller/Agent 控制连接，同时确保数据面未来可扩展。

**Files:**
- Create: `test/integration/control_dualstack_test.go`
- Create: `test/integration/data_family_boundary_test.go`
- Modify: endpoint URL formatter tests

**Steps:**
1. Linux 与 Windows 分别验证 Controller 仅使用一个逻辑配置端口（默认 3111），即可从 IPv4 与 IPv6 地址访问 UI/API/WebSocket。
2. Agent 测 IPv4-only、IPv6-only、A+AAAA、首选地址失败后 fallback；均能 enroll/reconnect/receive config。
3. V1 创建 IPv6/dual Forward ingress 返回稳定 `UNSUPPORTED_IN_V1`，不 panic、不写半成品 spec。
4. strategy interface 用 fake IPv6 implementation 通过编译/单测，证明后续可加 NAT66/pinhole 而无需改变公共 actor 和数据库主键结构。
5. Run: Linux + Windows integration；Expected: 控制面双栈通过，IPv6 数据面被准确拒绝。
6. Commit: `test: verify dual-stack control and reserved IPv6 data seams`。

### Task 22: NAT namespace 集成实验室

**Objective:** 可重复模拟 mapping、filtering、续租、地址变化与热切换。

**Files:**
- Create: `test/netns/topology.sh`
- Create: `test/netns/nft/*.nft`
- Create: `test/integration/traversal_test.go`

**Steps:**
1. 构建 target→agent→CPE→CGN→internet/independent-probe 多 namespace IPv4 拓扑；fake gateway 只用于确定性单测，不单独作为协议兼容性证据。
2. 覆盖 direct/manual、EIM-like、TIMEOUT、明确 RST/ICMP REJECTED、hairpin absent/WAN open，以及 Controller/Agent 同 NAT 时 hairpin 成功但仍 `NO_INDEPENDENT_VANTAGE`；不把 timeout 命名为 filtering fact。
3. 加入至少一个真实协议实现（例如可启用 IGD/NAT-PMP/PCP 的测试 daemon/VM/router）或经公开规范核对的 golden packet corpus；抓包验证 nonce/opcode/epoch/lease/framing。Windows shared-port/Defender 必须在真实 Windows VM/主机+路由器后验证。
4. 组合正向：CPE UPnP/PCP/NAT-PMP 第一跳成功 + CGN STUN/keepalive + independent OPEN；组合失败：FIRST_HOP_MAPPED 但上游 TIMEOUT。验证同一 source tuple 和 mapping journal。
5. 验证 sequential/parallel strategy detection、全失败仍可保存、临时 lease cleanup、permanent-only policy、PortRegistry 无残留、fingerprint/age 变 stale。
6. 改变 mapping、gateway epoch、route/interface、Agent suspend/resume、keepalive failure；新 endpoint 只有独立 OPEN 后才发布/触发 hook，Controller 离线时保持 UNVERIFIED。
7. 使用 `tc netem` 覆盖 MTU/PMTU、loss、reorder、fragment 和 policer；UDP 截断/Windows ICMP 在对应平台专项验证。
8. target 热修改保持已有 TCP；删除 Forward 立即关闭 listener/连接/session，并按 ownership journal best-effort 释放 mapping。
9. 覆盖 Forward 离线 deletion operation、Agent tombstone-before-stop、旧 snapshot 不能复活、ACK 丢失/重放；再覆盖 node normal/force delete crash/reconnect。
10. Linux arm64 使用原生 runner/实机跑安装、service、UDP、splice fallback 和 24h smoke；OpenRC 在真实 init 环境；不能用 cross-build/无 init container 代替。
11. 清理 trap 必须删除 namespace/nft/daemon/rule，即使测试失败。
12. Run: `sudo go test -tags=netns ./test/integration -count=1`; Expected: PASS。
13. Commit: `test: add reproducible layered IPv4 traversal and deletion laboratory`。

### Task 23: Minecraft 与 Web 性能/抖动验收

**Objective:** 用可复现的增量指标验证业务目标，并量化每个功能开关的代价。

**Files:**
- Create: `test/benchmark/README.md`
- Create: `test/benchmark/run.sh`
- Create: `test/benchmark/run.ps1`
- Create: `test/benchmark/minecraft_replay/*`
- Create: `internal/forward/*_test.go` benchmarks
- Create: `docs/performance.md`

**Steps:**
1. 测试分三级：PR CI 只做 correctness/Go benchmark/alloc/短时回归，不声称 2 Gbps；正式 SLO 在至少 10GbE 或实测有足够应用余量的专用物理 lab；真实 WAN 只做部署/稳定性 smoke，不承担 `<1 ms` 归因。
2. 固定 reference hardware、CPU governor、NIC/offload、switch/virtualization、MTU、target、Go/OS/kernel 和背景负载，跑 direct、Linux fast-splice、Windows buffered、detailed-stats、rate-limited、UDP。A/B 顺序随机，至少 5 个 paired round，每轮先 2 分钟 warm-up、再 10 分钟 measurement；保留命令、原始 histogram 与 bootstrap 95% CI，不挑最好一次。
3. **Minecraft-like jitter 定义**：同一 client process 在发送前用本机 monotonic clock 记录 `s_i`，echo response 携带 sequence，收到时记录 `r_i`；不跨主机比较时钟。`e_i=abs((r_i-r_{i-1})-(s_i-s_{i-1}))`。每轮算 `p99(e)`，paired `incremental_p99=p99_proxy-p99_direct`；默认开关关闭时，paired 差值的 bootstrap 95% CI 上界必须 `<1 ms`，50 clients 无 AntiNAT 引起断线。另用真实 Minecraft server 做 1 小时 smoke，synthetic 结果不得宣传成完整 Minecraft 认证。
4. **Web throughput 定义**：direct application-payload baseline 必须 `>=2.5 Gbps`；代理同时满足 10 分钟平均 `>=2.0 Gbps` 和 `>=80%` paired direct baseline，无 payload hash 错误/代理错误，报告 1 秒窗口分布与最长 zero-progress stall。20 clients 定义为至少 2 台独立 load-generator 上的 20 worker/source socket、总计 100 并发，不宣传为 20 条 WAN path；TLS 由 target/reverse proxy 终止。
5. 每个 2 Gbps×10 分钟 run 约 150 GB wire data，完整平台/开关矩阵可超过 1 TB；benchmark README 必须列网络、时间、存储/日志预算和 preflight，不能作为普通 CI 门禁。
6. Linux 和 Windows 各跑独立 direct baseline 与 Minecraft/Web SLO；Windows 不要求 zero-copy，但 SLO 和 RSS/handle budget 相同。未通过的平台可继续功能 beta，但不得声明达到对应性能。
7. 每组合报告 CPU、RSS/peak RSS、handles/FD、allocs、GC、p50/p95/p99 RTT/jitter、1 秒 throughput histogram、最长 stall、retransmit、qdisc/softnet、错误、payload hash、splice/fallback bytes 和 `overhead_reasons`。
8. 用 `tc netem`/物理 lab 覆盖 MTU/PMTU、loss、reorder、fragment、上游 policer 与 loaded latency；真实 WAN 结果单列，不与同机 A/B 因果统计混合。
9. 容量/滥用测试包括 1k/10k idle TCP、SYN/accept burst、slowloris、half-open backend dial、UDP source churn、单 IP flood、FD/ephemeral-port/buffer budget exhaustion 和 probe flood；作为容量观察而非营销承诺。
10. 只有基准证明收益才保留自定义 splice/batch；文档量化统计/限速、prefix probe window 和 fallback 的开销。
11. Commit: `perf: verify minecraft jitter and 2gbps web targets`。

### Task 24: 安全、故障与可观测性

**Objective:** 在发布前验证攻击面和故障恢复。

**Files:**
- Create: `SECURITY.md`, `docs/security.md`, `docs/operations.md`
- Create: `internal/*` fuzz tests
- Modify: systemd/OpenRC/Windows Service configs

**Steps:**
1. Linux 与 Windows 运行 `go test`/race（按平台支持）、`go vet`、`govulncheck`。
2. Fuzz STUN TCP/UDP framing、PCP、NAT-PMP、UPnP parser、probe frame/prefix classifier、控制 JSON、endpoint parser、hook template/crypto API。
3. 测 token/log redaction、Controller/Agent key challenge/rotation/revoke/replay、旧 connection epoch 迟到 ACK、durable outbox/inbox、CSRF、WebSocket oversize 和 session fixation。
4. 测明文 ws 不下发 hook secret，wss/受信 transport 可正常工作；AntiNAT 不管理证书。测试 trusted proxy 之外伪造 `X-Forwarded-Proto` 不能绕过。
5. SSRF corpus 覆盖 proxy env、redirect、mixed public+private A/AAAA、CGNAT、ULA、IPv4-mapped IPv6、metadata 和 DNS rebinding；hook at-least-once/DLQ 与 secret handle 不泄密。
6. kill Agent/Controller、磁盘满、DB busy、默认路由变化、DNS 失败、Controller 断网；验证 per-Forward LKG、delete tombstone、profile stale、critical stop/delete 优先和状态恢复。
7. 验证普通节点删除在 ACK 前不从 UI 消失，ACK 后 Agent 无 Forward/LKG 且重启不恢复；强制删除立即从 UI 消失但 `remote_cleanup_confirmed=false`，旧 Agent 重连只能完成 cleanup。
8. 验证强制删除时 Agent 永不重连的边界：主控不能证明远端已停止，审计和 UI 不得伪造成功。
9. 篡改 ownership manifest、构造 symlink/reparse/`..`/mount path/错误 file identity，卸载器必须拒绝；Controller 卸载有离线 Agent 时必须先告警并导出未确认清单。
10. pprof 默认只绑定 loopback且关闭，需显式开启；UI/API/WS/SSE/probe 资源配额互相隔离。
11. Commit: `security: harden AntiNAT failure and attack handling`。

### Task 25: Release candidate 与真实外部验证

**Objective:** 在真实 NAT/CGNAT/IPv6 环境证明产品边界。

**Files:**
- Create: `docs/release-checklist.md`
- Create: `docs/nat-support.md`
- Modify: `README.md`

**Steps:**
1. Linux 与 Windows Agent 至少覆盖公网 IPv4、家庭 gateway mapping、CPE+上游 CGNAT 和 manual-static/云 DNAT；另用 IPv4-only/IPv6-only/dual-stack 网络验证控制连接。每平台支持矩阵按 strategy/layer 单独记录。
2. 用独立 WAN client 做 TCP 应用响应与 UDP nonce，并与 controller-local/remote-signed probe 结果交叉验证；Controller-only 状态不作为唯一证据，hairpin 与 independent path 分开。
3. Windows 真实 Service+managed/manual Defender+router；Linux arm64/OpenRC 原生环境。重启 Agent、路由器/WAN reconnect、sleep/resume，确认 endpoint scope、revalidation、hook、首页和旧状态失效。
4. 运行 24h soak，检查 goroutine/FD/Windows handles/RSS/buffer budget、mapping journal、lease/keepalive/reprobe；详细统计关闭时不得产生流量历史开销。
5. 对 Linux 与 Windows 实际执行完整卸载残留扫描。
6. 发布 Linux/Windows 目标二进制、SBOM、checksums、签名；从 release artifact 重新安装验证。
7. README 致谢 Natter 并声明独立实现；只把实测通过的平台/拓扑/SLO 写为“支持”。
8. Commit: `release: prepare AntiNAT v1 candidate`。

## 15. 验收标准

### 15.1 功能

- Controller 在 IPv4/IPv6 的同一配置 TCP 端口（默认 3111）可访问；Agent 可经 IPv4 或 IPv6 endpoint 注册、重连、心跳和接收配置。
- 节点首次上线自动探测一次；顺序/并行均可完成 direct/manual/gateway+STUN/stun-only pipeline 并清理临时资源；FIRST_HOP_MAPPED 不冒充最终成功，全部失败仍可保存 TCP/UDP 默认 strategy。
- 只有 `controller-local` 独立视角或 pinned `remote-signed` provider 才能产生 VERIFIED OPEN；同网/hairpin/tunnel-only 无 remote provider 时为 UNKNOWN。
- probe frame 同时通过 provider 连接和 Agent token ACK，绑定 exact endpoint/activation；scanner、timeout、旧 token 和 probe infra failure 不能误激活，也不能武断归因 filtering。
- PortRegistry 保证同一 family/protocol/bind IP/local port 只有一个 listener owner；两 Forward/双 listener/wildcard 冲突 NACK，同端口 remap 复用 listener，reuse 不能造成随机分流。
- PCP/UPnP/NAT-PMP mapping journal crash-safe；永久 UPnP lease 默认拒绝，第三方/已变更 mapping 不删除。`port_policy` 的 `strict/prefer_requested/accept_any` 行为与 requested/assigned port 可审计。
- 打洞/Forward 失败不改变 Agent ONLINE；Controller 重启或控制断线不终止 last-known-good 数据面。
- 一个 Forward apply 失败不影响其他 Forward；失败项保持旧 `last_applied_spec`，成功项更新，Controller 收到逐资源 `PARTIAL` 结果。
- target 热更新后，已有 TCP 连接继续旧 target，新连接进入新 target。
- 在线 Agent 删除 Forward 时先持久化本地 delete tombstone，再立即停止 listener、TCP 连接和 UDP session，并 best-effort 释放 mapping；旧 snapshot 不能复活。离线时持久 operation 为 `DELETE_PENDING_OFFLINE`，重连优先 stop，ACK 前不虚称已停。
- 普通删除 node：Agent 先停止全部本地 Forward、关闭 listener/连接、清空 LKG/secret/job 并 ACK，随后主控删除节点；Agent 重启不恢复业务。网关 mapping 无法撤销时只产生 warning 并等待 lease 过期。
- 强制删除 node：主控立即移除节点且返回 `remote_cleanup_confirmed=false`，若旧 Agent 后续重连只能进入 cleanup-only 会话；未重连时不得宣称远端已停止。
- UDP STUN/keepalive/probe 不会被错误转发到 target，普通 payload 不会被错误吞掉。
- V1 不提供 IPv6 数据面；相关请求准确返回 `UNSUPPORTED_IN_V1`，扩展接口测试通过。
- Hook Activated/Changed 仅由独立 WAN 验证产生，删除/decommission 产生 Deactivated/ForwardDeleted；delivery 为可观测 at-least-once。隔离 runner 可用 AliDNS 风格签名 fixture 经 broker secret handle 发 API 请求；恶意脚本不能取得明文 secret 或终止 Agent/Forward。
- 离线/失败 Forward 置灰、红灯并显示带 stale 提示的最后已知地址；UI 中文/英文均通过测试且默认中文。
- Linux/Windows 完全卸载残留扫描通过。

### 15.2 安全

- DB/日志/API 中找不到明文密码、Agent 私钥、已消费 token 和 hook secret。
- enrollment token 过期、二次使用、并发重放，以及 Controller/Agent challenge 和逐消息 direction/sequence replay 均失败；Agent 拒绝非 pinned Controller key 的命令。
- 新 connection epoch 可 fence 旧 WebSocket 的迟到 ACK；关键 control outbox/inbox 在 Controller/Agent 崩溃重启后仍可幂等重放。
- Controller 只管理控制流量与 probe，不承载用户转发，也不通过 AntiNAT 打洞暴露自身。
- `http/ws` 有明确不安全警告且不能下发 hook secrets；AntiNAT 不签发/管理 TLS。
- 安装脚本校验 artifact；token 不出现在服务 argv/env/配置/日志；Windows managed-range/manual firewall policy 与 rule ownership 可验证；N/N-1 组合通过，升级失败连同 DB/bbolt/keys/config 恢复旧服务；卸载拒绝被篡改 manifest、路径穿越和 reparse/symlink，只删除验证过的 AntiNAT 资源。
- JS/webhook 默认不能访问 loopback/private/metadata、不能执行进程或读取真实文件系统。

### 15.3 性能

- 默认关闭限速与详细统计；状态必须报告真实 `data_path`、`zero_copy_active` 和 `overhead_reasons`。
- Minecraft-like：按 Task 23 的 inter-arrival error 公式、至少 5 个随机 paired round，paired `incremental_p99` 的 bootstrap 95% CI 上界 `<1 ms`，50 clients 无代理导致断线；真实 Minecraft 另做 1 小时 smoke，不混同认证。
- Web：专用 lab 的 direct baseline `>=2.5 Gbps`；至少 2 台 load-generator、20 workers、总计 100 并发时，代理 10 分钟平均应用 payload `>=2.0 Gbps` 且 `>=80%` paired baseline，无 payload hash/代理错误，并报告 1 秒窗口和最长 stall。
- Linux 与 Windows 分别报告结果；未通过的平台不得宣传满足相应 SLO。
- 另外报告 CPU、RSS/peak、FD/handle、allocs/GC、p50/p95/p99 增量延迟、UDP pps/丢包、1 秒吞吐 histogram、retransmit/qdisc/softnet、splice/fallback bytes，以及限速/详细统计的相对开销。普通 CI 不作 2 Gbps 或 `<1 ms` 宣称。

## 16. 主要风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 未先做共享端口/runner/SQLite spike | 大量 UI/协议代码建立在不可行假设上 | M0 Go/No-Go；失败立即缩 capability，不先做完整产品层 |
| 只认证 Agent、不认证 Controller 命令 | MITM/恶意代理可伪造 desired/delete/probe | Controller signing key pinning；双向 challenge；逐消息签名+direction/session/sequence |
| 新旧 WebSocket 并存 | 旧连接迟到 ACK 覆盖新状态 | 持久 connection epoch fencing；关键 command/ACK durable inbox/outbox |
| 全局 LKG 被部分失败 spec 覆盖 | 重启后恢复错误配置或丢失旧 ACTIVE | received desired 与 per-Forward last-applied 分离；逐资源 ACK；bbolt 事务 |
| NAT/ISP 不支持入站 | Forward 无法公网直连 | 节点探测和 Forward 状态准确失败；允许保存；后续才考虑公网 Agent Relay |
| 把 gateway mapping 与 STUN 当互斥模式 | 双层 NAT 第一跳成功但最终不可达/漏掉可行组合 | 可组合 strategy pipeline；endpoint scope；FIRST_HOP_MAPPED；同 source tuple 上游发现 |
| 首次探测结果过时 | 新 Forward 继承错误模式 | 保存 network fingerprint；变化标 stale；提示重测；Forward 可覆盖 |
| 并行探测相互干扰/污染路由器 | 误判或残留 mapping | bounded concurrency、独立端口/lease owner、统一 cleanup、默认 sequential |
| STUN 服务 TCP/UDP 不兼容 | mapping 失败 | 按协议分别预检外部 STUN list；不自建、不把 UDP 成功当 TCP 成功 |
| Controller probe 视角不独立 | hairpin/tunnel 被误判为公网可达 | 显示并校验 probe vantage；同 LAN/同主机/tunnel-only 返回 UNKNOWN；v1 可选 pinned remote-signed probe |
| probe 仅凭 accept/nonce | scanner 假激活或破坏业务首包 | signed bounded frame；provider connect + Agent ACK；verification gate/replayable prefix；anti-scan quotas |
| reuseport/双 generation 同 listener tuple | 新连接随机进入错误 Forward/旧 generation | 全局 PortRegistry；唯一 listener owner；同端口复用 listener；reuse 仅 STUN connected socket 组合 |
| mapping cleanup 所有权不足 | 覆盖/删除第三方 UPnP/NAT-PMP 规则 | crash-safe journal；create/delete 前查询核验；permanent-only 默认拒绝 |
| Windows 与 Linux socket reuse 语义不同 | 某些打洞模式失败/错路 | platform socket factory、真实 Windows router tests、capability 标记，不做虚假跨平台承诺 |
| Windows Service 无交互式防火墙弹窗 | listener/mapping 正确但 WAN 被 Defender 阻断 | install-time managed-range program rule 或 manual 明示；rule GUID ownership；范围外 repair |
| zero-copy 与限速/统计冲突 | 性能退化 | 默认关闭高开销开关；状态显示真实 data-path/原因；基准量化 |
| Windows 无 splice | CPU/吞吐较差 | pooled buffered IO、Windows 专项 benchmark；不声称 zero-copy |
| 互联网绝对 jitter 不可控 | `<1 ms` 承诺被误解 | 专用 lab paired A/B；明确 inter-arrival error 公式；bootstrap 95% CI；WAN 只 smoke |
| 2 Gbps 受 NIC/CPU/target/数据预算限制 | 环境未达标或测试不可持续 | >=10GbE lab；direct>=2.5、proxy>=2.0 且>=80%；约150GB/run预算；普通 CI 不宣传 |
| Forward 删除时 Agent 离线 | Controller 无法立即停止远端 LKG | `DELETE_PENDING_OFFLINE`；不得显示已完成；重连首条命令立即 stop |
| 普通 node 删除时 Agent 离线 | 主控无法完成删除 | 保持 `WAITING_ACK`，节点仍可见且禁止新配置；Agent 重连后先执行 terminal cleanup |
| 强制 node 删除时 Agent 未收到命令 | 主控已无节点但远端可能继续 LKG | 二次风险确认、`remote_cleanup_confirmed=false`、最小 cleanup tombstone、旧 key 仅 cleanup reconnect；不能从网络上保证永不重连的 Agent 已停止 |
| decommission 中 Agent 崩溃 | 重启后恢复旧业务 | terminal marker 必须先于 stop 写盘；重启见 marker 只继续清理，禁止加载 LKG |
| 明文 ws 跨不可信网络 | 配置/secret 泄露 | 强警告；禁止下发 hook secret；推荐用户已有 WSS/安全隧道；AntiNAT 不管理 TLS |
| 沙箱脚本 SSRF/资源耗尽 | 主机/内网风险或 Agent OOM | 独立短命 runner；broker；全部地址校验+DNS pin+redirect 重验；忽略 proxy env；secret sign handle；OS 资源限制 |
| Hook at-least-once 重复投递 | DNS/API 重复修改 | stable event ID、持久 bounded queue、重试/DLQ、要求目标幂等；不宣传 exactly-once |
| 动态 endpoint 与用户自定义 DNS | 地址可能陈旧 | verified Activated/Changed + best-effort Deactivated/ForwardDeleted；由用户幂等 JS/webhook 处理 DNS |
| 完全卸载误删用户文件 | 数据损失 | 二次 purge 确认；root/SYSTEM ACL+HMAC manifest；canonicalize/identity 校验；编译时 allowlist；幂等扫描 |
| IPv6 后期扩展导致大改 | v2 成本上升 | V1 保留 AddressFamily/strategy/socket/probe 接口和 DB 字段；运行时明确 unsupported |
| SQLite 写争用/历史膨胀 | 面板卡顿 | WAL；详细统计默认关闭；开启时 rollup/retention/单写事务 |
| GPL 代码污染许可证 | 发布风险 | Apache-2.0 项目只依据 RFC/独立设计实现；README 致谢 Natter；不复制 GPL 源码 |
| Installer 暴露 token | 节点被冒领 | token 一次、短 TTL、hash at rest；只经 stdin/0600 temp file 消费；不进入 service argv/env/配置/日志 |
| 只回滚 binary 不回滚 migration/key | 升级失败后旧版本无法启动或解密 | N/N-1 + expand/contract；一致 DB/bbolt/keys/config 备份；健康失败原子恢复整套状态 |
| Docker host network 平台差异 | Windows/Desktop 部署误导 | v1 只承诺 Linux host；Windows containers 拒绝；Desktop 明示 L4/ECI 限制 |

## 17. 参考依据

调研时直接检查了以下原始资料：

- Natter 仓库、README、`natter.py`、转发/脚本文档和 reuse-port C 模块；当前默认分支 `master`，调研到 release v2.2.1，许可证 GPL-3.0。
- 2026-08-07 复核：`https://go.dev/VERSION?m=text` 返回 `go1.26.5`；Go 1.26.5 `net.TCPConn` 提供 `ReadFrom/WriteTo`，Linux net path 含 `splice`，因此先验证标准库 `io.Copy`，不预设需要自定义 syscall 实现。
- Docker 官方 host network 文档：Linux host 原生支持；Docker Desktop 4.34+ 为可选 L4 功能且受 Enhanced Container Isolation 限制；Windows containers 不支持 host networking。因此 v1 Docker 范围限定为 Linux host。
- Natter 当前实现的重要启示：IPv4 STUN+keepalive、TCP/UDP 模式分离、UPnP 补充、iptables/nftables/socket 转发、映射变化通知。
- 需要修正的点：当前主流程主要是 IPv4；稳定映射不代表过滤开放；socket TCP 是多线程 8 KiB copy；UDP reuse-port 在部分环境可能竞争；映射 hook 在 WAN 验证前调用不适合本项目。
- RFC 4787：UDP NAT mapping/filtering 行为。
- RFC 5382：TCP NAT 行为与 endpoint-independent mapping。
- RFC 5128：P2P NAT traversal、TCP/UDP hole punching 局限。
- RFC 5780：STUN NAT behavior discovery 是实验性且不能 100% 正确，应用必须有 fallback。
- RFC 6886：NAT-PMP。
- RFC 6887：PCP。
- RFC 7857：NAT behavioral requirements 更新。
- RFC 8489：当前 STUN 标准。
- Go 标准库 Linux `net` 源码：TCP→TCP `ReadFrom` 可走 `splice` 以减少用户态拷贝；实现时仍需验证包装器不会破坏 fast path。

## 18. 决策记录与剩余问题

### 18.1 已确认，不再询问

1. Controller 由用户提供 Agent 可直接连接的地址，不使用 AntiNAT 打洞作为控制入口。
2. Agent/Controller 控制状态与打洞状态解耦；打洞失败不影响注册、心跳、配置或普通 LKG 恢复。
3. 节点首次上线自动探测一次，支持顺序/并行；探测失败也允许保存。
4. V1 Forward ingress 与 target 都仅支持 IPv4；IPv6 只用于 Controller 双栈访问和 Agent 控制连接，数据面接口为后续版本预留。
5. V1 支持 Linux 与 Windows Controller+Agent；Windows amd64 正式支持，arm64 先构建后实机验证；macOS 延后。
6. 默认无 root/Administrator 运行；安装服务时可短暂提权。
7. Linux TCP 尽量 zero-copy；UDP、Windows、限速、详细统计不虚称 zero-copy。
8. 限速按每 Forward 聚合；限速和详细统计默认关闭并显示开销。
9. 业务 SLO：50 Minecraft-like clients 的 Agent p99 增量 jitter `<1 ms`；20 回源节点/100 并发连接平均 `>=2.0 Gbps` 持续 10 分钟。
10. hook 采用通用 webhook + 独立 JavaScript runner/Agent HTTP broker；不内置 DDNS provider，安全 API 足以调用 AliDNS 等服务；local shell 不进入 v1。
11. HTTPS 展示开关只影响链接 scheme；AntiNAT 不为 target 或 Controller 管理 TLS。可信内网允许 `http/ws` 但警告且不下发 hook secret；公网/CDN 使用用户提供的 `https/wss` 或安全隧道。
12. Controller 对 IPv4/IPv6 仅使用一个逻辑 TCP 端口，默认 3111、安装时可改；不自建 STUN。
13. 节点保存 TCP 默认 strategy 和 UDP 默认 strategy；Forward 默认继承并允许单条覆盖。
14. 单独删除 Forward 必须立即停止实际业务；Agent 离线时保持 `DELETE_PENDING_OFFLINE`，不能虚称已停止。
15. 普通删除节点必须等待 Agent 停止全部本地 Forward、清空 LKG/secret/job 并 ACK，随后主控才删除节点；mapping 释放失败只作为 cleanup warning。
16. 节点删除对话框提供未默认勾选的“强制删除”：best-effort 下发同一 terminal command 后，主控立即删除节点且不等 ACK；保留最小 cleanup tombstone。Agent 未收到命令或永不重连时，主控不能保证远端已经停止。
17. Agent 收到 node decommission 后先持久化 terminal marker；重启不得恢复旧 LKG，重新使用必须重新 enrollment。
18. 离线/失败 Forward 置灰、红灯并显示最后已知地址。
19. 完全卸载不保留 AntiNAT 数据或服务残留。
20. UI 中英文，默认中文。
21. README 标注 Natter 为设计参考，但不复制其代码；项目采用 Apache-2.0。
22. 四个前端技能已安装；危险的完整 Impeccable payload 未放行，使用安全 standalone 方法论替代其 hooks/scripts。
23. Controller/Agent 控制消息双向签名；Agent pin Controller signing key 指纹；TLS 仍用于机密性。
24. Agent 状态采用 bbolt 的 received desired + per-Forward last-applied，terminal marker 独立原子文件。
25. Forward 删除采用持久 deletion operation；Controller probe 只有独立 vantage 才能把结果标为 OPEN。
26. Docker v1 仅支持 Linux host-network；Windows containers 不支持。

### 18.2 P0：已全部确认

- **License**：Apache-2.0。
- **V1 地址族**：Forward ingress/target 均 IPv4-only；控制面双栈；数据结构预留 IPv6。
- **节点 strategy 粒度**：TCP default + UDP default；Forward 继承且可覆盖，gateway mapping 可组合 same-port upstream STUN。
- **删除语义**：普通 node delete 等远端 cleanup ACK；强制 node delete 不等 ACK、立即从主控删除并保留 cleanup tombstone；单独 Forward 离线删除保持 pending。
- **控制传输**：可信内网允许 ws/http 但限制 secret；公网/CDN 由用户提供 wss/https 或安全隧道；AntiNAT 不管理 TLS；双向逐消息签名不替代机密性。
- **Controller 端口**：一个逻辑端口，默认 3111、可配置；监听配置与对外 endpoint 分离。
- **Windows**：amd64 是 v1 GA 目标，但只有真实 Winsock/Defender/Service/router/SLO 门禁通过后才列正式支持；arm64 先 cross-build，实机后再列支持。

### 18.3 P1：本轮按推荐值关闭

1. 首次探测默认 `sequential`，全局可改 bounded `parallel`。
2. 离线地址不可点击，显示 stale 风险；允许显式复制陈旧地址。
3. `port_policy` 默认 `accept_any`；可改 `prefer_requested` 或 `strict`，不覆盖第三方 mapping。
4. WAN probe 为 UNKNOWN 时允许管理员 force publish，但必须二次确认、持续风险标记和审计。
5. 用户自定义导航名称/简介 v1 保存单值；系统文案双语。
6. 自动更新默认关闭，仅提示签名 release，由管理员手动升级。
7. macOS 后续适配难度中等，保持接口抽象；不进入 v1。

### 18.4 尚待实测的技术闸门（不是产品问题）

- Linux/Windows PortRegistry + connected STUN socket/unique listener 是否确定无随机分流；不通过则对应 STUN TCP layer 为 unsupported。
- CPE gateway mapping + upstream STUN/keepalive 是否可在同 source tuple 工作；不通过则仅保留经实测的单层 strategy，不伪造组合支持。
- TCP/UDP probe frame、ACTIVE prefix replay 和 remote anti-scan spike；不通过则不得自动 VERIFIED/publish。
- Controller 是否具备独立 WAN probe vantage；不具备则默认 UNKNOWN，v1 可配置 pinned remote-signed probe。
- SQLite driver 的四目标交叉构建/WAL/backup/license 结果。
- JS runner 在 Linux/Windows 的 hard kill 与资源限制结果；不通过则 v1 只发布 webhook。
- Windows amd64 实机吞吐、Defender Firewall、Service 和 complete-uninstall；未通过不得列 GA。
- 专用 lab 的 jitter paired CI、direct>=2.5/proxy>=2.0 且>=80% 基准；未通过只影响性能宣称，不伪造结果。
- Go module path/代码托管 owner 在 Task 1 开工前填写，不影响架构。

## 19. P1 当前推荐默认值

- 首次 detection 默认 sequential，允许管理员切 parallel。
- 离线地址不可点击；提供带风险提示的显式复制按钮。
- `port_policy` 默认 `accept_any`，可选 `prefer_requested/strict`，显示 requested/assigned port。
- UNKNOWN endpoint 只有管理员 force + 审计才能发布。
- 用户内容字段单值；系统 UI 双语、默认中文。
- 自动更新默认关闭，仅提示签名 release。

---

产品 P0/P1 默认值已关闭。实施从 M0 的 Task 0、1、1A、1B 开始；M0 Go/No-Go 未通过前不得进入完整 UI/installer。不得跳过真实 Windows、独立 WAN、节点普通/强制删除、Forward 离线删除、卸载残留和性能验证，也不得在没有实测证据时宣称某种 NAT、平台、2 Gbps 或 zero-copy 已经支持。
