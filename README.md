# AntiNAT

[English](README.en.md)

AntiNAT 是一个“主控 + Agent”的 IPv4 公网访问工具。主控负责管理配置、节点、权限和探测结果；Agent 放在目标网络里，负责端口映射、NAT 穿透和转发真实业务流量。主控不会充当业务流量中继。

###目前还是半成品，还在测试中。

当前仓库是主控项目，同时包含一份集成版 Agent 和跨组件测试。独立 Agent 项目在 [gxbrave/AntiNAT-Agent](https://github.com/gxbrave/AntiNAT-Agent)。

## 能做什么

- 在主控里管理 Agent 节点和 TCP/UDP 转发规则。
- 让 Agent 尝试直连、STUN、PCP、NAT-PMP、UPnP 等路径，并把结果报告给主控。
- 通过签名的主控-Agent 控制通道下发配置、心跳、状态和生命周期操作。
- 保存主控和 Agent 的本地状态，重启、失败恢复和升级时尽量保持状态一致。
- 提供 Web 管理界面、HTTP API、`antinatctl` 命令行，以及受限制的 Webhook/脚本能力。
- 区分“看起来有公网地址”和“确实能从独立探测点访问”，避免把本地测试结果误报成公网可用。

## 项目组成

| 目录或命令 | 作用 |
| --- | --- |
| `cmd/antinat-controller` | 主控 HTTP 服务 |
| `cmd/antinat-agent` | 集成版 Agent 进程 |
| `cmd/antinatctl` | 管理主控、节点和转发规则的 CLI |
| `cmd/antinat-probe` | 独立探测服务 |
| `cmd/antinat-hook-runner` | 隔离的 Hook 执行器 |
| `internal/controller` | 主控状态、API、探测、生命周期和 Web UI |
| `internal/agent` | Agent 控制会话、本地状态和转发协调 |
| `internal/protocol` | 主控和 Agent 之间的签名协议 |
| `scripts/` | 构建验证、安装、升级、卸载和发布检查脚本 |
| `deploy/` | systemd、OpenRC 和发布信任根文件 |

## 支持范围

首个 `v1.0.0-beta.1` 制品面向 Debian 12、Ubuntu 22.04/24.04 的 Linux amd64。这个版本覆盖本地功能测试、竞态测试、静态检查、浏览器检查和隔离安装器测试；公网 NAT、长时间运行和其他平台仍按下方限制说明。

- Linux amd64：首个 Debian/Ubuntu Beta 发布目标，systemd 安装路径最完整。
- Linux arm64：保留交叉编译能力，但 ARM 主机已不在本次发布验证范围内。
- Windows amd64：只要求能通过 `cmd` 启动并完成构建检查，不列入首个 Debian/Ubuntu 发布支持范围。
- OpenRC、真实公网 WAN/CPE 路由器、OCI 仓库 digest 和长时间运行：证据还不完整。
- v1 不提供任意 NAT 都能打通、主控中继业务流量、IPv6 转发数据面或正式的 `2 Gbps`/`<1 ms` 性能承诺。

## 开始使用

### 环境要求

- Debian 12、Ubuntu 22.04 或 Ubuntu 24.04，Linux amd64
- Go 1.26.6，或与 CI 兼容的 Go 版本
- 编译检查需要 `bash`、`jq` 等常用工具；完整安装器检查还需要 root 权限

### 方式一：一键安装脚本

在 Debian/Ubuntu Linux amd64 主机运行（root 可省略 `sudo`）：

```bash
curl -fsSL https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo bash
```

菜单只有三个选项：

1. **仅安装主控**。
2. **安装主控 + Agent**：先安装主控，再由主控创建本地节点、生成认证参数，调用 [AntiNAT-Agent](https://github.com/gxbrave/AntiNAT-Agent) 的安装入口。两个组件始终是独立进程和服务。
3. **完全卸载**：删除本机主控和 Agent 的服务、所属配置和数据。

安装时可输入主控端口，默认 `3111`。本地 Agent 自动访问 `http://127.0.0.1:所选端口`，不需要提供公网地址、访问地址或注册 token。主控监听 `0.0.0.0:所选端口`；已安装主控时沿用现有端口，选 2 可继续添加本地 Agent。

参数也可以直接写在命令后：

```bash
# 主控 + 本地 Agent，主控端口 8080
curl -fsSL https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo bash -s -- 2 --port 8080

# 仅主控，使用默认端口 3111
curl -fsSL https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo bash -s -- 1

# 完全卸载本机安装（含配置和数据）
curl -fsSL https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo bash -s -- 3
```

远程 Agent 必须先在主控中创建节点，再使用主控生成的安装命令；主控仓库不提供无参数的独立 Agent 安装选项。Agent 入口在 AntiNAT-Agent 仓库，接收主控签发的节点、信任公钥和认证参数；注册 token 通过隐藏输入或 `0600` 文件传递。

此流程对应两仓库的 `v1.0.0-beta.2` 制品，需先发布配套版本，不能搭配旧版主控二进制。安装器验证 Release manifest 签名及制品 SHA-256。匿名下载要求仓库和 Release 公开；目标主机需要 `curl`、`python3`、`jq` 以及底层安装器所需工具。制品镜像分别用 `ANTINAT_RELEASE_BASE_URL`（主控）和 `ANTINAT_AGENT_RELEASE_BASE_URL`（Agent）设置。

Docker 用户直接通过主控镜像安装（[`docker/compose.yaml`](docker/compose.yaml) 只启动主控），不使用上述安装脚本。本地或远程 Agent 均由用户在主控中创建后自行安装。

### 方式二：自行编译

```bash
git clone https://github.com/gxbrave/AntiNAT.git
cd AntiNAT

# 跑测试和静态检查
GOWORK=off make check

# 编译主控和集成版 Agent
GOWORK=off make build

# 查看版本
./bin/antinat-controller version
./bin/antinat-agent version
```

启动一个本机主控：

```bash
./bin/antinat-controller \
  --listen 127.0.0.1:3111 \
  --store ./var/controller.db \
  --keydir ./var/keys
```

主控启动后，可以用 `antinatctl` 初始化管理员、登录、创建节点并签发一次性注册 token：

```bash
GOWORK=off go build -o bin/antinatctl ./cmd/antinatctl
./bin/antinatctl --endpoint http://127.0.0.1:3111 admin init
./bin/antinatctl --endpoint http://127.0.0.1:3111 login --username admin
./bin/antinatctl --endpoint http://127.0.0.1:3111 node create --name agent-1
./bin/antinatctl --endpoint http://127.0.0.1:3111 node list
```

然后把节点 ID、一次性 token 和主控公钥 pin 提供给 Agent。token 应放在权限为 `0600` 的文件中，Agent 成功注册后会消费它：

```bash
chmod 600 ./var/enrollment.token
./bin/antinat-agent \
  --endpoint http://127.0.0.1:3111 \
  --node <节点 ID> \
  --token-file ./var/enrollment.token \
  --pin <64 位十六进制主控公钥> \
  --state ./var/agent
```

也可以用环境变量 `ANTINAT_ENDPOINT`、`ANTINAT_NODE`、`ANTINAT_TOKEN_FILE`、`ANTINAT_PIN` 和 `ANTINAT_STATE`，不必把敏感值放进 shell 历史。

### 常用检查

```bash
GOWORK=off make verify-evidence
GOWORK=off go run ./scripts/verify-release-evidence.go ./artifacts/evidence
curl http://127.0.0.1:3111/healthz
curl http://127.0.0.1:3111/readyz
```

完整 Beta 检查可以运行：

```bash
GOWORK=off bash scripts/run-beta-gates.sh \
  --artifacts ./artifacts \
  --evidence ./artifacts/evidence
```

### 相关目录

- `var/`：本地运行时数据库、密钥和 Agent 状态，默认不应提交到 Git。
- `docs/support-matrix.md`：平台和能力支持矩阵。
- `docs/installer-contract.md`：安装器参数、安全边界和退出码。
- `docs/release-policy.md`：Beta 制品、签名和发布规则。

## 实现方式

主控和 Agent 分成两个故障域。主控保存期望配置，负责认证、Web/API、节点管理、探测协调和审计；Agent 保存本地实际状态，负责监听本地目标、建立映射、处理 TCP/UDP 数据面和恢复。业务数据只经过 Agent，不经过主控。

控制通道使用签名的协议帧和节点身份。配置变更会经过 Agent 的本地协调器和持久化状态机，转发更新、删除、重启恢复和失败回滚都有明确状态。公网可达性必须由命名的独立探测点完成认证探测；本地 bind、STUN 映射或读取公网 IP 只能算候选信息。

发布安装器从 Release 下载 manifest、签名和制品，先验证固定信任根、签名和 SHA-256，再原子安装文件。这样可以把“下载到了文件”和“运行的是经过验证的文件”区分开。更细的协议、状态机和安全约束见 `docs/`。

## 测试

```bash
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

部分沙箱测试需要专用身份：

```bash
ANTINAT_DEDICATED_UID=12001 \
ANTINAT_DEDICATED_GID=12001 \
GOWORK=off make check
```

## 许可证

本项目采用 [GPL-3.0](LICENSE) 发布。
