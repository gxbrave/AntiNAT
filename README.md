# AntiNAT

[English](README.en.md)

AntiNAT 用来尝试让外部网络访问内网中的 TCP/UDP 服务，例如家里的服务器。

它分为两部分：**主控**提供管理页面，用来管理节点和转发规则；**Agent**安装在目标网络中，负责端口映射、NAT 穿透和流量转发。业务流量经过 Agent，不经过主控。

> 项目仍是测试中的半成品（Beta）。能否从外网访问取决于运营商、路由器和防火墙，不保证所有 NAT 环境都能穿透。

## 一键安装（推荐）

**安装的是已编译好的二进制文件，不需要安装 Go，也不需要下载源码。** 当前脚本默认安装 `v1.0.0-beta.2`，对应文件已发布在 [Releases](https://github.com/gxbrave/AntiNAT/releases)。安装器会验证文件清单的签名和文件的 SHA-256 校验值。

### 1. 准备环境

推荐使用 Debian 12、Ubuntu 22.04 或 Ubuntu 24.04 的 **x86_64 / amd64** 主机，使用 systemd 管理服务。需要 root 权限，或可以使用 `sudo` 的账号。

安装所需的常用工具（无需 Go）：

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl python3 jq openssl libargon2-1 bash coreutils findutils util-linux passwd gawk hostname
```

下面命令中的 `sudo`，以 root 登录时可以省略。

### 2. 运行安装命令

GitHub 直连：

```bash
curl -fsSL https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo bash
```

国内镜像加速：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo env ANTINAT_DOWNLOAD_MIRROR=https://ghfast.top bash
```

镜像命令通过 `https://ghfast.top` 下载入口脚本和后续所需文件；选择安装本地 Agent 时，它的脚本和文件也会通过镜像下载。

### 3. 按菜单选择

| 选项 | 适用情况 |
| --- | --- |
| 1. 仅安装主控 | 这台机器只运行管理页面，Agent 安装在其他机器上 |
| 2. 安装主控 + Agent | 这台机器同时运行主控和本地 Agent，安装器会自动注册本地节点 |
| 3. 完全卸载 | 删除本机主控、Agent 及其配置和数据，请先备份 |

选择安装后，按提示依次设置：

1. **主控监听端口**：留空使用 `3111`。
2. **管理员账号**：留空随机生成 8 位字母数字组合。
3. **管理员密码**：输入时不显示，至少 8 个字符；留空随机生成 8 位字母数字组合。

安装完成会显示主控管理页面地址、管理员账号和密码，请保存好。随机账号和密码都同时包含字母和数字。

已有主控时会沿用原端口；已有管理员时保留原账号密码，不会重新设置或显示原密码。再选 2 可以补装本地 Agent。重复运行安装命令不是升级操作。

如需跳过菜单，例如安装主控和本地 Agent、使用 8080 端口（新管理员账号和密码自动随机生成，结束时显示）：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo env ANTINAT_DOWNLOAD_MIRROR=https://ghfast.top bash -s -- 2 --port 8080
```

## 安装后怎么使用

1. **保存登录信息**：一键安装已创建管理员，使用安装结束时显示的账号和密码。Docker、自行编译或旧版安装尚未创建账号时，见[首次创建管理员](docs/admin-setup.md)。
2. **打开管理页面**：浏览器访问 `http://主控IP:3111/admin`，使用刚创建的账号登录。修改过端口时，替换 `3111`。
3. **添加 Agent**：选项 2 已自动添加本地 Agent。其他机器上的 Agent，需要先在主控页面创建节点，再到目标机器执行主控生成的安装命令，详见 [AntiNAT-Agent](https://github.com/gxbrave/AntiNAT-Agent)。
4. **添加转发规则**：选择 Agent、TCP 或 UDP，以及要访问的目标服务地址和端口，再查看映射与探测结果。

主控默认监听所有 IPv4 网卡。请限制管理端口的访问范围；远程使用时应配置 HTTPS，远程 Agent 注册也需要 HTTPS 地址。页面打不开时，检查服务状态、端口以及主机防火墙和云服务器安全组。

“获取到了公网 IP”不代表外网一定能访问，仍需看实际探测结果。

## SSH 管理命令

通过一键脚本安装后，在主控机器的 SSH 终端输入：

```bash
sudo antinatctl
```

root 用户直接输入 `antinatctl` 即可打开管理菜单，无需重新下载脚本。

| 命令 | 功能 |
| --- | --- |
| `sudo antinatctl` | 打开管理菜单 |
| `sudo antinatctl status` | 查看主控、Agent 状态、访问地址和管理员账号 |
| `sudo antinatctl reset-admin` | 重设管理员账号或密码，不需要记得旧密码 |
| `sudo antinatctl restart` | 重启主控 |
| `sudo antinatctl upgrade` | 升级占位，暂未开放，不会执行升级 |
| `sudo antinatctl uninstall` | 完全卸载本机主控、Agent 及其配置和数据 |

**忘记账号或密码**：先用 `status` 查看账号，或直接运行 `reset-admin`。新账号留空保留原账号，新密码留空生成 8 位字母数字组合。重设时会短暂停止正在运行的主控，完成后恢复运行并显示新凭据；该管理员的旧登录会话会失效，节点和转发规则保留。原密码无法读取。

**卸载**：需要输入 `DELETE` 确认。卸载组件已缓存在本机，不需要连接 GitHub；成功后会移除 `antinatctl`。默认程序目录是 `/opt/antinat`，数据目录是 `/var/lib/antinat`，卸载前请备份需要保留的配置、数据库和密钥。

**已安装的旧用户**：如果提示找不到 `antinatctl`，按上方“准备环境”安装依赖后，重新运行以下命令补装管理工具。已有主控不会重新安装，原账号密码会保留：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo env ANTINAT_DOWNLOAD_MIRROR=https://ghfast.top bash -s -- 1
```

需要排查主控日志时：

```bash
sudo journalctl -u antinat-controller -n 100 --no-pager
```

## Docker 安装

也可以使用主控镜像，不需要 Go。准备好 Docker 和 Compose，下载仓库中的 [`docker/compose.yaml`](docker/compose.yaml)，在该文件所在目录执行：

```bash
docker compose up -d
```

该配置使用 Linux 主机网络，只启动主控，默认端口为 `3111`，数据保存在 Docker 卷中。Agent 需要另行创建和安装。更多说明见 [Docker 文档](docker/README.md)。

## 自行编译（开发者使用）

**只有自行编译或开发时才需要 Go。** 仓库使用 Go 1.26.6 工具链；还需要 Git、Make 和 Bash。

```bash
git clone https://github.com/gxbrave/AntiNAT.git
cd AntiNAT
make build
```

生成的主控和 Agent 位于 `bin/`。例如，仅在本机启动主控：

```bash
./bin/antinat-controller --listen 127.0.0.1:3111 --store ./var/controller.db --keydir ./var/keys
```

开发者如需直接调用 API 的 CLI，可以单独编译（它与一键安装提供的 SSH 管理菜单独立）：

```bash
go build -o bin/antinatctl ./cmd/antinatctl
```

开发检查：

```bash
make check
go test -race ./...
```

部分沙箱测试需要配置专用 UID/GID，完整验证步骤见 [`docs/support-matrix.md`](docs/support-matrix.md) 和 [`scripts/run-beta-gates.sh`](scripts/run-beta-gates.sh)。

## 当前限制与更多文档

- 当前一键安装发布目标是 Debian/Ubuntu 的 Linux amd64。ARM、Windows 和 OpenRC 不属于本次推荐安装范围。
- 不提供主控流量中继或 IPv6 转发数据面；真实公网、不同路由器和长期运行的验证仍不完整。
- [安装器参数与卸载说明](docs/installer-contract.md)
- [平台与功能支持范围](docs/support-matrix.md)
- [发布与签名规则](docs/release-policy.md)

## 许可证

[GPL-3.0](LICENSE)。
