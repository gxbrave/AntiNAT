# AntiNAT

[中文说明](README.md)

AntiNAT attempts to make TCP/UDP services inside a private network reachable from outside, such as a home server.

The **Controller** provides a web interface for managing nodes and forwarding rules. An **Agent** runs in the target network and handles port mapping, NAT traversal and traffic forwarding. Application traffic passes through the Agent, not the Controller.

> This is unfinished software under testing (Beta). Reachability depends on your ISP, router and firewall. Traversal is not guaranteed for every NAT environment.

## One-click installation (recommended)

**The installer downloads prebuilt binaries. You do not need Go or a source checkout.** It currently defaults to `v1.0.0-beta.2`, available in [Releases](https://github.com/gxbrave/AntiNAT/releases). It verifies the release manifest signature and file SHA-256 checksums.

### 1. Prepare the host

Use an **x86_64 / amd64** host running Debian 12, Ubuntu 22.04 or Ubuntu 24.04 with systemd. You need root access or an account with `sudo` privileges.

Install the required utilities (no Go needed):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl python3 jq openssl bash coreutils findutils util-linux passwd gawk hostname
```

You can omit `sudo` in the following commands when logged in as root.

### 2. Run the installer

Directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo bash
```

Mirror-accelerated installation in China:

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo env ANTINAT_DOWNLOAD_MIRROR=https://ghfast.top bash
```

The mirror command downloads the entry script and required files through `https://ghfast.top`. This also covers the local Agent's script and files when selected.

### 3. Choose from the menu

| Option | When to use it |
| --- | --- |
| 1. Controller only | Run the management interface here and install Agents elsewhere |
| 2. Controller + Agent | Run both on this host; the installer registers the local Agent automatically |
| 3. Complete removal | Delete both local components, including configuration and data; back up first |

Choose a Controller port during installation; the default is **3111**. An existing Controller keeps its port, and option 2 can add a local Agent later. Running the installer again does not upgrade an existing Controller.

To skip the menu, for example installing both components on port 8080:

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/gxbrave/AntiNAT/main/install.sh | sudo env ANTINAT_DOWNLOAD_MIRROR=https://ghfast.top bash -s -- 2 --port 8080
```

## After installation

1. **Create an administrator**: the installer does not create a management account, and there is no default password. Follow [administrator setup](docs/admin-setup.md) on the Controller host. No Go is required.
2. **Open the management page**: visit `http://CONTROLLER_IP:3111/admin` and sign in with your new account. Replace `3111` if you chose another port.
3. **Add Agents**: option 2 already registers the local Agent. For another machine, create a node in the Controller and run its generated installation command on that machine. See [AntiNAT-Agent](https://github.com/gxbrave/AntiNAT-Agent).
4. **Add forwarding rules**: choose an Agent, TCP or UDP, and the target service address and port, then check the mapping and probe results.

The Controller listens on all IPv4 interfaces by default. Restrict access to the management port until you create the first administrator. Configure HTTPS for remote use; remote Agent enrollment also requires an HTTPS endpoint. If the page does not load, check the service, port, host firewall and cloud security group.

Having a public IP does not by itself prove that a service is reachable from outside. Check the actual probe results.

### Check service status

Run on the Controller host, replacing `3111` if necessary:

```bash
sudo systemctl status antinat-controller --no-pager
sudo journalctl -u antinat-controller -n 100 --no-pager
curl -fsS http://127.0.0.1:3111/readyz
```

If you installed a local Agent:

```bash
sudo systemctl status antinat-agent --no-pager
```

Programs are installed under `/opt/antinat` and data under `/var/lib/antinat` by default. Back up configuration, databases and keys before removal.

## Docker installation

The Controller image also runs without Go. Install Docker and Compose, download [`docker/compose.yaml`](docker/compose.yaml), and run this in the directory containing that file:

```bash
docker compose up -d
```

This configuration uses Linux host networking and starts only the Controller, on port `3111`, with data stored in Docker volumes. Create and install Agents separately. See the [Docker documentation](docker/README.md).

## Build from source (developers)

**Go is required only for building from source or development.** The repository uses Go 1.26.6. You also need Git, Make and Bash.

```bash
git clone https://github.com/gxbrave/AntiNAT.git
cd AntiNAT
make build
```

The Controller and Agent binaries are written to `bin/`. To run a local-only Controller:

```bash
./bin/antinat-controller --listen 127.0.0.1:3111 --store ./var/controller.db --keydir ./var/keys
```

Build the optional management CLI separately:

```bash
go build -o bin/antinatctl ./cmd/antinatctl
```

Development checks:

```bash
make check
go test -race ./...
```

Some sandbox tests require a dedicated UID/GID. See [`docs/support-matrix.md`](docs/support-matrix.md) and [`scripts/run-beta-gates.sh`](scripts/run-beta-gates.sh) for full validation details.

## Current limits and documentation

- The current one-click release targets Linux amd64 on Debian/Ubuntu. ARM, Windows and OpenRC are outside the recommended installation scope.
- No Controller traffic relay or IPv6 forwarding data plane is provided. Public-network, router compatibility and long-running validation remain incomplete.
- [Installer options and removal](docs/installer-contract.md)
- [Platform and feature support](docs/support-matrix.md)
- [Release and signing policy](docs/release-policy.md)

## License

[GPL-3.0](LICENSE).
