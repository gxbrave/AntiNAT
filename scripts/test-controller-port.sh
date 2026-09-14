#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export ANTINAT_TEST_ROOT="$scratch/root" ANTINAT_TEST_MODE=1 ANTINAT_ROLE=controller
source "$repo_dir/scripts/libinstall.sh"
INSTALLER_COMMAND=install
ANTINAT_CONTROLLER_PORT=48221
installer_init_paths
[[ "$INSTALLER_CONTROLLER_PORT" == 48221 ]]
mkdir -p "$INSTALLER_SERVICE_DIR" "$INSTALLER_OPENRC_DIR"
installer_install_service_unit antinat-controller.service "$INSTALLER_CONTROLLER_UNIT"
rg -q -- '-listen 0.0.0.0:48221 ' "$INSTALLER_CONTROLLER_UNIT"
installer_install_embedded_unit antinat-controller.service "$scratch/embedded"
rg -q -- '-listen 0.0.0.0:48221 ' "$scratch/embedded"
installer_install_openrc_service antinat-controller
rg -q -- '-listen 0.0.0.0:48221 ' "$INSTALLER_OPENRC_DIR/antinat-controller"
for invalid in '' 0 65536 -1 1x 999999999999999999999999; do
    if (ANTINAT_CONTROLLER_PORT="$invalid"; installer_init_paths); then
        echo "accepted invalid port: $invalid" >&2; exit 1
    fi
done
unset ANTINAT_CONTROLLER_PORT
INSTALLER_COMMAND=upgrade
installer_init_paths
[[ "$INSTALLER_CONTROLLER_PORT" == 48221 ]]
ANTINAT_SERVICE_MANAGER=openrc installer_init_paths
[[ "$INSTALLER_CONTROLLER_PORT" == 48221 ]]
INSTALLER_COMMAND=install
installer_init_paths
[[ "$INSTALLER_CONTROLLER_PORT" == 3111 ]]
# Verify that the actual configured socket, including non-loopback binds, is checked.
python3 - "$scratch" <<'PY' &
import socket, sys, pathlib, time
s=socket.socket(); s.bind(('0.0.0.0',0)); s.listen()
pathlib.Path(sys.argv[1], 'port').write_text(str(s.getsockname()[1]))
while not pathlib.Path(sys.argv[1], 'stop').exists(): time.sleep(.02)
PY
listener=$!
for ((n=0;n<100;n++)); do [[ ! -f "$scratch/port" ]] || break; sleep .02; done
INSTALLER_CONTROLLER_PORT=$(cat "$scratch/port")
if installer_controller_port_available; then
    touch "$scratch/stop"; wait "$listener"; echo 'occupied configured port was accepted' >&2; exit 1
fi
touch "$scratch/stop"; wait "$listener"
installer_controller_port_available
printf 'controller port tests passed\n'
