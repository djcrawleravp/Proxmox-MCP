#!/usr/bin/env bash
# Installs a dedicated, passwordless SSH key for the Proxmox MCP on one node.
# The password is handled only by ssh-copy-id's local prompt; it is never read,
# logged, or saved by this script.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(CDPATH= cd -- "$script_dir/.." && pwd)"
key_dir="$repo_dir/keys"
key_path="$key_dir/proxmox-mcp-ed25519"
target="${1:-root@10.10.10.12}"

if ! command -v ssh-copy-id >/dev/null 2>&1; then
  echo "ssh-copy-id is required but was not found." >&2
  exit 1
fi

if [[ ! "$target" =~ ^root@([A-Za-z0-9.-]+)$ ]]; then
  echo "Usage: $0 [root@solid-management-address]" >&2
  exit 2
fi

umask 077
mkdir -p "$key_dir"

if [[ ! -f "$key_path" ]]; then
  ssh-keygen -q -t ed25519 -N '' -f "$key_path" -C 'proxmox-mcp-host-automation'
fi

echo "Installing the MCP public key on $target."
echo "Enter the root password once at the SSH prompt; it is not stored."
ssh-copy-id -i "$key_path.pub" "$target"

echo "Verifying passwordless access..."
ssh -i "$key_path" -o BatchMode=yes -o ConnectTimeout=10 "$target" 'hostname'

cat <<EOF

Ready. The private key is: $key_path
Keep it mode 0600 and do not copy it into git.

To let the MCP use it, start its service/container with:
  PROXMOX_HOST_SSH_KEY=$key_path

This only authorizes the MCP to connect to Solid. The direct LXC streaming
workflow then uses Solid's existing Proxmox SSH trust to reach liquid.
EOF
