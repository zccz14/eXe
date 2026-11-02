#!/bin/sh
# eXe installer.
#
#   curl -fsSL https://exe.ntnl.io/install.sh | sh
#
#   EXE_VERSION=v0.5.0      pin a version (fetched from GitHub instead of the relay)
#   EXE_INSTALL_DIR=~/bin   choose where the binary lands
#
# It installs a binary and nothing else: no service, no configuration, no sudo.
# Run `exe` afterwards to set the machine up.
set -eu

BASE="${EXE_BASE:-https://exe.ntnl.io}"
REPO="${EXE_REPO:-zccz14/eXe}"

say() { printf 'exe: %s\n' "$*"; }
die() { printf 'exe: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64 | Linux/amd64) target=x86_64-unknown-linux-gnu ;;
  Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-gnu ;;
  Darwin/arm64) target=aarch64-apple-darwin ;;
  Darwin/x86_64) target=x86_64-apple-darwin ;;
  *) die "no prebuilt binary for $(uname -s)/$(uname -m); build it from source with cargo" ;;
esac

asset="exe-$target.tar.gz"
dir="${EXE_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  # Never escalate: a binary that needs sudo to land is a binary that can wait.
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi

have curl || die "curl is required"
have tar || die "tar is required"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ -n "${EXE_VERSION:-}" ]; then
  url="https://github.com/$REPO/releases/download/$EXE_VERSION/$asset"
else
  url="$BASE/download/$asset"
fi

say "$url"
curl -fsSL "$url" -o "$tmp/$asset" || die "download failed"
curl -fsSL "$url.sha256" -o "$tmp/$asset.sha256" \
  || die "no checksum published for $asset — refusing to install"
( cd "$tmp" && { have sha256sum && sha256sum -c "$asset.sha256" || shasum -a 256 -c "$asset.sha256"; } >/dev/null ) \
  || die "checksum mismatch: the download is corrupt or was modified in transit"

tar -xzf "$tmp/$asset" -C "$tmp" exe || die "cannot unpack $asset"
mkdir -p "$dir"
cp "$tmp/exe" "$dir/exe"
chmod 0755 "$dir/exe"

say "installed $dir/exe ($("$dir/exe" version 2>/dev/null || echo unknown))"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "add $dir to PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac

cat <<'DONE'

Next, on this machine:

  exe                    set it up as a device: key, background service, proof
  exe --trust <address>  the same, and allow calls from that caller
  exe status             what the relay sees, and where the log is

To drive this machine from an agent harness, on the machine that runs the agent:

  exe mcp init           create the caller key and print its address
  claude mcp add exe -- exe mcp
DONE
