#!/usr/bin/env bash
# Create a deployment-owned certcrypt-node environment file from the complete
# public mold and generate its operator identity locally. The system-domain
# fingerprint is supplied independently from the signed foundation: deriving
# one from the other would turn the document being verified into its own trust
# anchor.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-}"
SYSTEM_ROOT_FINGERPRINT="${2:-}"
API_URL="${3:-}"
SYSTEM_FOUNDATION_PATH="${4:-}"
BIND_ADDR="${NODE_BIND_ADDR:-}"

# No default upstream, like the binary: a node pointed at the wrong issuance
# service by omission is worse than one that refuses to install.
if [[ -z "$TARGET" || -z "$SYSTEM_ROOT_FINGERPRINT" || -z "$API_URL" ]]; then
  echo "usage: [NODE_BIND_ADDR=host:port] ./scripts/install_node.sh ENV_FILE SYSTEM_ROOT_FINGERPRINT API_URL [SYSTEM_FOUNDATION_CACHE_PATH]" >&2
  exit 2
fi

if [[ ! "$SYSTEM_ROOT_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]]; then
  echo "certcrypt-node: system root fingerprint must be 64 lowercase hex chars" >&2
  exit 2
fi

if [[ ! "$API_URL" =~ ^https?://[^[:space:]]+$ ]]; then
  echo "certcrypt-node: API_URL must be an absolute http(s) URL" >&2
  exit 2
fi

if [[ -n "$BIND_ADDR" && ! "$BIND_ADDR" =~ ^[^[:space:]:]+:[0-9]+$ ]]; then
  echo "certcrypt-node: NODE_BIND_ADDR must have the form host:port" >&2
  exit 2
fi

if [[ -e "$TARGET" ]]; then
  if [[ -L "$TARGET" || ! -f "$TARGET" ]]; then
    echo "certcrypt-node: existing environment path must be a regular file, not a symlink: $TARGET" >&2
    exit 1
  fi
  echo "certcrypt-node: protected environment already exists; preserving its operator identity"
  echo "certcrypt-node: opening a fresh demonstrated link request"
  exec "$ROOT_DIR/scripts/link_node.sh" "$TARGET"
fi

TARGET_DIR="$(dirname "$TARGET")"
if [[ ! -d "$TARGET_DIR" ]]; then
  install -d -m 700 "$TARGET_DIR"
fi
TARGET="$(cd "$TARGET_DIR" && pwd)/$(basename "$TARGET")"

if [[ -z "$SYSTEM_FOUNDATION_PATH" ]]; then
  SYSTEM_FOUNDATION_PATH="$(dirname "$TARGET")/system-foundation.json"
fi

FOUNDATION_DIR="$(dirname "$SYSTEM_FOUNDATION_PATH")"
if [[ ! -d "$FOUNDATION_DIR" ]]; then
  install -d -m 700 "$FOUNDATION_DIR"
fi
SYSTEM_FOUNDATION_PATH="$(cd "$FOUNDATION_DIR" && pwd)/$(basename "$SYSTEM_FOUNDATION_PATH")"

generated="$(cd "$ROOT_DIR" && cargo run --quiet -p certcrypt-node --example gen_operator_key)"
sk_line="$(printf '%s\n' "$generated" | grep '^CERTCRYPT_NODE_OPERATOR_SK_B64=')"
pk_line="$(printf '%s\n' "$generated" | grep '^CERTCRYPT_NODE_OPERATOR_PK_B64=')"

if [[ -z "$sk_line" || -z "$pk_line" ]]; then
  echo "certcrypt-node: operator key generator returned incomplete output" >&2
  exit 1
fi

tmp="$(mktemp "${TARGET}.tmp.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
awk \
  -v fingerprint="$SYSTEM_ROOT_FINGERPRINT" \
  -v api_url="$API_URL" \
  -v foundation="$SYSTEM_FOUNDATION_PATH" \
  -v sk="$sk_line" \
  -v pk="$pk_line" \
  -v bind_addr="$BIND_ADDR" '
  /^NODE_BIND_ADDR=/ { if (bind_addr != "") print "NODE_BIND_ADDR=" bind_addr; else print; next }
  /^CERTCRYPT_API_URL=/ { print "CERTCRYPT_API_URL=" api_url; next }
  /^CERTCRYPT_SYSTEM_ROOT_FINGERPRINT=/ { print "CERTCRYPT_SYSTEM_ROOT_FINGERPRINT=" fingerprint; next }
  /^CERTCRYPT_SYSTEM_FOUNDATION_PATH=/ { print "CERTCRYPT_SYSTEM_FOUNDATION_PATH=" foundation; next }
  /^CERTCRYPT_NODE_OPERATOR_SK_B64=/ { print sk; next }
  /^CERTCRYPT_NODE_OPERATOR_PK_B64=/ { print pk; next }
  { print }
' "$ROOT_DIR/.env.example" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$TARGET"
trap - EXIT
echo "certcrypt-node: environment installed at $TARGET (mode 600)"
echo "certcrypt-node: operator identity generated locally; the private key was not printed"
echo "certcrypt-node: the signed system foundation will be downloaded and verified on first start if the cache is absent"
exec "$ROOT_DIR/scripts/link_node.sh" "$TARGET"
