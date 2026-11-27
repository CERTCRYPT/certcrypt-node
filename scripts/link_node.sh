#!/usr/bin/env bash
# Open a possession-proven node link request, wait for the console-side link,
# and store the returned recognition credential without printing the private key.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${1:-}"
if [[ -z "$ENV_FILE" || ! -f "$ENV_FILE" ]]; then
  echo "usage: ./scripts/link_node.sh ENV_FILE" >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

for name in CERTCRYPT_API_URL CERTCRYPT_NODE_OPERATOR_SK_B64 CERTCRYPT_NODE_OPERATOR_PK_B64; do
  if [[ -z "${!name:-}" ]]; then
    echo "certcrypt-node: $name is required in $ENV_FILE" >&2
    exit 2
  fi
done

credential_line="$(cd "$ROOT_DIR" && cargo run --quiet -p certcrypt-node --example link_node)"
if [[ "$credential_line" != CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64=* ]]; then
  echo "certcrypt-node: link client returned an invalid credential line" >&2
  exit 1
fi

tmp="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
awk -v credential="$credential_line" '
  /^CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64=/ { print credential; next }
  { print }
' "$ENV_FILE" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$ENV_FILE"
trap - EXIT
echo "certcrypt-node: demonstrated node link completed; credential stored in $ENV_FILE"
