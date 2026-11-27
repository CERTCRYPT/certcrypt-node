#!/usr/bin/env bash
# Run certcrypt-node locally with a fixed, repeatable configuration.
#
# The node reads process environment only — it has no .env loader — so this
# script is where a development setup lives: run it from the repo root and the
# node always comes up the same way.
#
# NOTHING SECRET IS WRITTEN HERE. Every credential and key reference comes from
# the environment, or from a file you point `CERTCRYPT_ENV_FILE` at. A default
# baked into a script is a default that ends up in a repository, and from there
# in every clone of it.
set -euo pipefail

# Optional: a file holding this deployment's configuration and secrets — the
# operator key/credential and the
# system-domain trust material (the pinned system_root_fingerprint and the path
# to the domain's signed foundation statement).
#
# The node must trust the SAME Level-1 public key that minted the bindings it will
# be shown; that is what lets it VERIFY an issuer's Level-1 binding OFFLINE,
# without asking anyone. Sourced first, so explicit exports below still win, and
# skipped without complaint when unset: the same values may already be exported.
ENV_FILE="${CERTCRYPT_ENV_FILE:-}"
if [[ -n "$ENV_FILE" ]]; then
  [[ -f "$ENV_FILE" ]] || {
    echo "certcrypt-node: CERTCRYPT_ENV_FILE does not exist: $ENV_FILE" >&2
    exit 1
  }
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

# --- runtime ---
export NODE_BIND_ADDR="${NODE_BIND_ADDR:-127.0.0.1:8080}"
export RUST_LOG="${RUST_LOG:-info}"

# Where this node forwards. It is always explicit: silently falling back to a
# different environment could activate or submit against the wrong system.
if [[ -z "${CERTCRYPT_API_URL:-}" || ! "$CERTCRYPT_API_URL" =~ ^https?://[^[:space:]]+$ ]]; then
  echo "certcrypt-node: CERTCRYPT_API_URL must be an explicit absolute http(s) URL" >&2
  [[ -n "$ENV_FILE" ]] && echo "certcrypt-node: set it in $ENV_FILE" >&2
  exit 1
fi
export CERTCRYPT_API_URL

# --- node -> issuance service ---
# There is no shared bearer. Every submit carries the current
# operator.recognition/1 credential and an exact possession proof. The separate
# install/link ceremony has already bound the demonstrated operator key to its
# administrative contract; no bootstrap secret is a runtime credential.

# --- issuer authentication: zero-trust, offline, protocol-driven ---
# There is NO static map of issuer credentials. The node verifies each issuer's
# self-verifying Level-1 proof against the system-domain public key published in
# the domain's signed foundation statement (system-foundation/1) — point it at
# the statement of the system domain you trust. The node verifies that statement
# against the pinned fingerprint at startup and fails closed on any mismatch,
# rather than trusting whatever it was handed.
#
#   Generate a statement around your own development key material with:
#     cargo run -p certcrypt-node --example gen_dev_foundation > system-foundation.json
#   (it prints the fingerprint to pin on stderr).
SYSTEM_ROOT_FINGERPRINT="${CERTCRYPT_SYSTEM_ROOT_FINGERPRINT:-}"
if [[ ! "$SYSTEM_ROOT_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]]; then
  echo "certcrypt-node: CERTCRYPT_SYSTEM_ROOT_FINGERPRINT must be the 64-character lowercase hexadecimal fingerprint obtained independently from the system domain" >&2
  [[ -n "$ENV_FILE" ]] && echo "certcrypt-node: replace its placeholder in $ENV_FILE; install_node.sh accepts it as its second argument" >&2
  exit 1
fi
export CERTCRYPT_SYSTEM_ROOT_FINGERPRINT="$SYSTEM_ROOT_FINGERPRINT"

SYSTEM_FOUNDATION_PATH="${CERTCRYPT_SYSTEM_FOUNDATION_PATH:-}"
if [[ -z "$SYSTEM_FOUNDATION_PATH" || ! -d "$(dirname "$SYSTEM_FOUNDATION_PATH")" ]]; then
  echo "certcrypt-node: CERTCRYPT_SYSTEM_FOUNDATION_PATH must name a cache file in an existing directory" >&2
  [[ -n "$ENV_FILE" ]] && echo "certcrypt-node: the node downloads and verifies it on first start; check the path configured in $ENV_FILE" >&2
  exit 1
fi
export CERTCRYPT_SYSTEM_FOUNDATION_PATH="$SYSTEM_FOUNDATION_PATH"

for required in CERTCRYPT_NODE_OPERATOR_SK_B64 CERTCRYPT_NODE_OPERATOR_PK_B64 CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64; do
  if [[ -z "${!required:-}" ]]; then
    echo "certcrypt-node: $required is empty; complete operator recognition before starting the node" >&2
    exit 1
  fi
done

# A file-backed journal, so a restart keeps the outbox. Use ":memory:" for a
# throwaway run.
export NODE_JOURNAL="${NODE_JOURNAL:-node-journal.sqlite}"

echo "certcrypt-node: bind=$NODE_BIND_ADDR upstream=$CERTCRYPT_API_URL"
exec cargo run -p certcrypt-node
