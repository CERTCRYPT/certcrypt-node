#!/usr/bin/env bash
#
# The same checks the pre-push hook runs, callable by hand: `bash scripts/ci.sh`.
#
# It exists so "what CI will say" is one command, not a guess. A separate check
# that drifted from the hook would be worse than none — it would report green on
# a push the hook is about to refuse.
#
# WHAT IS ENFORCED:
#
#   cargo fmt           — ENFORCED. The tree is formatted; run
#                         `cargo fmt --all` before pushing.
#   clippy -D warnings  — ENFORCED.
#   cargo test          — ENFORCED.
#
# FMT_STRICT=0 reports formatting without failing. Use it only to land a
# deliberate reformat as its own commit, never to get a push through.
set -u

FMT_STRICT="${FMT_STRICT:-1}"
fail=0

echo "▸ formatting"
if cargo fmt --all --check >/dev/null 2>&1; then
  echo "  ✓ formatting"
else
  dirty="$(cargo fmt --all --check 2>&1 | grep -c '^Diff' || true)"
  if [ "$FMT_STRICT" = "1" ]; then
    echo "  ✗ formatting — ${dirty} diffs. Run: cargo fmt --all"
    fail=1
  else
    echo "  ⚠ formatting — ${dirty} diffs (not blocking; see scripts/ci.sh)"
  fi
fi

# `cmd | tail` returns TAIL's status, not the command's — tail always succeeds,
# so `if cargo clippy ... | tail; then` is green no matter what clippy found.
# Run the command on its own line, keep its status, and only then show the tail
# of the output.
run_cargo() {
  local label="$1"; shift
  local out status
  out="$("$@" 2>&1)"
  status=$?
  if [ "$status" -eq 0 ]; then
    echo "  ✓ ${label}"
  else
    printf '%s\n' "$out" | tail -30
    echo "  ✗ ${label}"
    fail=1
  fi
}

echo "▸ clippy"
run_cargo "clippy" cargo clippy --workspace --all-targets -- -D warnings

echo "▸ tests"
run_cargo "tests" cargo test --workspace

exit "$fail"
