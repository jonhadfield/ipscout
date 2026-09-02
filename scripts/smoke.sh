#!/usr/bin/env bash
#
# Smoke test the packaged release binary.
#
# `go build` in the working tree is not the thing users run. The archive is,
# and it behaves differently: there is no go.mod above it, no repository
# alongside it, and no existing config or cache. Bugs that only appear under
# those conditions have shipped before, so this extracts the archive
# goreleaser produced and exercises it from a temporary directory with a
# throwaway HOME.
#
# Runs entirely offline. Anything needing the network belongs in a test, not
# in a release gate.
#
# Usage: scripts/smoke.sh [dist-dir]

set -euo pipefail

DIST="${1:-dist}"

# Provider tables a default config renders. This is registry.All() minus the
# providers that cannot be enabled without configuration: Azure WAF is the
# only one, as it needs Azure resource IDs, so this is expectedProviderCount
# in registry/registry_test.go minus one.
#
# Asserting the exact number is the point. A provider that stops resolving in
# the packaged binary still leaves the others rendering, so a "greater than
# zero" check passes while most of the tool is broken - which is the class of
# bug this script exists to catch.
EXPECTED_TABLES=73

fail() {
    echo "smoke: FAIL: $*" >&2
    exit 1
}

pass() {
    echo "smoke: ok: $*"
}

case "$(uname -s)" in
    Darwin) goos=darwin ;;
    Linux) goos=linux ;;
    *) fail "unsupported host $(uname -s); run this on darwin or linux" ;;
esac

case "$(uname -m)" in
    arm64 | aarch64) goarch=arm64 ;;
    x86_64 | amd64) goarch=amd64 ;;
    *) fail "unsupported host architecture $(uname -m)" ;;
esac

archive="${DIST}/ipscout_${goos}_${goarch}.tar.gz"
[ -f "$archive" ] || fail "no archive at $archive; run goreleaser first"

# explicit templates: some mktemp implementations require one
work="$(mktemp -d "${TMPDIR:-/tmp}/ipscout-smoke-work.XXXXXX")"
home="$(mktemp -d "${TMPDIR:-/tmp}/ipscout-smoke-home.XXXXXX")"
trap 'rm -rf "$work" "$home"' EXIT

tar xzf "$archive" -C "$work" || fail "could not extract $archive"

bin="${work}/ipscout"
[ -x "$bin" ] || fail "no executable ipscout inside $archive"

pass "extracted $(basename "$archive")"

# Run from a directory with no go.mod above it, so anything resolved relative
# to the source tree fails here rather than in a user's hands.
cd "$work"
export HOME="$home"

# 1. the binary runs and is stamped with a version
version_output="$("$bin" Version 2>&1)" || fail "ipscout Version exited non-zero: ${version_output}"
case "$version_output" in
    *IPScout*) ;;
    *) fail "unexpected version output: ${version_output}" ;;
esac
pass "reports version: ${version_output}"

# 2. --help works, so the command tree is wired
"$bin" --help >/dev/null 2>&1 || fail "ipscout --help exited non-zero"
pass "help output"

# 3. test data resolves outside the source tree.
#
# This is the regression that shipped in 0.9.0: the providers resolved their
# test data relative to the directory containing go.mod, so every provider
# silently returned no result for an installed binary. It passed every unit
# test, because the tests run inside the repository.
utd="$("$bin" 8.8.8.8 --use-test-data 2>&1)" || fail "--use-test-data exited non-zero"
case "$utd" in
    *"no results found"*) fail "--use-test-data returned no results; test data is not reachable outside the source tree" ;;
esac
tables="$(printf '%s\n' "$utd" | grep -c '| Host:' || true)"
[ "$tables" -gt 0 ] || fail "--use-test-data rendered no provider tables"
[ "$tables" -eq "$EXPECTED_TABLES" ] || fail "--use-test-data rendered ${tables} provider tables, expected ${EXPECTED_TABLES}. If you added or removed a provider, update EXPECTED_TABLES in this script; otherwise a provider has silently stopped rendering"
pass "--use-test-data rendered ${tables} provider tables"

# 4. first run seeds a config, and it uses the keys the reader looks up.
#
# 0.9.0 shipped rating.use-ai and rating.openai-api-key while the reader
# looked up use_ai and openai_api_key, so enabling AI rating did nothing.
# The reader now falls back to the old names, but the seeded config should
# still ship the canonical ones.
config="${home}/.config/ipscout/config.yaml"
[ -f "$config" ] || fail "first run did not create ${config}"
pass "seeded config at ~/.config/ipscout/config.yaml"

for key in "use_ai:" "openai_api_key:" "config_path:"; do
    grep -q "  ${key}" "$config" || fail "seeded config is missing the ${key} key"
done

# the reader still accepts these as a fallback for config files written
# before the keys were corrected, so shipping them is stale rather than
# broken; the seeded config should use the canonical names
for stale in "use-ai:" "openai-api-key:"; do
    if grep -q "  ${stale}" "$config"; then
        fail "seeded config ships the deprecated ${stale} key, which is only read as a fallback for older config files"
    fi
done
pass "seeded config uses the canonical rating keys"

echo "smoke: all checks passed against the packaged binary"
