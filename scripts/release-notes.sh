#!/usr/bin/env bash
#
# Print the changelog section for a release, for goreleaser --release-notes.
#
# Without this, the release body is goreleaser's generated commit list: bare
# subjects and 40 character SHAs. The maintained entry in docs/CHANGELOG.md
# says what actually changed and why, so it is the better thing to publish,
# and keeping one source avoids the two drifting apart.
#
# Fails rather than printing nothing. Empty release notes would publish
# silently and are hard to correct once people have seen them.
#
# Usage: scripts/release-notes.sh [version]
#
# Version defaults to the tag at HEAD, which is what goreleaser releases.

set -euo pipefail

CHANGELOG="docs/CHANGELOG.md"

die() {
  printf 'release-notes: %s\n' "$1" >&2
  exit 1
}

version="${1:-}"
if [ -z "$version" ]; then
  version="$(git tag --points-at HEAD | head -n 1)"
  [ -n "$version" ] || die "no tag at HEAD and no version argument; tag the release first"
fi

[ -f "$CHANGELOG" ] || die "$CHANGELOG not found; run from the repository root"

# Match "## [1.2.3]" literally rather than as a regex, so the dots in the
# version cannot match other characters.
notes="$(
  awk -v head="## [$version]" '
    index($0, head) == 1 { inside = 1; next }
    inside && index($0, "## [") == 1 { exit }
    inside { print }
  ' "$CHANGELOG"
)"

# Trim leading and trailing blank lines left by the section boundaries.
notes="$(printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')"

[ -n "$notes" ] || die "no changelog section for $version in $CHANGELOG; add one before releasing"

printf '%s\n' "$notes"
