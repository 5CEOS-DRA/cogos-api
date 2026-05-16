#!/usr/bin/env bash
# Release the cogos Node SDK to npm.
#
# Flow:
#   1) Run the SDK's own tests (npm test). Exit on failure.
#   2) Bump the version per --patch or --minor flag (or --version=X.Y.Z).
#      Uses `npm version --no-git-tag-version` so package.json +
#      package-lock.json stay in sync without npm creating its own tag.
#   3) Build (npm run build).
#   4) Show a dry-run summary and wait for explicit `y` on stdin.
#   5) Publish (npm publish --access public).
#   6) Tag the git commit `sdk-node-vX.Y.Z`.
#   7) Print the `git push` command — DO NOT auto-push.
#
# Required env: NPM_TOKEN (an npm automation token with publish rights).
#
# Usage:
#   NPM_TOKEN=npm_XXXX scripts/release-node-sdk.sh --patch
#   NPM_TOKEN=npm_XXXX scripts/release-node-sdk.sh --minor
#   NPM_TOKEN=npm_XXXX scripts/release-node-sdk.sh --version=0.2.3
#
# Hard constraints:
#   - Never reads .env or any other secrets file.
#   - Never force-pushes anything.
#   - Never pushes the git tag — operator does that explicitly.
#   - Bails out at the first failure (set -euo pipefail).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="${REPO_ROOT}/sdks/node"
PKG_JSON="${SDK_DIR}/package.json"

err() { echo "[release-node-sdk] ERROR: $*" >&2; exit 1; }
log() { echo "[release-node-sdk] $*"; }

# ---- arg parse ----
BUMP=""
EXPLICIT_VERSION=""
for arg in "$@"; do
  case "$arg" in
    --patch) BUMP="patch" ;;
    --minor) BUMP="minor" ;;
    --version=*) EXPLICIT_VERSION="${arg#--version=}" ;;
    *) err "unknown arg: $arg (use --patch | --minor | --version=X.Y.Z)" ;;
  esac
done
if [ -z "$BUMP" ] && [ -z "$EXPLICIT_VERSION" ]; then
  err "must pass --patch | --minor | --version=X.Y.Z"
fi
if [ -n "$BUMP" ] && [ -n "$EXPLICIT_VERSION" ]; then
  err "pass --patch OR --minor OR --version=, not multiple"
fi

# ---- preflight ----
[ -d "$SDK_DIR" ]      || err "sdk dir not found: $SDK_DIR"
[ -f "$PKG_JSON" ]     || err "package.json not found: $PKG_JSON"
[ -n "${NPM_TOKEN:-}" ] || err "NPM_TOKEN env var is required (generate at https://www.npmjs.com/settings/~/tokens with Automation scope)"

command -v node >/dev/null 2>&1 || err "node not found on PATH"
command -v npm  >/dev/null 2>&1 || err "npm not found on PATH"
command -v git  >/dev/null 2>&1 || err "git not found on PATH"

# Clean working tree check.
if [ -n "$(git -C "$REPO_ROOT" status --porcelain "$SDK_DIR")" ]; then
  err "working tree under $SDK_DIR is dirty; commit or stash before releasing"
fi

# ---- current version (read via node, robust to formatting) ----
CURRENT_VERSION=$(node -p "require('$PKG_JSON').version")
[ -n "$CURRENT_VERSION" ] || err "could not read .version from $PKG_JSON"
log "current version: ${CURRENT_VERSION}"

# ---- compute next version ----
if [ -n "$EXPLICIT_VERSION" ]; then
  NEXT_VERSION="$EXPLICIT_VERSION"
else
  IFS='.' read -r MAJ MIN PAT <<<"$CURRENT_VERSION"
  case "$BUMP" in
    patch) NEXT_VERSION="${MAJ}.${MIN}.$((PAT + 1))" ;;
    minor) NEXT_VERSION="${MAJ}.$((MIN + 1)).0" ;;
  esac
fi
echo "$NEXT_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([abrc0-9.+-]*)?$' \
  || err "next version is not semver-ish: $NEXT_VERSION"
log "next version:    ${NEXT_VERSION}"

TAG="sdk-node-v${NEXT_VERSION}"
if git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  err "git tag ${TAG} already exists — pick a different version"
fi

# ---- run tests BEFORE bumping anything ----
log "running npm test in $SDK_DIR..."
(
  cd "$SDK_DIR"
  npm test
) || err "npm test failed; aborting release"
log "npm test passed."

# ---- dry-run summary BEFORE destructive ops ----
echo ""
echo "============================================================"
echo " DRY-RUN SUMMARY — review before confirming"
echo "============================================================"
echo " package:       cogos  (npm)"
echo " current:       ${CURRENT_VERSION}"
echo " next:          ${NEXT_VERSION}"
echo " bump:          ${BUMP:-explicit (${EXPLICIT_VERSION})}"
echo " file to edit:  ${PKG_JSON} (+ package-lock.json)"
echo " build cmd:     npm run build"
echo " publish cmd:   npm publish --access public"
echo " git tag:       ${TAG}  (NOT auto-pushed)"
echo "============================================================"
echo ""
printf "Proceed with bump + build + publish + tag? Type 'y' to confirm: "
read -r CONFIRM
[ "$CONFIRM" = "y" ] || err "aborted by operator (got '$CONFIRM', expected 'y')"

# ---- bump version ----
# --no-git-tag-version: we'll create our own tag with our own naming
# scheme after publish succeeds. --allow-same-version: no.
log "bumping package.json version..."
(
  cd "$SDK_DIR"
  npm version "$NEXT_VERSION" --no-git-tag-version --allow-same-version=false >/dev/null
)
NEW_PKG_VERSION=$(node -p "require('$PKG_JSON').version")
[ "$NEW_PKG_VERSION" = "$NEXT_VERSION" ] || err "package.json did not update to $NEXT_VERSION (got: $NEW_PKG_VERSION)"
log "package.json synced at ${NEXT_VERSION}."

# ---- build ----
log "cleaning previous dist/ + dist-test/..."
rm -rf "$SDK_DIR/dist" "$SDK_DIR/dist-test"

log "building (npm run build)..."
(
  cd "$SDK_DIR"
  npm run build
) || err "npm run build failed"

[ -d "$SDK_DIR/dist" ] || err "build did not produce dist/"
log "build artifacts:"
ls "$SDK_DIR/dist/" | sed 's/^/    /'

# ---- commit version bump ----
log "committing version bump..."
# Stage package.json + package-lock.json if it changed.
git -C "$REPO_ROOT" add "$PKG_JSON"
if [ -f "$SDK_DIR/package-lock.json" ]; then
  git -C "$REPO_ROOT" add "$SDK_DIR/package-lock.json" || true
fi
git -C "$REPO_ROOT" commit -m "release(sdk-node): cogos v${NEXT_VERSION}"

# ---- publish ----
# Set the npm token in a per-invocation .npmrc so we don't touch the
# user's global ~/.npmrc.
NPMRC_TMP=$(mktemp -t cogos-npmrc.XXXXXX)
trap 'rm -f "$NPMRC_TMP"' EXIT
cat >"$NPMRC_TMP" <<NPMRC
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
registry=https://registry.npmjs.org/
NPMRC

log "publishing to npm..."
(
  cd "$SDK_DIR"
  npm publish --userconfig "$NPMRC_TMP" --access public
) || err "npm publish failed (release commit is local, no tag yet — fix + retry)"
log "published cogos ${NEXT_VERSION} to npm."

# ---- tag ----
git -C "$REPO_ROOT" tag -a "$TAG" -m "cogos node SDK ${NEXT_VERSION}"
log "tagged ${TAG} locally."

# ---- next steps ----
echo ""
echo "============================================================"
echo " DONE — cogos ${NEXT_VERSION} is on npm."
echo "============================================================"
echo " Next, push the commit + tag yourself (NOT auto-pushed):"
echo ""
echo "   git push origin HEAD"
echo "   git push origin ${TAG}"
echo ""
echo " Verify: https://www.npmjs.com/package/cogos/v/${NEXT_VERSION}"
echo "============================================================"
