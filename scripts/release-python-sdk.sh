#!/usr/bin/env bash
# Release the cogos Python SDK to PyPI.
#
# Flow:
#   1) Run the SDK's own tests (pytest). Exit on failure.
#   2) Bump the version per --patch or --minor flag (or --version=X.Y.Z).
#      Keeps pyproject.toml [project].version and cogos/__init__.py
#      __version__ in sync.
#   3) Build the sdist + wheel (python -m build).
#   4) Show a dry-run summary and wait for explicit `y` on stdin.
#   5) Publish (twine upload dist/*).
#   6) Tag the git commit `sdk-py-vX.Y.Z`.
#   7) Print the `git push` command — DO NOT auto-push.
#
# Required env: PYPI_TOKEN (a __token__-style PyPI API token).
# Optional env: PYTHON (path to python interpreter; default `python3`).
#
# Usage:
#   PYPI_TOKEN=pypi-XXXX scripts/release-python-sdk.sh --patch
#   PYPI_TOKEN=pypi-XXXX scripts/release-python-sdk.sh --minor
#   PYPI_TOKEN=pypi-XXXX scripts/release-python-sdk.sh --version=0.2.3
#
# Hard constraints:
#   - Never reads .env or any other secrets file.
#   - Never force-pushes anything.
#   - Never pushes the git tag — operator does that explicitly.
#   - Bails out at the first failure (set -euo pipefail).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="${REPO_ROOT}/sdks/python"
PYPROJECT="${SDK_DIR}/pyproject.toml"
INIT_PY="${SDK_DIR}/cogos/__init__.py"
PYTHON_BIN="${PYTHON:-python3}"

err() { echo "[release-python-sdk] ERROR: $*" >&2; exit 1; }
log() { echo "[release-python-sdk] $*"; }

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
[ -d "$SDK_DIR" ]       || err "sdk dir not found: $SDK_DIR"
[ -f "$PYPROJECT" ]     || err "pyproject.toml not found: $PYPROJECT"
[ -f "$INIT_PY" ]       || err "cogos/__init__.py not found: $INIT_PY"
[ -n "${PYPI_TOKEN:-}" ] || err "PYPI_TOKEN env var is required (generate at https://pypi.org/manage/account/token/)"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || err "python interpreter not found: $PYTHON_BIN"
command -v git           >/dev/null 2>&1 || err "git not found on PATH"

# Clean working tree check — releasing dirty state is a footgun.
if [ -n "$(git -C "$REPO_ROOT" status --porcelain "$SDK_DIR")" ]; then
  err "working tree under $SDK_DIR is dirty; commit or stash before releasing"
fi

# ---- current version ----
CURRENT_VERSION=$(grep -E '^version[[:space:]]*=' "$PYPROJECT" | head -1 | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')
[ -n "$CURRENT_VERSION" ] || err "could not parse current version from $PYPROJECT"
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
# Loose semver-ish validation.
echo "$NEXT_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([abrc0-9.+-]*)?$' \
  || err "next version is not semver-ish: $NEXT_VERSION"
log "next version:    ${NEXT_VERSION}"

TAG="sdk-py-v${NEXT_VERSION}"
if git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  err "git tag ${TAG} already exists — pick a different version"
fi

# ---- run tests BEFORE bumping anything ----
log "running pytest in $SDK_DIR..."
(
  cd "$SDK_DIR"
  "$PYTHON_BIN" -m pytest -q
) || err "pytest failed; aborting release"
log "pytest passed."

# ---- dry-run summary BEFORE destructive ops ----
echo ""
echo "============================================================"
echo " DRY-RUN SUMMARY — review before confirming"
echo "============================================================"
echo " package:       cogos  (PyPI)"
echo " current:       ${CURRENT_VERSION}"
echo " next:          ${NEXT_VERSION}"
echo " bump:          ${BUMP:-explicit (${EXPLICIT_VERSION})}"
echo " files to edit:"
echo "   - ${PYPROJECT}"
echo "   - ${INIT_PY}"
echo " build cmd:     ${PYTHON_BIN} -m build"
echo " publish cmd:   twine upload dist/cogos-${NEXT_VERSION}*"
echo " git tag:       ${TAG}  (NOT auto-pushed)"
echo "============================================================"
echo ""
printf "Proceed with bump + build + publish + tag? Type 'y' to confirm: "
read -r CONFIRM
[ "$CONFIRM" = "y" ] || err "aborted by operator (got '$CONFIRM', expected 'y')"

# ---- bump versions ----
log "bumping version in $PYPROJECT..."
# Match the first `version = "..."` under [project]. We use a portable
# sed invocation (BSD + GNU compatible) — a temp file then mv.
TMP="${PYPROJECT}.tmp"
awk -v new="$NEXT_VERSION" '
  BEGIN { done = 0 }
  /^version[[:space:]]*=/ && !done { sub(/"[^"]+"/, "\"" new "\""); done = 1 }
  { print }
' "$PYPROJECT" > "$TMP"
mv "$TMP" "$PYPROJECT"

log "bumping __version__ in $INIT_PY..."
TMP="${INIT_PY}.tmp"
awk -v new="$NEXT_VERSION" '
  /^__version__[[:space:]]*=/ { sub(/"[^"]+"/, "\"" new "\""); }
  { print }
' "$INIT_PY" > "$TMP"
mv "$TMP" "$INIT_PY"

# Sanity-check both files now report the same new version.
PY_VER=$(grep -E '^version[[:space:]]*=' "$PYPROJECT" | head -1 | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')
INIT_VER=$(grep -E '^__version__[[:space:]]*=' "$INIT_PY" | head -1 | sed -E 's/^__version__[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')
[ "$PY_VER"   = "$NEXT_VERSION" ] || err "pyproject.toml did not update to $NEXT_VERSION (got: $PY_VER)"
[ "$INIT_VER" = "$NEXT_VERSION" ] || err "cogos/__init__.py did not update to $NEXT_VERSION (got: $INIT_VER)"
log "version files synced at ${NEXT_VERSION}."

# ---- build ----
log "cleaning previous dist/ + build/..."
rm -rf "$SDK_DIR/dist" "$SDK_DIR/build" "$SDK_DIR"/cogos.egg-info

log "building sdist + wheel..."
(
  cd "$SDK_DIR"
  "$PYTHON_BIN" -m build
) || err "python -m build failed"

ARTIFACTS=$(ls "$SDK_DIR"/dist/ 2>/dev/null || true)
[ -n "$ARTIFACTS" ] || err "no build artifacts in $SDK_DIR/dist/"
log "build artifacts:"
echo "$ARTIFACTS" | sed 's/^/    /'

# ---- commit version bump ----
log "committing version bump..."
git -C "$REPO_ROOT" add "$PYPROJECT" "$INIT_PY"
git -C "$REPO_ROOT" commit -m "release(sdk-py): cogos v${NEXT_VERSION}"

# ---- publish ----
log "uploading to PyPI via twine..."
(
  cd "$SDK_DIR"
  TWINE_USERNAME="__token__" \
  TWINE_PASSWORD="$PYPI_TOKEN" \
    "$PYTHON_BIN" -m twine upload dist/*
) || err "twine upload failed (release commit is local, no tag yet — fix + retry)"
log "published cogos ${NEXT_VERSION} to PyPI."

# ---- tag ----
git -C "$REPO_ROOT" tag -a "$TAG" -m "cogos python SDK ${NEXT_VERSION}"
log "tagged ${TAG} locally."

# ---- next steps ----
echo ""
echo "============================================================"
echo " DONE — cogos ${NEXT_VERSION} is on PyPI."
echo "============================================================"
echo " Next, push the commit + tag yourself (NOT auto-pushed):"
echo ""
echo "   git push origin HEAD"
echo "   git push origin ${TAG}"
echo ""
echo " Verify: https://pypi.org/project/cogos/${NEXT_VERSION}/"
echo "============================================================"
