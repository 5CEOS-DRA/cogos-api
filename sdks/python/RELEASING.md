# Releasing the cogos Python SDK

One-page operator guide for cutting a `cogos` release on PyPI.

## One-time setup

1. **Create a PyPI account** at <https://pypi.org/account/register/> and
   enable 2FA. The account that owns the `cogos` project must add you as
   a maintainer before your first publish.
2. **Generate an API token** at
   <https://pypi.org/manage/account/token/>. Scope it to the `cogos`
   project (NOT account-wide) the first time you can — account-wide is
   the bootstrap option only, until the project exists.
3. **Install build + upload tools** into the Python environment you use
   for releases:

   ```
   python3 -m pip install --upgrade build twine
   ```

4. **DO NOT** put the token in `~/.pypirc` or any committed file. The
   release script reads it from the `PYPI_TOKEN` env var per
   invocation and nowhere else.

## Cutting a release

From the repo root, with a clean working tree on `main`:

```
PYPI_TOKEN=pypi-AgENdGV... scripts/release-python-sdk.sh --patch
```

Flags:

- `--patch` — bumps `X.Y.Z` → `X.Y.(Z+1)` (bug fix only)
- `--minor` — bumps `X.Y.Z` → `X.(Y+1).0` (new feature, no break)
- `--version=X.Y.Z` — set an explicit version (for `0.x` jumps, RCs,
  whatever the moment calls for)

What the script does:

1. Runs `pytest` in `sdks/python/` and exits on any failure.
2. Prints a dry-run summary (current → next version, files to edit,
   commands to run) and waits for you to type `y` on stdin.
3. Bumps `pyproject.toml [project].version` AND
   `cogos/__init__.py __version__` together — keeping them in sync is
   load-bearing (one without the other ships a wrong `__version__`
   attribute).
4. Builds `dist/cogos-X.Y.Z.tar.gz` and `dist/cogos-X.Y.Z-py3-none-any.whl`.
5. Commits the version bump as `release(sdk-py): cogos vX.Y.Z`.
6. Uploads to PyPI via `twine` using `__token__` + your `PYPI_TOKEN`.
7. Creates a local-only git tag `sdk-py-vX.Y.Z`.
8. **Does NOT push.** Prints the `git push` commands for you to run.

## After the script finishes

```
git push origin HEAD
git push origin sdk-py-vX.Y.Z
```

Then verify:

- `pip install cogos==X.Y.Z` in a fresh venv resolves and imports.
- `https://pypi.org/project/cogos/X.Y.Z/` renders the README.

## If something fails

The script bails out early — before publish — on a dirty working tree,
test failure, version-collision tag, or build error. None of those
states leave you in a half-released world.

If `twine upload` itself fails (network blip, token expired, name
collision), the local version-bump commit exists but no tag and no
PyPI artifact. Fix the upstream issue and re-run the script with the
SAME `--version=X.Y.Z` — it will skip the bump (versions already
match) only if you patch the script... in practice, just `git reset
--soft HEAD~1` to undo the bump commit, then re-run.

## First release

This is currently `0.1.0`. The first publish (`scripts/release-python-sdk.sh
--patch` → `0.1.1`) will also be the first time PyPI sees the package
name `cogos`. Confirm the name isn't squatted before your first publish:

```
pip install cogos 2>&1 | head -5
```

If it returns a different project, escalate to PyPI support before
running the release script — `twine` will refuse to publish to a name
you don't own.
