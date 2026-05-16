# Releasing the cogos Node SDK

One-page operator guide for cutting a `cogos` release on npm.

## One-time setup

1. **Create an npm account** at <https://www.npmjs.com/signup> and
   enable 2FA (`auth-only`, not `auth-and-writes` — automation tokens
   would otherwise fail). The account that owns the `cogos` package
   must add you as a maintainer before your first publish.
2. **Generate an automation token** at
   <https://www.npmjs.com/settings/~/tokens>:
   - Type: **Automation** (bypasses 2FA — required for scripted publish).
   - Scope: read + publish on the `cogos` package once it exists, or
     a broad "publish new packages" scope for the very first release.
3. **Node + npm**: the SDK targets `engines.node >= 20`. The release
   script does not pin a version; whatever `node`/`npm` your shell has
   is what runs the build.
4. **DO NOT** write the token to `~/.npmrc` globally. The release
   script writes a *per-invocation* `.npmrc` to a tmp file from
   `NPM_TOKEN` and deletes it on exit. Your shared shell stays clean.

## Cutting a release

From the repo root, with a clean working tree on `main`:

```
NPM_TOKEN=npm_AbCdE... scripts/release-node-sdk.sh --patch
```

Flags:

- `--patch` — `X.Y.Z` → `X.Y.(Z+1)` (bug fix only)
- `--minor` — `X.Y.Z` → `X.(Y+1).0` (new feature, no break)
- `--version=X.Y.Z` — set an explicit version

What the script does:

1. Runs `npm test` in `sdks/node/` (which also runs `npm run build:test`)
   and exits on any failure.
2. Prints a dry-run summary and waits for you to type `y` on stdin.
3. Bumps `package.json` via `npm version --no-git-tag-version`
   (so npm doesn't create its own tag — we make our own with our own
   naming scheme).
4. Cleans `dist/` + `dist-test/` and runs `npm run build`.
5. Commits the version bump as `release(sdk-node): cogos vX.Y.Z`.
6. Publishes via `npm publish --access public` using the tmp `.npmrc`
   that carries `NPM_TOKEN`. `prepublishOnly` rebuilds + retests as a
   second safety belt.
7. Creates a local-only git tag `sdk-node-vX.Y.Z`.
8. **Does NOT push.** Prints the `git push` commands.

## After the script finishes

```
git push origin HEAD
git push origin sdk-node-vX.Y.Z
```

Then verify:

- `npm install cogos@X.Y.Z` in a fresh directory resolves the wheel.
- `https://www.npmjs.com/package/cogos/v/X.Y.Z` renders the README.

## If something fails

The script bails out early — before publish — on a dirty working tree,
test failure, version-collision tag, or build error. None of those
states leave you in a half-released world.

If `npm publish` itself fails (network blip, token expired, version
already on the registry), the local version-bump commit exists but no
tag and no npm artifact. To recover:

- Token / network issue: `git reset --soft HEAD~1` to undo the bump,
  fix the upstream cause, re-run the script.
- Version-already-on-registry: pick the next version with
  `--version=X.Y.(Z+1)` after `git reset --soft HEAD~1`.

`npm` does not allow overwriting a published version — even unpublished
versions stay reserved for 72 hours. Don't try to force it.

## First release

This is currently `0.1.0`. The first publish (`--patch` → `0.1.1`)
will also be the first time npm sees the package name `cogos`. Confirm
the name isn't squatted before your first publish:

```
npm view cogos 2>&1 | head -5
```

If it returns a different project's metadata, escalate to
<https://www.npmjs.com/support> before running the release script — npm
will refuse to publish to a name you don't own.
