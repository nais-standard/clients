# Contributing to the NAIS SDKs

This monorepo holds three SDKs — `js/` (npm `@nais-standard/sdk`), `python/` (PyPI
`nais-sdk`, import `nais_sdk`), and `php/` (Packagist `nais-standard/sdk`) — plus a shared
conformance suite that guarantees they agree byte-for-byte on canonicalization
and signature verification.

## Golden rule

The three implementations of `canonicalize` and `verifyCard` **must stay in
lockstep**. A divergence is a security bug: a tampered card could verify in one
language and fail in another. Any change to canonicalization or verification
must keep all three conformance runners green.

## Local development

```bash
# Run the shared conformance vectors against each SDK:
node   conformance/run.cjs     # JavaScript (Node 18+)
python conformance/run.py      # Python (pip install cryptography)
php    conformance/run.php     # PHP (ext-sodium)
```

If you change the signing scheme or the demo card, regenerate the vectors and
commit them:

```bash
php conformance/make-vectors.php
```

CI (`.github/workflows/ci.yml`) runs all three runners plus a check that the
committed vectors are fresh.

### MCP gateway

The `@nais-standard/mcp` local gateway is a thin layer over `@nais-standard/sdk` and lives in its
own repository, [`nais-standard/mcp`](https://github.com/nais-standard/mcp).
Keep verification in the SDK, not in the gateway. When the SDK's `resolve()` /
`verifyCard()` surface changes, update the gateway repo in step.

## Versioning

The SDK **major** version tracks the NAIS spec major (NAIS 1.x → SDK 1.x).
Minor/patch move independently per language. Tag releases as `js-vX.Y.Z`,
`py-vX.Y.Z`, `php-vX.Y.Z`.

## Release runbook

Releases are **manual** via `.github/workflows/release.yml`
(`workflow_dispatch`). Publishing is gated behind the repo variable
`PUBLISH_ENABLED` — until it is `"true"`, every job runs in dry-run mode.

### One-time setup

1. Claim the namespaces: `@nais-standard` org on npm, `nais-standard` vendor on Packagist.
2. Create the PHP mirror repo `nais-standard/nais-php` (Packagist installs from
   it because Composer can't install a subdirectory). Add a deploy key with
   write access.
3. Add repository secrets: `NPM_TOKEN`, `PYPI_API_TOKEN`, `PHP_SPLIT_DEPLOY_KEY`.
4. Point Packagist at `nais-standard/nais-php` and enable its webhook.

### Cutting a release

1. Bump the version (npm `version` field, `pyproject.toml`, or git tag for PHP)
   and update the relevant `CHANGELOG`.
2. Confirm `PUBLISH_ENABLED` is set correctly:
   - leave unset/`false` for a dry run (recommended first pass),
   - set `"true"` to actually publish.
3. Actions → **Release** → choose the package and version → run.
   - **js** → `npm publish` from `js/`.
   - **python** → `python -m build` + `twine upload` from `python/`.
   - **php** → `splitsh-lite --prefix=php` produces a single-package tree, which
     is force-pushed and tagged on the mirror; Packagist picks up the tag.

> `@nais-standard/mcp` is released from its own repo (`nais-standard/mcp`), **after**
> `@nais-standard/sdk` is on npm (it depends on it).

### Reserving names without releasing

Run the workflow with `PUBLISH_ENABLED` unset to verify the build and packaging
end to end (dry run) before any real upload.
