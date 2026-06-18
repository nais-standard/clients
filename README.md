# NAIS Clients (SDKs)

Official SDK implementations for resolving and validating NAIS agent identities.

Each SDK resolves agent domains **directly via DNS** — it reads the `_agent.<domain>` TXT record, fetches the signed card over HTTPS, and verifies the card's Ed25519 signature against the DNS `k=` key. There is no central resolver in the trust or availability path. These SDKs are **server-side only**: they need real DNS access and crypto primitives, which browsers cannot provide.

## Available SDKs

| Language | Directory | Package | Requirements |
|----------|-----------|---------|--------------|
| JavaScript/TypeScript | `js/` | `@nais-standard/sdk` | Node.js 18+ (built-in `dns`, `fetch`, `crypto`; no third-party deps) |
| Python | `python/` | `nais-sdk` (import `nais_sdk`) | Python 3.8+ (`dnspython` for DNS, `cryptography` for signatures; PyNaCl also supported) |
| PHP | `php/` | `nais-standard/sdk` | PHP 7.4+ (built-in `dns_get_record`, `ext-curl`, `ext-sodium`; no third-party deps) |

## Quick Examples

### JavaScript

```js
const { resolve, validate } = require('@nais-standard/sdk');

const r = await resolve('weatheragent.nais.id');
if (r.signature.verified) console.log(r.card.mcp);

const result = await validate('weatheragent.nais.id');
console.log(result.signatureVerified, result.tags, result.payTo);
```

### Python

```python
from nais_sdk import resolve, validate

r = resolve("weatheragent.nais.id")
if r["signature"]["verified"]:
    print(r["card"]["mcp"])

result = validate("weatheragent.nais.id")
print(result["signature_verified"], result["tags"], result["pay_to"])
```

### PHP

```php
use Nais\Resolver;

$r = (new Resolver())->resolve('weatheragent.nais.id');
if ($r['signature']['verified']) {
    echo $r['card']['mcp'];
}

$result = (new Resolver())->validate('weatheragent.nais.id');
echo $result['signature_verified'];
```

## Structure

This is a **monorepo**: one development repo holds all three SDKs plus a shared
conformance suite, so cross-language signature/canonicalization agreement is
proven by one CI run. Each language directory is an independently publishable
package.

```
js/      → npm:       @nais-standard/sdk   (dual ESM/CJS)
python/  → PyPI:      nais-sdk             (import: nais_sdk)
php/     → Packagist: nais-standard/sdk
```

A shared `conformance/` suite verifies that all three agree byte-for-byte on
canonicalization and signature verification.

## MCP gateway

For AI agents, the SDKs are wrapped by a **local MCP gateway** (`@nais-standard/mcp`) that
lets any MCP-capable client discover, verify, and call NAIS agents by domain:

```bash
claude mcp add nais -- npx -y @nais-standard/mcp
```

It lives in its own repository, [`nais-standard/mcp`](https://github.com/nais-standard/mcp),
and depends on `@nais-standard/sdk`.

## API

Each SDK provides two main functions plus two signature helpers.

### `resolve(domain)`

Resolves a domain directly via DNS and HTTPS, then returns a structured result object:

- `ok` — overall success flag.
- `domain` — the normalized domain.
- `agent_host` (JS: `agentHost`) — the host serving the card.
- `dns` — `{ records, parsed }`, where `parsed` exposes `v`, `manifest`, and `k`.
- `manifest_url` (JS: `manifestUrl`) — the URL the card was fetched from.
- `card` — the decoded `agent.json`.
- `signature` — `{ present, verified, kid, alg, reason }`.
- `validation` — `{ valid, errors, warnings }`.

`resolve()` throws on an invalid domain, when no NAIS TXT record is found, or when the card fetch fails. It does **not** throw on a bad signature — that surfaces as `signature.verified === false` and `validation.valid === false`.

### `validate(domain)`

Returns a flattened validation summary — useful for quick checks. Fields (JS camelCase / Python+PHP snake_case): `valid`, `domain`, `version`, `manifestUrl`/`manifest_url`, `mcpEndpoint`/`mcp_endpoint`, `hasMcp`/`has_mcp`, `hasCard`/`has_card`, `signatureVerified`/`signature_verified`, `signatureReason`/`signature_reason`, `key` (the DNS `k=` value), `kid`, `auth` (array of scheme names), `payments` (e.g. `["x402"]`), `payTo`/`pay_to` (only populated when the signature verifies), `tags`, `warnings`, `errors`.

`valid` is true only when the card resolved, passed validation, **and** the signature verified.

### Signature helpers

Each SDK exports a card-verification helper and a canonicalizer (plus DNS/domain parsing helpers):

- JS: `verifyCard(card, dnsKey)`, `canonicalize(value)`, `parseNaisTxt`, `normalizeDomain`.
- Python: `verify_card(card, dns_key)`, `canonicalize(value)`, `parse_nais_txt`, `normalize_domain`.
- PHP: `\Nais\Resolver::verifyCard($card, $dnsKey)`, `\Nais\Resolver::canonicalize($value)`, `\Nais\Resolver::normalizeDomain`, `\Nais\Resolver::parseNaisTxt`.

### Testing without DNS or network

`resolve()` and `validate()` accept injected `lookupTxt`/`fetchCard` overrides so resolution can be tested offline. JS takes an options object, Python takes `lookup_txt`/`fetch_card` kwargs, and PHP takes them via the constructor: `new Resolver(['lookupTxt' => ..., 'fetchCard' => ...])`.

## Trust model

Every card carries a mandatory detached Ed25519 JWS over its canonical body. The signing key's fingerprint lives in DNS (`k=`), and `signature.kid` must match it. A web-server compromise alone cannot forge a card or swap the `payTo` address — that requires both the DNS zone and the private key. Never use `payTo` from an unverified card: x402 payments are irreversible.

## Related

- [spec](https://github.com/nais-standard/spec) — Protocol specification
- [examples](https://github.com/nais-standard/examples) — Demo agents to test against
