# @nais-standard/sdk

JavaScript/Node.js SDK for the [Network Agent Identity Standard (NAIS)](https://nais.id).

Resolve and validate NAIS-compliant agent domains. Requires Node.js 18+ and uses only built-in modules (`dns`, `fetch`, `crypto`) — no third-party dependencies. The SDK resolves directly: it reads the `_agent.<domain>` DNS TXT record, fetches the signed card over HTTPS (HTTPS-only, no cross-host redirects, 1 MiB cap), and verifies the card's mandatory Ed25519 signature against the DNS `k=` key. Server-side only — browsers cannot perform DNS lookups.

## Installation

```bash
npm install @nais-standard/sdk
```

The package ships both ESM and CommonJS entry points, so either import style works:

```javascript
import { resolve, validate, verifyCard } from '@nais-standard/sdk'; // ESM
const { resolve, validate, verifyCard } = require('@nais-standard/sdk'); // CommonJS
```

## Usage

### resolve(domain)

Resolves a domain directly via DNS and HTTPS and returns a structured result object:

- `ok` — overall success flag.
- `domain` — the normalized domain.
- `agentHost` — the host serving the card.
- `dns` — `{ records, parsed }`, where `parsed` exposes `v`, `manifest`, and `k`.
- `manifestUrl` — the URL the card was fetched from.
- `card` — the decoded `agent.json`.
- `signature` — `{ present, verified, kid, alg, reason }`.
- `validation` — `{ valid, errors, warnings }`.

```javascript
const { resolve } = require('@nais-standard/sdk');

const r = await resolve('weatheragent.nais.id');
if (r.signature.verified) console.log(r.card.mcp);
// https://weatheragent.nais.id/mcp

console.log(r.dns.parsed.k);
// ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ
```

`resolve()` throws on an invalid domain, when no NAIS TXT record is found, or when the card fetch fails. It does **not** throw on a bad signature — that surfaces as `signature.verified === false` and `validation.valid === false`.

### validate(domain)

Returns a flattened summary object with a single `valid` boolean and all key fields normalized. Ideal for quick checks before calling an agent.

```javascript
const { validate } = require('@nais-standard/sdk');

const summary = await validate('weatheragent.nais.id');
console.log(summary);
```

Example output:

```json
{
  "valid": true,
  "domain": "weatheragent.nais.id",
  "version": "nais1",
  "manifestUrl": "https://weatheragent.nais.id/.well-known/agent.json",
  "mcpEndpoint": "https://weatheragent.nais.id/mcp",
  "hasMcp": true,
  "hasCard": true,
  "signatureVerified": true,
  "signatureReason": null,
  "key": "ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ",
  "kid": "ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ",
  "auth": ["wallet"],
  "payments": ["x402"],
  "payTo": ["0x742d35Cc6634C0532925a3b8D4C9B7F1A2e3d4E5"],
  "tags": ["forecast", "current_weather", "alerts"],
  "linkedAgents": [
    { "domain": "alerts.weatheragent.nais.id", "relation": "partner", "verified": true, "name": "Severe Weather Alerts" }
  ],
  "warnings": [],
  "errors": []
}
```

`valid` is `true` only when the card resolved, the schema validates, **and** the signature verifies.

```javascript
const { validate } = require('@nais-standard/sdk');

const summary = await validate('weatheragent.nais.id');
if (summary.signatureVerified) {
  console.log(summary.tags);  // ['forecast', 'current_weather', 'alerts']
  console.log(summary.payTo); // payTo only populated for verified cards
}
```

### verifyCard / canonicalize

The SDK also exports `verifyCard(card, dnsKey)` and `canonicalize(value)` for verifying a card you already hold against a DNS `k=` key. It also exports `parseNaisTxt` and `normalizeDomain`.

```javascript
const { verifyCard, canonicalize } = require('@nais-standard/sdk');

const result = verifyCard(card, 'ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ');
console.log(result.verified, result.reason);
```

### Error handling

```javascript
const { resolve, NaisResolutionError } = require('@nais-standard/sdk');

try {
  const result = await resolve('not-a-real-agent.example.com');
} catch (err) {
  if (err instanceof NaisResolutionError) {
    console.error(`Resolution failed for ${err.domain}: ${err.message}`);
  }
}
```

### Testing without DNS or network

`resolve()` and `validate()` accept an options object with injected `lookupTxt` and `fetchCard` functions, so resolution can be tested offline:

```javascript
const r = await resolve('weatheragent.nais.id', {
  lookupTxt: async (name) => ['v=nais1; manifest=https://weatheragent.nais.id/.well-known/agent.json; k=ed25519:...'],
  fetchCard: async (url) => ({ /* decoded agent.json */ }),
});
```

## Notes

- Requires Node.js 18+ for the built-in `dns`, `fetch`, and `crypto` modules. No third-party dependencies.
- Resolution is performed locally and directly: DNS TXT lookup, HTTPS card fetch, and Ed25519 signature verification all happen in-process. There is no central resolver.
- The card fetch is HTTPS-only, refuses cross-host redirects, and caps responses at 1 MiB.
- Server-side only: browsers cannot perform DNS lookups.

## License

MIT
