# Changelog

All notable changes to `@nais-standard/sdk` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/); the major version tracks the NAIS
spec major (NAIS 1.x → SDK 1.x).

## [1.0.1]

### Added
- `validate(domain)` now surfaces `linkedAgents` — advisory pointers to related
  agents, each `{ domain, relation, verified, name }`. A link confers no trust:
  every linked domain must be resolved and verified independently. Added the
  `LinkedAgentSummary` type to the TypeScript declarations.

## [1.0.0]

Initial release, implementing NAIS 1.0.

### Added
- Decentralized resolution: `resolve(domain)` reads the `_agent.<domain>` DNS
  TXT record with the native `dns` module, fetches the signed card over HTTPS
  (HTTPS-only, no cross-host redirects, 1 MiB cap, timeout-bounded), and verifies
  the card's signature locally. No hosted resolver in the trust or availability
  path.
- Mandatory signature verification: `verifyCard(card, dnsKey)` checks the
  detached EdDSA (Ed25519) JWS over the canonical card body and enforces that
  `signature.kid` equals the DNS `k=` key.
- `canonicalize(value)` — the RFC 8785-subset canonical JSON used as the JWS
  payload.
- `validate(domain)` — flattened summary; `payTo` is surfaced only when the
  signature verifies. `valid` requires resolution, schema validation, and a
  verified signature.
- Injectable `lookupTxt` / `fetchCard` for offline testing.
- TypeScript declarations (`index.d.ts`).

### Requirements
- Node.js 18+ (uses built-in `dns`, `fetch`, `crypto`). No third-party
  dependencies. Server-side only.
