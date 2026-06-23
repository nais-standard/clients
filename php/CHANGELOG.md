# Changelog

All notable changes to `nais-standard/sdk` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/); the major version tracks the NAIS
spec major (NAIS 1.x → SDK 1.x).

## [1.0.1]

### Added
- `Resolver::validate($domain)` now surfaces `linked_agents` — advisory pointers
  to related agents, each `{ domain, relation, verified, name }`. A link confers
  no trust: every linked domain must be resolved and verified independently.

## [1.0.0]

Initial release, implementing NAIS 1.0.

### Added
- Decentralized resolution: `Resolver::resolve($domain)` reads the
  `_agent.<domain>` DNS TXT record via `dns_get_record`, fetches the signed card
  over HTTPS (HTTPS-only, no cross-host redirects, 1 MiB cap, full TLS
  verification), and verifies the card's signature locally. No hosted resolver
  in the trust or availability path.
- Mandatory signature verification: `Resolver::verifyCard($card, $dnsKey)`
  checks the detached EdDSA (Ed25519) JWS over the canonical card body and
  enforces that `signature.kid` equals the DNS `k=` key.
- `Resolver::canonicalize($value)` — the RFC 8785-subset canonical JSON used as
  the JWS payload.
- `Resolver::validate($domain)` — flattened summary; `pay_to` is surfaced only
  when the signature verifies. `valid` requires resolution, schema validation,
  and a verified signature.
- Injectable `lookupTxt` / `fetchCard` via the constructor for offline testing.

### Requirements
- PHP 7.4+ with `ext-curl` and `ext-sodium`. No third-party Composer
  dependencies. Server-side only.
