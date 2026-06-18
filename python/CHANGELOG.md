# Changelog

All notable changes to `nais-sdk` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/); the major version tracks the NAIS
spec major (NAIS 1.x → SDK 1.x).

## [1.0.0]

Initial release, implementing NAIS 1.0.

### Added
- Decentralized resolution: `resolve(domain)` reads the `_agent.<domain>` DNS
  TXT record via `dnspython`, fetches the signed card over HTTPS (HTTPS-only, no
  cross-host redirects, 1 MiB cap), and verifies the card's signature locally.
  No hosted resolver in the trust or availability path.
- Mandatory signature verification: `verify_card(card, dns_key)` checks the
  detached EdDSA (Ed25519) JWS over the canonical card body and enforces that
  `signature.kid` equals the DNS `k=` key.
- `canonicalize(value)` — the RFC 8785-subset canonical JSON used as the JWS
  payload.
- `validate(domain)` — flattened summary; `pay_to` is surfaced only when the
  signature verifies. `valid` requires resolution, schema validation, and a
  verified signature.
- Injectable `lookup_txt` / `fetch_card` for offline testing.
- Type hints shipped (`py.typed`).

### Requirements
- Python 3.8+. Depends on `dnspython` (DNS) and `cryptography` (signatures;
  PyNaCl supported as an alternative). Server-side only.
