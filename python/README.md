# nais-sdk

Python SDK for the [Network Agent Identity Standard (NAIS)](https://nais.id).

Resolve and validate NAIS-compliant agent domains. Requires Python 3.8+ and depends on `dnspython` (DNS lookups) and `cryptography` (Ed25519 signature verification; PyNaCl is also supported). `pip install nais-sdk` pulls both. The SDK resolves directly: it reads the `_agent.<domain>` DNS TXT record, fetches the signed card over HTTPS (HTTPS-only, no cross-host redirects, 1 MiB cap), and verifies the card's mandatory Ed25519 signature against the DNS `k=` key. Server-side only — browsers cannot perform DNS lookups.

## Installation

```bash
pip install nais-sdk
```

## Usage

### resolve(domain)

Resolves a domain directly via DNS and HTTPS and returns a structured result dictionary:

- `ok` — overall success flag.
- `domain` — the normalized domain.
- `agent_host` — the host serving the card.
- `dns` — `{records, parsed}`, where `parsed` exposes `v`, `manifest`, and `k`.
- `manifest_url` — the URL the card was fetched from.
- `card` — the decoded `agent.json`.
- `signature` — `{present, verified, kid, alg, reason}`.
- `validation` — `{valid, errors, warnings}`.

```python
from nais_sdk import resolve

r = resolve("weatheragent.nais.id")
if r["signature"]["verified"]:
    print(r["card"]["mcp"])
# https://weatheragent.nais.id/mcp

print(r["dns"]["parsed"]["k"])
# ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ
```

`resolve()` raises on an invalid domain, when no NAIS TXT record is found, or when the card fetch fails. It does **not** raise on a bad signature — that surfaces as `signature["verified"] is False` and `validation["valid"] is False`.

### validate(domain)

Returns a flattened summary dictionary. Best for quick validation checks before using an agent.

```python
from nais_sdk import validate

summary = validate("weatheragent.nais.id")
print(summary)
```

Example output:

```python
{
    "valid": True,
    "domain": "weatheragent.nais.id",
    "version": "nais1",
    "manifest_url": "https://weatheragent.nais.id/.well-known/agent.json",
    "mcp_endpoint": "https://weatheragent.nais.id/mcp",
    "has_mcp": True,
    "has_card": True,
    "signature_verified": True,
    "signature_reason": None,
    "key": "ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ",
    "kid": "ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ",
    "auth": ["wallet"],
    "payments": ["x402"],
    "pay_to": ["0x742d35Cc6634C0532925a3b8D4C9B7F1A2e3d4E5"],
    "tags": ["forecast", "current_weather", "alerts"],
    "linked_agents": [
        {"domain": "alerts.weatheragent.nais.id", "relation": "partner", "verified": True, "name": "Severe Weather Alerts"}
    ],
    "warnings": [],
    "errors": []
}
```

`valid` is `True` only when the card resolved, the schema validates, **and** the signature verifies.

```python
from nais_sdk import validate

summary = validate("weatheragent.nais.id")
if summary["signature_verified"]:
    print(summary["tags"])    # ['forecast', 'current_weather', 'alerts']
    print(summary["pay_to"])  # pay_to only populated for verified cards
```

### verify_card / canonicalize

The SDK also exports `verify_card(card, dns_key)` and `canonicalize(value)` for verifying a card you already hold against a DNS `k=` key. It also exports `parse_nais_txt` and `normalize_domain`.

```python
from nais_sdk import verify_card, canonicalize

result = verify_card(card, "ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ")
print(result["verified"], result["reason"])
```

### Error handling

```python
from nais_sdk import resolve, ResolutionError

try:
    result = resolve("not-a-real-agent.example.com")
except ResolutionError as e:
    print(f"Failed to resolve {e.domain}: {e}")
```

### Timeout

Both `resolve()` and `validate()` accept an optional `timeout` argument (default: 10 seconds):

```python
result = resolve("weatheragent.nais.id", timeout=5)
```

### Testing without DNS or network

`resolve()` and `validate()` accept injected `lookup_txt` and `fetch_card` callables as keyword arguments, so resolution can be tested offline:

```python
result = resolve(
    "weatheragent.nais.id",
    lookup_txt=lambda name: ["v=nais1; manifest=https://weatheragent.nais.id/.well-known/agent.json; k=ed25519:..."],
    fetch_card=lambda url: {...},  # decoded agent.json
)
```

## Notes

- Requires Python 3.8+. Depends on `dnspython` (DNS) and `cryptography` (signatures; PyNaCl also supported); `pip install nais-sdk` installs both.
- Resolution is performed locally and directly: DNS TXT lookup, HTTPS card fetch, and Ed25519 signature verification all happen in-process. There is no central resolver.
- The card fetch is HTTPS-only, refuses cross-host redirects, and caps responses at 1 MiB.
- Server-side only: browsers cannot perform DNS lookups.

## License

MIT
