# nais-standard/sdk

PHP SDK for the [Network Agent Identity Standard (NAIS)](https://nais.id).

Resolve and validate NAIS-compliant agent domains. Requires PHP 7.4+ and uses only built-in facilities — `dns_get_record`, `ext-curl`, and `ext-sodium` — with no third-party Composer dependencies. The SDK resolves directly: it reads the `_agent.<domain>` DNS TXT record, fetches the signed card over HTTPS (HTTPS-only, no cross-host redirects, 1 MiB cap), and verifies the card's mandatory Ed25519 signature against the DNS `k=` key. Server-side only — browsers cannot perform DNS lookups.

## Installation

```bash
composer require nais-standard/sdk
```

## Usage

### resolve(string $domain): array

Resolves a domain directly via DNS and HTTPS and returns a structured result array:

- `ok` — overall success flag.
- `domain` — the normalized domain.
- `agent_host` — the host serving the card.
- `dns` — `['records', 'parsed']`, where `parsed` exposes `v`, `manifest`, and `k`.
- `manifest_url` — the URL the card was fetched from.
- `card` — the decoded `agent.json`.
- `signature` — `['present', 'verified', 'kid', 'alg', 'reason']`.
- `validation` — `['valid', 'errors', 'warnings']`.

```php
<?php

require 'vendor/autoload.php';

use Nais\Resolver;

$r = (new Resolver())->resolve('weatheragent.nais.id');
if ($r['signature']['verified']) {
    echo $r['card']['mcp'];
    // https://weatheragent.nais.id/mcp
}

echo $r['dns']['parsed']['k'];
// ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ
```

`resolve()` throws on an invalid domain, when no NAIS TXT record is found, or when the card fetch fails. It does **not** throw on a bad signature — that surfaces as `$r['signature']['verified'] === false` and `$r['validation']['valid'] === false`.

### validate(string $domain): array

Returns a flattened summary array. Ideal for quick validation checks before using an agent.

```php
$summary = (new Resolver())->validate('weatheragent.nais.id');
var_dump($summary);
```

Example output:

```php
array(16) {
  ["valid"]              => bool(true)
  ["domain"]             => string(22) "weatheragent.nais.id"
  ["version"]            => string(5) "nais1"
  ["manifest_url"]       => string(55) "https://weatheragent.nais.id/.well-known/agent.json"
  ["mcp_endpoint"]       => string(34) "https://weatheragent.nais.id/mcp"
  ["has_mcp"]            => bool(true)
  ["has_card"]           => bool(true)
  ["signature_verified"] => bool(true)
  ["signature_reason"]   => NULL
  ["key"]                => string(50) "ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ"
  ["kid"]                => string(50) "ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ"
  ["auth"]               => array(1) { [0]=> string(6) "wallet" }
  ["payments"]           => array(1) { [0]=> string(4) "x402" }
  ["pay_to"]             => array(1) { [0]=> "0x742d35Cc6634C0532925a3b8D4C9B7F1A2e3d4E5" }
  ["tags"]               => array(3) { [0]=> "forecast" [1]=> "current_weather" [2]=> "alerts" }
  ["warnings"]           => array(0) {}
  ["errors"]             => array(0) {}
}
```

`valid` is `true` only when the card resolved, the schema validates, **and** the signature verifies.

```php
$summary = (new Resolver())->validate('weatheragent.nais.id');
if ($summary['signature_verified']) {
    print_r($summary['tags']);    // ['forecast', 'current_weather', 'alerts']
    print_r($summary['pay_to']);  // pay_to only populated for verified cards
}
```

### verifyCard / canonicalize

The SDK also exposes the static helpers `\Nais\Resolver::verifyCard($card, $dnsKey)` and `\Nais\Resolver::canonicalize($value)` for verifying a card you already hold against a DNS `k=` key. The static helpers `\Nais\Resolver::normalizeDomain` and `\Nais\Resolver::parseNaisTxt` are also available.

```php
$result = \Nais\Resolver::verifyCard($card, 'ed25519:oc5a92N1h1Vg9PlnM8CrB0MAw3mMddFhZTrVuMkzceQ');
var_dump($result['verified'], $result['reason']);
```

### Error handling

```php
use Nais\Resolver;
use Nais\ResolutionException;

try {
    $result = (new Resolver())->resolve('not-a-real-agent.example.com');
} catch (ResolutionException $e) {
    echo "Failed to resolve {$e->getDomain()}: {$e->getMessage()}";
} catch (\InvalidArgumentException $e) {
    echo "Invalid input: {$e->getMessage()}";
}
```

### Testing without DNS or network

The constructor accepts injected `lookupTxt` and `fetchCard` callables, so resolution can be tested offline:

```php
$resolver = new \Nais\Resolver([
    'lookupTxt' => fn($name) => ['v=nais1; manifest=https://weatheragent.nais.id/.well-known/agent.json; k=ed25519:...'],
    'fetchCard' => fn($url) => [/* decoded agent.json */],
]);
$r = $resolver->resolve('weatheragent.nais.id');
```

## Requirements

- PHP 7.4 or higher
- `ext-curl`
- `ext-json`
- `ext-sodium` (Ed25519 card signature verification)

No third-party Composer dependencies; DNS lookups use the built-in `dns_get_record`.

## Notes

- Resolution is performed locally and directly: DNS TXT lookup, HTTPS card fetch, and Ed25519 signature verification all happen in-process. There is no central resolver.
- The card fetch is HTTPS-only, refuses cross-host redirects, and caps responses at 1 MiB.
- All SSL verification is enabled by default.
- Server-side only: browsers cannot perform DNS lookups.

## License

MIT
