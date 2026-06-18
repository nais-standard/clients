# NAIS SDK Conformance Suite

Every official NAIS SDK MUST produce **identical results** for the vectors in
`vectors/`. This is what guarantees that a card signed by one implementation
verifies in all the others — and, critically, that a tampered card is rejected
everywhere. A divergence here is a **security bug**, not a cosmetic one.

## What is tested

Each vector is a JSON file:

```json
{
  "name": "valid",
  "description": "...",
  "dnsKey": "ed25519:…",          // the _agent TXT k= value (or null)
  "card": { … },                  // the agent.json card
  "expect": { "present": true, "verified": true },
  "canonicalSha256": "…"          // optional: SHA-256 of canonicalize(card − signature)
}
```

A runner loads every vector, calls the SDK's `verifyCard` / `verify_card`, and
asserts:

1. `verified` matches `expect.verified`,
2. `present` matches `expect.present`,
3. when `canonicalSha256` is given, `sha256(canonicalize(card − signature))`
   matches it byte-for-byte (this pins the RFC 8785-subset canonicalization
   across languages).

Current vectors: `valid`, `tampered-payto`, `wrong-key`, `bad-alg`, `unsigned`.

## Running locally

```bash
# Signature/canonicalization conformance (the cross-language vectors):
node   conformance/run.cjs     # JavaScript
python conformance/run.py      # Python  (pip install cryptography)
php    conformance/run.php     # PHP     (ext-sodium)

# End-to-end resolve()/validate() pipeline, offline (DNS + fetch injected):
node   conformance/resolve-test.cjs
python conformance/resolve-test.py
php    conformance/resolve-test.php
```

The vector runners must report `N/N vectors passed`; the resolve tests print
`… offline tests passed`. All exit 0 on success. CI runs both for each SDK.

## Regenerating vectors

The vectors are derived from the bundled signed demo card
(`conformance/fixtures/agent.json`, a copy of the reference weatheragent card).
After the card or signing scheme changes, update the fixture and regenerate:

```bash
php conformance/make-vectors.php
```

CI runs all three runners on every push; do not edit `vectors/*.json` by hand.
