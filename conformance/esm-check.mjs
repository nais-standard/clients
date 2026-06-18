// Guards the dual CJS/ESM package wiring: confirms the ESM entry re-exports the
// named bindings as functions (and verifies one against the demo card).
import assert from 'assert';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { resolve, validate, verifyCard, canonicalize } from '../js/src/index.mjs';

for (const [name, fn] of Object.entries({ resolve, validate, verifyCard, canonicalize })) {
  assert.strictEqual(typeof fn, 'function', `${name} should be a function via ESM import`);
}

const here = dirname(fileURLToPath(import.meta.url));
const card = JSON.parse(readFileSync(join(here, 'fixtures', 'agent.json'), 'utf8'));
assert.strictEqual(verifyCard(card, card.signature.kid).verified, true, 'ESM verifyCard should verify the demo card');

console.log('[js] ESM named imports resolve correctly');
