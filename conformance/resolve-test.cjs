#!/usr/bin/env node
'use strict';

/**
 * Offline test of the JS SDK's direct-DNS resolve()/validate() pipeline.
 * DNS + card fetch are injected, so no network is touched. Exits non-zero on
 * any failed assertion.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { resolve, validate, NaisResolutionError } = require('../js/src/index.js');

const card = JSON.parse(fs.readFileSync(
  path.join(__dirname, 'fixtures', 'agent.json'), 'utf8'));
const kid = card.signature.kid;
const txt = `v=nais1; manifest=https://weatheragent.nais.id/.well-known/agent.json; k=${kid}`;
const dns = async () => [txt];
const fetchOk = async () => card;

(async () => {
  // valid card → verified, valid, payTo surfaced
  const r = await resolve('weatheragent.nais.id', { lookupTxt: dns, fetchCard: fetchOk });
  assert.strictEqual(r.signature.verified, true, 'valid card should verify');
  assert.strictEqual(r.validation.valid, true, 'valid card should validate');
  const s = await validate('weatheragent.nais.id', { lookupTxt: dns, fetchCard: fetchOk });
  assert.strictEqual(s.valid, true);
  assert.strictEqual(s.mcpEndpoint, 'https://weatheragent.nais.id/mcp');
  assert.deepStrictEqual(s.payTo, ['0x742d35Cc6634C0532925a3b8D4C9B7F1A2e3d4E5']);

  // tampered → not verified, payTo withheld
  const tampered = JSON.parse(JSON.stringify(card));
  tampered.payment.payTo = ['0xBAD'];
  const st = await validate('weatheragent.nais.id', { lookupTxt: dns, fetchCard: async () => tampered });
  assert.strictEqual(st.signatureVerified, false);
  assert.strictEqual(st.valid, false);
  assert.deepStrictEqual(st.payTo, []);

  // no record → throws
  await assert.rejects(
    () => resolve('weatheragent.nais.id', { lookupTxt: async () => [], fetchCard: fetchOk }),
    NaisResolutionError);

  // invalid domain → throws
  await assert.rejects(() => resolve('not a domain'), NaisResolutionError);

  console.log('[js] resolve/validate offline tests passed');
})().catch((err) => { console.error('FAIL:', err.message); process.exit(1); });
