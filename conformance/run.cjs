#!/usr/bin/env node
'use strict';

/**
 * Cross-language conformance runner — JavaScript.
 * Loads every vector in ./vectors and asserts the JS SDK's verifyCard()
 * produces the expected verdict, plus that canonicalize() matches the recorded
 * canonical SHA-256. Exits non-zero on any mismatch.
 *
 *   node conformance/run.cjs
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { verifyCard, canonicalize } = require('../js/src/index.js');

const dir = path.join(__dirname, 'vectors');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();

let failures = 0;
for (const file of files) {
  const vec = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
  const got = verifyCard(vec.card, vec.dnsKey);

  const okVerified = got.verified === vec.expect.verified;
  const okPresent = got.present === vec.expect.present;
  let okCanon = true;

  if (vec.canonicalSha256) {
    const body = { ...vec.card };
    delete body.signature;
    const sha = crypto.createHash('sha256').update(canonicalize(body)).digest('hex');
    okCanon = sha === vec.canonicalSha256;
  }

  const pass = okVerified && okPresent && okCanon;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${vec.name}` +
    (pass ? '' : `  (verified=${got.verified}/${vec.expect.verified} present=${got.present}/${vec.expect.present} canon=${okCanon} reason=${got.reason})`));
}

console.log(`\n[js] ${files.length - failures}/${files.length} vectors passed`);
process.exit(failures ? 1 : 0);
