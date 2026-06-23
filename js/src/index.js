'use strict';

/**
 * @nais-standard/sdk — JavaScript SDK for the Network Agent Identity Standard.
 * Server-side Node.js 18+ (uses native dns, fetch, and crypto).
 *
 * Resolution is fully decentralized: the SDK reads the agent's _agent DNS TXT
 * record itself, fetches the signed card, and verifies the signature against the
 * DNS-published key. There is no central resolver in the trust or availability
 * path — trust travels with the signed card.
 */

const crypto = require('crypto');
const dnsPromises = require('dns').promises;

const MAX_CARD_BYTES = 1024 * 1024; // 1 MiB
const DEFAULT_TIMEOUT_MS = 8000;

// ─────────────────────────────────────────────────────────────────────────────
// Signature verification — detached EdDSA JWS over the canonical card
// ─────────────────────────────────────────────────────────────────────────────

/**
 * NAIS canonical JSON (a subset of RFC 8785 / JCS): object keys sorted ascending
 * by code point, no whitespace, "/" and non-ASCII unescaped, integers as
 * integers. Cards MUST NOT contain floating-point numbers.
 * @param {*} v
 * @returns {string}
 */
function canonicalize(v) {
  if (Array.isArray(v)) {
    return '[' + v.map(canonicalize).join(',') + ']';
  }
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('NAIS cards must not contain floating-point numbers');
    return String(v);
  }
  // strings, booleans, null — JSON.stringify leaves "/" and unicode unescaped
  return JSON.stringify(v);
}

function b64urlToBuf(s) {
  return Buffer.from(s, 'base64url');
}

/**
 * Verify a NAIS card's detached EdDSA JWS against the DNS-published key.
 *
 * The card is authentic only when it carries a valid Ed25519 signature over its
 * own canonical body AND signature.kid equals the k= fingerprint from the
 * _agent DNS record. Forging it requires both DNS control and the private key.
 *
 * @param {object} card   The decoded agent.json card
 * @param {string|null} dnsKey  The k= value published in the _agent TXT record
 * @returns {{present: boolean, verified: boolean, kid: string|null, alg: string|null, reason: string|null}}
 */
function verifyCard(card, dnsKey) {
  const out = { present: false, verified: false, kid: null, alg: null, reason: null };
  const sig = card && card.signature;
  if (!sig || typeof sig !== 'object') {
    out.reason = 'no signature object';
    return out;
  }
  out.present = true;
  out.kid = sig.kid || null;
  out.alg = sig.alg || null;

  if (sig.alg !== 'EdDSA') { out.reason = 'unsupported alg (expected EdDSA)'; return out; }
  if (!sig.kid || !sig.jws) { out.reason = 'signature missing kid or jws'; return out; }
  if (!String(sig.kid).startsWith('ed25519:')) { out.reason = 'kid is not an ed25519 key'; return out; }
  if (!dnsKey) { out.reason = 'no k= key published in the _agent DNS record to anchor trust'; return out; }
  if (dnsKey !== sig.kid) { out.reason = 'signature.kid does not match the DNS k= key'; return out; }

  const parts = String(sig.jws).split('.');
  if (parts.length !== 3 || parts[1] !== '') { out.reason = 'jws is not a detached compact JWS'; return out; }
  const [protectedB64, , sigB64] = parts;

  let signingInput;
  try {
    const body = { ...card };
    delete body.signature;
    signingInput = protectedB64 + '.' + Buffer.from(canonicalize(body)).toString('base64url');
  } catch (err) {
    out.reason = 'canonicalization failed: ' + err.message;
    return out;
  }

  try {
    const raw = b64urlToBuf(sig.kid.slice('ed25519:'.length));
    if (raw.length !== 32) { out.reason = 'malformed ed25519 public key in kid'; return out; }
    const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
    const keyObj = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    out.verified = crypto.verify(null, Buffer.from(signingInput), keyObj, b64urlToBuf(sigB64));
    if (!out.verified) out.reason = 'Ed25519 signature does not match the canonical card body';
  } catch (err) {
    out.reason = 'verification error: ' + err.message;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain, DNS, and card fetching
// ─────────────────────────────────────────────────────────────────────────────

/** Normalize input to a bare lowercase hostname, or null if not a valid host. */
function normalizeDomain(input) {
  if (!input || typeof input !== 'string') return null;
  let s = input.trim().replace(/^https?:\/\//i, '');
  s = s.split('/')[0].split('?')[0];
  const lastColon = s.lastIndexOf(':');
  if (lastColon > 0) s = s.slice(0, lastColon);
  s = s.toLowerCase().replace(/\.+$/, '');
  if (!s || s.length > 253) return null;
  const labels = s.split('.');
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label) || label.length > 63) return null;
  }
  return s;
}

/** Parse a NAIS TXT record into a key/value object (semicolon-delimited). */
function parseNaisTxt(raw) {
  const out = {};
  for (const seg of String(raw).split(';')) {
    const s = seg.trim();
    const eq = s.indexOf('=');
    if (eq <= 0) continue;
    out[s.slice(0, eq).trim().toLowerCase()] = s.slice(eq + 1).trim();
  }
  return out;
}

/** Default DNS TXT lookup at _agent.<domain> using Node's resolver. */
async function defaultLookupTxt(host) {
  try {
    const recs = await dnsPromises.resolveTxt(host);
    return recs.map(chunks => chunks.join(''));
  } catch (err) {
    if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) return [];
    throw err;
  }
}

/**
 * Default card fetcher: HTTPS only, no cross-host redirects, size-capped,
 * timeout-bounded. Returns the parsed JSON card.
 */
async function defaultFetchCard(url, timeoutMs) {
  if (!/^https:\/\//i.test(url)) {
    throw new Error('card URL must use HTTPS');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(url, { headers: { Accept: 'application/json' }, redirect: 'follow', signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new Error(`server returned HTTP ${res.status}`);
  if (res.url && new URL(res.url).host !== new URL(url).host) {
    throw new Error('card URL redirected to a different host');
  }
  const text = await res.text();
  if (text.length > MAX_CARD_BYTES) throw new Error('card exceeds 1 MiB');
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error('card is not valid JSON: ' + err.message);
  }
}

/**
 * Validate a decoded card against the NAIS 1.0 schema (structural + signature).
 * @returns {{valid: boolean, errors: string[], warnings: string[]}}
 */
function validateCard(card, expectedDomain, signature) {
  const errors = [];
  const warnings = [];

  if (card.nais == null) errors.push('Missing required field: nais — expected "nais": "1.0"');
  else if (!String(card.nais).startsWith('1.')) warnings.push(`Unexpected nais version "${card.nais}" — this SDK implements 1.x`);

  if (card.cardVersion == null) errors.push('Missing required field: cardVersion (integer)');
  else if (!Number.isInteger(card.cardVersion)) errors.push('Field cardVersion must be an integer');

  if (!card.updated) warnings.push('Missing recommended field: updated (ISO 8601 timestamp)');
  if (!card.name) errors.push('Missing required field: name');

  if (!card.domain) errors.push('Missing required field: domain');
  else if (String(card.domain).toLowerCase().replace(/\.+$/, '') !== expectedDomain) {
    errors.push(`Field domain "${card.domain}" does not match resolved domain "${expectedDomain}"`);
  }

  if (!signature.present) errors.push('Missing required field: signature — every NAIS 1.0 card MUST carry a detached EdDSA JWS');
  else if (!signature.verified) errors.push('Signature verification failed: ' + (signature.reason || 'unknown reason'));

  if (!card.mcp) warnings.push('No MCP endpoint declared (mcp)');
  if (card.capabilities !== undefined) warnings.push('Field capabilities is deprecated in NAIS 1.0 — use free-form "tags"');

  if (card.payment) {
    if (!card.payment.payTo || !card.payment.payTo.length) warnings.push('payment present but payment.payTo is empty');
    else if (!signature.verified) warnings.push('payment.payTo MUST NOT be used: the card signature is not verified');
  }

  if (card.mcpSnapshot && Array.isArray(card.mcpSnapshot.tools) && card.mcpSnapshot.toolsHash) {
    try {
      const computed = 'sha256:' + crypto.createHash('sha256').update(canonicalize(card.mcpSnapshot.tools)).digest('hex');
      if (computed !== card.mcpSnapshot.toolsHash) {
        warnings.push('mcpSnapshot.toolsHash does not match the snapshot tools — snapshot may be stale or altered');
      }
    } catch { /* ignore */ }
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Custom error class for NAIS resolution failures.
 * Carries the domain that was being resolved when the error occurred.
 */
class NaisResolutionError extends Error {
  constructor(message, domain) {
    super(message);
    this.name = 'NaisResolutionError';
    this.domain = domain;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NaisResolutionError);
    }
  }
}

/**
 * Resolve a NAIS agent domain directly: read the _agent DNS TXT record, fetch
 * the signed card, and verify its signature against the DNS-published key.
 *
 * @param {string} domain - The agent domain, e.g. "weatheragent.nais.id"
 * @param {{lookupTxt?: Function, fetchCard?: Function, timeout?: number}} [opts]
 *   Optional overrides for DNS lookup and card fetching (used for testing).
 * @returns {Promise<object>} Resolution result: { ok, domain, agentHost, dns, manifestUrl, card, signature, validation }
 * @throws {NaisResolutionError} If the domain is invalid, has no NAIS record, or the card cannot be fetched.
 *
 * @example
 * const result = await resolve('weatheragent.nais.id');
 * if (result.signature.verified) console.log(result.card.mcp);
 */
async function resolve(domain, opts = {}) {
  const normalized = normalizeDomain(domain);
  if (!normalized) {
    throw new NaisResolutionError('Invalid domain — provide a bare hostname such as weatheragent.nais.id', domain);
  }

  const lookupTxt = opts.lookupTxt || defaultLookupTxt;
  const fetchCard = opts.fetchCard || ((url) => defaultFetchCard(url, opts.timeout || DEFAULT_TIMEOUT_MS));
  const agentHost = '_agent.' + normalized;

  let records;
  try {
    records = await lookupTxt(agentHost);
  } catch (err) {
    throw new NaisResolutionError(`DNS lookup failed for ${agentHost}: ${err.message}`, normalized);
  }

  const naisRecords = (records || []).filter(r => r.includes('v='));
  if (!naisRecords.length) {
    throw new NaisResolutionError(`No NAIS TXT record found at ${agentHost}`, normalized);
  }

  const parsed = parseNaisTxt(naisRecords[0]);
  const manifestUrl = parsed.manifest || `https://${normalized}/.well-known/agent.json`;

  let card;
  try {
    card = await fetchCard(manifestUrl);
  } catch (err) {
    throw new NaisResolutionError(`Failed to fetch card from ${manifestUrl}: ${err.message}`, normalized);
  }
  if (!card || typeof card !== 'object') {
    throw new NaisResolutionError(`Card at ${manifestUrl} is not a JSON object`, normalized);
  }

  const signature = verifyCard(card, parsed.k || null);
  const validation = validateCard(card, normalized, signature);

  return {
    ok: true,
    domain: normalized,
    agentHost,
    dns: { records, parsed },
    manifestUrl,
    card,
    signature,
    validation,
  };
}

/**
 * Resolve and return a flattened, verification-aware summary.
 *
 * @param {string} domain
 * @param {object} [opts] - Same overrides as resolve().
 * @returns {Promise<object>} Summary including signatureVerified, mcpEndpoint, tags, payTo, etc.
 * @throws {NaisResolutionError} If resolution fails entirely.
 *
 * @example
 * const s = await validate('weatheragent.nais.id');
 * if (s.valid && s.hasMcp) { /* safe to call s.mcpEndpoint and pay s.payTo *\/ }
 */
async function validate(domain, opts = {}) {
  const r = await resolve(domain, opts);
  const card = r.card || {};
  const sig = r.signature;
  const v = r.validation;
  const signatureVerified = !!sig.verified;

  const authSchemes = Array.isArray(card.auth)
    ? card.auth.map(a => (a && typeof a === 'object' ? a.scheme : a)).filter(Boolean).map(String)
    : [];
  const payments = card.payment && card.payment.type ? [String(card.payment.type)] : [];
  const tags = Array.isArray(card.tags) ? card.tags.map(String) : [];

  // Advisory pointers to related agents. A link confers no trust — each domain
  // must be resolved and verified independently before it is relied upon.
  const linkedAgents = Array.isArray(card.linkedAgents)
    ? card.linkedAgents
        .filter(l => l && typeof l === 'object' && l.domain)
        .map(l => ({
          domain: String(l.domain),
          relation: l.relation != null ? String(l.relation) : null,
          verified: l.verified === true,
          name: l.name != null ? String(l.name) : null,
        }))
    : [];

  // payTo is only safe to surface once the signature is verified.
  const payToRaw = card.payment && card.payment.payTo;
  const payTo = signatureVerified && Array.isArray(payToRaw) ? payToRaw.map(String) : [];

  return {
    valid: !!(r.ok && v.valid && signatureVerified),
    domain: r.domain,
    version: r.dns.parsed.v || null,
    manifestUrl: r.manifestUrl,
    mcpEndpoint: card.mcp || null,
    hasMcp: !!card.mcp,
    hasCard: !!r.card,
    signatureVerified,
    signatureReason: signatureVerified ? null : (sig.reason || null),
    key: r.dns.parsed.k || null,
    kid: sig.kid || null,
    auth: authSchemes,
    payments,
    payTo,
    tags,
    linkedAgents,
    warnings: v.warnings,
    errors: v.errors,
  };
}

module.exports = {
  resolve,
  validate,
  verifyCard,
  canonicalize,
  parseNaisTxt,
  normalizeDomain,
  NaisResolutionError,
};
