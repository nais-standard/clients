// Type declarations for @nais-standard/sdk

/** Result of verifying a card's detached EdDSA JWS. */
export interface SignatureVerification {
  present: boolean;
  verified: boolean;
  kid: string | null;
  alg: string | null;
  reason: string | null;
}

/** An advisory pointer to a related agent. A link confers no trust: resolve and verify the linked domain independently. */
export interface LinkedAgentSummary {
  domain: string;
  relation: string | null;
  verified: boolean;
  name: string | null;
}

/** Flattened summary returned by validate(). */
export interface ValidationSummary {
  valid: boolean;
  domain: string;
  version: string | null;
  hasManifest: boolean;
  manifestUrl: string | null;
  mcpEndpoint: string | null;
  hasMcp: boolean;
  signatureVerified: boolean;
  signatureReason: string | null;
  key: string | null;
  kid: string | null;
  auth: string[];
  payments: string[];
  payTo: string[];
  tags: string[];
  linkedAgents: LinkedAgentSummary[];
  warnings: string[];
  errors: string[];
  cached: boolean;
}

/** Error thrown when resolution fails. */
export class NaisResolutionError extends Error {
  domain: string;
  constructor(message: string, domain: string);
}

/** The public NAIS resolver endpoint used by default. */
export const RESOLVER_URL: string;

/**
 * Resolve a NAIS agent domain via the public resolver, then independently
 * verify the card signature. The resolver response is returned with an added
 * `localVerification` property.
 */
export function resolve(domain: string): Promise<Record<string, any> & { localVerification: SignatureVerification }>;

/** Resolve and return a flattened, verification-aware summary. */
export function validate(domain: string): Promise<ValidationSummary>;

/**
 * Verify a card's detached EdDSA JWS against the DNS-published key.
 * The card is authentic only when the signature verifies and its kid equals dnsKey.
 */
export function verifyCard(card: Record<string, any>, dnsKey: string | null): SignatureVerification;

/** NAIS canonical JSON (subset of RFC 8785 / JCS) used as the JWS payload. */
export function canonicalize(value: unknown): string;
