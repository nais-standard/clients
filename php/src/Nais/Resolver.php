<?php

declare(strict_types=1);

namespace Nais;

/**
 * Exception thrown when NAIS domain resolution fails.
 */
class ResolutionException extends \RuntimeException
{
    private string $domain;

    public function __construct(string $message, string $domain, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->domain = $domain;
    }

    /** Returns the domain that failed to resolve. */
    public function getDomain(): string
    {
        return $this->domain;
    }
}

/**
 * NAIS Resolver — PHP 7.4+ SDK for the Network Agent Identity Standard.
 *
 * Resolution is fully decentralized: the SDK reads the agent's _agent DNS TXT
 * record itself (dns_get_record), fetches the signed card over HTTPS, and
 * verifies the signature against the DNS-published key. There is no central
 * resolver in the trust or availability path. Requires ext-curl and ext-sodium.
 *
 * @example
 * ```php
 * $resolver = new \Nais\Resolver();
 * $result   = $resolver->resolve('weatheragent.nais.id');
 * if ($result['signature']['verified']) {
 *     echo $result['card']['mcp'];
 * }
 *
 * $summary = $resolver->validate('weatheragent.nais.id');
 * var_dump($summary['valid'], $summary['pay_to']);
 * ```
 */
class Resolver
{
    private const MAX_CARD_BYTES = 1048576; // 1 MiB

    /** @var callable|null fn(string $host): string[] */
    private $lookupTxt;
    /** @var callable|null fn(string $url): array */
    private $fetchCard;
    private int $timeout;

    /**
     * @param array{lookupTxt?: callable, fetchCard?: callable, timeout?: int} $opts
     *        Optional overrides for DNS lookup and card fetching (used for testing).
     */
    public function __construct(array $opts = [])
    {
        $this->lookupTxt = $opts['lookupTxt'] ?? null;
        $this->fetchCard = $opts['fetchCard'] ?? null;
        $this->timeout   = (int) ($opts['timeout'] ?? 8);
    }

    /**
     * Resolve a NAIS agent domain directly: read the _agent DNS TXT record,
     * fetch the signed card, and verify its signature against the DNS key.
     *
     * @return array<string,mixed> { ok, domain, agent_host, dns, manifest_url, card, signature, validation }
     *
     * @throws \InvalidArgumentException If the domain is empty.
     * @throws ResolutionException       If the domain is invalid, has no NAIS record, or the card can't be fetched.
     */
    public function resolve(string $domain): array
    {
        if (trim($domain) === '') {
            throw new \InvalidArgumentException('Domain must be a non-empty string');
        }

        $normalized = self::normalizeDomain($domain);
        if ($normalized === null) {
            throw new ResolutionException('Invalid domain — provide a bare hostname such as weatheragent.nais.id', $domain);
        }

        $agentHost = '_agent.' . $normalized;

        try {
            $records = $this->lookupTxt
                ? (array) ($this->lookupTxt)($agentHost)
                : self::defaultLookupTxt($agentHost);
        } catch (\Throwable $e) {
            throw new ResolutionException("DNS lookup failed for {$agentHost}: " . $e->getMessage(), $normalized);
        }

        $naisRecords = array_values(array_filter($records, static fn($r) => strpos((string) $r, 'v=') !== false));
        if (!$naisRecords) {
            throw new ResolutionException("No NAIS TXT record found at {$agentHost}", $normalized);
        }

        $parsed      = self::parseNaisTxt($naisRecords[0]);
        $manifestUrl = !empty($parsed['manifest'])
            ? (string) $parsed['manifest']
            : 'https://' . $normalized . '/.well-known/agent.json';

        try {
            $card = $this->fetchCard
                ? (array) ($this->fetchCard)($manifestUrl)
                : self::defaultFetchCard($manifestUrl, $this->timeout);
        } catch (\Throwable $e) {
            throw new ResolutionException("Failed to fetch card from {$manifestUrl}: " . $e->getMessage(), $normalized);
        }

        $signature  = self::verifyCard($card, $parsed['k'] ?? null);
        $validation = self::validateCard($card, $normalized, $signature);

        return [
            'ok'           => true,
            'domain'       => $normalized,
            'agent_host'   => $agentHost,
            'dns'          => ['records' => array_values($records), 'parsed' => $parsed],
            'manifest_url' => $manifestUrl,
            'card'         => $card,
            'signature'    => $signature,
            'validation'   => $validation,
        ];
    }

    /**
     * Resolve and return a flattened, verification-aware summary.
     *
     * @return array{
     *   valid: bool, domain: string, version: string|null, manifest_url: string|null,
     *   mcp_endpoint: string|null, has_mcp: bool, has_card: bool, signature_verified: bool,
     *   signature_reason: string|null, key: string|null, kid: string|null,
     *   auth: array<string>, payments: array<string>, pay_to: array<string>,
     *   tags: array<string>, warnings: array<string>, errors: array<string>
     * }
     *
     * @throws ResolutionException If resolution fails entirely.
     */
    public function validate(string $domain): array
    {
        $r    = $this->resolve($domain);
        $card = $r['card'];
        $sig  = $r['signature'];
        $v    = $r['validation'];
        $signatureVerified = !empty($sig['verified']);

        $auth = [];
        foreach (($card['auth'] ?? []) as $entry) {
            if (is_array($entry) && isset($entry['scheme'])) {
                $auth[] = (string) $entry['scheme'];
            } elseif (is_string($entry)) {
                $auth[] = $entry;
            }
        }

        $payments = isset($card['payment']['type']) ? [(string) $card['payment']['type']] : [];
        $tags     = isset($card['tags']) && is_array($card['tags']) ? array_map('strval', $card['tags']) : [];

        // pay_to is only safe to surface once the signature is verified.
        $payTo = [];
        if ($signatureVerified && isset($card['payment']['payTo']) && is_array($card['payment']['payTo'])) {
            $payTo = array_map('strval', $card['payment']['payTo']);
        }

        return [
            'valid'              => !empty($r['ok']) && !empty($v['valid']) && $signatureVerified,
            'domain'             => $r['domain'],
            'version'            => $r['dns']['parsed']['v'] ?? null,
            'manifest_url'       => $r['manifest_url'],
            'mcp_endpoint'       => $card['mcp'] ?? null,
            'has_mcp'            => !empty($card['mcp']),
            'has_card'           => !empty($card),
            'signature_verified' => $signatureVerified,
            'signature_reason'   => $signatureVerified ? null : ($sig['reason'] ?? null),
            'key'                => $r['dns']['parsed']['k'] ?? null,
            'kid'                => $sig['kid'] ?? null,
            'auth'               => $auth,
            'payments'           => $payments,
            'pay_to'             => $payTo,
            'tags'               => $tags,
            'warnings'           => $v['warnings'],
            'errors'             => $v['errors'],
        ];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Domain / DNS / card fetching
    // ─────────────────────────────────────────────────────────────────────────

    /** Normalize input to a bare lowercase hostname, or null if invalid. */
    public static function normalizeDomain(string $input): ?string
    {
        $input = trim($input);
        $input = (string) preg_replace('#^https?://#i', '', $input);
        $input = explode('/', $input)[0];
        $input = explode('?', $input)[0];
        if (($c = strrpos($input, ':')) !== false && $c > 0) {
            $input = substr($input, 0, $c);
        }
        $input = strtolower(rtrim($input, '.'));
        if ($input === '' || strlen($input) > 253) {
            return null;
        }
        $labels = explode('.', $input);
        if (count($labels) < 2) {
            return null;
        }
        foreach ($labels as $label) {
            if (strlen($label) > 63 || !preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/', $label)) {
                return null;
            }
        }
        return $input;
    }

    /** Parse a NAIS TXT record into a key/value map (semicolon-delimited). */
    public static function parseNaisTxt(string $raw): array
    {
        $out = [];
        foreach (explode(';', $raw) as $seg) {
            $seg = trim($seg);
            $eq  = strpos($seg, '=');
            if ($eq === false || $eq === 0) {
                continue;
            }
            $out[strtolower(trim(substr($seg, 0, $eq)))] = trim(substr($seg, $eq + 1));
        }
        return $out;
    }

    /** Default DNS TXT lookup at _agent.<domain>. @return string[] */
    private static function defaultLookupTxt(string $host): array
    {
        $records = @dns_get_record($host, DNS_TXT);
        if (!is_array($records)) {
            return [];
        }
        $out = [];
        foreach ($records as $rec) {
            if (isset($rec['txt']) && $rec['txt'] !== '') {
                $out[] = $rec['txt'];
            } elseif (isset($rec['entries']) && is_array($rec['entries'])) {
                $out[] = implode('', $rec['entries']);
            }
        }
        return $out;
    }

    /**
     * Default card fetcher: HTTPS only, max 3 redirects, no cross-host redirect,
     * size-capped, timeout-bounded, full TLS verification.
     *
     * @return array<string,mixed>
     */
    private static function defaultFetchCard(string $url, int $timeout): array
    {
        if (stripos($url, 'https://') !== 0) {
            throw new \RuntimeException('card URL must use HTTPS');
        }
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('the cURL extension is required');
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => max(2, (int) ($timeout / 2)),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'nais-php-sdk/1.0.0',
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);
        $body     = curl_exec($ch);
        $status   = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $finalUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $err      = curl_error($ch);
        curl_close($ch);

        if ($body === false || $err !== '') {
            throw new \RuntimeException('network error: ' . $err);
        }
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException("server returned HTTP {$status}");
        }
        if (strlen((string) $body) > self::MAX_CARD_BYTES) {
            throw new \RuntimeException('card exceeds 1 MiB');
        }
        if ($finalUrl !== '' && parse_url($finalUrl, PHP_URL_HOST) !== parse_url($url, PHP_URL_HOST)) {
            throw new \RuntimeException('card URL redirected to a different host');
        }

        $data = json_decode((string) $body, true);
        if (!is_array($data)) {
            throw new \RuntimeException('card is not valid JSON: ' . json_last_error_msg());
        }
        return $data;
    }

    /**
     * Validate a decoded card against the NAIS 1.0 schema (structural + signature).
     *
     * @param array{present:bool,verified:bool,kid:?string,alg:?string,reason:?string} $signature
     * @return array{valid: bool, errors: string[], warnings: string[]}
     */
    public static function validateCard(array $card, string $expectedDomain, array $signature): array
    {
        $errors   = [];
        $warnings = [];

        if (!isset($card['nais'])) {
            $errors[] = 'Missing required field: nais — expected "nais": "1.0"';
        } elseif (strpos((string) $card['nais'], '1.') !== 0) {
            $warnings[] = sprintf('Unexpected nais version "%s" — this SDK implements 1.x', $card['nais']);
        }

        if (!isset($card['cardVersion'])) {
            $errors[] = 'Missing required field: cardVersion (integer)';
        } elseif (!is_int($card['cardVersion'])) {
            $errors[] = 'Field cardVersion must be an integer';
        }

        if (empty($card['updated'])) {
            $warnings[] = 'Missing recommended field: updated (ISO 8601 timestamp)';
        }
        if (empty($card['name'])) {
            $errors[] = 'Missing required field: name';
        }

        if (empty($card['domain'])) {
            $errors[] = 'Missing required field: domain';
        } elseif (strtolower(rtrim((string) $card['domain'], '.')) !== $expectedDomain) {
            $errors[] = sprintf('Field domain "%s" does not match resolved domain "%s"', $card['domain'], $expectedDomain);
        }

        if (empty($signature['present'])) {
            $errors[] = 'Missing required field: signature — every NAIS 1.0 card MUST carry a detached EdDSA JWS';
        } elseif (empty($signature['verified'])) {
            $errors[] = 'Signature verification failed: ' . ($signature['reason'] ?? 'unknown reason');
        }

        if (empty($card['mcp'])) {
            $warnings[] = 'No MCP endpoint declared (mcp)';
        }
        if (isset($card['capabilities'])) {
            $warnings[] = 'Field capabilities is deprecated in NAIS 1.0 — use free-form "tags"';
        }

        if (isset($card['payment'])) {
            if (empty($card['payment']['payTo'])) {
                $warnings[] = 'payment present but payment.payTo is empty';
            } elseif (empty($signature['verified'])) {
                $warnings[] = 'payment.payTo MUST NOT be used: the card signature is not verified';
            }
        }

        if (isset($card['mcpSnapshot']['tools'], $card['mcpSnapshot']['toolsHash']) && is_array($card['mcpSnapshot']['tools'])) {
            $computed = 'sha256:' . hash('sha256', self::canonicalize($card['mcpSnapshot']['tools']));
            if (!hash_equals((string) $card['mcpSnapshot']['toolsHash'], $computed)) {
                $warnings[] = 'mcpSnapshot.toolsHash does not match the snapshot tools — snapshot may be stale or altered';
            }
        }

        return ['valid' => empty($errors), 'errors' => $errors, 'warnings' => $warnings];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signature verification — detached EdDSA JWS over the canonical card
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * NAIS canonical JSON (a subset of RFC 8785 / JCS): object keys sorted
     * ascending by byte value, no whitespace, "/" and non-ASCII unescaped,
     * integers emitted as integers. Cards MUST NOT contain floating-point numbers.
     *
     * @param mixed $value
     */
    public static function canonicalize($value): string
    {
        if (is_array($value)) {
            $isList = $value === [] || array_keys($value) === range(0, count($value) - 1);
            if ($isList) {
                return '[' . implode(',', array_map([self::class, 'canonicalize'], $value)) . ']';
            }
            $keys = array_keys($value);
            sort($keys, SORT_STRING);
            $parts = [];
            foreach ($keys as $k) {
                $parts[] = json_encode((string) $k, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                    . ':' . self::canonicalize($value[$k]);
            }
            return '{' . implode(',', $parts) . '}';
        }
        if (is_string($value)) {
            return (string) json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        throw new \RuntimeException('NAIS cards must not contain floating-point numbers');
    }

    /**
     * Verify a NAIS card's detached EdDSA JWS against the DNS-published key.
     *
     * The card is authentic only when it carries a valid Ed25519 signature over
     * its own canonical body AND signature.kid equals the k= fingerprint from the
     * _agent DNS record. Forging it requires both DNS control and the private key.
     *
     * @param  array<string,mixed> $card    The decoded agent.json card
     * @param  string|null         $dnsKey  The k= value from the _agent TXT record
     * @return array{present:bool,verified:bool,kid:?string,alg:?string,reason:?string}
     */
    public static function verifyCard(array $card, ?string $dnsKey): array
    {
        $out = ['present' => false, 'verified' => false, 'kid' => null, 'alg' => null, 'reason' => null];

        $sig = $card['signature'] ?? null;
        if (!is_array($sig)) {
            $out['reason'] = 'no signature object';
            return $out;
        }
        $out['present'] = true;
        $out['kid'] = $sig['kid'] ?? null;
        $out['alg'] = $sig['alg'] ?? null;

        if (($sig['alg'] ?? null) !== 'EdDSA') {
            $out['reason'] = 'unsupported alg (expected EdDSA)';
            return $out;
        }
        if (empty($sig['kid']) || empty($sig['jws'])) {
            $out['reason'] = 'signature missing kid or jws';
            return $out;
        }
        if (strpos((string) $sig['kid'], 'ed25519:') !== 0) {
            $out['reason'] = 'kid is not an ed25519 key';
            return $out;
        }
        if ($dnsKey === null || $dnsKey === '') {
            $out['reason'] = 'no k= key published in the _agent DNS record to anchor trust';
            return $out;
        }
        if (!hash_equals($dnsKey, (string) $sig['kid'])) {
            $out['reason'] = 'signature.kid does not match the DNS k= key';
            return $out;
        }
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            $out['reason'] = 'libsodium (ext-sodium) is required for signature verification';
            return $out;
        }

        $parts = explode('.', (string) $sig['jws']);
        if (count($parts) !== 3 || $parts[1] !== '') {
            $out['reason'] = 'jws is not a detached compact JWS';
            return $out;
        }
        [$protectedB64, , $sigB64] = $parts;

        $body = $card;
        unset($body['signature']);
        try {
            $payload = self::canonicalize($body);
        } catch (\RuntimeException $e) {
            $out['reason'] = 'canonicalization failed: ' . $e->getMessage();
            return $out;
        }
        $signingInput = $protectedB64 . '.' . self::b64url($payload);

        $pub = self::b64urlDecode(substr((string) $sig['kid'], strlen('ed25519:')));
        if (strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            $out['reason'] = 'malformed ed25519 public key in kid';
            return $out;
        }

        $out['verified'] = sodium_crypto_sign_verify_detached(self::b64urlDecode($sigB64), $signingInput, $pub);
        if (!$out['verified']) {
            $out['reason'] = 'Ed25519 signature does not match the canonical card body';
        }
        return $out;
    }

    private static function b64url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private static function b64urlDecode(string $s): string
    {
        return (string) base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4));
    }
}
