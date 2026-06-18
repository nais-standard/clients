<?php
declare(strict_types=1);

/**
 * Generate the cross-language conformance vectors from the real signed demo
 * card. Every SDK MUST produce identical verdicts (and identical canonical
 * bytes) for these. Run: php conformance/make-vectors.php
 */

require __DIR__ . '/../php/src/Nais/Resolver.php';

use Nais\Resolver;

$cardPath = __DIR__ . '/fixtures/agent.json';
$card     = json_decode((string) file_get_contents($cardPath), true, 64, JSON_THROW_ON_ERROR);
$kid      = $card['signature']['kid'];

$outDir = __DIR__ . '/vectors';
@mkdir($outDir, 0755, true);

function b64url(string $b): string { return rtrim(strtr(base64_encode($b), '+/', '-_'), '='); }

$body = $card;
unset($body['signature']);
$canonicalSha256 = hash('sha256', Resolver::canonicalize($body));

// A syntactically valid but different ed25519 key (32 zero bytes).
$otherKey = 'ed25519:' . b64url(str_repeat("\0", 32));

$tampered = $card;
$tampered['payment']['payTo'] = ['0xDEAD000000000000000000000000000000000000'];

$badAlg = $card;
$badAlg['signature']['alg'] = 'RS256';

$unsigned = $card;
unset($unsigned['signature']);

$vectors = [
    'valid' => [
        'name'            => 'valid',
        'description'     => 'Authentic signed card with the matching DNS k= key. MUST verify.',
        'dnsKey'          => $kid,
        'card'            => $card,
        'expect'          => ['present' => true, 'verified' => true],
        'canonicalSha256' => $canonicalSha256,
    ],
    'tampered-payto' => [
        'name'        => 'tampered-payto',
        'description' => 'payTo altered after signing. MUST be rejected (signature no longer matches body).',
        'dnsKey'      => $kid,
        'card'        => $tampered,
        'expect'      => ['present' => true, 'verified' => false],
    ],
    'wrong-key' => [
        'name'        => 'wrong-key',
        'description' => 'Valid card but the DNS k= key does not match signature.kid. MUST be rejected.',
        'dnsKey'      => $otherKey,
        'card'        => $card,
        'expect'      => ['present' => true, 'verified' => false],
    ],
    'bad-alg' => [
        'name'        => 'bad-alg',
        'description' => 'Signature alg is not EdDSA. MUST be rejected.',
        'dnsKey'      => $kid,
        'card'        => $badAlg,
        'expect'      => ['present' => true, 'verified' => false],
    ],
    'unsigned' => [
        'name'        => 'unsigned',
        'description' => 'Card with no signature member. MUST be rejected (signature is mandatory).',
        'dnsKey'      => $kid,
        'card'        => $unsigned,
        'expect'      => ['present' => false, 'verified' => false],
    ],
];

foreach ($vectors as $key => $vec) {
    file_put_contents(
        $outDir . '/' . $key . '.json',
        json_encode($vec, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n"
    );
}

fwrite(STDERR, "Wrote " . count($vectors) . " vectors to $outDir\n");
fwrite(STDERR, "canonicalSha256 = $canonicalSha256\n");
