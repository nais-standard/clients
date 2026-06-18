<?php
declare(strict_types=1);

/**
 * Cross-language conformance runner — PHP.
 * Loads every vector in ./vectors and asserts the PHP SDK's verifyCard()
 * produces the expected verdict, plus that canonicalize() matches the recorded
 * canonical SHA-256. Exits non-zero on any mismatch.
 *
 *   php conformance/run.php
 */

require __DIR__ . '/../php/src/Nais/Resolver.php';

use Nais\Resolver;

$files = glob(__DIR__ . '/vectors/*.json');
sort($files);

$failures = 0;
foreach ($files as $file) {
    $vec = json_decode((string) file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
    $got = Resolver::verifyCard($vec['card'], $vec['dnsKey']);

    $okVerified = $got['verified'] === $vec['expect']['verified'];
    $okPresent  = $got['present'] === $vec['expect']['present'];
    $okCanon    = true;

    if (!empty($vec['canonicalSha256'])) {
        $body = $vec['card'];
        unset($body['signature']);
        $sha     = hash('sha256', Resolver::canonicalize($body));
        $okCanon = $sha === $vec['canonicalSha256'];
    }

    $ok = $okVerified && $okPresent && $okCanon;
    if (!$ok) {
        $failures++;
    }
    $extra = $ok ? '' : sprintf(
        '  (verified=%s/%s present=%s/%s canon=%s reason=%s)',
        var_export($got['verified'], true), var_export($vec['expect']['verified'], true),
        var_export($got['present'], true), var_export($vec['expect']['present'], true),
        var_export($okCanon, true), (string) ($got['reason'] ?? '')
    );
    printf("%s  %s%s\n", $ok ? 'PASS' : 'FAIL', $vec['name'], $extra);
}

printf("\n[php] %d/%d vectors passed\n", count($files) - $failures, count($files));
exit($failures ? 1 : 0);
