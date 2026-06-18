<?php
declare(strict_types=1);

/**
 * Offline test of the PHP SDK's direct-DNS resolve()/validate() pipeline.
 * DNS + card fetch are injected, so no network is touched. Exits non-zero on
 * any failed assertion.
 */

require __DIR__ . '/../php/src/Nais/Resolver.php';

use Nais\Resolver;
use Nais\ResolutionException;

function check(bool $cond, string $msg): void
{
    if (!$cond) {
        fwrite(STDERR, "FAIL: {$msg}\n");
        exit(1);
    }
}

$card = json_decode((string) file_get_contents(__DIR__ . '/fixtures/agent.json'), true);
$kid  = $card['signature']['kid'];
$txt  = "v=nais1; manifest=https://weatheragent.nais.id/.well-known/agent.json; k={$kid}";
$dns  = fn($h) => [$txt];
$fetchOk = fn($u) => $card;

// valid card → verified, valid, pay_to surfaced
$r = (new Resolver(['lookupTxt' => $dns, 'fetchCard' => $fetchOk]))->resolve('weatheragent.nais.id');
check($r['signature']['verified'] === true, 'valid card should verify');
check($r['validation']['valid'] === true, 'valid card should validate');
$s = (new Resolver(['lookupTxt' => $dns, 'fetchCard' => $fetchOk]))->validate('weatheragent.nais.id');
check($s['valid'] === true, 'summary valid');
check($s['mcp_endpoint'] === 'https://weatheragent.nais.id/mcp', 'mcp endpoint');
check($s['pay_to'] === ['0x742d35Cc6634C0532925a3b8D4C9B7F1A2e3d4E5'], 'pay_to surfaced');

// tampered → not verified, pay_to withheld
$tampered = $card;
$tampered['payment']['payTo'] = ['0xBAD'];
$st = (new Resolver(['lookupTxt' => $dns, 'fetchCard' => fn($u) => $tampered]))->validate('weatheragent.nais.id');
check($st['signature_verified'] === false, 'tampered not verified');
check($st['valid'] === false, 'tampered invalid');
check($st['pay_to'] === [], 'tampered pay_to withheld');

// no record → throws
try {
    (new Resolver(['lookupTxt' => fn($h) => [], 'fetchCard' => $fetchOk]))->resolve('weatheragent.nais.id');
    check(false, 'expected ResolutionException for missing record');
} catch (ResolutionException $e) {
    // expected
}

// invalid domain → throws
try {
    (new Resolver())->resolve('not a domain');
    check(false, 'expected ResolutionException for invalid domain');
} catch (ResolutionException $e) {
    // expected
}

echo "[php] resolve/validate offline tests passed\n";
