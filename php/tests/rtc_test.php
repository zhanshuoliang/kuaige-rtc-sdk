<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/rtc.php';

use function Kuaige\Rtc\issueViewToken;
use function Kuaige\Rtc\parseLicensePage;
use function Kuaige\Rtc\prepareLicenseQuery;

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function rejects(callable $call, string $message): void
{
    try {
        $call();
    } catch (InvalidArgumentException | RuntimeException $expected) {
        return;
    }
    throw new RuntimeException($message);
}

$app = 'app_' . str_repeat('a', 32);
$license = 'lic_' . str_repeat('b', 32);
$secret = 'synthetic-private-secret';
$play = issueViewToken($app, $secret, $license, 'KRTSYNTHETIC1', 'user-1', 'play');
$again = issueViewToken($app, $secret, $license, 'KRTSYNTHETIC1', 'user-1', 'play');
check($play['token'] !== $again['token'], 'Token must have a fresh jti');
check($play['expires_at'] - time() <= 300 && $play['expires_at'] - time() >= 295, 'bad expiry');
rejects(static function () use ($app, $secret, $license) {
    issueViewToken($app, $secret, $license, 'KRTSYNTHETIC1', 'user-1', 'renew');
}, 'renew without session accepted');
rejects(static function () use ($app, $secret, $license) {
    issueViewToken($app, $secret, $license, 'lowercase', 'user-1', 'play');
}, 'invalid SN accepted');
rejects(static function () use ($app, $secret, $license) {
    issueViewToken($app, $secret, $license, 'KRTSYNTHETIC1', 'user-1', 'play', '', 901);
}, 'too long TTL accepted');
$one = prepareLicenseQuery($app, $secret, 0, 2);
$two = prepareLicenseQuery($app, $secret, 0, 2);
check($one['body'] === '{"cursor":0,"limit":2}', 'query body differs');
check($one['headers']['X-RTC-Nonce'] !== $two['headers']['X-RTC-Nonce'], 'nonce reused');
rejects(static function () use ($app, $secret) { prepareLicenseQuery($app, $secret, -1, 2); }, 'bad cursor accepted');
rejects(static function () { parseLicensePage(401, '{}', 0); }, 'HTTP error accepted');
rejects(static function () { parseLicensePage(200, '{"licenses":{},"next_cursor":null}', 0); }, 'object as list accepted');
rejects(static function () { parseLicensePage(200, '{"licenses":[],"next_cursor":0}', 0); }, 'stale cursor accepted');
$row = ['license_id' => $license, 'active' => true, 'expires_at' => null,
    'created_at' => '2026-11-09T00:00:00Z', 'updated_at' => '2026-11-09T00:00:00Z'];
$page = parseLicensePage(200, json_encode(['licenses' => [$row], 'next_cursor' => null], JSON_THROW_ON_ERROR), 0);
check(count($page['licenses']) === 1 && $page['licenses'][0]['expires_at'] === null, 'valid page rejected');
$row['expires_at'] = 'not-a-timestamp';
rejects(static function () use ($row) {
    parseLicensePage(200, json_encode(['licenses' => [$row], 'next_cursor' => null], JSON_THROW_ON_ERROR), 0);
}, 'invalid expiry accepted');
echo "PHP backend examples: passed\n";
