<?php
declare(strict_types=1);

// SDK functions for trusted vendor backends only. These helpers do not
// authenticate users, authorize device sharing, allocate licenses, or sign a
// device_grant. Never put an AppSecret in an H5, mini program, or mobile app.
namespace Kuaige\Rtc;

const LICENSE_QUERY_PATH = '/rtc/v1/applications/licenses/query';
const LICENSE_QUERY_URL = 'https://live.kuaige.cloud' . LICENSE_QUERY_PATH;
const MAX_RESPONSE_BYTES = 262144;

function base64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

/** Return a new single-use view token and its Unix expiry. */
function issueViewToken(
    string $appKey,
    string $appSecret,
    string $licenseId,
    string $deviceSn,
    string $subject,
    string $purpose,
    string $sessionId = '',
    int $ttlSeconds = 300
): array {
    if (PHP_INT_SIZE < 8) {
        throw new \RuntimeException('64-bit PHP is required');
    }
    if (!preg_match('/\Aapp_[A-Za-z0-9_-]{24,64}\z/', $appKey) || $appSecret === '' ||
        !preg_match('/\Alic_[A-Za-z0-9_-]{24,64}\z/', $licenseId) ||
        !preg_match('/\A[A-Z0-9_-]{4,64}\z/', $deviceSn) ||
        !preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,79}\z/', $subject) ||
        $ttlSeconds < 60 || $ttlSeconds > 900 ||
        ($purpose !== 'play' && $purpose !== 'renew') ||
        ($purpose === 'play' && $sessionId !== '') ||
        ($purpose === 'renew' && !preg_match('/\A[A-Za-z0-9_-]{16,96}\z/', $sessionId))) {
        throw new \InvalidArgumentException('invalid RTC token parameters');
    }
    $issuedAt = time();
    $expiresAt = $issuedAt + $ttlSeconds;
    $claims = [
        'iss' => $appKey,
        'aud' => 'kuaige-rtc-view',
        'sub' => $subject,
        'iat' => $issuedAt,
        'exp' => $expiresAt,
        'jti' => base64url(random_bytes(24)),
        'license_id' => $licenseId,
        'device_sn' => $deviceSn,
        'purpose' => $purpose,
    ];
    if ($purpose === 'renew') {
        $claims['session_id'] = $sessionId;
    }
    $header = base64url('{"alg":"HS256","typ":"JWT"}');
    $payload = base64url(json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    $signed = $header . '.' . $payload;
    // Use the original AppSecret string as bytes; do not base64-decode it.
    $signature = base64url(hash_hmac('sha256', $signed, $appSecret, true));
    return ['token' => $signed . '.' . $signature, 'expires_at' => $expiresAt];
}

/** Build the exact body and signed headers; never log the returned headers. */
function prepareLicenseQuery(string $appKey, string $appSecret, int $cursor = 0, int $limit = 100): array
{
    if (PHP_INT_SIZE < 8) {
        throw new \RuntimeException('64-bit PHP is required');
    }
    if (!preg_match('/\Aapp_[A-Za-z0-9_-]{24,64}\z/', $appKey) || $appSecret === '' ||
        $cursor < 0 || $limit < 1 || $limit > 100) {
        throw new \InvalidArgumentException('invalid license query parameters');
    }
    $body = json_encode(['cursor' => $cursor, 'limit' => $limit], JSON_THROW_ON_ERROR);
    $timestamp = (string) time();
    $nonce = base64url(random_bytes(24));
    $canonical = implode("\n", [
        'RTC-APP-V1', $appKey, $timestamp, $nonce, 'POST', LICENSE_QUERY_PATH, hash('sha256', $body),
    ]);
    $signature = hash_hmac('sha256', $canonical, $appSecret);
    return [
        'body' => $body,
        'headers' => [
            'Content-Type' => 'application/json',
            'X-RTC-App-Key' => $appKey,
            'X-RTC-Timestamp' => $timestamp,
            'X-RTC-Nonce' => $nonce,
            'X-RTC-Signature' => $signature,
        ],
    ];
}

/** Check the server's RFC 3339 timestamps without changing their value. */
function isRtcTimestamp($value): bool
{
    if (!is_string($value) || !preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\z/', $value)) {
        return false;
    }
    try {
        new \DateTimeImmutable($value);
        $errors = \DateTimeImmutable::getLastErrors();
        return $errors === false || ($errors['warning_count'] === 0 && $errors['error_count'] === 0);
    } catch (\Exception $error) {
        return false;
    }
}

/** Validate a page without including server response content in errors. */
function parseLicensePage(int $httpStatus, string $body, int $cursor): array
{
    if ($httpStatus !== 200) {
        throw new \RuntimeException('RTC license query returned HTTP ' . $httpStatus);
    }
    if (strlen($body) > MAX_RESPONSE_BYTES) {
        throw new \RuntimeException('invalid RTC license response');
    }
    try {
        $data = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
    } catch (\JsonException $error) {
        throw new \RuntimeException('invalid RTC license response');
    }
    if (!($data instanceof \stdClass) || !property_exists($data, 'licenses') || !is_array($data->licenses) ||
        !property_exists($data, 'next_cursor') ||
        ($data->next_cursor !== null && (!is_int($data->next_cursor) || $data->next_cursor <= $cursor))) {
        throw new \RuntimeException('invalid RTC license response');
    }
    $licenses = [];
    foreach ($data->licenses as $license) {
        if (!($license instanceof \stdClass) || !isset($license->license_id) || !is_string($license->license_id) ||
            !preg_match('/\Alic_[A-Za-z0-9_-]{24,64}\z/', $license->license_id) ||
            !isset($license->active) || !is_bool($license->active) ||
            !property_exists($license, 'expires_at') ||
            ($license->expires_at !== null && !isRtcTimestamp($license->expires_at)) ||
            !isset($license->created_at, $license->updated_at) ||
            !isRtcTimestamp($license->created_at) || !isRtcTimestamp($license->updated_at)) {
            throw new \RuntimeException('invalid RTC license response');
        }
        $licenses[] = (array) $license;
    }
    return ['licenses' => $licenses, 'next_cursor' => $data->next_cursor];
}

/** Query only this application's licenses. Requires PHP cURL and trusted CA. */
function queryLicensePage(string $appKey, string $appSecret, int $cursor = 0, int $limit = 100): array
{
    $request = prepareLicenseQuery($appKey, $appSecret, $cursor, $limit);
    if (!function_exists('curl_init')) {
        throw new \RuntimeException('PHP cURL extension is required');
    }
    $handle = curl_init(LICENSE_QUERY_URL);
    if ($handle === false) {
        throw new \RuntimeException('RTC license query unavailable');
    }
    $headers = [];
    foreach ($request['headers'] as $name => $value) {
        $headers[] = $name . ': ' . $value;
    }
    $response = '';
    $tooLarge = false;
    try {
        $configured = curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $request['body'],
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$response, &$tooLarge): int {
                if (strlen($response) + strlen($chunk) > MAX_RESPONSE_BYTES) {
                    $tooLarge = true;
                    return 0;
                }
                $response .= $chunk;
                return strlen($chunk);
            },
        ]);
        if (!$configured || curl_exec($handle) === false) {
            throw new \RuntimeException($tooLarge ? 'invalid RTC license response' : 'RTC license query unavailable');
        }
        $status = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
    } finally {
        curl_close($handle);
    }
    return parseLicensePage($status, $response, $cursor);
}
