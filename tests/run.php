<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/src/ScrubResult.php';
require $root . '/src/Scrubber.php';
require $root . '/src/Cli.php';

use PasteGuard\Cli;
use PasteGuard\Scrubber;

$failures = 0;
$checks = 0;

function check(bool $ok, string $message): void
{
    global $failures, $checks;
    $checks++;
    if ($ok) {
        return;
    }
    $failures++;
    fwrite(STDERR, "FAIL {$message}\n");
}

function token(string $prefix, int $length, string $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'): string
{
    $out = '';
    $max = strlen($alphabet) - 1;
    for ($i = 0; $i < $length; $i++) {
        $out .= $alphabet[$i % ($max + 1)];
    }

    return $prefix . $out;
}

$scrubber = new Scrubber();

$github = token('ghp_', 36);
$result = $scrubber->scrub("token={$github}\n");
check(!str_contains($result->text, $github), 'github token removed');
check(str_contains($result->text, '[REDACTED:github_token]'), 'github placeholder');
check(($result->counts['github_token'] ?? 0) === 1, 'github count');

$pat = 'github_pat_' . str_repeat('A', 22) . str_repeat('1', 10);
$result = $scrubber->scrub($pat);
check(!str_contains($result->text, $pat), 'github fine grained removed');

$gitlab = 'glpat-' . str_repeat('b', 20);
$result = $scrubber->scrub("x {$gitlab} y");
check(($result->counts['gitlab_token'] ?? 0) === 1, 'gitlab token');
check(!str_contains($result->text, $gitlab), 'gitlab removed');

$slack = 'xoxb-' . str_repeat('1', 12) . '-' . str_repeat('c', 24);
$result = $scrubber->scrub($slack);
check(($result->counts['slack_token'] ?? 0) === 1, 'slack token');

$stripe = 'sk_live_' . str_repeat('d', 24);
$result = $scrubber->scrub("key {$stripe}");
check(($result->counts['stripe_key'] ?? 0) === 1, 'stripe key');
check(!str_contains($result->text, $stripe), 'stripe removed');

$aws = 'AKIA' . 'IOSFODNN7EXAMPLE';
$result = $scrubber->scrub("AWS_ACCESS_KEY_ID={$aws}");
check(($result->counts['aws_access_key'] ?? 0) === 1, 'aws access key');

$google = 'AIza' . str_repeat('e', 35);
$result = $scrubber->scrub($google);
check(($result->counts['google_api_key'] ?? 0) === 1, 'google api key');

$openai = 'sk-proj-' . str_repeat('f', 24);
$result = $scrubber->scrub($openai);
check(($result->counts['openai_key'] ?? 0) === 1, 'openai key');

$npm = 'npm_' . str_repeat('g', 36);
$result = $scrubber->scrub($npm);
check(($result->counts['npm_token'] ?? 0) === 1, 'npm token');

$sendgrid = 'SG.' . str_repeat('h', 22) . '.' . str_repeat('i', 22);
$result = $scrubber->scrub($sendgrid);
check(($result->counts['sendgrid_key'] ?? 0) === 1, 'sendgrid key');

$hook = 'https://hooks.slack.com/services/T' . str_repeat('A', 8) . '/B' . str_repeat('B', 8) . '/' . str_repeat('C', 24);
$result = $scrubber->scrub("webhook {$hook} end");
check(($result->counts['slack_webhook'] ?? 0) === 1, 'slack webhook');
check(!str_contains($result->text, $hook), 'webhook removed');

$jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
$result = $scrubber->scrub("Authorization: Bearer {$jwt}");
check(!str_contains($result->text, 'eyJhbGci'), 'jwt removed before bearer');
check(($result->counts['jwt'] ?? 0) === 1, 'jwt counted once');
check(($result->counts['auth_header'] ?? 0) === 0, 'bearer not double counted');

$bearer = 'Bearer ' . str_repeat('Z', 24);
$result = $scrubber->scrub("Authorization: {$bearer}");
check(str_contains($result->text, 'Bearer [REDACTED:auth_header]'), 'opaque bearer kept scheme');
check(!str_contains($result->text, str_repeat('Z', 24)), 'opaque bearer secret gone');

$pem = "-----BEGIN PRIVATE KEY-----\nMIIFakeKeyMaterialNotRealButLongEnough\n-----END PRIVATE KEY-----\n";
$result = $scrubber->scrub("key follows\n{$pem}done\n");
check(!str_contains($result->text, 'MIIFake'), 'pem body removed');
check(str_contains($result->text, '[REDACTED:pem_private_key]'), 'pem placeholder');
check(str_contains($result->text, 'done'), 'text after pem kept');

$url = 'postgres://app_user:s3cr3tPass@db.internal:5432/billing';
$result = $scrubber->scrub("DATABASE_URL={$url}");
check(str_contains($result->text, 'postgres://app_user:[REDACTED:url_password]@db.internal:5432/billing'), 'url password redacted, user kept');
check(!str_contains($result->text, 's3cr3tPass'), 'url secret gone');

$redis = 'redis://:onlypassword@127.0.0.1:6379/0';
$result = $scrubber->scrub($redis);
check(str_contains($result->text, 'redis://:[REDACTED:url_password]@127.0.0.1:6379/0'), 'empty-user redis url');

$result = $scrubber->scrub("DB_PASSWORD=SuperSecret1\npassword=changeme\nAPI_KEY=\"abcdEFGHijkl1234\"\nSECRET=\${DB_PASSWORD}\nnote=the password format is invalid\n");
check(str_contains($result->text, 'DB_PASSWORD=[REDACTED:generic_secret]'), 'env password');
check(str_contains($result->text, 'password=changeme'), 'placeholder password kept');
check(str_contains($result->text, 'API_KEY="[REDACTED:generic_secret]"'), 'quoted api key keeps quotes');
check(str_contains($result->text, 'SECRET=${DB_PASSWORD}'), 'env interpolation kept');
check(str_contains($result->text, 'the password format is invalid'), 'prose untouched');

$awsSecret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
$result = $scrubber->scrub("AWS_SECRET_ACCESS_KEY={$awsSecret}");
check(($result->counts['aws_secret_key'] ?? 0) === 1, 'aws secret labelled');
check(!str_contains($result->text, 'wJalr'), 'aws secret removed');

$result = $scrubber->scrub("contact luc@kamix.app and docs@example.com and root@localhost");
check(str_contains($result->text, '[REDACTED:email]'), 'real email redacted');
check(!str_contains($result->text, 'luc@kamix.app'), 'real email gone');
check(str_contains($result->text, 'docs@example.com'), 'example.com kept');
check(str_contains($result->text, 'root@localhost'), 'localhost email kept');

$noEmail = (new Scrubber(false))->scrub('luc@kamix.app');
check($noEmail->text === 'luc@kamix.app', 'emails can be disabled');

$card = 'card 4242 4242 4242 4242 was declined';
$result = $scrubber->scrub($card);
check(str_contains($result->text, '[REDACTED:payment_card] was declined'), 'separated card redacted, spacing kept');
check(!str_contains($result->text, '4242'), 'card digits gone');

$bare = 'order 4242424242424242 packed';
$result = $scrubber->scrub($bare);
check(str_contains($result->text, '4242424242424242'), 'bare luhn number without context kept');

$withWord = 'visa 4242424242424242 ok';
$result = $scrubber->scrub($withWord);
check(str_contains($result->text, '[REDACTED:payment_card]'), 'keyword card redacted');

$clean = "[2026-10-19 20:00:00] production.ERROR: SQLSTATE[HY000] [2002] Connection refused {\"userId\":42}\n";
$result = $scrubber->scrub($clean);
check($result->text === $clean, 'ordinary laravel log unchanged');
check($result->total() === 0, 'ordinary log has zero findings');

$once = $scrubber->scrub("email luc@kamix.app token {$github}");
$twice = $scrubber->scrub($once->text);
check($twice->total() === 0, 'second pass is idempotent');
check($twice->text === $once->text, 'second pass text stable');

$ips = (new Scrubber(true, true))->scrub('peer 8.8.8.8 connected');
check(str_contains($ips->text, '[REDACTED:ipv4]'), 'ipv4 opt-in');
$noIps = $scrubber->scrub('peer 8.8.8.8 connected');
check(str_contains($noIps->text, '8.8.8.8'), 'ipv4 off by default');

$tmp = tempnam(sys_get_temp_dir(), 'pg');
if ($tmp === false) {
    fwrite(STDERR, "FAIL temp file\n");
    exit(1);
}
file_put_contents($tmp, "hello luc@kamix.app\n");

ob_start();
$code = (new Cli())->run(['pasteguard', '--quiet', '--check', $tmp]);
$out = (string) ob_get_clean();
check($code === 1, 'check exits 1 when dirty');
check(str_contains($out, '[REDACTED:email]'), 'check still prints scrubbed text');

file_put_contents($tmp, "hello world\n");
ob_start();
$code = (new Cli())->run(['pasteguard', '--quiet', '--check', $tmp]);
ob_end_clean();
check($code === 0, 'check exits 0 when clean');

ob_start();
$code = (new Cli())->run(['pasteguard', '--json', '--quiet', $tmp]);
$json = (string) ob_get_clean();
$decoded = json_decode($json, true);
check($code === 0 && is_array($decoded) && ($decoded['total'] ?? -1) === 0, 'json clean shape');
check(is_array($decoded) && $decoded['counts'] === [], 'json empty counts become object then decode to array');

ob_start();
$code = (new Cli())->run(['pasteguard', '--quiet', $tmp, $tmp . '.missing']);
ob_end_clean();
check($code === 2, 'missing file exits 2');

ob_start();
$code = (new Cli())->run(['pasteguard', '--demo', '--quiet']);
$demo = (string) ob_get_clean();
check($code === 0, 'demo exits 0');
check(str_contains($demo, '--- avant ---') && str_contains($demo, '--- apres ---'), 'demo frames');
check(!str_contains(substr($demo, (int) strpos($demo, '--- apres ---')), 's3cr3tPass'), 'demo secret removed after');
check(!str_contains(substr($demo, (int) strpos($demo, '--- apres ---')), 'luc@kamix.app'), 'demo email removed after');

unlink($tmp);

if ($failures > 0) {
    fwrite(STDERR, "{$failures}/{$checks} checks failed\n");
    exit(1);
}

fwrite(STDOUT, "{$checks} checks passed\n");
