<?php

declare(strict_types=1);

/**
 * Prints a fake leaky log. Secrets are assembled here so the repository
 * never stores a contiguous credential that hosting scanners would flag.
 *
 *   php examples/make-leaky.php | php bin/pasteguard
 */

$github = 'ghp_' . str_repeat('a', 36);
$jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
$aws = 'AKIA' . 'IOSFODNN7EXAMPLE';

echo <<<LOG
[2026-10-19 20:00:01] production.ERROR: paiement refuse {"userId":42}
customer=luc@kamix.app
card=4242 4242 4242 4242
Authorization: Bearer {$jwt}
GITHUB_TOKEN={$github}
AWS_ACCESS_KEY_ID={$aws}
DATABASE_URL=postgres://app_user:s3cr3tPass@db.internal:5432/billing
password=changeme
retry=3 note=connection timeout, nothing secret in this line

LOG;
