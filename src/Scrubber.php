<?php

declare(strict_types=1);

namespace PasteGuard;

/**
 * Best-effort redaction of secrets and personal data before a log is pasted
 * into Slack, a GitHub issue, or a chat model. This is not a security boundary:
 * always re-read the result.
 */
final class Scrubber
{
    /** @var array<string, true> */
    private const GENERIC_DENY = [
        'changeme' => true,
        'password' => true,
        'secret' => true,
        'example' => true,
        'placeholder' => true,
        'todo' => true,
        'test' => true,
        'string' => true,
        'null' => true,
        'none' => true,
        'false' => true,
        'true' => true,
        'undefined' => true,
        'foo' => true,
        'bar' => true,
        'xxx' => true,
        'redacted' => true,
        'your_api_key' => true,
        'your-api-key' => true,
        'insert_token_here' => true,
        'n/a' => true,
        'na' => true,
    ];

    public function __construct(
        private readonly bool $emails = true,
        private readonly bool $ips = false,
    ) {}

    public function scrub(string $input): ScrubResult
    {
        /** @var array<string, int> $counts */
        $counts = [];
        $text = $input;

        $text = $this->replace(
            $text,
            $counts,
            'pem_private_key',
            '/-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----.*?-----END (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----/s'
        );

        $literal = [
            'github_token' => '/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/',
            'gitlab_token' => '/\bglpat-[A-Za-z0-9\-_]{20,}\b/',
            'slack_token' => '/\bxox[baprs]-[A-Za-z0-9]+(?:-[A-Za-z0-9]+){1,4}/',
            'stripe_key' => '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/',
            'aws_access_key' => '/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/',
            'google_api_key' => '/\bAIza[0-9A-Za-z\-_]{35}\b/',
            'openai_key' => '/\bsk-(?:proj-|ant-)?[A-Za-z0-9][A-Za-z0-9_\-]{19,}\b/',
            'npm_token' => '/\bnpm_[A-Za-z0-9]{36}\b/',
            'sendgrid_key' => '/\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/',
            'slack_webhook' => '#https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+#',
            'jwt' => '/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/',
        ];

        foreach ($literal as $kind => $pattern) {
            $text = $this->replace($text, $counts, $kind, $pattern);
        }

        $text = $this->replaceCallback(
            $text,
            $counts,
            'url_password',
            '#\b([a-z][a-z0-9+.-]*://[^\s/:@]*):([^\s/@]+)@#i',
            static fn (array $match): string => $match[1] . ':[REDACTED:url_password]@'
        );

        $text = $this->replaceCallback(
            $text,
            $counts,
            'auth_header',
            '/\b((?:Bearer|Basic)\s+)(?!\[REDACTED:)([A-Za-z0-9\-._~+\/=]{12,})/i',
            static fn (array $match): string => $match[1] . '[REDACTED:auth_header]'
        );

        $text = $this->scrubAssignments($text, $counts);

        if ($this->emails) {
            $text = $this->scrubEmails($text, $counts);
        }

        $text = $this->scrubCards($text, $counts);

        if ($this->ips) {
            $text = $this->replace(
                $text,
                $counts,
                'ipv4',
                '/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/'
            );
        }

        ksort($counts);

        return new ScrubResult($text, $counts);
    }

    /**
     * @param array<string, int> $counts
     */
    private function scrubAssignments(string $text, array &$counts): string
    {
        $pattern = '/(?i)\b((?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token)(?:[_-][A-Za-z0-9]+)*)\b(\s*(?:=>|[:=])\s*)(?:([\'"])([^\'"]{0,300})\3|([^\s,;}{\'"]{4,}))/';

        $out = preg_replace_callback(
            $pattern,
            function (array $match) use (&$counts): string {
                $quote = $match[3];
                $value = $quote !== '' ? $match[4] : $match[5];
                $suffix = '';
                if ($quote === '' && preg_match('/^(.*?)(\.)$/', $value, $trimmed) === 1 && $trimmed[1] !== '') {
                    $value = $trimmed[1];
                    $suffix = $trimmed[2];
                }

                if (!$this->shouldRedactGeneric($value)) {
                    return $match[0];
                }

                $key = strtolower($match[1]);
                $kind = 'generic_secret';
                if (str_contains($key, 'aws_secret') || str_contains($key, 'secret_access_key')) {
                    $kind = 'aws_secret_key';
                }

                $counts[$kind] = ($counts[$kind] ?? 0) + 1;

                return $match[1] . $match[2] . $quote . '[REDACTED:' . $kind . ']' . $quote . $suffix;
            },
            $text
        );

        return $out ?? $text;
    }

    /**
     * @param array<string, int> $counts
     */
    private function scrubEmails(string $text, array &$counts): string
    {
        return $this->replaceCallback(
            $text,
            $counts,
            'email',
            '/\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i',
            static function (array $match): string {
                if (preg_match('/@(?:example\.(?:com|org|net)|test\.com|localhost)$/i', $match[0]) === 1) {
                    return $match[0];
                }

                return '[REDACTED:email]';
            }
        );
    }

    /**
     * @param array<string, int> $counts
     */
    private function scrubCards(string $text, array &$counts): string
    {
        $replaced = 0;
        $out = preg_replace_callback(
            '/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/',
            static function (array $match) use ($text, &$counts): string {
                $raw = $match[0][0];
                $offset = $match[0][1];
                $digits = preg_replace('/\D/', '', $raw) ?? '';
                $length = strlen($digits);
                if ($length < 13 || $length > 19 || preg_match('/^(\d)\1+$/', $digits) === 1 || !self::luhn($digits)) {
                    return $raw;
                }

                $hasSeparator = preg_match('/[ -]/', $raw) === 1;
                $from = max(0, $offset - 48);
                $window = substr($text, $from, 48 + strlen($raw) + 48);
                $hasKeyword = preg_match('/\b(?:card|cc|pan|visa|mastercard|amex|cvv)\b/i', $window) === 1;
                if (!$hasSeparator && !$hasKeyword) {
                    return $raw;
                }

                $counts['payment_card'] = ($counts['payment_card'] ?? 0) + 1;

                return '[REDACTED:payment_card]';
            },
            $text,
            -1,
            $replaced,
            PREG_OFFSET_CAPTURE
        );

        return $out ?? $text;
    }

    private function shouldRedactGeneric(string $value): bool
    {
        if ($value === '' || str_starts_with($value, '[REDACTED:')) {
            return false;
        }

        $lower = strtolower($value);
        if (isset(self::GENERIC_DENY[$lower])) {
            return false;
        }

        if (preg_match('/^(?:\*+|x+|\.+|-+|_+)$/i', $value) === 1) {
            return false;
        }

        if (preg_match('/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/', $value) === 1) {
            return false;
        }

        if (preg_match('/^\{\{.+\}\}$/', $value) === 1 || preg_match('/^<[^>]+>$/', $value) === 1) {
            return false;
        }

        $length = strlen($value);
        if ($length < 6) {
            return false;
        }

        $hasDigit = preg_match('/\d/', $value) === 1;
        $mixedCase = preg_match('/[a-z]/', $value) === 1 && preg_match('/[A-Z]/', $value) === 1;

        if ($length >= 20 || ($hasDigit && $length >= 8) || ($mixedCase && $length >= 10)) {
            return true;
        }

        return $length >= 12 && self::entropy($value) >= 3.2;
    }

    /**
     * @param array<string, int> $counts
     */
    private function replace(string $text, array &$counts, string $kind, string $pattern): string
    {
        return $this->replaceCallback(
            $text,
            $counts,
            $kind,
            $pattern,
            static fn (): string => '[REDACTED:' . $kind . ']'
        );
    }

    /**
     * @param array<string, int> $counts
     * @param callable(array<int|string, string>): string $callback
     */
    private function replaceCallback(string $text, array &$counts, string $kind, string $pattern, callable $callback): string
    {
        $out = preg_replace_callback(
            $pattern,
            static function (array $match) use (&$counts, $kind, $callback): string {
                $replacement = $callback($match);
                if ($replacement === $match[0]) {
                    return $match[0];
                }

                $counts[$kind] = ($counts[$kind] ?? 0) + 1;

                return $replacement;
            },
            $text
        );

        return $out ?? $text;
    }

    private static function luhn(string $digits): bool
    {
        $sum = 0;
        $alternate = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $n = ord($digits[$i]) - 48;
            if ($n < 0 || $n > 9) {
                return false;
            }
            if ($alternate) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $alternate = !$alternate;
        }

        return $sum % 10 === 0;
    }

    private static function entropy(string $value): float
    {
        $length = strlen($value);
        if ($length === 0) {
            return 0.0;
        }

        $freq = count_chars($value, 1);
        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }
}
