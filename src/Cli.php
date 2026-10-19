<?php

declare(strict_types=1);

namespace PasteGuard;

final class Cli
{
    public const VERSION = '1.0.0';

    public function run(array $argv): int
    {
        $json = false;
        $check = false;
        $quiet = false;
        $emails = true;
        $ips = false;
        $demo = false;
        $files = [];

        $args = array_slice($argv, 1);
        $end = false;
        foreach ($args as $arg) {
            if (!$end && $arg === '--') {
                $end = true;
                continue;
            }
            if (!$end && str_starts_with($arg, '-') && $arg !== '-') {
                switch ($arg) {
                    case '--json':
                        $json = true;
                        break;
                    case '--check':
                        $check = true;
                        break;
                    case '--quiet':
                        $quiet = true;
                        break;
                    case '--no-email':
                        $emails = false;
                        break;
                    case '--ips':
                        $ips = true;
                        break;
                    case '--demo':
                        $demo = true;
                        break;
                    case '-h':
                    case '--help':
                        $this->help();
                        return 0;
                    case '-v':
                    case '--version':
                        echo self::VERSION . PHP_EOL;
                        return 0;
                    default:
                        fwrite(STDERR, "Option inconnue : {$arg}\n\n");
                        $this->help(STDERR);
                        return 2;
                }
                continue;
            }
            $files[] = $arg;
        }

        if ($demo && $files !== []) {
            fwrite(STDERR, "--demo ne prend pas de fichier.\n");
            return 2;
        }

        $scrubber = new Scrubber($emails, $ips);

        if ($demo) {
            $sample = self::demoSample();
            $result = $scrubber->scrub($sample);
            echo "--- avant ---\n" . $sample . "\n--- apres ---\n" . $result->text;
            if (!str_ends_with($result->text, "\n")) {
                echo "\n";
            }
            if (!$quiet) {
                $this->summary($result);
            }

            return $check && $result->leaked() ? 1 : 0;
        }

        if ($files === []) {
            if (stream_isatty(STDIN)) {
                $this->help();
                return 2;
            }
            $chunks = [];
            $chunks[] = ['name' => null, 'body' => stream_get_contents(STDIN) ?: ''];
        } else {
            $chunks = [];
            foreach ($files as $file) {
                if ($file === '-') {
                    $chunks[] = ['name' => null, 'body' => stream_get_contents(STDIN) ?: ''];
                    continue;
                }
                if (!is_file($file) || !is_readable($file)) {
                    fwrite(STDERR, "Fichier illisible : {$file}\n");
                    return 2;
                }
                $body = file_get_contents($file);
                if ($body === false) {
                    fwrite(STDERR, "Lecture impossible : {$file}\n");
                    return 2;
                }
                $chunks[] = ['name' => $file, 'body' => $body];
            }
        }

        $counts = [];
        $parts = [];
        $multi = count($chunks) > 1;
        foreach ($chunks as $chunk) {
            $result = $scrubber->scrub($chunk['body']);
            foreach ($result->counts as $kind => $count) {
                $counts[$kind] = ($counts[$kind] ?? 0) + $count;
            }
            $body = $result->text;
            if ($multi && $chunk['name'] !== null) {
                $body = "===== {$chunk['name']} =====\n" . $body;
                if (!str_ends_with($body, "\n")) {
                    $body .= "\n";
                }
            }
            $parts[] = $body;
        }

        ksort($counts);
        $merged = new ScrubResult(implode('', $parts), $counts);

        if ($json) {
            echo json_encode([
                'text' => $merged->text,
                'counts' => $merged->counts === [] ? new \stdClass() : $merged->counts,
                'total' => $merged->total(),
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . PHP_EOL;
        } else {
            echo $merged->text;
            if (!$quiet) {
                $this->summary($merged);
            }
        }

        return $check && $merged->leaked() ? 1 : 0;
    }

    private function summary(ScrubResult $result): void
    {
        if (!$result->leaked()) {
            fwrite(STDERR, "pasteguard: rien a masquer\n");
            return;
        }

        $bits = [];
        foreach ($result->counts as $kind => $count) {
            $bits[] = $kind . ' ' . $count;
        }
        fwrite(STDERR, 'pasteguard: masque ' . $result->total() . ' (' . implode(', ', $bits) . ")\n");
    }

    /** @param resource|null $stream */
    private function help($stream = null): void
    {
        $text = <<<TXT
PasteGuard — masque secrets et donnees perso avant de coller un log.

Usage:
  php bin/pasteguard [options] [fichier...]
  cat app.log | php bin/pasteguard

Options:
  --demo        Exemple avant/apres, sans fichier
  --check       Code de sortie 1 si quelque chose a ete masque
  --json        Sortie JSON (text, counts, total)
  --no-email    Ne pas masquer les e-mails
  --ips         Masquer aussi les adresses IPv4
  --quiet       Pas de resume sur stderr
  -h, --help    Cette aide
  -v, --version Version

Sans fichier, lit l'entree standard (un terminal seul affiche l'aide).
Le texte masque va sur stdout, le resume sur stderr.

TXT;
        if ($stream === null) {
            echo $text;
            return;
        }
        fwrite($stream, $text);
    }

    public static function demoSample(): string
    {
        $github = 'ghp_' . str_repeat('a', 36);
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $aws = 'AKIA' . 'IOSFODNN7EXAMPLE';

        return <<<LOG
[2026-10-19 20:00:01] production.ERROR: paiement refuse
user=luc@kamix.app card=4242 4242 4242 4242
Authorization: Bearer {$jwt}
GITHUB_TOKEN={$github}
AWS_ACCESS_KEY_ID={$aws}
DATABASE_URL=postgres://app_user:s3cr3tPass@db.internal:5432/billing
password=changeme
LOG;
    }
}
