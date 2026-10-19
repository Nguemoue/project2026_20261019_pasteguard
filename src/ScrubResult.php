<?php

declare(strict_types=1);

namespace PasteGuard;

final class ScrubResult
{
    /**
     * @param array<string, int> $counts
     */
    public function __construct(
        public readonly string $text,
        public readonly array $counts,
    ) {}

    public function total(): int
    {
        $total = 0;
        foreach ($this->counts as $count) {
            $total += $count;
        }

        return $total;
    }

    public function leaked(): bool
    {
        return $this->total() > 0;
    }
}
