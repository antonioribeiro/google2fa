<?php
declare(strict_types = 1);

if (!function_exists('d')) {
    /**
     * @param array<mixed> $args
     */
    function d(array $args): void
    {
        foreach ($args as $arg) {
            var_dump($arg);
        }
    }
}

if (!function_exists('dd')) {
    function dd(): void
    {
        d(func_get_args());

        exit;
    }
}
