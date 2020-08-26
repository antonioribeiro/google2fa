<?php

if (!function_exists('d')) {
    function d($args)
    {
        foreach ($args as $arg) {
            var_dump($arg);
        }
    }
}

if (!function_exists('dd')) {
    function dd()
    {
        d(func_get_args());

        exit();
    }
}
