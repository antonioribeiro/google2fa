#!/bin/bash
source tests/tools/helpers.sh

function main
{
    get_paths

    banner

    $PHPSTAN analyse -c phpstan.neon
    $PSALM
}

function get_paths()
{
    current_directory

    PHPSTAN="$ROOT_DIRECTORY/vendor/bin/phpstan"
    PSALM="$ROOT_DIRECTORY/vendor/bin/psalm"
}

function banner
{
    echo  Google2FA testing framework
    echo -----------------------------
    echo
    echo You can execute these tests by running
    echo - $PHPSTAN
    echo - $PSALM
    echo
}

main
