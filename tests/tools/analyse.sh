#!/bin/bash
source tests/tools/helpers.sh

function main
{
    get_phpstan_path

    banner

    $PHPSTAN analyse --level max src
}

function get_phpstan_path()
{
    current_directory

    PHPSTAN="$ROOT_DIRECTORY/vendor/bin/phpstan"
}

function banner
{
    echo  Google2FA testing framework
    echo -----------------------------
    echo
    echo You can execute these tests by running $PHPSTAN
    echo
}

main
