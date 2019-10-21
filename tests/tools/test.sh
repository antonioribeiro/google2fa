#!/bin/bash
source tests/tools/helpers.sh

function main
{
    get_phpunit_path

    banner

    $PHPUNIT
}

function get_phpunit_path()
{
    current_directory

    PHPUNIT="$ROOT_DIRECTORY/vendor/bin/phpunit"
}

function banner
{
    echo  Google2FA testing framework
    echo -----------------------------
    echo
    echo You can execute these tests by running $PHPUNIT
    echo
}

main
