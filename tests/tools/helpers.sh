#!/usr/bin/env bash

function current_directory() {
    SOURCE="${BASH_SOURCE[0]}"

    while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
        DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
        SOURCE="$(readlink "$SOURCE")"
        [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
    done

    CURRENT_DIRECTORY="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
    TESTS_DIRECTORY="$( cd -P "$( dirname "$CURRENT_DIRECTORY" )" >/dev/null 2>&1 && pwd )"
    ROOT_DIRECTORY="$( cd -P "$( dirname "$TESTS_DIRECTORY" )" >/dev/null 2>&1 && pwd )"
}
