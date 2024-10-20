#!/bin/sh

message()
{
    echo "${YELLOW}$1${NC}"
}

errorMessage()
{
    echo "${RED}$1${NC}"
}

fatalError()
{
    echo "${RED}FATAL ERROR: $1${NC}"

    exit 1
}

loadColors()
{
    . "$(dirname -- "$0")/../tools/colors.sh"
}

loadColors
