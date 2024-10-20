#!/usr/bin/env bash

export NC='\033[0m' # No Color
export YELLOW='\033[0;33m'
export CYAN='\033[0;36m'
export GREEN='\033[0;32m'
export RED='\033[0;31m'
export MAGENTA='\033[0;35m'
export BG_RED
export BG_NC

BG_RED=$(tput setab 1)
BG_NC=$(tput sgr0)
