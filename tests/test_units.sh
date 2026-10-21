#!/usr/bin/env bash
#
# Build and run the unprivileged unit tests for the
# network policy logic (domain and IP handling, verdict
# computation). No root, no BPF kernel load required.
#
# Usage:
#   bash tests/test_units.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN=build/unit_net_policy

if [ ! -f include/cerberus/common.h ]; then
    echo "Run this from the repository root."
    exit 1
fi

if [ ! -f build/ips_core.skel.h ]; then
    # net_policy does not include the skeleton; the build
    # dir is only needed by make.
    :
fi

g++ -O2 -Wall -std=c++17 -Iinclude -Ibuild -Isrc/agent \
    src/agent/net_policy.cpp tests/unit_net_policy.cpp \
    -lbpf -lelf -lz -o "$BIN" || exit 1

"$BIN"
