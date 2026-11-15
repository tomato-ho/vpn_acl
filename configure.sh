#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build \
  -DVPN_WITH_DB=ON \
  -DVPN_WITH_ADMIN=ON
cmake --build build -j
ctest --test-dir build --output-on-failure

install -m0755 build/vpn-policyd build/vpn-admin build/vpn-policyctl \
                 build/vpn-client-connect build/vpn-client-disconnect \
                 build/vpn-auth-check /usr/local/sbin/
