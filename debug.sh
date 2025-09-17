#!/usr/bin/env bash

set -e
set -x

cargo build
RUST_LOG=debug RUST_BACKTRACE=1 \
  sudo -E nnd target/debug/rns-vpn -p 4242 -f 127.0.0.1:4243 -i "vpn-test-client"

exit 0
