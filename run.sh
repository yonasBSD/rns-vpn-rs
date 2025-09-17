#!/usr/bin/env bash

set -e
set -x

cargo build
RNS_VPN_PRIVKEY_PATH="./privkey.pem" \
RNS_VPN_SIGNKEY_PATH="./signkey.pem" \
RUST_LOG=debug RUST_BACKTRACE=1 \
  sudo -E target/debug/rns-vpn -p 4242 -f 127.0.0.1:4243 #-i "vpn-test-client"

exit 0
