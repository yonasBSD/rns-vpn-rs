#!/usr/bin/env bash

set -e
set -x

openssl genpkey -algorithm ed25519 -out signkey.pem
openssl genpkey -algorithm X25519 -out privkey.pem

exit 0
