# `rns-vpn`

> P2P VPN over Reticulum mesh network

Library and application for VPN client over Reticulum mesh network.

## Building

Building `Reticulum-rs` requires `protoc` binary for compiling `.proto` files.

## Client configuration

`vpn_ip` -- the IP assigned to this client in CIDR format (e.g. `10.0.0.1/24`)

`peers` -- a map of `<ip> = <destination-hash>` pairs for each peer to communicate with
on the network

## Client application

Client application uses a Reticulum UDP interface that is configured with command-line
arguments.

Private keys can be generated with `openssl` tool using the `genkeys.sh` script.

Running with log level INFO will log the destination hash generated for the clients
configured private keys and should be provided to peers to add to their configurations.

Command-line options:

`-p <port>` -- required: local UDP port for Reticulum interface

`-f <ip>:<port>` -- required: IP and port for upstream Reticulum node

`[-i <name>]` -- optional: use string to generate private ID; overrides
creation of identity with `RNS_VPN_PRIVKEY_PATH`/`RNS_VPN_SIGNKEY_PATH` variables

Environment variables:

`RNS_VPN_PRIVKEY_PATH` -- path to X25519 private key in PEM format for Reticulum
identity

`RNS_VPN_SIGNKEY_PATH` -- path to ed25519 signing key in PEM format for Reticulum
identity

`RUST_LOG` -- adjust log level: `trace`, `debug`, `info` (default), `warn`, `error`
