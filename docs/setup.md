# Node Setup And Upgrades

## Build

The checked toolchain is Rust 1.97.1, pinned in `rust-toolchain.toml`.
On Linux install Git, CMake, a C/C++ toolchain and Rust/rustup, then run
`bash scripts/build-native.sh`. Linux execution remains a preparation gate.
On Windows use Visual Studio Build Tools with the C++ and CMake components,
open a developer PowerShell and run `./scripts/build-native.ps1`.

The scripts check out a pinned RandomX commit, link it statically, explicitly
select `native-randomx`, and run both upstream-ABI and BLQ RX/2 vector tests.
Do not distribute a binary built without that feature as a mainnet node.

## Configure And Start

1. Keep `config/native-genesis.json` and the chain/profile parameters unchanged.
2. Configure a writable `node.data_dir` with sufficient filesystem headroom.
3. The example has two P2P-only public seeds in `network.bootstrap_peers`:
   `203.159.95.9:30334` and `31.76.127.228:30334`. A node uses either as its
   first contact, completes the normal authenticated handshake, then learns
   compatible peers through peer exchange. Do not replace these with an HTTPS
    JSON-RPC URL or port.
4. `network.max_saved_peers` defaults to `32`. The node stores only routes
   proven by an authenticated handshake in `data_dir/peer-routes.json`, so it
   can retry healthy learned peers after a restart. Bootstrap peers remain the
   fallback; cached routes never change chain selection.
5. `network.max_inbound_peers` defaults to `18`. This limits incoming P2P
   handlers while preserving six of the 24 P2P sessions for outbound bootstrap,
   sync, and recovery work. Lower it on a small host; it must remain between
   `1` and `18`.
6. Configure a reachable P2P advertised endpoint if accepting inbound peers.
   Do not put an RPC/admin endpoint in the peer list.
7. Keep RPC on localhost. The example permits local administrative operations;
   do not expose port 8545 directly to the Internet. Optional gateway tooling
   must be separately configured with method restrictions and HTTPS.
8. Run `target/release/blq-node full-node --config config/mainnet.toml`.

The example starts without mining. It uses archive storage with a 100 GiB
configured cap; account for database overhead and free-space reserve as well.
A node cannot discover mainnet from nothing. A running process without an
authenticated peer is not evidence of synchronization.

## Linux Service Example

Create a dedicated unprivileged `blq` account and a writable `/srv/blq-node`
directory. Install source/config and the built binary there, review
`deploy/blq-node.service`, and install it in your systemd unit directory.
The service working directory matters because config/data paths are relative.
Use `systemctl daemon-reload` and start only the BLQ service after review.
No install script in this repository changes firewall or production services.

## Upgrade And Rollback

Record the binary SHA-256 and preserve the previous binary, config, and a
consistent backup before upgrading. Stop only the node service, replace only
its binary, restart it, and verify chain ID, genesis, profile, canonical tip,
roots, synchronization, peers and storage reserve. Keep logs if it fails.
Rollback requires a storage-compatible previous binary; never overwrite a
live database or manually select a fork. Do not delete data to repair sync.

## Checks

Run `cargo fmt --all -- --check`, `cargo check --locked --workspace`, and
`cargo test --locked --workspace`. With the RandomX library environment set
by the build script, also run
`cargo test --locked --workspace --features blq-node/native-randomx`.
The fallback tests are development checks, not a mainnet build profile.
