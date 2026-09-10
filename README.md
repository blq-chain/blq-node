# BLQ Node

BLQ is a custom Proof-of-Work blockchain. Chain ID: 707070. Genesis:
`79a7f512edc606d2ef444382099b870edc0c4e78b82b8a3d81d758254e49d352`.
The mainnet profile uses BLQ-RX/2, time-based issuance of 0.1 BLQ/minute,
and block-time V2 activation at 14100 with a 15-second target.

## Build and run

Install the pinned Rust 1.97.1 toolchain, Git, CMake and a C++ compiler (MSVC on Windows,
build-essential on Linux). Run `bash scripts/build-native.sh` on Linux or
`./scripts/build-native.ps1` from a Visual Studio developer PowerShell.
Release builds require native RandomX. A plain fallback Cargo build is not
a mainnet artifact. RandomX v2.0.1 is pinned by commit in the scripts.

Configure `config/mainnet.toml`, then run:
`target/release/blq-node full-node --config config/mainnet.toml`.
RPC binds to localhost and mining is disabled. The example bootstraps through
two public BLQ P2P seed endpoints: `203.159.95.9:30334` and
`31.76.127.228:30334`. Their P2P TCP reachability was checked on 2026-09-11.
The node authenticates a seed before accepting data, then uses authenticated
peer exchange to learn other compatible peers. Never use an RPC port as a peer.
It saves up to 32 proven peer identities and routes in `data/node/peer-routes.json`
so it can reconnect after restart; bootstrap seeds remain the fallback.
`network.max_inbound_peers` defaults to 18, leaving six of the 24 P2P sessions
available for outbound synchronization and recovery.

Use stable network connectivity and budget disk for the configured archive
(100 GiB cap in this example), database overhead and filesystem reserve.
Hardware minima require measurement; no unsupported minimum is promised.
Keep database data outside Git. Check node status, disk reserve and sync before
enabling any mining templates. Preserve data and config on upgrades.
See [setup and rollback instructions](docs/setup.md) for service installation.

## Optional gateway

`gateway/` contains the public RPC edge and policy tests. Configure
`BLQ_UPSTREAMS`, `BLQ_MINING_UPSTREAMS`, `BLQ_TRANSACTION_UPSTREAMS`,
`BLQ_EXPECTED_GENESIS_HASH`, and `BLQ_EXPECTED_CONSENSUS_PROFILE` explicitly.
Documentation addresses in defaults are placeholders. Run
`python -m unittest discover -s gateway` and configure HTTPS separately.

## Preparation status

This is a working-tree source export. Consult the parent preparation manifest
for provenance and checks. It is not a signed release or an independent audit.

## Public services

- https://blq-chain.online
- https://rpc.blq-chain.online/rpc
- https://explorer.blq-chain.online
- https://bridge.blq-chain.online
