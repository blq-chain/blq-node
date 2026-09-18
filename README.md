# BLQ Node

BLQ is a custom Proof-of-Work blockchain. Chain ID: 707070. Genesis:
`79a7f512edc606d2ef444382099b870edc0c4e78b82b8a3d81d758254e49d352`.
The mainnet profile uses BLQ-RX/2, time-based issuance of 0.1 BLQ/minute,
and a 15-second block-time target.

## Build and run

Install current stable Rust, Git, CMake and a C++ compiler (MSVC on Windows,
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

Use stable network connectivity and budget disk for the configured archive
(100 GiB cap in this example), database overhead and filesystem reserve.
Hardware minima require measurement; no unsupported minimum is promised.
Keep database data outside Git. Check node status, disk reserve and sync before
enabling any mining templates. Preserve data and config on upgrades.

## Recovery behavior

Forward recovery uses one active ordered range provider per node. When another
authenticated peer advertises a moving tip, it remains available as a witness
or failover route instead of starting a competing range download against the
same durable recovery cursor. This prevents valid range responses from being
discarded when concurrent providers race the cursor.

The v0.1.2 recovery update changes node synchronization only. It does not
change chain ID, genesis, BLQ-RX/2 Proof of Work, transaction rules, mining
selection, account state, or canonical fork choice.

## Optional gateway

`gateway/` contains the public RPC edge and policy tests. Configure
`BLQ_UPSTREAMS`, `BLQ_MINING_UPSTREAMS`, `BLQ_TRANSACTION_UPSTREAMS`,
`BLQ_EXPECTED_GENESIS_HASH`, and `BLQ_EXPECTED_CONSENSUS_PROFILE` explicitly.
Documentation addresses in defaults are placeholders. Run
`python -m unittest discover -s gateway` and configure HTTPS separately.

## Release source status

This repository contains the v0.1.0 public source snapshot, the v0.1.1 native
RandomX cache correction, and the v0.1.2 recovery update. See
`RELEASE-v0.1.2.md` for the current patch scope; earlier release records remain
available for provenance. `source-manifest.json` records the original exported
snapshot hashes. This source release is not an independent security audit.

## Public services

- https://blq-chain.online
- https://rpc.blq-chain.online/rpc
- https://explorer.blq-chain.online
- https://bridge.blq-chain.online
