# BLQ v0.1.0 Release Note

BLQ v0.1.0 is the first public source and release-artifact preparation for the
live BLQ Proof-of-Work network. This note describes measured validation only;
it is not an independent security audit and does not assign monetary value.

## Public services

- Website: <https://blq-chain.online>
- JSON-RPC: <https://rpc.blq-chain.online/rpc>
- Explorer: <https://explorer.blq-chain.online>
- Bridge: <https://bridge.blq-chain.online>
- WebSocket RPC: <wss://rpc.blq-chain.online/ws>

BLQ uses chain ID `707070`, genesis
`79a7f512edc606d2ef444382099b870edc0c4e78b82b8a3d81d758254e49d352`, and
the BLQ-RX/2 Proof-of-Work profile. Wallets submit signed raw transactions
through `eth_sendRawTransaction`. Solo miners use the public RPC and should
start with one thread.

## Validated scope

- A 1,440-sample no-miner soak completed without failures.
- One-thread public mining and a bounded two-miner canonical/stale race passed.
- Transactions submitted through each non-mining relay node reached the mining
  node, received canonical receipts through all nodes and public RPC, and left
  pending views after inclusion.
- Warp and Unwarp on BLQ Chain, plus both directions of the BLQ Chain/Polygon
  bridge, were operator-tested.
- WebSocket `eth_subscribe` supports `newHeads`, `logs`, and
  `newPendingTransactions`; subscription lifecycle controls are bounded.

## Known limitations

- BLQ has not received an independent external security audit.
- Ethereum compatibility is substantial but is not a claim of complete parity
  with every wallet, RPC method, or contract pattern.
- Contract source verification, fuller token/NFT indexing, multicall, and
  additional analytics APIs are planned post-release work.
- `blq_reportHashrate` is optional telemetry; mining can work when it is not
  available from public RPC.

## Release assets

The public source repositories contain reproducible node and miner build
instructions. Release binaries and SHA-256 checksums are produced from the
tagged source revision; binaries are not committed to source repositories.

Report security issues privately through the publication host's private
vulnerability-reporting feature. Do not include keys, credentials, private
infrastructure details, or exploit payloads in public issues.
