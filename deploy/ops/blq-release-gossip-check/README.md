# BLQ release gossip check

`blq-release-gossip-check` is an operations-only, opt-in validator for the
final live transaction-gossip release gate. It creates a disposable account in
process memory, mines a bounded reward, and sends two zero-value self transfers
through the non-mining nodes.

It never writes a private key, raw signing payload, seed phrase, or raw
transaction to disk or output. The JSON report contains public addresses,
transaction hashes, heights, timings, and pass/fail evidence only.

Run it only during the bounded release-validation window:

```powershell
cargo run -p blq-release-gossip-check -- `
  --live `
  --miner C:\path\to\blq-miner.exe `
  --node39 http://192.0.2.39:8545 `
  --node43 http://192.0.2.43:8546 `
  --node201 http://192.0.2.201:8546 `
  --public-rpc https://rpc.blq-chain.online/rpc `
  --explorer https://explorer.blq-chain.online `
  --report $env:TEMP\blq-release-gossip-evidence.json
```

The miner is restricted to one thread. Every spawned miner is stopped on
success, timeout, or error. The tool is intentionally not a node command,
system service, or CI target.
