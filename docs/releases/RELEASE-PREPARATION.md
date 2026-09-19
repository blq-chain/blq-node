# v0.1.0 verification record

This source snapshot was exported from the recorded working tree and verified
from isolated staging copies on Windows:

- Node and miner Rust formatting, locked dependency checks, and workspace tests
  passed.
- Explorer package installation, tests, and JavaScript syntax checks passed.
- Website local-link checks and desktop/mobile browser layout checks passed.
- The public WebSocket endpoint accepted newHeads, logs, and
  newPendingTransactions subscriptions, then accepted unsubscribe and
  rejected an unsupported subscription.
- Source file hashes are listed in `SHA256SUMS-v0.1.0`.

The native RandomX Windows artifact build requires CMake and an MSVC developer
environment. They were not available on the staging host, so that artifact
build is intentionally recorded as unavailable here, not passed. Linux-native
artifact builds must likewise be performed by a Linux release runner. Existing
release evidence documents live validation separately; this file does not
replace an independent security audit.
