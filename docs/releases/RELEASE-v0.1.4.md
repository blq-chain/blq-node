# BLQ v0.1.4

## Canonical-gossip recovery update

This patch fixes a forward-recovery edge case exposed by a live moving tip. A
node can receive the first missing block through ordinary authenticated P2P
gossip while it also owns a durable range-recovery cursor. The node now records
that proven canonical root, advances its cursor through the locally verified
prefix, and requests only the next missing height.

Timed-out bounded recovery transports now end cleanly. The persisted cursor
and verified spool remain available to the next authenticated provider, rather
than retaining a peer-closed connection.

## Compatibility

This changes synchronization bookkeeping only. Chain ID, genesis, BLQ-RX/2,
transaction and block validation, mining rules, and canonical fork choice are
unchanged. Existing node data and configuration require no reset or migration.

Build platform artifacts with the native RandomX scripts in `scripts/` and
verify their checksums before deployment. This repository is not an independent
security audit.
