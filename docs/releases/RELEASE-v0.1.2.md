# BLQ v0.1.2

## Recovery synchronization update

This source update prevents concurrent forward-recovery providers from racing
the same durable recovery cursor while peer tips advance. A node keeps one
active ordered range provider; authenticated compatible peers remain eligible
as bounded witnesses and failover candidates once that provider ends.

This avoids stale-response churn during catch-up and allows a recovering node
to continue advancing toward the canonical chain.

## Compatibility

The update does not modify consensus behavior or chain identity. BLQ-RX/2,
chain ID, genesis, transaction validation, block validation, mining selection,
and canonical fork choice are unchanged. Existing chain data and node
configuration do not require a reset or migration.

Build platform artifacts with the native RandomX scripts in `scripts/` and
verify the resulting checksums before deployment. This repository is not an
independent security audit.
