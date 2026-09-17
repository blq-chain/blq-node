# BLQ v0.1.1

This patch release fixes the native RandomX cache used by the upstream
compatibility test. Cache identity now retains the actual key bytes instead of
requiring every key to be 32 bytes.

BLQ consensus mining continues to use the same 32-byte deterministic epoch
seed, so the production BLQ-RX/2 hash path and consensus profile are unchanged.

Run the native build script to verify RandomX and produce the platform binary.
