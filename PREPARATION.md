# Preparation Evidence

Status: local source preparation; publication is blocked.

Source revision: `c4bb6c576e7fb75ccf1a5bd359b24e7d73815314` plus allow-listed working-tree changes.
See `source-manifest.json` for file hashes, dependencies, adjustments, and checks.

## Checks

- defaultWorkspaceTests: **passed** (187 tests).
- nativeWorkspaceTests: **passed** (189 tests).
- gatewayUnitTests: **passed** (16 tests).
- publicP2pSeedTcpReachability: **passed**.
- linuxNativeBuild: **not-run**.
- format: **passed**.
- dependencyIsolation: **passed**.
- workspaceCheck: **passed**.

## Export Adjustments

- Self-contained workspace closure and pruned original lockfile.
- Private operational addresses replaced by documentation-only fixture addresses.
- Localhost RPC, two public P2P-only seeds, mining and relay services disabled in example.
- Upstream RandomX test uses native ABI directly for its short test key; production hashing unchanged.
- Build metadata/toolchain conservatively set to tested Rust 1.97.1.

## Outstanding Gates

- Linux-native node and miner builds must pass CI before release.
- Web source and image redistribution licenses require owner approval.
- Private security-reporting contact must be established before publication.

No production deployment, mining, live transaction validation, release tag or GitHub publication was performed.
