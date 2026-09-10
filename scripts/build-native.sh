#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rx="$PWD/.build/RandomX"
if [ ! -d "$rx/.git" ]; then git clone https://github.com/tevador/RandomX.git "$rx"; fi
git -C "$rx" checkout --detach aaafe71322df6602c21a5c72937ac284724ae561
cmake -S "$rx" -B "$rx/build" -DARCH=default
cmake --build "$rx/build" --config Release --parallel 2
export RANDOMX_LIB_DIR="$rx/build"
export RANDOMX_INCLUDE_DIR="$rx/src"
cargo build --locked --release -p blq-node --features native-randomx
cargo test --locked -p blq-pow --features native-randomx
