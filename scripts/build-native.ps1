param([switch]$Fast)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$rx = Join-Path $root '.build/RandomX'
if (!(Test-Path "$rx/.git")) { git clone https://github.com/tevador/RandomX.git $rx; if ($LASTEXITCODE) { throw 'clone failed' } }
git -C $rx checkout --detach aaafe71322df6602c21a5c72937ac284724ae561
if ($LASTEXITCODE) { throw 'RandomX checkout failed' }
cmake -S $rx -B "$rx/build" -DARCH=default
if ($LASTEXITCODE) { throw 'CMake configuration failed' }
cmake --build "$rx/build" --config Release --parallel 2
if ($LASTEXITCODE) { throw 'RandomX build failed' }
$env:RANDOMX_LIB_DIR = if (Test-Path "$rx/build/Release/randomx.lib") { "$rx/build/Release" } else { "$rx/build" }
$env:RANDOMX_INCLUDE_DIR = "$rx/src"
$feature = if ($Fast) { 'native-randomx-fast' } else { 'native-randomx' }
Push-Location $root
try {
    cargo build --locked --release -p blq-node --features $feature
    if ($LASTEXITCODE) { throw 'Rust build failed' }
    cargo test --locked -p blq-pow --features native-randomx
    if ($LASTEXITCODE) { throw 'RX/2 tests failed' }
} finally { Pop-Location }
