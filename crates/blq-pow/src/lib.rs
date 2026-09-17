use blq_primitives::{BlockHeader, Hash256, MAINNET_CHAIN_ID};
use thiserror::Error;

#[cfg(feature = "native-randomx")]
pub const POW_ALGORITHM: &str = "BLQ-RX/2";
#[cfg(not(feature = "native-randomx"))]
pub const POW_ALGORITHM: &str = "BLQ-RX/1";
pub const POW_EPOCH_LENGTH: u64 = 2_048;
pub const POW_DATASET_BYTES: u64 = 256 * 1024 * 1024;
pub const POW_LIGHT_CACHE_BYTES: u64 = 16 * 1024 * 1024;
pub const TEST_SCRATCHPAD_BYTES: usize = 256 * 1024;

#[cfg(feature = "native-randomx")]
mod native_randomx {
    use super::{epoch_seed, pow_preimage, PowResult};
    use blq_primitives::{BlockHeader, Hash256};
    use std::cell::RefCell;
    use std::ffi::c_void;
    use std::sync::{OnceLock, RwLock};

    const RANDOMX_FLAG_HARD_AES: u32 = 2;
    const RANDOMX_FLAG_JIT: u32 = 8;

    #[repr(C)]
    struct RandomXCache {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct RandomXVm {
        _private: [u8; 0],
    }
    #[cfg(feature = "native-randomx-fast")]
    #[repr(C)]
    struct RandomXDataset {
        _private: [u8; 0],
    }

    #[cfg(feature = "native-randomx-fast")]
    struct FastState {
        key: [u8; 32],
        cache: *mut RandomXCache,
        dataset: *mut RandomXDataset,
    }

    #[cfg(feature = "native-randomx-fast")]
    unsafe impl Send for FastState {}

    #[cfg(feature = "native-randomx-fast")]
    impl Drop for FastState {
        fn drop(&mut self) {
            unsafe {
                randomx_release_dataset(self.dataset);
                randomx_release_cache(self.cache);
            }
        }
    }

    #[cfg(feature = "native-randomx-fast")]
    static FAST_STATE: OnceLock<RwLock<Option<FastState>>> = OnceLock::new();

    #[cfg(not(feature = "native-randomx-fast"))]
    struct LightState {
        key: [u8; 32],
        cache: *mut RandomXCache,
        vm: *mut RandomXVm,
    }

    #[cfg(not(feature = "native-randomx-fast"))]
    unsafe impl Send for LightState {}

    #[cfg(not(feature = "native-randomx-fast"))]
    impl Drop for LightState {
        fn drop(&mut self) {
            unsafe {
                randomx_destroy_vm(self.vm);
                randomx_release_cache(self.cache);
            }
        }
    }

    #[cfg(not(feature = "native-randomx-fast"))]
    thread_local! {
        // RandomX VMs are not thread-safe. Each hashing worker owns its VM;
        // this avoids serializing all miner threads behind one global lock.
        static LIGHT_STATE: RefCell<Option<LightState>> = const { RefCell::new(None) };
    }

    unsafe extern "C" {
        fn randomx_get_flags() -> u32;
        fn randomx_alloc_cache(flags: u32) -> *mut RandomXCache;
        fn randomx_init_cache(cache: *mut RandomXCache, key: *const c_void, key_size: usize);
        #[cfg(feature = "native-randomx-fast")]
        fn randomx_alloc_dataset(flags: u32) -> *mut RandomXDataset;
        #[cfg(feature = "native-randomx-fast")]
        fn randomx_dataset_item_count() -> usize;
        #[cfg(feature = "native-randomx-fast")]
        fn randomx_init_dataset(
            dataset: *mut RandomXDataset,
            cache: *mut RandomXCache,
            start_item: usize,
            item_count: usize,
        );
        #[cfg(feature = "native-randomx-fast")]
        fn randomx_release_dataset(dataset: *mut RandomXDataset);
        fn randomx_create_vm(
            flags: u32,
            cache: *mut RandomXCache,
            dataset: *mut c_void,
        ) -> *mut RandomXVm;
        fn randomx_destroy_vm(vm: *mut RandomXVm);
        fn randomx_release_cache(cache: *mut RandomXCache);
        fn randomx_calculate_hash(
            vm: *mut RandomXVm,
            input: *const c_void,
            input_size: usize,
            output: *mut c_void,
        );
    }

    pub fn hash(header: &BlockHeader, genesis_hash: Hash256) -> PowResult {
        let key = epoch_seed(super::epoch_for_height(header.number.0), genesis_hash);
        let input = pow_preimage(header);
        let output = hash_keyed(&key.0, &input);
        PowResult {
            mix_hash: Hash256(output),
            final_hash: Hash256(output),
        }
    }

    fn hash_keyed(key: &[u8], input: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe {
            let detected_flags = randomx_get_flags();
            let cache_flags = detected_flags | RANDOMX_FLAG_JIT | RANDOMX_FLAG_HARD_AES;
            #[cfg(feature = "native-randomx-fast")]
            {
                let fast_state = FAST_STATE.get_or_init(|| RwLock::new(None));
                {
                    let mut state = fast_state.write().expect("RandomX dataset lock poisoned");
                    if state.as_ref().is_none_or(|item| item.key != key) {
                        let cache = randomx_alloc_cache(cache_flags);
                        assert!(!cache.is_null(), "RandomX cache allocation failed");
                        randomx_init_cache(cache, key.as_ptr().cast(), key.len());
                        let dataset = randomx_alloc_dataset(cache_flags);
                        assert!(!dataset.is_null(), "RandomX dataset allocation failed");
                        randomx_init_dataset(dataset, cache, 0, randomx_dataset_item_count());
                        *state = Some(FastState {
                            key: key.try_into().expect("RandomX epoch key must be 32 bytes"),
                            cache,
                            dataset,
                        });
                    }
                }
                let state = fast_state.read().expect("RandomX dataset lock poisoned");
                let state = state.as_ref().expect("RandomX dataset state missing");
                let vm = randomx_create_vm(cache_flags, state.cache, state.dataset.cast());
                assert!(!vm.is_null(), "RandomX VM allocation failed");
                randomx_calculate_hash(
                    vm,
                    input.as_ptr().cast(),
                    input.len(),
                    output.as_mut_ptr().cast(),
                );
                randomx_destroy_vm(vm);
            }
            #[cfg(not(feature = "native-randomx-fast"))]
            {
                LIGHT_STATE.with(|slot| {
                    let mut light_state = slot.borrow_mut();
                    if light_state.as_ref().is_none_or(|state| state.key != key) {
                        let cache = randomx_alloc_cache(cache_flags);
                        assert!(!cache.is_null(), "RandomX cache allocation failed");
                        randomx_init_cache(cache, key.as_ptr().cast(), key.len());
                        let vm = randomx_create_vm(cache_flags, cache, std::ptr::null_mut());
                        assert!(!vm.is_null(), "RandomX VM allocation failed");
                        *light_state = Some(LightState {
                            key: key.try_into().expect("RandomX epoch key must be 32 bytes"),
                            cache,
                            vm,
                        });
                    }
                    let state = light_state.as_ref().expect("RandomX cache state missing");
                    randomx_calculate_hash(
                        state.vm,
                        input.as_ptr().cast(),
                        input.len(),
                        output.as_mut_ptr().cast(),
                    );
                });
            }
        }
        output
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn matches_upstream_api_example_vector() {
            let output = hash_keyed(b"RandomX example key\0", b"RandomX example input\0");
            assert_eq!(
                Hash256(output).to_hex(),
                "8a48e5f9db45ab79d9080574c4d81954fe6ac63842214aff73c244b26330b7c9"
            );
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PowError {
    #[error("unsupported proof of work algorithm")]
    UnsupportedAlgorithm,
    #[error("proof of work epoch does not match block height")]
    InvalidEpoch,
    #[error("proof of work mix hash does not match header")]
    InvalidMixHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowResult {
    pub mix_hash: Hash256,
    pub final_hash: Hash256,
}

pub fn epoch_for_height(height: u64) -> u64 {
    height / POW_EPOCH_LENGTH
}

pub fn epoch_seed(epoch: u64, genesis_hash: Hash256) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POW_ALGORITHM.as_bytes());
    hasher.update(b"-EPOCH-SEED");
    hasher.update(&MAINNET_CHAIN_ID.to_be_bytes());
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&genesis_hash.0);
    Hash256(*hasher.finalize().as_bytes())
}

pub fn pow_preimage(header: &BlockHeader) -> Vec<u8> {
    header.pow_preimage_bytes()
}

pub fn blq_rx_hash(header: &BlockHeader, genesis_hash: Hash256) -> PowResult {
    #[cfg(feature = "native-randomx")]
    {
        return native_randomx::hash(header, genesis_hash);
    }
    #[cfg(not(feature = "native-randomx"))]
    blq_rx_hash_with_scratchpad(header, genesis_hash, TEST_SCRATCHPAD_BYTES)
}

pub fn blq_rx_hash_with_scratchpad(
    header: &BlockHeader,
    genesis_hash: Hash256,
    scratchpad_bytes: usize,
) -> PowResult {
    let epoch = epoch_for_height(header.number.0);
    let seed = epoch_seed(epoch, genesis_hash);
    let input = pow_preimage(header);
    let scratchpad = scratchpad_bytes.max(32).next_power_of_two();
    let lanes = scratchpad / 32;
    let mut memory = vec![[0u8; 32]; lanes];

    for (index, lane) in memory.iter_mut().enumerate() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(POW_ALGORITHM.as_bytes());
        hasher.update(b"-SCRATCHPAD");
        hasher.update(&seed.0);
        hasher.update(&input);
        hasher.update(&(index as u64).to_be_bytes());
        *lane = *hasher.finalize().as_bytes();
    }

    let mut acc = seed.0;
    let rounds = (lanes * 2).max(1_024);
    for round in 0..rounds {
        let pick = usize::from_be_bytes([
            acc[0], acc[1], acc[2], acc[3], acc[4], acc[5], acc[6], acc[7],
        ]) & (lanes - 1);
        let lane = memory[pick];
        let mut hasher = blake3::Hasher::new();
        hasher.update(POW_ALGORITHM.as_bytes());
        hasher.update(b"-MIX");
        hasher.update(&acc);
        hasher.update(&lane);
        hasher.update(&input);
        hasher.update(&(round as u64).to_be_bytes());
        acc = *hasher.finalize().as_bytes();
        memory[pick] = acc;
    }

    let mix_hash = Hash256(acc);
    let mut final_hasher = blake3::Hasher::new();
    final_hasher.update(b"BLQ-POW-FINAL");
    final_hasher.update(&mix_hash.0);
    final_hasher.update(&input);
    PowResult {
        mix_hash,
        final_hash: Hash256(*final_hasher.finalize().as_bytes()),
    }
}

pub fn validate_pow_fields(header: &BlockHeader, genesis_hash: Hash256) -> Result<(), PowError> {
    if header.pow_algorithm != POW_ALGORITHM {
        return Err(PowError::UnsupportedAlgorithm);
    }
    if header.pow_epoch != epoch_for_height(header.number.0) {
        return Err(PowError::InvalidEpoch);
    }
    let result = blq_rx_hash(header, genesis_hash);
    if header.mix_hash != result.mix_hash {
        return Err(PowError::InvalidMixHash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blq_primitives::genesis_header;

    #[test]
    fn epoch_seed_changes_by_epoch() {
        let genesis = genesis_header().hash();
        assert_ne!(epoch_seed(0, genesis), epoch_seed(1, genesis));
    }

    #[test]
    fn pow_hash_is_deterministic() {
        let genesis = genesis_header().hash();
        let mut header = genesis_header();
        header.number.0 = 1;
        header.pow_epoch = epoch_for_height(1);
        header.nonce = 42;
        let first = blq_rx_hash_with_scratchpad(&header, genesis, 1024);
        let second = blq_rx_hash_with_scratchpad(&header, genesis, 1024);
        assert_eq!(first, second);
    }

    #[cfg(feature = "native-randomx")]
    #[test]
    fn native_blq_vector_is_stable() {
        let genesis = genesis_header().hash();
        let mut header = genesis_header();
        header.number.0 = 1;
        header.pow_epoch = epoch_for_height(1);
        header.timestamp_seconds = 10;
        header.nonce = 42;
        let result = blq_rx_hash(&header, genesis);
        assert_eq!(
            genesis.to_hex(),
            "5290fb3bdce2ada5b0336a05f371b044bfd7a288686f760b0a0a9e366538950c"
        );
        assert_eq!(
            result.mix_hash.to_hex(),
            "d373cfcf6cbd5dd16d5e9bae236cfc4895394b20f40877982dbb6c2010e97cd4"
        );
        assert_eq!(result.final_hash, result.mix_hash);
    }
}
