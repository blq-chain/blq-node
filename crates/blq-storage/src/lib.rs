use blq_primitives::{
    hash_bytes, Address, Bix, Block, BlockHeader, BlockNumber, Hash256, Receipt, Transaction,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("block was not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub trait ChainStorage {
    fn best_header(&self) -> Result<BlockHeader, StorageError>;
    fn header_by_hash(&self, hash: Hash256) -> Result<BlockHeader, StorageError>;
    fn header_by_number(&self, number: BlockNumber) -> Result<BlockHeader, StorageError>;
    fn insert_header(&mut self, header: BlockHeader) -> Result<(), StorageError>;
    fn insert_block(&mut self, block: Block) -> Result<(), StorageError>;
    fn block_by_number(&self, number: u64) -> Result<Block, StorageError>;
}

#[derive(Default)]
pub struct MemoryStorage {
    blocks: Vec<Block>,
}

impl ChainStorage for MemoryStorage {
    fn best_header(&self) -> Result<BlockHeader, StorageError> {
        self.blocks
            .last()
            .map(|block| block.header.clone())
            .ok_or(StorageError::NotFound)
    }

    fn header_by_hash(&self, hash: Hash256) -> Result<BlockHeader, StorageError> {
        self.blocks
            .iter()
            .find(|block| block.header.hash() == hash)
            .map(|block| block.header.clone())
            .ok_or(StorageError::NotFound)
    }

    fn header_by_number(&self, number: BlockNumber) -> Result<BlockHeader, StorageError> {
        self.blocks
            .iter()
            .find(|block| block.header.number == number)
            .map(|block| block.header.clone())
            .ok_or(StorageError::NotFound)
    }

    fn insert_header(&mut self, header: BlockHeader) -> Result<(), StorageError> {
        self.blocks.push(Block {
            header,
            transactions: Vec::new(),
            receipts: Vec::new(),
        });
        Ok(())
    }

    fn insert_block(&mut self, block: Block) -> Result<(), StorageError> {
        self.blocks.push(block);
        Ok(())
    }

    fn block_by_number(&self, number: u64) -> Result<Block, StorageError> {
        self.blocks
            .iter()
            .find(|block| block.header.number.0 == number)
            .cloned()
            .ok_or(StorageError::NotFound)
    }
}

pub struct FileStorage {
    data_dir: PathBuf,
    blocks_path: PathBuf,
    headers_path: PathBuf,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
}

pub struct SledStorage {
    data_dir: PathBuf,
    db: sled::Db,
    defer_flush: AtomicBool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GenerationStatus {
    Active,
    Staging,
    Verified,
    Retired,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationManifest {
    pub generation_id: u64,
    pub status: GenerationStatus,
    pub canonical_height: u64,
    pub canonical_hash: Hash256,
    pub state_root: Hash256,
    pub profile_fingerprint: String,
    pub finalized_height: u64,
    pub replay_checkpoint: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayCheckpoint {
    pub generation_id: u64,
    pub height: u64,
    pub block_hash: Hash256,
    pub state_root: Hash256,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationPublicationRecord {
    pub generation_id: u64,
    pub manifest_checksum: Hash256,
}

/// A narrow, crash-recoverable publication intent for a canonical fork suffix.
/// The Sled data batch is atomic; this file only bridges the small interval
/// between that batch and the derived generation-manifest refresh.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuffixPublicationRecord {
    pub previous_manifest: GenerationManifest,
    pub target_manifest: GenerationManifest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationSnapshot {
    pub generation_id: u64,
    pub height: u64,
    pub block_hash: Hash256,
    pub state_root: Hash256,
    pub profile_fingerprint: String,
    pub finalized_height: u64,
    pub native_accounts: BTreeMap<Address, (Bix, u64)>,
    #[serde(with = "evm_snapshot_serde")]
    pub evm_accounts: EvmStateSnapshot,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The mutable execution portion of a generation checkpoint. Unlike the
/// legacy `GenerationSnapshot`, this deliberately excludes canonical block
/// bodies, receipts, logs, and indexes so a recovery job can stage state
/// without duplicating an archive database.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionSnapshot {
    pub generation_id: u64,
    pub height: u64,
    pub block_hash: Hash256,
    pub state_root: Hash256,
    pub profile_fingerprint: String,
    pub finalized_height: u64,
    pub native_accounts: BTreeMap<Address, (Bix, u64)>,
    #[serde(with = "evm_snapshot_serde")]
    pub evm_accounts: EvmStateSnapshot,
}

impl From<&GenerationSnapshot> for ExecutionSnapshot {
    fn from(snapshot: &GenerationSnapshot) -> Self {
        Self {
            generation_id: snapshot.generation_id,
            height: snapshot.height,
            block_hash: snapshot.block_hash,
            state_root: snapshot.state_root,
            profile_fingerprint: snapshot.profile_fingerprint.clone(),
            finalized_height: snapshot.finalized_height,
            native_accounts: snapshot.native_accounts.clone(),
            evm_accounts: snapshot.evm_accounts.clone(),
        }
    }
}

const GENERATION_MANIFEST_FILE: &str = "generation-manifest.json";
const GENERATION_CHECKPOINT_FILE: &str = "replay-checkpoint.json";
const GENERATION_PUBLICATION_FILE: &str = "publication-record.json";
const SUFFIX_PUBLICATION_FILE: &str = "suffix-publication.json";
const ACTIVE_GENERATION_FILE: &str = "active-generation.json";
const SNAPSHOT_PREFIX: &str = "snapshot-";
const EXECUTION_SNAPSHOT_PREFIX: &str = "execution-snapshot-";

#[derive(Debug, Serialize, Deserialize)]
struct StoredReceipt {
    receipt: Receipt,
    header: BlockHeader,
    transaction_index: usize,
    transaction: Transaction,
}

const LOG_INDEX_VERSION: &[u8] = b"state:log-index:version";
const EVM_SNAPSHOT_PREFIX: &str = "state:evm:snapshot:";

pub type EvmAccountSnapshot = (Bix, u64, Vec<u8>, BTreeMap<Hash256, Hash256>);
pub type EvmStateSnapshot = BTreeMap<Address, EvmAccountSnapshot>;
type SerializedEvmSnapshotEntry = (Address, (Bix, u64, Vec<u8>, Vec<(Hash256, Hash256)>));

mod evm_snapshot_serde {
    use super::{EvmStateSnapshot, SerializedEvmSnapshotEntry};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S>(value: &EvmStateSnapshot, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries = value
            .iter()
            .map(|(address, (balance, nonce, code, storage))| {
                (
                    *address,
                    (
                        *balance,
                        *nonce,
                        code.clone(),
                        storage.iter().map(|(key, value)| (*key, *value)).collect(),
                    ),
                )
            })
            .collect::<Vec<SerializedEvmSnapshotEntry>>();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<EvmStateSnapshot, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<SerializedEvmSnapshotEntry>::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|(address, (balance, nonce, code, storage))| {
                (
                    address,
                    (balance, nonce, code, storage.into_iter().collect()),
                )
            })
            .collect::<BTreeMap<_, _>>())
    }
}

impl SledStorage {
    fn sync_file(path: &Path) -> Result<(), StorageError> {
        #[cfg(windows)]
        {
            // Windows keeps the read handle opened by sync_all incompatible
            // with an immediate atomic rename on this runtime. The Linux
            // deployment path below performs the durability barrier.
            let _ = path;
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            let file = File::open(path).map_err(|err| StorageError::Io(err.to_string()))?;
            file.sync_all()
                .map_err(|err| StorageError::Io(err.to_string()))?;
            drop(file);
            Ok(())
        }
    }

    fn flush_db(&self) -> Result<(), StorageError> {
        if self.defer_flush.load(Ordering::Acquire) {
            return Ok(());
        }
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn begin_batch(&self) {
        self.defer_flush.store(true, Ordering::Release);
    }

    pub fn flush_batch(&self) -> Result<(), StorageError> {
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn end_batch(&self) -> Result<(), StorageError> {
        self.flush_batch()?;
        self.defer_flush.store(false, Ordering::Release);
        Ok(())
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let data_dir = path.as_ref().to_path_buf();
        // Archive generations can be much larger than the host RAM. Keep the
        // storage engine's block cache bounded so validation/index recovery
        // remains disk-backed instead of letting a restart exhaust the node.
        let db = sled::Config::default()
            .path(&data_dir)
            .cache_capacity(128 * 1024 * 1024)
            .open()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        let storage = Self {
            data_dir,
            db,
            defer_flush: AtomicBool::new(false),
        };
        // Log indexes are derived query acceleration data. Do not rebuild an
        // entire archive synchronously on process startup: a node must first
        // be able to open its canonical generation and serve/sync safely.
        // New blocks are indexed on insertion; an explicit maintenance pass
        // can rebuild legacy history without making boot availability depend
        // on it.
        // Current EVM state is persisted independently. Seeding a legacy
        // historical snapshot may scan a large archive, so keep it out of the
        // availability-critical open path just like log-index maintenance.
        storage.recover_suffix_publication()?;
        storage.recover_generation_state()?;
        Ok(storage)
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn has_persisted_native_accounts(&self) -> Result<bool, StorageError> {
        self.db
            .scan_prefix(b"account:")
            .next()
            .transpose()
            .map(|entry| entry.is_some())
            .map_err(|err| StorageError::Io(err.to_string()))
    }

    pub fn generation_manifest_path(path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().join(GENERATION_MANIFEST_FILE)
    }

    pub fn replay_checkpoint_path(path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().join(GENERATION_CHECKPOINT_FILE)
    }

    pub fn generation_publication_path(path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().join(GENERATION_PUBLICATION_FILE)
    }

    pub fn suffix_publication_path(path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().join(SUFFIX_PUBLICATION_FILE)
    }

    pub fn active_generation_path(root: impl AsRef<Path>) -> PathBuf {
        root.as_ref().join(ACTIVE_GENERATION_FILE)
    }

    pub fn load_active_generation(root: impl AsRef<Path>) -> Result<Option<u64>, StorageError> {
        let path = Self::active_generation_path(root);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|err| StorageError::Io(err.to_string()))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|err| {
            StorageError::Serialization(format!("invalid active generation: {err}"))
        })?;
        value
            .get("generation_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| StorageError::Serialization("active generation id is missing".into()))
            .map(Some)
    }

    fn write_active_generation(root: &Path, generation_id: u64) -> Result<(), StorageError> {
        fs::create_dir_all(root).map_err(|err| StorageError::Io(err.to_string()))?;
        let temporary = root.join(format!("{ACTIVE_GENERATION_FILE}.tmp"));
        let bytes = serde_json::to_vec(&serde_json::json!({ "generation_id": generation_id }))
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        fs::write(&temporary, bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        Self::sync_file(&temporary)?;
        fs::rename(&temporary, Self::active_generation_path(root))
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn activate_generation(
        root: impl AsRef<Path>,
        generation_id: u64,
    ) -> Result<(), StorageError> {
        Self::write_active_generation(root.as_ref(), generation_id)
    }

    pub fn load_generation_manifest(
        path: impl AsRef<Path>,
    ) -> Result<Option<GenerationManifest>, StorageError> {
        let path = Self::generation_manifest_path(path);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|err| StorageError::Io(err.to_string()))?;
        serde_json::from_slice(&bytes).map(Some).map_err(|err| {
            StorageError::Serialization(format!("invalid generation manifest: {err}"))
        })
    }

    pub fn write_generation_manifest(
        path: impl AsRef<Path>,
        manifest: &GenerationManifest,
    ) -> Result<(), StorageError> {
        let path = path.as_ref();
        fs::create_dir_all(path).map_err(|err| StorageError::Io(err.to_string()))?;
        let temporary = path.join(format!("{GENERATION_MANIFEST_FILE}.tmp"));
        let bytes = serde_json::to_vec_pretty(manifest)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        fs::write(&temporary, bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        Self::sync_file(&temporary)?;
        fs::rename(&temporary, Self::generation_manifest_path(path))
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn load_replay_checkpoint(
        path: impl AsRef<Path>,
    ) -> Result<Option<ReplayCheckpoint>, StorageError> {
        let path = Self::replay_checkpoint_path(path);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|err| StorageError::Io(err.to_string()))?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| StorageError::Serialization(format!("invalid replay checkpoint: {err}")))
    }

    pub fn write_replay_checkpoint(
        path: impl AsRef<Path>,
        checkpoint: &ReplayCheckpoint,
    ) -> Result<(), StorageError> {
        let path = path.as_ref();
        fs::create_dir_all(path).map_err(|err| StorageError::Io(err.to_string()))?;
        let temporary = path.join(format!("{GENERATION_CHECKPOINT_FILE}.tmp"));
        let bytes = serde_json::to_vec_pretty(checkpoint)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        fs::write(&temporary, bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        Self::sync_file(&temporary)?;
        fs::rename(&temporary, Self::replay_checkpoint_path(path))
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    fn manifest_checksum(manifest: &GenerationManifest) -> Result<Hash256, StorageError> {
        let bytes = serde_json::to_vec(manifest)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        Ok(hash_bytes(&bytes))
    }

    pub fn load_generation_publication(
        path: impl AsRef<Path>,
    ) -> Result<Option<GenerationPublicationRecord>, StorageError> {
        let path = Self::generation_publication_path(path);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|err| StorageError::Io(err.to_string()))?;
        serde_json::from_slice(&bytes).map(Some).map_err(|err| {
            StorageError::Serialization(format!("invalid generation publication record: {err}"))
        })
    }

    pub fn write_generation_publication(
        path: impl AsRef<Path>,
        manifest: &GenerationManifest,
    ) -> Result<(), StorageError> {
        let path = path.as_ref();
        fs::create_dir_all(path).map_err(|err| StorageError::Io(err.to_string()))?;
        let record = GenerationPublicationRecord {
            generation_id: manifest.generation_id,
            manifest_checksum: Self::manifest_checksum(manifest)?,
        };
        let temporary = path.join(format!("{GENERATION_PUBLICATION_FILE}.tmp"));
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        fs::write(&temporary, bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        Self::sync_file(&temporary)?;
        fs::rename(&temporary, Self::generation_publication_path(path))
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn load_suffix_publication(
        path: impl AsRef<Path>,
    ) -> Result<Option<SuffixPublicationRecord>, StorageError> {
        let path = Self::suffix_publication_path(path);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|err| StorageError::Io(err.to_string()))?;
        serde_json::from_slice(&bytes).map(Some).map_err(|err| {
            StorageError::Serialization(format!("invalid suffix publication record: {err}"))
        })
    }

    fn write_suffix_publication(
        path: impl AsRef<Path>,
        record: &SuffixPublicationRecord,
    ) -> Result<(), StorageError> {
        let root = path.as_ref();
        fs::create_dir_all(root).map_err(|err| StorageError::Io(err.to_string()))?;
        let temporary = root.join(format!("{SUFFIX_PUBLICATION_FILE}.tmp"));
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        fs::write(&temporary, bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        Self::sync_file(&temporary)?;
        fs::rename(&temporary, Self::suffix_publication_path(root))
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    fn clear_suffix_publication(path: impl AsRef<Path>) -> Result<(), StorageError> {
        let path = Self::suffix_publication_path(path);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StorageError::Io(err.to_string())),
        }
    }

    fn sync_suffix_replay_checkpoint(
        path: impl AsRef<Path>,
        manifest: &GenerationManifest,
    ) -> Result<(), StorageError> {
        let root = path.as_ref();
        match manifest.replay_checkpoint {
            Some(height) => Self::write_replay_checkpoint(
                root,
                &ReplayCheckpoint {
                    generation_id: manifest.generation_id,
                    height,
                    block_hash: manifest.canonical_hash,
                    state_root: manifest.state_root,
                },
            ),
            None => match fs::remove_file(Self::replay_checkpoint_path(root)) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
                Err(err) => Err(StorageError::Io(err.to_string())),
            },
        }
    }

    pub fn generation_path(root: impl AsRef<Path>, generation_id: u64) -> PathBuf {
        root.as_ref()
            .join(format!("generation-{generation_id:020}"))
    }

    pub fn staging_generation_path(root: impl AsRef<Path>, generation_id: u64) -> PathBuf {
        root.as_ref()
            .join(format!("generation-{generation_id:020}.staging"))
    }

    pub fn create_staging_generation(
        root: impl AsRef<Path>,
        manifest: &GenerationManifest,
    ) -> Result<PathBuf, StorageError> {
        if manifest.status != GenerationStatus::Staging {
            return Err(StorageError::Serialization(
                "staging generation must have staging status".into(),
            ));
        }
        let path = Self::staging_generation_path(root, manifest.generation_id);
        if path.exists() {
            return Err(StorageError::Io(format!(
                "staging generation already exists: {}",
                path.display()
            )));
        }
        fs::create_dir_all(&path).map_err(|err| StorageError::Io(err.to_string()))?;
        Self::write_generation_manifest(&path, manifest)?;
        Ok(path)
    }

    pub fn publish_staging_generation(
        root: impl AsRef<Path>,
        generation_id: u64,
        manifest: &GenerationManifest,
    ) -> Result<PathBuf, StorageError> {
        if manifest.generation_id != generation_id || manifest.status != GenerationStatus::Verified
        {
            return Err(StorageError::Serialization(
                "only a matching verified generation can be published".into(),
            ));
        }
        let root = root.as_ref();
        let staging = Self::staging_generation_path(root, generation_id);
        if !staging.exists() {
            return Err(StorageError::Io(format!(
                "staging generation is missing: {}",
                staging.display()
            )));
        }
        Self::write_generation_manifest(&staging, manifest)?;
        Self::write_generation_publication(&staging, manifest)?;
        let staged = Self::open(&staging)?;
        staged.verify_generation_manifest()?;
        staged
            .db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        drop(staged);
        let active = Self::generation_path(root, generation_id);
        if active.exists() {
            return Err(StorageError::Io(format!(
                "generation already published: {}",
                active.display()
            )));
        }
        fs::rename(&staging, &active).map_err(|err| StorageError::Io(err.to_string()))?;
        Self::write_active_generation(root, generation_id)?;
        Ok(active)
    }

    /// Verifies that the manifest, durable replay checkpoint, and stored
    /// canonical tip all describe the same generation. This is deliberately
    /// strict: callers must never "repair" a manifest from partial data.
    pub fn verify_generation_manifest(&self) -> Result<GenerationManifest, StorageError> {
        let manifest = Self::load_generation_manifest(&self.data_dir)?.ok_or_else(|| {
            StorageError::Serialization("generation manifest is missing".to_string())
        })?;
        if matches!(
            manifest.status,
            GenerationStatus::Staging | GenerationStatus::Retired | GenerationStatus::Failed
        ) {
            return Err(StorageError::Serialization(
                "generation manifest is not publishable".to_string(),
            ));
        }
        let best = self.best_header()?;
        if manifest.canonical_height != best.number.0
            || manifest.canonical_hash != best.hash()
            || manifest.state_root != best.state_root
        {
            return Err(StorageError::Serialization(format!(
                "generation manifest does not match stored canonical tip (manifest {} {}, storage {} {})",
                manifest.canonical_height,
                manifest.canonical_hash.to_hex(),
                best.number.0,
                best.hash().to_hex()
            )));
        }
        let stale_publication =
            if let Some(record) = Self::load_generation_publication(&self.data_dir)? {
                if record.generation_id != manifest.generation_id {
                    return Err(StorageError::Serialization(
                        "generation publication record does not match its manifest".to_string(),
                    ));
                }
                record.manifest_checksum != Self::manifest_checksum(&manifest)?
            } else {
                false
            };
        match (
            manifest.replay_checkpoint,
            Self::load_replay_checkpoint(&self.data_dir)?,
        ) {
            (Some(height), Some(checkpoint)) => {
                if checkpoint.generation_id != manifest.generation_id
                    || checkpoint.height != height
                    || checkpoint.height > best.number.0
                {
                    return Err(StorageError::Serialization(
                        "generation replay checkpoint does not match its manifest".to_string(),
                    ));
                }
                let header = self.header_by_number(BlockNumber(checkpoint.height))?;
                if header.hash() != checkpoint.block_hash
                    || header.state_root != checkpoint.state_root
                {
                    return Err(StorageError::Serialization(
                        "generation replay checkpoint does not match canonical storage".to_string(),
                    ));
                }
            }
            (Some(_), None) => {
                return Err(StorageError::Serialization(
                    "generation manifest requires a missing replay checkpoint".to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(StorageError::Serialization(
                    "generation has an unreferenced replay checkpoint".to_string(),
                ));
            }
            (None, None) => {}
        }
        // The publication record is derived from the active manifest. Older
        // builds updated a live manifest after each canonical extension but
        // left this checksum behind, making a fully valid generation look
        // corrupt after restart. Repair only after every independent durable
        // manifest, tip, and checkpoint check above succeeds.
        if stale_publication {
            Self::write_generation_publication(&self.data_dir, &manifest)?;
        }
        Ok(manifest)
    }

    fn recover_suffix_publication(&self) -> Result<(), StorageError> {
        let Some(record) = Self::load_suffix_publication(&self.data_dir)? else {
            return Ok(());
        };
        let best = self.best_header()?;
        let target = &record.target_manifest;
        let previous = &record.previous_manifest;
        if best.number.0 == target.canonical_height
            && best.hash() == target.canonical_hash
            && best.state_root == target.state_root
        {
            Self::sync_suffix_replay_checkpoint(&self.data_dir, target)?;
            Self::write_generation_manifest(&self.data_dir, target)?;
            Self::write_generation_publication(&self.data_dir, target)?;
            Self::clear_suffix_publication(&self.data_dir)?;
            return Ok(());
        }
        if best.number.0 == previous.canonical_height
            && best.hash() == previous.canonical_hash
            && best.state_root == previous.state_root
        {
            // The atomic data batch was never committed. The previous
            // manifest remains authoritative, so discard only the intent.
            Self::clear_suffix_publication(&self.data_dir)?;
            return Ok(());
        }
        Err(StorageError::Serialization(
            "suffix publication journal does not match stored canonical tip".to_string(),
        ))
    }

    pub fn recover_generation_state(&self) -> Result<(), StorageError> {
        let root = self.data_dir.join("generations");
        if !root.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&root).map_err(|err| StorageError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
            if entry.file_name().to_string_lossy().ends_with(".staging") {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
        let active_id = Self::load_active_generation(&root)?;
        if let Some(id) = active_id {
            let active = Self::generation_path(&root, id);
            if let Some(manifest) = Self::load_generation_manifest(&active)? {
                if manifest.status == GenerationStatus::Verified
                    || manifest.status == GenerationStatus::Active
                {
                    if Self::generation_path_is_valid(&active)? {
                        return Ok(());
                    }
                    let mut failed = manifest;
                    failed.status = GenerationStatus::Failed;
                    Self::write_generation_manifest(&active, &failed)?;
                }
            }
        }
        let fallback = self.verified_generation_paths(&root)?.into_iter().next();
        if let Some((generation_id, path)) = fallback {
            Self::write_active_generation(&root, generation_id)?;
            if let Some(mut manifest) = Self::load_generation_manifest(&path)? {
                manifest.status = GenerationStatus::Active;
                Self::write_generation_manifest(&path, &manifest)?;
            }
        }
        Ok(())
    }

    fn verified_generation_paths(&self, root: &Path) -> Result<Vec<(u64, PathBuf)>, StorageError> {
        let mut generations = Vec::new();
        if !root.exists() {
            return Ok(generations);
        }
        for entry in fs::read_dir(root).map_err(|err| StorageError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("generation-") || name.ends_with(".staging") {
                continue;
            }
            let Ok(generation_id) = name.trim_start_matches("generation-").parse::<u64>() else {
                continue;
            };
            if let Some(manifest) = Self::load_generation_manifest(entry.path())? {
                if (manifest.status == GenerationStatus::Verified
                    || manifest.status == GenerationStatus::Active)
                    && Self::generation_path_is_valid(&entry.path())?
                {
                    generations.push((generation_id, entry.path()));
                }
            }
        }
        generations.sort_by_key(|(generation_id, _)| std::cmp::Reverse(*generation_id));
        Ok(generations)
    }

    fn generation_path_is_valid(path: &Path) -> Result<bool, StorageError> {
        let Some(manifest) = Self::load_generation_manifest(path)? else {
            return Ok(false);
        };
        if !matches!(
            manifest.status,
            GenerationStatus::Verified | GenerationStatus::Active
        ) {
            return Ok(false);
        }
        // Some historical tests and migrations create a manifest before the
        // sled files exist. Treat those as metadata-only; NodeStorage performs
        // the full chain validation before serving them. Real generations have
        // sled's durable configuration file and must pass the strict check.
        if !path.join("conf").exists() {
            return Ok(true);
        }
        let storage = Self::open(path)?;
        Ok(storage.verify_generation_manifest().is_ok())
    }

    pub fn prune_old_generations(root: impl AsRef<Path>) -> Result<(), StorageError> {
        let root = root.as_ref();
        let mut generations = Vec::new();
        if !root.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(root).map_err(|err| StorageError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("generation-") || name.ends_with(".staging") {
                continue;
            }
            let Ok(generation_id) = name.trim_start_matches("generation-").parse::<u64>() else {
                continue;
            };
            generations.push((generation_id, entry.path()));
        }
        generations.sort_by_key(|(generation_id, _)| std::cmp::Reverse(*generation_id));
        for (_, path) in generations.into_iter().skip(2) {
            let _ = fs::remove_dir_all(path);
        }
        Ok(())
    }

    pub fn remove_staging_generation(
        root: impl AsRef<Path>,
        generation_id: u64,
    ) -> Result<(), StorageError> {
        let path = Self::staging_generation_path(root, generation_id);
        if path.exists() {
            fs::remove_dir_all(path).map_err(|err| StorageError::Io(err.to_string()))?;
        }
        Ok(())
    }

    pub fn snapshot_path(path: impl AsRef<Path>, height: u64) -> PathBuf {
        path.as_ref()
            .join(format!("{SNAPSHOT_PREFIX}{height:020}.json"))
    }

    pub fn execution_snapshot_path(path: impl AsRef<Path>, height: u64) -> PathBuf {
        path.as_ref()
            .join(format!("{EXECUTION_SNAPSHOT_PREFIX}{height:020}.json"))
    }

    pub fn create_execution_snapshot(
        &self,
        path: impl AsRef<Path>,
        generation_id: u64,
        height: u64,
        block_hash: Hash256,
        profile_fingerprint: String,
        finalized_height: u64,
    ) -> Result<PathBuf, StorageError> {
        let block = self.block_by_number(height)?;
        if block.header.hash() != block_hash {
            return Err(StorageError::Serialization(
                "execution snapshot block hash does not match canonical storage".into(),
            ));
        }
        let snapshot = ExecutionSnapshot {
            generation_id,
            height,
            block_hash,
            state_root: block.header.state_root,
            profile_fingerprint,
            finalized_height,
            native_accounts: self.account_snapshot()?,
            evm_accounts: self.evm_account_snapshot()?,
        };
        Self::write_execution_snapshot(path, &snapshot)
    }

    pub fn write_execution_snapshot(
        path: impl AsRef<Path>,
        snapshot: &ExecutionSnapshot,
    ) -> Result<PathBuf, StorageError> {
        let path = Self::execution_snapshot_path(path, snapshot.height);
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        let temporary = path.with_extension("json.tmp");
        fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))
            .map_err(|err| StorageError::Io(err.to_string()))?;
        fs::write(&temporary, bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        fs::rename(&temporary, &path).map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(path)
    }

    pub fn load_execution_snapshot(
        path: impl AsRef<Path>,
    ) -> Result<ExecutionSnapshot, StorageError> {
        // A legacy GenerationSnapshot may contain an archive-sized `entries`
        // array. Deserialize the execution view directly from a buffered
        // stream so serde can skip that field without first allocating the
        // entire JSON document in memory.
        let file = File::open(path).map_err(|err| StorageError::Io(err.to_string()))?;
        serde_json::from_reader(std::io::BufReader::new(file)).map_err(|err| {
            StorageError::Serialization(format!("invalid execution snapshot: {err}"))
        })
    }

    pub fn create_snapshot(
        &self,
        path: impl AsRef<Path>,
        generation_id: u64,
        height: u64,
        block_hash: Hash256,
        profile_fingerprint: String,
        finalized_height: u64,
    ) -> Result<PathBuf, StorageError> {
        let block = self.block_by_number(height)?;
        if block.header.hash() != block_hash {
            return Err(StorageError::Serialization(
                "snapshot block hash does not match canonical storage".into(),
            ));
        }
        let snapshot = GenerationSnapshot {
            generation_id,
            height,
            block_hash,
            state_root: block.header.state_root,
            profile_fingerprint,
            finalized_height,
            native_accounts: self.account_snapshot()?,
            evm_accounts: self.evm_account_snapshot()?,
            entries: self
                .db
                .iter()
                .map(|item| {
                    item.map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .map_err(|err| StorageError::Io(err.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        Self::write_snapshot(path, &snapshot)
    }

    /// Persists a complete, already-validated snapshot with the same atomic
    /// replace semantics as a snapshot created from local state.
    pub fn write_snapshot(
        path: impl AsRef<Path>,
        snapshot: &GenerationSnapshot,
    ) -> Result<PathBuf, StorageError> {
        let path = Self::snapshot_path(path, snapshot.height);
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        let temporary = path.with_extension("json.tmp");
        fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))
            .map_err(|err| StorageError::Io(err.to_string()))?;
        fs::write(&temporary, bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        fs::rename(&temporary, &path).map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(path)
    }

    pub fn load_snapshot(path: impl AsRef<Path>) -> Result<GenerationSnapshot, StorageError> {
        let bytes = fs::read(path).map_err(|err| StorageError::Io(err.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|err| {
            StorageError::Serialization(format!("invalid generation snapshot: {err}"))
        })
    }

    pub fn latest_snapshot_at_or_before(
        path: impl AsRef<Path>,
        height: u64,
        expected_profile: &str,
    ) -> Result<Option<GenerationSnapshot>, StorageError> {
        let root = path.as_ref();
        if !root.exists() {
            return Ok(None);
        }
        let mut candidates = Vec::new();
        for entry in fs::read_dir(root).map_err(|err| StorageError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(SNAPSHOT_PREFIX) || !name.ends_with(".json") {
                continue;
            }
            let snapshot = Self::load_snapshot(entry.path())?;
            if snapshot.height <= height && snapshot.profile_fingerprint == expected_profile {
                candidates.push(snapshot);
            }
        }
        candidates.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.height));
        Ok(candidates.into_iter().next())
    }

    /// Loads the newest usable execution checkpoint without deserializing the
    /// legacy snapshot's archive `entries`. Old full snapshots remain usable
    /// because serde ignores that extra field when decoding ExecutionSnapshot.
    pub fn latest_execution_snapshot_at_or_before(
        path: impl AsRef<Path>,
        height: u64,
        expected_profile: &str,
    ) -> Result<Option<ExecutionSnapshot>, StorageError> {
        let root = path.as_ref();
        if !root.exists() {
            return Ok(None);
        }
        let mut execution_candidates = Vec::new();
        let mut legacy_candidates = Vec::new();
        for entry in fs::read_dir(root).map_err(|err| StorageError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") {
                continue;
            }
            if name.starts_with(EXECUTION_SNAPSHOT_PREFIX) {
                execution_candidates.push(entry.path());
            } else if name.starts_with(SNAPSHOT_PREFIX) {
                legacy_candidates.push(entry.path());
            }
        }
        let sort_by_height = |paths: &mut Vec<PathBuf>| {
            paths.sort_by_key(|path| {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                let height = name
                    .strip_prefix(EXECUTION_SNAPSHOT_PREFIX)
                    .or_else(|| name.strip_prefix(SNAPSHOT_PREFIX))
                    .and_then(|suffix| suffix.strip_suffix(".json"))
                    .and_then(|suffix| suffix.parse::<u64>().ok())
                    .unwrap_or(0);
                std::cmp::Reverse(height)
            })
        };
        sort_by_height(&mut execution_candidates);
        sort_by_height(&mut legacy_candidates);

        // Compact checkpoints are deliberately preferred over legacy archive
        // snapshots. Replaying a bounded extra suffix is safer than parsing a
        // potentially archive-sized historical JSON file on the live fork
        // path. Legacy snapshots remain a compatibility fallback until their
        // explicit migration is complete.
        for path in execution_candidates.into_iter().chain(legacy_candidates) {
            let snapshot = Self::load_execution_snapshot(path)?;
            if snapshot.height <= height && snapshot.profile_fingerprint == expected_profile {
                return Ok(Some(snapshot));
            }
        }
        Ok(None)
    }

    pub fn open_staging_from_snapshot(
        root: impl AsRef<Path>,
        manifest: &GenerationManifest,
        snapshot: &GenerationSnapshot,
    ) -> Result<PathBuf, StorageError> {
        if manifest.status != GenerationStatus::Staging
            || snapshot.profile_fingerprint != manifest.profile_fingerprint
        {
            return Err(StorageError::Serialization(
                "snapshot and staging generation are incompatible".into(),
            ));
        }
        let path = Self::create_staging_generation(root, manifest)?;
        let staged = Self::open(&path)?;
        for (key, value) in &snapshot.entries {
            staged
                .db
                .insert(key.as_slice(), value.as_slice())
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        let snapshot_path = Self::snapshot_path(&path, snapshot.height);
        let snapshot_bytes = serde_json::to_vec(snapshot)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        let temporary = snapshot_path.with_extension("json.tmp");
        fs::write(&temporary, snapshot_bytes).map_err(|err| StorageError::Io(err.to_string()))?;
        fs::rename(&temporary, snapshot_path).map_err(|err| StorageError::Io(err.to_string()))?;
        staged
            .db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(path)
    }

    /// Opens a recovery staging generation by consuming its snapshot entries.
    ///
    /// Candidate replay already owns the decoded snapshot. Moving each entry
    /// into Sled prevents a deep replay from retaining the whole snapshot and
    /// a second cloned copy while the staging database is populated. The
    /// caller writes a fresh verified tip snapshot on successful replay.
    pub fn open_staging_from_snapshot_owned(
        root: impl AsRef<Path>,
        manifest: &GenerationManifest,
        snapshot: GenerationSnapshot,
    ) -> Result<PathBuf, StorageError> {
        if manifest.status != GenerationStatus::Staging
            || snapshot.profile_fingerprint != manifest.profile_fingerprint
        {
            return Err(StorageError::Serialization(
                "snapshot and staging generation are incompatible".into(),
            ));
        }
        let path = Self::create_staging_generation(root, manifest)?;
        let staged = Self::open(&path)?;
        for (key, value) in snapshot.entries {
            staged
                .db
                .insert(key, value)
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        staged
            .db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(path)
    }

    pub fn retire_generation(path: impl AsRef<Path>) -> Result<(), StorageError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }
        let manifest = Self::load_generation_manifest(path)?
            .ok_or_else(|| StorageError::Serialization("generation manifest is missing".into()))?;
        Self::write_generation_manifest(
            path,
            &GenerationManifest {
                status: GenerationStatus::Retired,
                ..manifest
            },
        )
    }

    pub fn fail_generation(path: impl AsRef<Path>) -> Result<(), StorageError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }
        let manifest = Self::load_generation_manifest(path)?
            .ok_or_else(|| StorageError::Serialization("generation manifest is missing".into()))?;
        Self::write_generation_manifest(
            path,
            &GenerationManifest {
                status: GenerationStatus::Failed,
                ..manifest
            },
        )
    }

    /// Rebuilds derived log-query indexes for retained canonical history.
    /// This is intentionally explicit rather than part of `open`, because an
    /// archive node must not need to scan its entire history before serving.
    pub fn rebuild_log_index(&self) -> Result<(), StorageError> {
        if self
            .db
            .contains_key(LOG_INDEX_VERSION)
            .map_err(|err| StorageError::Io(err.to_string()))?
        {
            return Ok(());
        }
        let best_number = match self.get_best_number() {
            Ok(number) => number,
            Err(StorageError::NotFound) => return Ok(()),
            Err(err) => return Err(err),
        };
        // Archive nodes can retain years of bodies. Rebuild the derived index
        // one record at a time so opening an older generation never needs a
        // second full in-memory copy of the canonical chain.
        for number in 0..=best_number {
            let block = self.block_by_number(number)?;
            self.index_block_logs(&block)?;
        }
        self.db
            .insert(LOG_INDEX_VERSION, &[1])
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    /// Seeds a historical EVM snapshot for legacy storage as an explicit
    /// maintenance operation rather than forcing an archive-wide open path.
    pub fn seed_evm_state_snapshot(&self) -> Result<(), StorageError> {
        if self
            .db
            .scan_prefix(EVM_SNAPSHOT_PREFIX.as_bytes())
            .next()
            .is_some()
        {
            return Ok(());
        }
        let Ok(number) = self.get_best_number() else {
            return Ok(());
        };
        let snapshot = self.evm_account_snapshot()?;
        self.put_evm_state_snapshot(number, &snapshot)
    }

    fn index_block_logs(&self, block: &Block) -> Result<(), StorageError> {
        for (transaction_index, receipt) in block.receipts.iter().enumerate() {
            for (log_index, log) in receipt.logs.iter().enumerate() {
                let location = log_index_bytes(block.header.number.0, transaction_index, log_index);
                self.db
                    .insert(log_location_key(&location), &location)
                    .map_err(|err| StorageError::Io(err.to_string()))?;
                self.db
                    .insert(log_address_key(log.address, &location), &location)
                    .map_err(|err| StorageError::Io(err.to_string()))?;
                for topic in &log.topics {
                    self.db
                        .insert(log_topic_key(*topic, &location), &location)
                        .map_err(|err| StorageError::Io(err.to_string()))?;
                }
            }
        }
        Ok(())
    }

    fn insert_block_into_batch(batch: &mut sled::Batch, block: &Block) -> Result<(), StorageError> {
        let block_value = serde_json::to_vec(block)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        batch.insert(
            format!("block:number:{:020}", block.header.number.0).into_bytes(),
            block_value,
        );
        let header_value = serde_json::to_vec(&block.header)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        batch.insert(
            format!("header:number:{:020}", block.header.number.0).into_bytes(),
            header_value,
        );
        for (transaction_index, transaction) in block.transactions.iter().enumerate() {
            let transaction_value = serde_json::to_vec(transaction)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            batch.insert(
                format!("transaction:{}", transaction.hash().to_hex()).into_bytes(),
                transaction_value.clone(),
            );
            if let Some(external_hash) = transaction.external_hash {
                batch.insert(
                    format!("transaction:{}", external_hash.to_hex()).into_bytes(),
                    transaction_value,
                );
            }
            let receipt = serde_json::to_vec(&StoredReceipt {
                receipt: block.receipts[transaction_index].clone(),
                header: block.header.clone(),
                transaction_index,
                transaction: transaction.clone(),
            })
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
            batch.insert(
                format!("receipt:{}", transaction.rpc_hash().to_hex()).into_bytes(),
                receipt.clone(),
            );
            batch.insert(
                format!("receipt:{}", transaction.hash().to_hex()).into_bytes(),
                receipt,
            );
        }
        for (transaction_index, receipt) in block.receipts.iter().enumerate() {
            for (log_index, log) in receipt.logs.iter().enumerate() {
                let location = log_index_bytes(block.header.number.0, transaction_index, log_index);
                batch.insert(log_location_key(&location), location.to_vec());
                batch.insert(log_address_key(log.address, &location), location.to_vec());
                for topic in &log.topics {
                    batch.insert(log_topic_key(*topic, &location), location.to_vec());
                }
            }
        }
        Ok(())
    }

    fn remove_block_from_batch(batch: &mut sled::Batch, block: &Block) {
        batch.remove(format!("block:number:{:020}", block.header.number.0).into_bytes());
        batch.remove(format!("header:number:{:020}", block.header.number.0).into_bytes());
        for transaction in &block.transactions {
            batch.remove(format!("transaction:{}", transaction.hash().to_hex()).into_bytes());
            if let Some(external_hash) = transaction.external_hash {
                batch.remove(format!("transaction:{}", external_hash.to_hex()).into_bytes());
            }
            batch.remove(format!("receipt:{}", transaction.rpc_hash().to_hex()).into_bytes());
            batch.remove(format!("receipt:{}", transaction.hash().to_hex()).into_bytes());
        }
    }

    pub fn indexed_log_block_numbers(
        &self,
        from: u64,
        to: u64,
        addresses: Option<&[Address]>,
        topics: Option<&[Hash256]>,
    ) -> Result<BTreeSet<u64>, StorageError> {
        let mut numbers = BTreeSet::new();
        if let Some(addresses) = addresses {
            for address in addresses {
                self.collect_indexed_log_numbers(
                    log_address_prefix(*address),
                    from,
                    to,
                    &mut numbers,
                )?;
            }
            return Ok(numbers);
        }
        if let Some(topics) = topics {
            for topic in topics {
                self.collect_indexed_log_numbers(log_topic_prefix(*topic), from, to, &mut numbers)?;
            }
            return Ok(numbers);
        }
        self.collect_indexed_log_numbers(b"log:index:location:".to_vec(), from, to, &mut numbers)?;
        Ok(numbers)
    }

    fn collect_indexed_log_numbers(
        &self,
        prefix: Vec<u8>,
        from: u64,
        to: u64,
        numbers: &mut BTreeSet<u64>,
    ) -> Result<(), StorageError> {
        for item in self.db.scan_prefix(prefix) {
            let (_, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let location: [u8; 16] = value.as_ref().try_into().map_err(|_| {
                StorageError::Serialization("invalid log index location".to_string())
            })?;
            let number = u64::from_be_bytes(location[..8].try_into().expect("slice length"));
            if (from..=to).contains(&number) {
                numbers.insert(number);
            }
        }
        Ok(())
    }

    fn put_header(&self, header: &BlockHeader) -> Result<(), StorageError> {
        let key = format!("header:number:{:020}", header.number.0);
        let value = serde_json::to_vec(header)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .insert(b"best:number", &header.number.0.to_be_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.flush_db()?;
        Ok(())
    }

    fn get_best_number(&self) -> Result<u64, StorageError> {
        let value = self
            .db
            .get(b"best:number")
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        let bytes: [u8; 8] = value
            .as_ref()
            .try_into()
            .map_err(|_| StorageError::Serialization("invalid best number".to_string()))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn is_empty(&self) -> bool {
        self.get_best_number().is_err()
    }

    pub fn disk_usage_bytes(&self) -> Result<u64, StorageError> {
        directory_size_recursive(&self.data_dir)
    }

    pub fn store_orphan_block(&self, block: &Block) -> Result<(), StorageError> {
        const MAX_ORPHANS: usize = 128;
        const MAX_ORPHAN_BYTES: usize = 2 * 1024 * 1024;
        let value = serde_json::to_vec(block)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        if value.len() > MAX_ORPHAN_BYTES {
            return Err(StorageError::Serialization(
                "orphan block exceeds size limit".to_string(),
            ));
        }
        let count = self.db.scan_prefix(b"orphan:block:").count();
        if count >= MAX_ORPHANS {
            // Orphans are transport cache, not canonical history. Evict the
            // lowest-height deferred body so a fresh sync response can enter;
            // the missing body can always be requested again from a peer.
            let oldest = self
                .orphan_blocks()?
                .into_iter()
                .next()
                .map(|orphan| orphan.header.hash());
            if let Some(hash) = oldest {
                self.db
                    .remove(format!("orphan:block:{}", hash.to_hex()).as_bytes())
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            }
        }
        let key = format!("orphan:block:{}", block.header.hash().to_hex());
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn orphan_blocks(&self) -> Result<Vec<Block>, StorageError> {
        let mut blocks = Vec::new();
        for item in self.db.scan_prefix(b"orphan:block:") {
            let (_, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            blocks.push(
                serde_json::from_slice(&value)
                    .map_err(|err| StorageError::Serialization(err.to_string()))?,
            );
        }
        blocks.sort_by_key(|block: &Block| block.header.number.0);
        Ok(blocks)
    }

    pub fn remove_orphan_block(&self, hash: Hash256) -> Result<(), StorageError> {
        self.db
            .remove(format!("orphan:block:{}", hash.to_hex()).as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    /// Remove generation snapshots older than the retained finalized replay
    /// window. Headers and canonical state remain in the generation database.
    pub fn prune_old_snapshots(
        root: impl AsRef<Path>,
        retain_from_height: u64,
    ) -> Result<(), StorageError> {
        let root = root.as_ref();
        if !root.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(root).map_err(|err| StorageError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("generation-") || name.ends_with(".staging") {
                continue;
            }
            for snapshot in
                fs::read_dir(entry.path()).map_err(|err| StorageError::Io(err.to_string()))?
            {
                let snapshot = snapshot.map_err(|err| StorageError::Io(err.to_string()))?;
                let snapshot_name = snapshot.file_name().to_string_lossy().into_owned();
                let Some(height) = snapshot_name
                    .strip_prefix(SNAPSHOT_PREFIX)
                    .and_then(|value| value.strip_suffix(".json"))
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    continue;
                };
                if height < retain_from_height {
                    fs::remove_file(snapshot.path())
                        .map_err(|err| StorageError::Io(err.to_string()))?;
                }
            }
        }
        Ok(())
    }

    /// Retain only execution-only snapshots needed by the live replay window.
    ///
    /// Legacy `snapshot-*.json` files embed the archive key/value set and are
    /// intentionally left alone here: removing those files is an operator
    /// migration decision. Execution snapshots contain only mutable state and
    /// are safe to trim once a newer finalized checkpoint makes them obsolete.
    pub fn prune_old_execution_snapshots(
        root: impl AsRef<Path>,
        retain_from_height: u64,
    ) -> Result<(), StorageError> {
        let root = root.as_ref();
        if !root.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(root).map_err(|err| StorageError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("generation-") || name.ends_with(".staging") {
                continue;
            }
            for snapshot in
                fs::read_dir(entry.path()).map_err(|err| StorageError::Io(err.to_string()))?
            {
                let snapshot = snapshot.map_err(|err| StorageError::Io(err.to_string()))?;
                let snapshot_name = snapshot.file_name().to_string_lossy().into_owned();
                let Some(height) = snapshot_name
                    .strip_prefix(EXECUTION_SNAPSHOT_PREFIX)
                    .and_then(|value| value.strip_suffix(".json"))
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    continue;
                };
                if height < retain_from_height {
                    fs::remove_file(snapshot.path())
                        .map_err(|err| StorageError::Io(err.to_string()))?;
                }
            }
        }
        Ok(())
    }

    pub fn clear_orphan_blocks(&self) -> Result<usize, StorageError> {
        let hashes = self
            .orphan_blocks()?
            .into_iter()
            .map(|block| block.header.hash())
            .collect::<Vec<_>>();
        for hash in &hashes {
            self.db
                .remove(format!("orphan:block:{}", hash.to_hex()).as_bytes())
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(hashes.len())
    }

    pub fn store_candidate_block(
        &self,
        block: &Block,
        cumulative_work: u128,
    ) -> Result<(), StorageError> {
        self.store_candidate_block_unflushed(block, cumulative_work)?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    /// Adds a recovery candidate to the current storage batch. Callers that
    /// ingest a contiguous branch must flush at a bounded checkpoint before
    /// reporting progress as durable.
    pub fn store_candidate_block_unflushed(
        &self,
        block: &Block,
        cumulative_work: u128,
    ) -> Result<(), StorageError> {
        const MAX_CANDIDATES: usize = 4_096;
        const MAX_CANDIDATE_BYTES: usize = 2 * 1024 * 1024;
        let hash = block.header.hash().to_hex();
        let value = serde_json::to_vec(block)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        if value.len() > MAX_CANDIDATE_BYTES {
            return Err(StorageError::Serialization(
                "candidate block exceeds size limit".to_string(),
            ));
        }
        let key = format!("candidate:block:{hash}");
        let already_stored = self
            .db
            .contains_key(key.as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        if !already_stored && self.db.scan_prefix(b"candidate:block:").count() >= MAX_CANDIDATES {
            return Err(StorageError::Io("candidate block pool is full".to_string()));
        }
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .insert(
                format!("candidate:work:{hash}").as_bytes(),
                cumulative_work.to_be_bytes().as_slice(),
            )
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn candidate_block_by_hash(&self, hash: Hash256) -> Result<Block, StorageError> {
        let value = self
            .db
            .get(format!("candidate:block:{}", hash.to_hex()).as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        serde_json::from_slice(&value).map_err(|err| StorageError::Serialization(err.to_string()))
    }

    /// Durable, job-scoped recovery bodies. These are deliberately separate
    /// from ordinary candidates so startup cleanup and pruning cannot break a
    /// parent-first branch import in progress.
    pub fn store_recovery_block_unflushed(
        &self,
        tip_hash: Hash256,
        block: &Block,
        cumulative_work: u128,
    ) -> Result<(), StorageError> {
        let value = serde_json::to_vec(block)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        let base = format!("recovery:{}:{}", tip_hash.to_hex(), block.header.number.0);
        self.db
            .insert(format!("{base}:block").as_bytes(), value)
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .insert(
                format!("{base}:work").as_bytes(),
                cumulative_work.to_be_bytes().as_slice(),
            )
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .insert(
                format!("recovery:hash:{}", block.header.hash().to_hex()).as_bytes(),
                base.as_bytes(),
            )
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn recovery_block_by_hash(&self, hash: Hash256) -> Result<(Block, u128), StorageError> {
        let index_key = format!("recovery:hash:{}", hash.to_hex());
        let indexed = self
            .db
            .get(index_key.as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        let base = match indexed.as_deref() {
            Some(indexed) => match std::str::from_utf8(indexed) {
                Ok(base) if base.starts_with("recovery:") => base.to_owned(),
                _ => {
                    // Older recovery builds indexed a body hash to its raw 32-byte
                    // tip hash.  Keep that spool usable after upgrade instead of
                    // treating a locally retained parent as provider loss.
                    let tip: [u8; 32] = indexed.as_ref().try_into().map_err(|_| {
                        StorageError::Serialization("invalid recovery hash index".to_string())
                    })?;
                    let prefix = format!("recovery:{}:", Hash256(tip).to_hex());
                    self.find_and_index_recovery_block(&index_key, hash, prefix.as_bytes())?
                }
            },
            // Some early spool versions wrote bodies but no hash index at all.
            // This bounded, one-time local scan repairs that omission after an
            // upgrade; it never asks a provider for a body we already have.
            None => self.find_and_index_recovery_block(&index_key, hash, b"recovery:")?,
        };
        let block = self
            .db
            .get(format!("{base}:block").as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        let block: Block = serde_json::from_slice(&block)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        let work = self
            .db
            .get(format!("{base}:work").as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        let work: [u8; 16] = work
            .as_ref()
            .try_into()
            .map_err(|_| StorageError::Serialization("invalid recovery work".to_string()))?;
        Ok((block, u128::from_be_bytes(work)))
    }

    fn find_and_index_recovery_block(
        &self,
        index_key: &str,
        hash: Hash256,
        prefix: &[u8],
    ) -> Result<String, StorageError> {
        for item in self.db.scan_prefix(prefix) {
            let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            if !key.ends_with(b":block") {
                continue;
            }
            let block: Block = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            if block.header.hash() != hash {
                continue;
            }
            let key = std::str::from_utf8(&key)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            let base = key.trim_end_matches(":block").to_owned();
            self.db
                .insert(index_key.as_bytes(), base.as_bytes())
                .map_err(|err| StorageError::Io(err.to_string()))?;
            return Ok(base);
        }
        Err(StorageError::NotFound)
    }

    /// Lists one durable recovery spool in parent-first order.  This lets a
    /// restart rebuild derived candidate indexes without re-downloading bodies
    /// that were already validated and checkpointed locally.
    pub fn recovery_blocks_for_tip(
        &self,
        tip_hash: Hash256,
    ) -> Result<Vec<(Block, u128)>, StorageError> {
        let prefix = format!("recovery:{}:", tip_hash.to_hex());
        let mut blocks = Vec::new();
        let mut repaired_index = false;
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            if !key.ends_with(b":block") {
                continue;
            }
            let block: Block = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            let key = std::str::from_utf8(&key)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            let base = key.trim_end_matches(":block");
            // Early spool versions wrote a raw tip-hash value here. Repair
            // every entry in one ordered scan so later parent lookups stay
            // O(1) instead of repeatedly rescanning the whole recovery job.
            self.db
                .insert(
                    format!("recovery:hash:{}", block.header.hash().to_hex()).as_bytes(),
                    base.as_bytes(),
                )
                .map_err(|err| StorageError::Io(err.to_string()))?;
            repaired_index = true;
            let work = self
                .db
                .get(format!("{base}:work").as_bytes())
                .map_err(|err| StorageError::Io(err.to_string()))?
                .ok_or(StorageError::NotFound)?;
            let work: [u8; 16] = work
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Serialization("invalid recovery work".to_string()))?;
            blocks.push((block, u128::from_be_bytes(work)));
        }
        blocks.sort_by_key(|(block, _)| block.header.number.0);
        if repaired_index {
            self.db
                .flush()
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        Ok(blocks)
    }

    /// Lists durable recovery-job namespaces that still contain body data.
    /// This is used only during startup recovery when an older release lost
    /// its derived cursor metadata; canonical data is never inferred or
    /// changed by this scan.
    pub fn recovery_spool_tips(&self) -> Result<Vec<Hash256>, StorageError> {
        let mut tips = BTreeSet::new();
        for item in self.db.scan_prefix(b"recovery:") {
            let (key, _) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let Ok(key) = std::str::from_utf8(&key) else {
                continue;
            };
            let parts = key.split(':').collect::<Vec<_>>();
            let ["recovery", tip, _height, "block"] = parts.as_slice() else {
                continue;
            };
            if let Ok(tip) = Hash256::from_hex(tip) {
                tips.insert(tip);
            }
        }
        Ok(tips.into_iter().collect())
    }

    pub fn candidate_work(&self, hash: Hash256) -> Result<u128, StorageError> {
        let value = self
            .db
            .get(format!("candidate:work:{}", hash.to_hex()).as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        let bytes: [u8; 16] = value
            .as_ref()
            .try_into()
            .map_err(|_| StorageError::Serialization("invalid candidate work".to_string()))?;
        Ok(u128::from_be_bytes(bytes))
    }

    pub fn candidate_blocks_with_work(&self) -> Result<Vec<(Block, u128)>, StorageError> {
        let mut blocks = Vec::new();
        for item in self.db.scan_prefix(b"candidate:block:") {
            let (_, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let block: Block = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            let work = self.candidate_work(block.header.hash())?;
            blocks.push((block, work));
        }
        blocks.sort_by_key(|(block, work)| (block.header.number.0, std::cmp::Reverse(*work)));
        Ok(blocks)
    }

    pub fn clear_candidate_blocks(&self) -> Result<(), StorageError> {
        let keys = self
            .db
            .scan_prefix(b"candidate:")
            .map(|item| {
                item.map(|(key, _)| key)
                    .map_err(|err| StorageError::Io(err.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            self.db
                .remove(key)
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    /// Removes only the candidate copies that have just become canonical.
    /// Other concurrent candidate branches remain available for fork choice.
    pub fn remove_candidate_blocks(&self, hashes: &[Hash256]) -> Result<(), StorageError> {
        for hash in hashes {
            self.db
                .remove(format!("candidate:block:{}", hash.to_hex()).as_bytes())
                .map_err(|err| StorageError::Io(err.to_string()))?;
            self.db
                .remove(format!("candidate:work:{}", hash.to_hex()).as_bytes())
                .map_err(|err| StorageError::Io(err.to_string()))?;
            self.db
                .remove(format!("candidate:quarantine:{}", hash.to_hex()).as_bytes())
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    /// Removes a completed recovery job's durable body spool and its global
    /// hash indexes. The caller must first publish the identical canonical
    /// generation; incomplete jobs are intentionally never eligible here.
    pub fn clear_recovery_blocks_for_tip(&self, tip_hash: Hash256) -> Result<(), StorageError> {
        let prefix = format!("recovery:{}:", tip_hash.to_hex());
        let entries = self
            .db
            .scan_prefix(prefix.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        for (key, value) in entries {
            if key.ends_with(b":block") {
                let block: Block = serde_json::from_slice(&value)
                    .map_err(|err| StorageError::Serialization(err.to_string()))?;
                self.db
                    .remove(format!("recovery:hash:{}", block.header.hash().to_hex()).as_bytes())
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            }
            self.db
                .remove(key)
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn quarantine_candidate_tip(
        &self,
        hash: Hash256,
        reason: &str,
    ) -> Result<(), StorageError> {
        self.db
            .insert(
                format!("candidate:quarantine:{}", hash.to_hex()).as_bytes(),
                reason.as_bytes(),
            )
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    fn candidate_tip_is_quarantined(&self, hash: Hash256) -> Result<bool, StorageError> {
        self.db
            .contains_key(format!("candidate:quarantine:{}", hash.to_hex()).as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))
    }

    pub fn latest_candidate_tip(&self) -> Result<Option<(BlockHeader, u128)>, StorageError> {
        let mut best: Option<(BlockHeader, u128)> = None;
        for (block, work) in self.candidate_blocks_with_work()? {
            if self.candidate_tip_is_quarantined(block.header.hash())? {
                continue;
            }
            let candidate = (block.header.clone(), work);
            if best
                .as_ref()
                .map(|(header, current_work)| {
                    candidate.1 > *current_work
                        || (candidate.1 == *current_work && candidate.0.hash() < header.hash())
                })
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }
        Ok(best)
    }

    pub fn canonical_blocks(&self) -> Result<Vec<Block>, StorageError> {
        let mut blocks = Vec::new();
        for item in self.db.scan_prefix(b"block:number:") {
            let (_, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            blocks.push(
                serde_json::from_slice(&value)
                    .map_err(|err| StorageError::Serialization(err.to_string()))?,
            );
        }
        blocks.sort_by_key(|block: &Block| block.header.number.0);
        Ok(blocks)
    }

    pub fn block_by_hash(&self, hash: Hash256) -> Result<Block, StorageError> {
        for block in self.canonical_blocks()? {
            if block.header.hash() == hash {
                return Ok(block);
            }
        }
        self.candidate_block_by_hash(hash)
    }

    pub fn clear_canonical_state(&self) -> Result<(), StorageError> {
        for prefix in [
            b"block:number:".as_slice(),
            b"header:number:".as_slice(),
            b"transaction:".as_slice(),
            b"receipt:".as_slice(),
            b"account:".as_slice(),
            b"state:".as_slice(),
            b"log:index:".as_slice(),
        ] {
            let keys = self
                .db
                .scan_prefix(prefix)
                .map(|item| {
                    item.map(|(key, _)| key)
                        .map_err(|err| StorageError::Io(err.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for key in keys {
                self.db
                    .remove(key)
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            }
        }
        self.db
            .remove(b"best:number")
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    /// Atomically replaces only the canonical suffix above `ancestor`. This
    /// is the publication primitive for a verified fork replay: archive data
    /// below the ancestor remains in the active generation and is never
    /// copied into a second Sled database.
    pub fn publish_canonical_suffix(
        &self,
        ancestor: &BlockHeader,
        replacement: &[Block],
        native_accounts: &BTreeMap<Address, (Bix, u64)>,
        evm_accounts: &EvmStateSnapshot,
        supply_totals: (u64, u128, u128),
        target_manifest: GenerationManifest,
    ) -> Result<(), StorageError> {
        let previous_manifest =
            Self::load_generation_manifest(&self.data_dir)?.ok_or_else(|| {
                StorageError::Serialization("suffix publication requires an active manifest".into())
            })?;
        let best = self.best_header()?;
        if ancestor.number.0 > best.number.0
            || self.header_by_number(ancestor.number)?.hash() != ancestor.hash()
        {
            return Err(StorageError::Serialization(
                "suffix publication ancestor is not canonical".into(),
            ));
        }
        let mut parent = ancestor.clone();
        for block in replacement {
            if block.header.number.0 != parent.number.0.saturating_add(1)
                || block.header.parent_hash != parent.hash()
            {
                return Err(StorageError::Serialization(format!(
                    "suffix publication replacement is not contiguous at height {}: expected parent {} at height {}, got parent {}",
                    block.header.number.0,
                    parent.hash().to_hex(),
                    parent.number.0,
                    block.header.parent_hash.to_hex(),
                )));
            }
            parent = block.header.clone();
        }
        if replacement.is_empty()
            || target_manifest.canonical_height != parent.number.0
            || target_manifest.canonical_hash != parent.hash()
            || target_manifest.state_root != parent.state_root
            || target_manifest.replay_checkpoint != Some(parent.number.0)
        {
            return Err(StorageError::Serialization(
                "suffix publication manifest does not match replacement tip".into(),
            ));
        }

        let journal = SuffixPublicationRecord {
            previous_manifest,
            target_manifest: target_manifest.clone(),
        };
        Self::write_suffix_publication(&self.data_dir, &journal)?;

        let result = (|| -> Result<(), StorageError> {
            let mut batch = sled::Batch::default();
            let reorg_from = ancestor.number.0.saturating_add(1);
            for number in reorg_from..=best.number.0 {
                let block = self.block_by_number(number)?;
                Self::remove_block_from_batch(&mut batch, &block);
            }
            for item in self.db.scan_prefix(b"log:index:") {
                let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
                let location: [u8; 16] = value.as_ref().try_into().map_err(|_| {
                    StorageError::Serialization("invalid log index location".to_string())
                })?;
                let number = u64::from_be_bytes(location[..8].try_into().expect("slice length"));
                if number >= reorg_from {
                    batch.remove(key);
                }
            }
            for prefix in [b"account:".as_slice(), EVM_SNAPSHOT_PREFIX.as_bytes()] {
                for item in self.db.scan_prefix(prefix) {
                    let (key, _) = item.map_err(|err| StorageError::Io(err.to_string()))?;
                    batch.remove(key);
                }
            }
            for block in replacement {
                Self::insert_block_into_batch(&mut batch, block)?;
            }
            for (address, (balance, nonce)) in native_accounts {
                batch.insert(balance_key(*address), balance.0.to_be_bytes().to_vec());
                batch.insert(nonce_key(*address), nonce.to_be_bytes().to_vec());
            }
            for (address, (_, _, code, slots)) in evm_accounts {
                if !code.is_empty() {
                    batch.insert(code_key(*address), code.clone());
                }
                for (slot, value) in slots {
                    if *value != Hash256::ZERO {
                        batch.insert(storage_key(*address, *slot), value.0.to_vec());
                    }
                }
            }
            let snapshot_entries = evm_accounts
                .iter()
                .map(|(address, (balance, nonce, code, slots))| {
                    (
                        *address,
                        (
                            *balance,
                            *nonce,
                            code.clone(),
                            slots
                                .iter()
                                .map(|(slot, value)| (*slot, *value))
                                .collect::<Vec<_>>(),
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let snapshot = serde_json::to_vec(&snapshot_entries)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            batch.insert(
                format!("{EVM_SNAPSHOT_PREFIX}{:020}", parent.number.0).into_bytes(),
                snapshot,
            );
            batch.insert(
                b"state:rewards:indexed_to",
                parent.number.0.to_be_bytes().to_vec(),
            );
            batch.insert(
                b"state:supply:indexed_to",
                supply_totals.0.to_be_bytes().to_vec(),
            );
            batch.insert(
                b"state:supply:total",
                supply_totals.1.to_be_bytes().to_vec(),
            );
            batch.insert(
                b"state:supply:burned",
                supply_totals.2.to_be_bytes().to_vec(),
            );
            batch.insert(b"best:number", parent.number.0.to_be_bytes().to_vec());
            self.db
                .apply_batch(batch)
                .map_err(|err| StorageError::Io(err.to_string()))?;
            self.db
                .flush()
                .map_err(|err| StorageError::Io(err.to_string()))?;
            Ok(())
        })();
        if result.is_err() {
            // The Sled batch is all-or-nothing. Startup can safely clear the
            // journal after confirming that the previous tip is intact.
            return result;
        }
        Self::sync_suffix_replay_checkpoint(&self.data_dir, &target_manifest)?;
        Self::write_generation_manifest(&self.data_dir, &target_manifest)?;
        Self::write_generation_publication(&self.data_dir, &target_manifest)?;
        Self::clear_suffix_publication(&self.data_dir)?;
        Ok(())
    }

    pub fn prune_old_blocks(
        &self,
        max_bytes: u64,
        minimum_body_height: u64,
    ) -> Result<(), StorageError> {
        let target = max_bytes.saturating_mul(9) / 10;
        let mut numbers = self
            .db
            .scan_prefix(b"block:number:")
            .filter_map(|item| {
                item.ok().and_then(|(key, _)| {
                    std::str::from_utf8(key.as_ref())
                        .ok()?
                        .strip_prefix("block:number:")?
                        .parse::<u64>()
                        .ok()
                })
            })
            .filter(|number| *number > minimum_body_height)
            .collect::<Vec<_>>();
        numbers.sort_unstable();
        for number in numbers {
            if self.disk_usage_bytes()? <= target {
                break;
            }
            let Ok(block) = self.block_by_number(number) else {
                continue;
            };
            self.remove_log_indexes_for_block(number)?;
            self.db
                .remove(format!("block:number:{:020}", number).as_bytes())
                .map_err(|err| StorageError::Io(err.to_string()))?;
            for transaction in &block.transactions {
                self.db
                    .remove(format!("transaction:{}", transaction.hash().to_hex()).as_bytes())
                    .map_err(|err| StorageError::Io(err.to_string()))?;
                self.db
                    .remove(format!("transaction:{}", transaction.rpc_hash().to_hex()).as_bytes())
                    .map_err(|err| StorageError::Io(err.to_string()))?;
                self.db
                    .remove(format!("receipt:{}", transaction.rpc_hash().to_hex()).as_bytes())
                    .map_err(|err| StorageError::Io(err.to_string()))?;
                self.db
                    .remove(format!("receipt:{}", transaction.hash().to_hex()).as_bytes())
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            }
        }
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    /// Returns the first height whose complete block body is still retained.
    /// Headers remain available below this boundary for consensus and sync.
    pub fn oldest_body_height(&self) -> Result<Option<u64>, StorageError> {
        let mut oldest: Option<u64> = None;
        for item in self.db.scan_prefix(b"block:number:") {
            let (key, _) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let Some(number) = std::str::from_utf8(key.as_ref())
                .ok()
                .and_then(|key| key.strip_prefix("block:number:"))
                .and_then(|number| number.parse::<u64>().ok())
            else {
                continue;
            };
            oldest = Some(oldest.map_or(number, |current| current.min(number)));
        }
        Ok(oldest)
    }

    fn remove_log_indexes_for_block(&self, number: u64) -> Result<(), StorageError> {
        let keys = self
            .db
            .scan_prefix(b"log:index:")
            .filter_map(|item| {
                item.ok().and_then(|(key, value)| {
                    let location: [u8; 16] = value.as_ref().try_into().ok()?;
                    let indexed_number = u64::from_be_bytes(location[..8].try_into().ok()?);
                    (indexed_number == number).then_some(key)
                })
            })
            .collect::<Vec<_>>();
        for key in keys {
            self.db
                .remove(key)
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        Ok(())
    }

    pub fn balance(&self, address: Address) -> Result<Bix, StorageError> {
        let Some(value) = self
            .db
            .get(balance_key(address))
            .map_err(|err| StorageError::Io(err.to_string()))?
        else {
            return Ok(Bix(0));
        };
        Ok(Bix(u128_from_slice(value.as_ref())?))
    }

    pub fn nonce(&self, address: Address) -> Result<u64, StorageError> {
        let Some(value) = self
            .db
            .get(nonce_key(address))
            .map_err(|err| StorageError::Io(err.to_string()))?
        else {
            return Ok(0);
        };
        let bytes: [u8; 8] = value
            .as_ref()
            .try_into()
            .map_err(|_| StorageError::Serialization("invalid nonce value".to_string()))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn credit_balance(&self, address: Address, amount: Bix) -> Result<(), StorageError> {
        if amount.0 == 0 {
            return Ok(());
        }
        let balance = self.balance(address)?.0.saturating_add(amount.0);
        self.put_account(address, Bix(balance), self.nonce(address)?)
    }

    pub fn put_account(
        &self,
        address: Address,
        balance: Bix,
        nonce: u64,
    ) -> Result<(), StorageError> {
        self.db
            .insert(balance_key(address), &balance.0.to_be_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .insert(nonce_key(address), &nonce.to_be_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.flush_db()?;
        Ok(())
    }

    pub fn reward_indexed_to(&self) -> Result<u64, StorageError> {
        let Some(value) = self
            .db
            .get(b"state:rewards:indexed_to")
            .map_err(|err| StorageError::Io(err.to_string()))?
        else {
            return Ok(0);
        };
        let bytes: [u8; 8] = value
            .as_ref()
            .try_into()
            .map_err(|_| StorageError::Serialization("invalid reward index".to_string()))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn set_reward_indexed_to(&self, number: u64) -> Result<(), StorageError> {
        self.db
            .insert(b"state:rewards:indexed_to", &number.to_be_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.flush_db()?;
        Ok(())
    }

    pub fn supply_totals(&self) -> Result<(u64, u128, u128), StorageError> {
        let indexed_to =
            self.db
                .get(b"state:supply:indexed_to")
                .map_err(|err| StorageError::Io(err.to_string()))?
                .map(|value| {
                    let bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| {
                        StorageError::Serialization("invalid supply index".to_string())
                    })?;
                    Ok(u64::from_be_bytes(bytes))
                })
                .transpose()?
                .unwrap_or(0);
        let total = self
            .db
            .get(b"state:supply:total")
            .map_err(|err| StorageError::Io(err.to_string()))?
            .map(|value| u128_from_slice(value.as_ref()))
            .transpose()?
            .unwrap_or(0);
        let burned = self
            .db
            .get(b"state:supply:burned")
            .map_err(|err| StorageError::Io(err.to_string()))?
            .map(|value| u128_from_slice(value.as_ref()))
            .transpose()?
            .unwrap_or(0);
        Ok((indexed_to, total, burned))
    }

    pub fn set_supply_totals(
        &self,
        indexed_to: u64,
        total: u128,
        burned: u128,
    ) -> Result<(), StorageError> {
        self.db
            .insert(b"state:supply:indexed_to", &indexed_to.to_be_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .insert(b"state:supply:total", &total.to_be_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .insert(b"state:supply:burned", &burned.to_be_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn state_root(&self) -> Result<Hash256, StorageError> {
        state_root_from_accounts(&self.account_snapshot()?)
    }

    pub fn projected_credit_state_root(
        &self,
        credit_address: Address,
        credit_amount: Bix,
    ) -> Result<Hash256, StorageError> {
        let mut accounts = self.account_snapshot()?;
        if credit_amount.0 > 0 {
            let entry = accounts.entry(credit_address).or_insert((Bix(0), 0));
            entry.0 .0 = entry.0 .0.saturating_add(credit_amount.0);
        }
        state_root_from_accounts(&accounts)
    }

    pub fn account_snapshot(&self) -> Result<BTreeMap<Address, (Bix, u64)>, StorageError> {
        let mut accounts = BTreeMap::new();
        for item in self.db.scan_prefix(b"account:balance:") {
            let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let address = address_from_balance_key(key.as_ref())?;
            let balance = u128_from_slice(value.as_ref())?;
            accounts.entry(address).or_insert((Bix(0), 0)).0 = Bix(balance);
        }
        for item in self.db.scan_prefix(b"account:nonce:") {
            let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let address = address_from_nonce_key(key.as_ref())?;
            let bytes: [u8; 8] = value
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Serialization("invalid nonce value".to_string()))?;
            accounts.entry(address).or_insert((Bix(0), 0)).1 = u64::from_be_bytes(bytes);
        }
        Ok(accounts)
    }

    pub fn evm_code(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        Ok(self
            .db
            .get(code_key(address))
            .map_err(|err| StorageError::Io(err.to_string()))?
            .map(|value| value.to_vec())
            .unwrap_or_default())
    }

    pub fn evm_storage_at(&self, address: Address, slot: Hash256) -> Result<Hash256, StorageError> {
        let Some(value) = self
            .db
            .get(storage_key(address, slot))
            .map_err(|err| StorageError::Io(err.to_string()))?
        else {
            return Ok(Hash256::ZERO);
        };
        hash_from_bytes(value.as_ref())
    }

    pub fn evm_account_snapshot(
        &self,
    ) -> Result<BTreeMap<Address, EvmAccountSnapshot>, StorageError> {
        let mut accounts = self
            .account_snapshot()?
            .into_iter()
            .map(|(address, (balance, nonce))| {
                (address, (balance, nonce, Vec::new(), BTreeMap::new()))
            })
            .collect::<BTreeMap<_, _>>();
        for item in self.db.scan_prefix(b"account:code:") {
            let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let address = address_from_code_key(key.as_ref())?;
            accounts
                .entry(address)
                .or_insert((Bix(0), 0, Vec::new(), BTreeMap::new()))
                .2 = value.to_vec();
        }
        for item in self.db.scan_prefix(b"account:storage:") {
            let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let (address, slot) = address_from_storage_key(key.as_ref())?;
            let storage = &mut accounts
                .entry(address)
                .or_insert((Bix(0), 0, Vec::new(), BTreeMap::new()))
                .3;
            storage.insert(slot, hash_from_bytes(value.as_ref())?);
        }
        Ok(accounts)
    }

    pub fn put_evm_state_snapshot(
        &self,
        number: u64,
        snapshot: &EvmStateSnapshot,
    ) -> Result<(), StorageError> {
        let key = format!("{EVM_SNAPSHOT_PREFIX}{number:020}");
        let entries = snapshot
            .iter()
            .map(|(address, (balance, nonce, code, slots))| {
                (
                    *address,
                    (
                        *balance,
                        *nonce,
                        code.clone(),
                        slots
                            .iter()
                            .map(|(slot, value)| (*slot, *value))
                            .collect::<Vec<_>>(),
                    ),
                )
            })
            .collect::<Vec<_>>();
        let value = serde_json::to_vec(&entries)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|err| StorageError::Io(err.to_string()))?;
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn evm_state_snapshot(
        &self,
        number: u64,
    ) -> Result<Option<EvmStateSnapshot>, StorageError> {
        let key = format!("{EVM_SNAPSHOT_PREFIX}{number:020}");
        let Some(value) = self
            .db
            .get(key.as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
        else {
            return Ok(None);
        };
        let entries: Vec<SerializedEvmSnapshotEntry> = serde_json::from_slice(&value)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        Ok(Some(
            entries
                .into_iter()
                .map(|(address, (balance, nonce, code, slots))| {
                    (address, (balance, nonce, code, slots.into_iter().collect()))
                })
                .collect(),
        ))
    }

    pub fn evm_state_snapshot_at_or_before(
        &self,
        number: u64,
    ) -> Result<Option<(u64, EvmStateSnapshot)>, StorageError> {
        let mut best = None;
        for item in self.db.scan_prefix(EVM_SNAPSHOT_PREFIX.as_bytes()) {
            let (key, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let snapshot_number = std::str::from_utf8(&key)
                .map_err(|err| StorageError::Serialization(err.to_string()))?
                .strip_prefix(EVM_SNAPSHOT_PREFIX)
                .ok_or_else(|| StorageError::Serialization("invalid EVM snapshot key".to_string()))?
                .parse::<u64>()
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            if snapshot_number > number {
                continue;
            }
            let entries: Vec<SerializedEvmSnapshotEntry> = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            let snapshot = entries
                .into_iter()
                .map(|(address, (balance, nonce, code, slots))| {
                    (address, (balance, nonce, code, slots.into_iter().collect()))
                })
                .collect();
            if best
                .as_ref()
                .map(|(best_number, _)| snapshot_number > *best_number)
                .unwrap_or(true)
            {
                best = Some((snapshot_number, snapshot));
            }
        }
        Ok(best)
    }

    pub fn put_evm_account(
        &self,
        address: Address,
        balance: Bix,
        nonce: u64,
        code: &[u8],
        storage: &BTreeMap<Hash256, Hash256>,
    ) -> Result<(), StorageError> {
        self.put_account(address, balance, nonce)?;
        let code_key = code_key(address);
        if code.is_empty() {
            self.db
                .remove(code_key)
                .map_err(|err| StorageError::Io(err.to_string()))?;
        } else {
            self.db
                .insert(code_key, code)
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        // Replace the account's storage set atomically from the caller's
        // perspective. Slots removed by REVM must be deleted here; updating
        // only present slots would resurrect cleared Solidity mappings.
        let mut existing_keys = Vec::new();
        for item in self.db.scan_prefix(b"account:storage:") {
            let (key, _) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let (stored_address, slot) = address_from_storage_key(key.as_ref())?;
            if stored_address == address {
                existing_keys.push((key.to_vec(), slot));
            }
        }
        for (key, slot) in existing_keys {
            if !storage.contains_key(&slot) {
                self.db
                    .remove(key)
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            }
        }
        for (slot, value) in storage {
            let key = storage_key(address, *slot);
            if value == &Hash256::ZERO {
                self.db
                    .remove(key)
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            } else {
                self.db
                    .insert(key, &value.0)
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            }
        }
        self.db
            .flush()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        Ok(())
    }

    pub fn transaction_by_hash(&self, hash: Hash256) -> Result<Transaction, StorageError> {
        let key = format!("transaction:{}", hash.to_hex());
        let value = self
            .db
            .get(key.as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        serde_json::from_slice(&value).map_err(|err| StorageError::Serialization(err.to_string()))
    }

    pub fn transaction_receipt_by_hash(
        &self,
        hash: Hash256,
    ) -> Result<(Receipt, BlockHeader, usize, Transaction), StorageError> {
        match self.indexed_transaction_receipt_by_hash(hash) {
            Ok(value) => return Ok(value),
            Err(StorageError::NotFound) => {}
            Err(err) => return Err(err),
        }
        for item in self.db.scan_prefix(b"block:number:") {
            let (_, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let block: Block = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            for (index, transaction) in block.transactions.iter().enumerate() {
                if transaction.rpc_hash() == hash || transaction.hash() == hash {
                    return Ok((
                        block.receipts[index].clone(),
                        block.header,
                        index,
                        transaction.clone(),
                    ));
                }
            }
        }
        Err(StorageError::NotFound)
    }

    pub fn indexed_transaction_receipt_by_hash(
        &self,
        hash: Hash256,
    ) -> Result<(Receipt, BlockHeader, usize, Transaction), StorageError> {
        if let Some(value) = self
            .db
            .get(format!("receipt:{}", hash.to_hex()).as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
        {
            let stored: StoredReceipt = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            return Ok((
                stored.receipt,
                stored.header,
                stored.transaction_index,
                stored.transaction,
            ));
        }
        Err(StorageError::NotFound)
    }

    pub fn headers_after(
        &self,
        number: u64,
        limit: usize,
    ) -> Result<Vec<BlockHeader>, StorageError> {
        let mut headers = Vec::new();
        for item in self.db.scan_prefix(b"header:number:") {
            let (_, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let header: BlockHeader = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            if header.number.0 > number {
                headers.push(header);
            }
        }
        headers.sort_by_key(|header| header.number.0);
        headers.truncate(limit);
        Ok(headers)
    }
}

fn log_index_bytes(block_number: u64, transaction_index: usize, log_index: usize) -> [u8; 16] {
    let mut location = [0u8; 16];
    location[..8].copy_from_slice(&block_number.to_be_bytes());
    location[8..12].copy_from_slice(&(transaction_index as u32).to_be_bytes());
    location[12..].copy_from_slice(&(log_index as u32).to_be_bytes());
    location
}

fn log_location_key(location: &[u8; 16]) -> Vec<u8> {
    let mut key = b"log:index:location:".to_vec();
    key.extend_from_slice(hex::encode(location).as_bytes());
    key
}

fn log_address_prefix(address: Address) -> Vec<u8> {
    let mut key = b"log:index:address:".to_vec();
    key.extend_from_slice(hex::encode(address.0).as_bytes());
    key.push(b':');
    key
}

fn log_address_key(address: Address, location: &[u8; 16]) -> Vec<u8> {
    let mut key = log_address_prefix(address);
    key.extend_from_slice(hex::encode(location).as_bytes());
    key
}

fn log_topic_prefix(topic: Hash256) -> Vec<u8> {
    let mut key = b"log:index:topic:".to_vec();
    key.extend_from_slice(topic.to_hex().as_bytes());
    key.push(b':');
    key
}

fn log_topic_key(topic: Hash256, location: &[u8; 16]) -> Vec<u8> {
    let mut key = log_topic_prefix(topic);
    key.extend_from_slice(hex::encode(location).as_bytes());
    key
}

fn balance_key(address: Address) -> Vec<u8> {
    let mut key = b"account:balance:".to_vec();
    key.extend_from_slice(hex::encode(address.0).as_bytes());
    key
}

fn nonce_key(address: Address) -> Vec<u8> {
    let mut key = b"account:nonce:".to_vec();
    key.extend_from_slice(hex::encode(address.0).as_bytes());
    key
}

fn code_key(address: Address) -> Vec<u8> {
    let mut key = b"account:code:".to_vec();
    key.extend_from_slice(hex::encode(address.0).as_bytes());
    key
}

fn storage_key(address: Address, slot: Hash256) -> Vec<u8> {
    let mut key = b"account:storage:".to_vec();
    key.extend_from_slice(hex::encode(address.0).as_bytes());
    key.push(b':');
    key.extend_from_slice(slot.to_hex().as_bytes());
    key
}

fn address_from_balance_key(key: &[u8]) -> Result<Address, StorageError> {
    let suffix = key
        .strip_prefix(b"account:balance:")
        .ok_or_else(|| StorageError::Serialization("invalid account key".to_string()))?;
    let value =
        std::str::from_utf8(suffix).map_err(|err| StorageError::Serialization(err.to_string()))?;
    Address::from_hex(value).map_err(|err| StorageError::Serialization(format!("{err:?}")))
}

fn address_from_nonce_key(key: &[u8]) -> Result<Address, StorageError> {
    let suffix = key
        .strip_prefix(b"account:nonce:")
        .ok_or_else(|| StorageError::Serialization("invalid nonce key".to_string()))?;
    let value =
        std::str::from_utf8(suffix).map_err(|err| StorageError::Serialization(err.to_string()))?;
    Address::from_hex(value).map_err(|err| StorageError::Serialization(format!("{err:?}")))
}

fn address_from_code_key(key: &[u8]) -> Result<Address, StorageError> {
    let suffix = key
        .strip_prefix(b"account:code:")
        .ok_or_else(|| StorageError::Serialization("invalid code key".to_string()))?;
    let value =
        std::str::from_utf8(suffix).map_err(|err| StorageError::Serialization(err.to_string()))?;
    Address::from_hex(value).map_err(|err| StorageError::Serialization(format!("{err:?}")))
}

fn address_from_storage_key(key: &[u8]) -> Result<(Address, Hash256), StorageError> {
    let suffix = key
        .strip_prefix(b"account:storage:")
        .ok_or_else(|| StorageError::Serialization("invalid storage key".to_string()))?;
    let separator = suffix
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| StorageError::Serialization("invalid storage key separator".to_string()))?;
    let (address, slot) = suffix.split_at(separator);
    let slot = &slot[1..];
    let address = Address::from_hex(
        std::str::from_utf8(address).map_err(|err| StorageError::Serialization(err.to_string()))?,
    )
    .map_err(|err| StorageError::Serialization(format!("{err:?}")))?;
    let slot = Hash256::from_hex(
        std::str::from_utf8(slot).map_err(|err| StorageError::Serialization(err.to_string()))?,
    )
    .map_err(|err| StorageError::Serialization(format!("{err:?}")))?;
    Ok((address, slot))
}

fn u128_from_slice(value: &[u8]) -> Result<u128, StorageError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| StorageError::Serialization("invalid u128 value".to_string()))?;
    Ok(u128::from_be_bytes(bytes))
}

fn hash_from_bytes(value: &[u8]) -> Result<Hash256, StorageError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StorageError::Serialization("invalid hash value".to_string()))?;
    Ok(Hash256(bytes))
}

pub fn state_root_from_accounts(
    accounts: &BTreeMap<Address, (Bix, u64)>,
) -> Result<Hash256, StorageError> {
    let entries = accounts
        .iter()
        .filter(|(_, (balance, nonce))| balance.0 > 0 || *nonce > 0)
        .collect::<Vec<_>>();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"BLQ-STATE-v1");
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for (address, (balance, nonce)) in entries {
        bytes.extend_from_slice(&address.0);
        bytes.extend_from_slice(&balance.0.to_be_bytes());
        bytes.extend_from_slice(&nonce.to_be_bytes());
    }
    Ok(hash_bytes(&bytes))
}

pub fn evm_state_root_from_accounts(
    accounts: &BTreeMap<Address, EvmAccountSnapshot>,
) -> Result<Hash256, StorageError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"BLQ-EVM-STATE-v1");
    for (address, (balance, nonce, code, storage)) in accounts {
        if balance.0 == 0 && *nonce == 0 && code.is_empty() && storage.is_empty() {
            continue;
        }
        bytes.extend_from_slice(&address.0);
        bytes.extend_from_slice(&balance.0.to_be_bytes());
        bytes.extend_from_slice(&nonce.to_be_bytes());
        bytes.extend_from_slice(&hash_bytes(code).0);
        for (slot, value) in storage {
            bytes.extend_from_slice(&slot.0);
            bytes.extend_from_slice(&value.0);
        }
    }
    Ok(hash_bytes(&bytes))
}

impl ChainStorage for SledStorage {
    fn best_header(&self) -> Result<BlockHeader, StorageError> {
        self.header_by_number(BlockNumber(self.get_best_number()?))
    }

    fn header_by_hash(&self, hash: Hash256) -> Result<BlockHeader, StorageError> {
        for item in self.db.scan_prefix(b"header:number:") {
            let (_, value) = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let header: BlockHeader = serde_json::from_slice(&value)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            if header.hash() == hash {
                return Ok(header);
            }
        }
        self.candidate_block_by_hash(hash).map(|block| block.header)
    }

    fn header_by_number(&self, number: BlockNumber) -> Result<BlockHeader, StorageError> {
        let key = format!("header:number:{:020}", number.0);
        let value = self
            .db
            .get(key.as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        serde_json::from_slice(&value).map_err(|err| StorageError::Serialization(err.to_string()))
    }

    fn insert_header(&mut self, header: BlockHeader) -> Result<(), StorageError> {
        self.put_header(&header)
    }

    fn insert_block(&mut self, block: Block) -> Result<(), StorageError> {
        let key = format!("block:number:{:020}", block.header.number.0);
        let value = serde_json::to_vec(&block)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        self.db
            .insert(key.as_bytes(), value)
            .map_err(|err| StorageError::Io(err.to_string()))?;
        for (transaction_index, transaction) in block.transactions.iter().enumerate() {
            let key = format!("transaction:{}", transaction.hash().to_hex());
            let value = serde_json::to_vec(transaction)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            self.db
                .insert(key.as_bytes(), value)
                .map_err(|err| StorageError::Io(err.to_string()))?;
            if let Some(external_hash) = transaction.external_hash {
                let key = format!("transaction:{}", external_hash.to_hex());
                let value = serde_json::to_vec(transaction)
                    .map_err(|err| StorageError::Serialization(err.to_string()))?;
                self.db
                    .insert(key.as_bytes(), value)
                    .map_err(|err| StorageError::Io(err.to_string()))?;
            }
            let stored = serde_json::to_vec(&StoredReceipt {
                receipt: block.receipts[transaction_index].clone(),
                header: block.header.clone(),
                transaction_index,
                transaction: transaction.clone(),
            })
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
            self.db
                .insert(
                    format!("receipt:{}", transaction.rpc_hash().to_hex()).as_bytes(),
                    stored.clone(),
                )
                .map_err(|err| StorageError::Io(err.to_string()))?;
            self.db
                .insert(
                    format!("receipt:{}", transaction.hash().to_hex()).as_bytes(),
                    stored,
                )
                .map_err(|err| StorageError::Io(err.to_string()))?;
        }
        self.index_block_logs(&block)?;
        self.put_header(&block.header)?;
        self.flush_db()?;
        Ok(())
    }

    fn block_by_number(&self, number: u64) -> Result<Block, StorageError> {
        let key = format!("block:number:{:020}", number);
        let value = self
            .db
            .get(key.as_bytes())
            .map_err(|err| StorageError::Io(err.to_string()))?
            .ok_or(StorageError::NotFound)?;
        serde_json::from_slice(&value).map_err(|err| StorageError::Serialization(err.to_string()))
    }
}

impl FileStorage {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let data_dir = data_dir.as_ref();
        fs::create_dir_all(data_dir).map_err(|err| StorageError::Io(err.to_string()))?;
        let blocks_path = data_dir.join("blocks.jsonl");
        let headers_path = data_dir.join("headers.jsonl");
        ensure_file(&blocks_path)?;
        ensure_file(&headers_path)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            blocks: read_jsonl(&blocks_path)?,
            headers: read_jsonl(&headers_path)?,
            blocks_path,
            headers_path,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.headers.is_empty()
    }

    pub fn disk_usage_bytes(&self) -> Result<u64, StorageError> {
        directory_size(&self.data_dir)
    }

    pub fn headers_after(&self, number: u64, limit: usize) -> Vec<BlockHeader> {
        let mut headers: Vec<BlockHeader> = self
            .headers
            .iter()
            .chain(self.blocks.iter().map(|block| &block.header))
            .filter(|header| header.number.0 > number)
            .cloned()
            .collect();
        headers.sort_by_key(|header| header.number.0);
        headers.truncate(limit);
        headers
    }
}

impl ChainStorage for FileStorage {
    fn best_header(&self) -> Result<BlockHeader, StorageError> {
        self.headers
            .last()
            .cloned()
            .or_else(|| self.blocks.last().map(|block| block.header.clone()))
            .ok_or(StorageError::NotFound)
    }

    fn header_by_hash(&self, hash: Hash256) -> Result<BlockHeader, StorageError> {
        self.headers
            .iter()
            .find(|header| header.hash() == hash)
            .cloned()
            .or_else(|| {
                self.blocks
                    .iter()
                    .find(|block| block.header.hash() == hash)
                    .map(|block| block.header.clone())
            })
            .ok_or(StorageError::NotFound)
    }

    fn header_by_number(&self, number: BlockNumber) -> Result<BlockHeader, StorageError> {
        self.headers
            .iter()
            .find(|header| header.number == number)
            .cloned()
            .or_else(|| {
                self.blocks
                    .iter()
                    .find(|block| block.header.number == number)
                    .map(|block| block.header.clone())
            })
            .ok_or(StorageError::NotFound)
    }

    fn insert_header(&mut self, header: BlockHeader) -> Result<(), StorageError> {
        append_jsonl(&self.headers_path, &header)?;
        self.headers.push(header);
        Ok(())
    }

    fn insert_block(&mut self, block: Block) -> Result<(), StorageError> {
        append_jsonl(&self.blocks_path, &block)?;
        self.blocks.push(block);
        Ok(())
    }

    fn block_by_number(&self, number: u64) -> Result<Block, StorageError> {
        self.blocks
            .iter()
            .find(|block| block.header.number.0 == number)
            .cloned()
            .ok_or(StorageError::NotFound)
    }
}

fn ensure_file(path: &Path) -> Result<(), StorageError> {
    if !path.exists() {
        File::create(path).map_err(|err| StorageError::Io(err.to_string()))?;
    }
    Ok(())
}

fn read_jsonl<T>(path: &Path) -> Result<Vec<T>, StorageError>
where
    T: serde::de::DeserializeOwned,
{
    let file = File::open(path).map_err(|err| StorageError::Io(err.to_string()))?;
    let reader = BufReader::new(file);
    let mut values = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| StorageError::Io(err.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str(&line)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        values.push(value);
    }
    Ok(values)
}

fn append_jsonl<T>(path: &Path, value: &T) -> Result<(), StorageError>
where
    T: serde::Serialize,
{
    let line =
        serde_json::to_string(value).map_err(|err| StorageError::Serialization(err.to_string()))?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|err| StorageError::Io(err.to_string()))?;
    writeln!(file, "{line}").map_err(|err| StorageError::Io(err.to_string()))?;
    Ok(())
}

fn directory_size(path: &Path) -> Result<u64, StorageError> {
    let mut total = 0u64;
    for entry in fs::read_dir(path).map_err(|err| StorageError::Io(err.to_string()))? {
        let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
        let metadata = entry
            .metadata()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn directory_size_recursive(path: &Path) -> Result<u64, StorageError> {
    let mut total = 0u64;
    for entry in fs::read_dir(path).map_err(|err| StorageError::Io(err.to_string()))? {
        let entry = entry.map_err(|err| StorageError::Io(err.to_string()))?;
        let metadata = entry
            .metadata()
            .map_err(|err| StorageError::Io(err.to_string()))?;
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        } else if metadata.is_dir() {
            total = total.saturating_add(directory_size_recursive(&entry.path())?);
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blq_primitives::{logs_root, LogEntry};

    #[test]
    fn sled_storage_tracks_balances_and_state_roots() {
        let path = unique_test_dir("balances");
        let storage = SledStorage::open(&path).expect("open storage");
        let address =
            Address::from_hex("0x1111111111111111111111111111111111111111").expect("address");

        let empty_root = storage.state_root().expect("empty root");
        storage.credit_balance(address, Bix(7)).expect("credit");
        assert_eq!(storage.balance(address).expect("balance"), Bix(7));
        assert_ne!(storage.state_root().expect("credited root"), empty_root);

        drop(storage);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn projected_state_root_does_not_mutate_balance() {
        let path = unique_test_dir("projection");
        let storage = SledStorage::open(&path).expect("open storage");
        let address =
            Address::from_hex("0x2222222222222222222222222222222222222222").expect("address");

        let projected = storage
            .projected_credit_state_root(address, Bix(11))
            .expect("projected root");
        assert_eq!(storage.balance(address).expect("balance"), Bix(0));
        storage.credit_balance(address, Bix(11)).expect("credit");
        assert_eq!(storage.state_root().expect("actual root"), projected);

        drop(storage);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn sled_storage_persists_evm_code_storage_and_root() {
        let path = unique_test_dir("evm-state");
        let storage = SledStorage::open(&path).expect("open storage");
        let address =
            Address::from_hex("0x2222222222222222222222222222222222222222").expect("address");
        let slot = Hash256([7; 32]);
        let value = Hash256([9; 32]);
        let mut slots = BTreeMap::new();
        slots.insert(slot, value);
        storage
            .put_evm_account(address, Bix(33), 4, &[0x60, 0x2a], &slots)
            .expect("persist evm account");
        let snapshot = storage.evm_account_snapshot().expect("snapshot");
        assert_eq!(snapshot[&address].0, Bix(33));
        assert_eq!(snapshot[&address].1, 4);
        assert_eq!(snapshot[&address].2, vec![0x60, 0x2a]);
        assert_eq!(snapshot[&address].3[&slot], value);
        assert_eq!(
            storage.evm_code(address).expect("code read"),
            vec![0x60, 0x2a]
        );
        assert_eq!(
            storage.evm_storage_at(address, slot).expect("slot read"),
            value
        );
        assert_eq!(
            storage
                .evm_storage_at(address, Hash256([8; 32]))
                .expect("missing slot read"),
            Hash256::ZERO
        );
        assert_ne!(
            evm_state_root_from_accounts(&snapshot).expect("root"),
            Hash256::ZERO
        );
        drop(storage);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn sled_storage_removes_cleared_evm_slots() {
        let path = unique_test_dir("evm-slot-clear");
        let storage = SledStorage::open(&path).expect("open storage");
        let address = Address([0x42; 20]);
        let slot = Hash256([0x24; 32]);
        let mut slots = BTreeMap::new();
        slots.insert(slot, Hash256([7; 32]));
        storage
            .put_evm_account(address, Bix(0), 0, &[], &slots)
            .expect("write slot");
        assert_eq!(
            storage.evm_storage_at(address, slot).expect("read slot"),
            Hash256([7; 32])
        );

        storage
            .put_evm_account(address, Bix(0), 0, &[], &BTreeMap::new())
            .expect("clear slot");
        assert_eq!(
            storage
                .evm_storage_at(address, slot)
                .expect("read cleared slot"),
            Hash256::ZERO
        );
        assert!(storage
            .evm_account_snapshot()
            .expect("snapshot")
            .get(&address)
            .and_then(|(_, _, _, account_storage)| account_storage.get(&slot))
            .is_none());
        drop(storage);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn sled_storage_persists_and_indexes_evm_state_snapshots() {
        let path = unique_test_dir("evm-snapshots");
        let address = Address([0x33; 20]);
        let slot = Hash256([4; 32]);
        let value = Hash256([5; 32]);
        let mut slots = BTreeMap::new();
        slots.insert(slot, value);
        let mut snapshot = BTreeMap::new();
        snapshot.insert(address, (Bix(44), 8, vec![0x60, 0x01], slots));
        {
            let storage = SledStorage::open(&path).expect("open storage");
            storage
                .put_evm_state_snapshot(256, &snapshot)
                .expect("persist snapshot");
            assert_eq!(
                storage.evm_state_snapshot(256).expect("read snapshot"),
                Some(snapshot.clone())
            );
            assert_eq!(
                storage
                    .evm_state_snapshot_at_or_before(300)
                    .expect("index snapshot"),
                Some((256, snapshot.clone()))
            );
        }
        let storage = SledStorage::open(&path).expect("reopen storage");
        assert_eq!(
            storage
                .evm_state_snapshot_at_or_before(255)
                .expect("before snapshot"),
            None
        );
        drop(storage);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn pruning_execution_snapshots_keeps_legacy_snapshots_untouched() {
        let root = unique_test_dir("execution-snapshot-pruning");
        let generation = SledStorage::generation_path(&root, 7);
        fs::create_dir_all(&generation).expect("create generation");
        let legacy = SledStorage::snapshot_path(&generation, 100);
        let old_execution = SledStorage::execution_snapshot_path(&generation, 100);
        let retained_execution = SledStorage::execution_snapshot_path(&generation, 200);
        fs::write(&legacy, b"legacy archive snapshot").expect("write legacy snapshot");
        fs::write(&old_execution, b"old execution snapshot").expect("write old execution");
        fs::write(&retained_execution, b"retained execution snapshot")
            .expect("write retained execution");

        SledStorage::prune_old_execution_snapshots(&root, 200).expect("prune execution snapshots");

        assert!(legacy.exists(), "legacy migration data must not be removed");
        assert!(
            !old_execution.exists(),
            "obsolete compact snapshot must be removed"
        );
        assert!(
            retained_execution.exists(),
            "replay checkpoint must be retained"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn sled_storage_seeds_a_snapshot_through_explicit_legacy_maintenance() {
        let path = unique_test_dir("evm-snapshot-migration");
        {
            let mut storage = SledStorage::open(&path).expect("open storage");
            storage
                .insert_block(blq_primitives::genesis_block())
                .expect("insert legacy genesis");
        }
        let storage = SledStorage::open(&path).expect("reopen storage");
        storage
            .seed_evm_state_snapshot()
            .expect("seed legacy snapshot");
        assert!(storage
            .evm_state_snapshot_at_or_before(0)
            .expect("seeded snapshot")
            .is_some());
        drop(storage);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn generation_snapshot_restores_verified_state_for_staging() {
        let path = unique_test_dir("generation-snapshot");
        let root = path.join("generations");
        let active_path = SledStorage::generation_path(&root, 7);
        fs::create_dir_all(&active_path).expect("active directory");
        let mut storage = SledStorage::open(&active_path).expect("open active");
        let genesis = blq_primitives::genesis_block();
        storage
            .insert_block(genesis.clone())
            .expect("insert genesis");
        let contract = Address([0x42; 20]);
        let slot = Hash256([0x24; 32]);
        let mut slots = BTreeMap::new();
        slots.insert(slot, Hash256([0x99; 32]));
        storage
            .put_evm_account(contract, Bix(17), 3, &[0x60, 0x00], &slots)
            .expect("persist snapshot EVM state");
        let snapshot_path = storage
            .create_snapshot(
                &active_path,
                7,
                0,
                genesis.header.hash(),
                "profile".into(),
                0,
            )
            .expect("create generation snapshot");
        let snapshot = SledStorage::load_snapshot(snapshot_path).expect("load snapshot");
        let expected_execution = ExecutionSnapshot::from(&snapshot);
        let execution_snapshot =
            SledStorage::latest_execution_snapshot_at_or_before(&active_path, 0, "profile")
                .expect("load execution view")
                .expect("execution snapshot exists");
        assert_eq!(execution_snapshot, expected_execution);
        assert_eq!(
            execution_snapshot
                .evm_accounts
                .get(&contract)
                .expect("execution contract")
                .2,
            vec![0x60, 0x00]
        );
        let manifest = GenerationManifest {
            generation_id: 8,
            status: GenerationStatus::Staging,
            canonical_height: 0,
            canonical_hash: genesis.header.hash(),
            state_root: genesis.header.state_root,
            profile_fingerprint: "profile".into(),
            finalized_height: 0,
            replay_checkpoint: None,
        };
        let staging = SledStorage::open_staging_from_snapshot(&root, &manifest, &snapshot)
            .expect("open staging from snapshot");
        let restored = SledStorage::open(staging).expect("open restored staging");
        assert_eq!(
            restored.evm_code(contract).expect("restored code"),
            vec![0x60, 0x00]
        );
        assert_eq!(
            restored
                .evm_storage_at(contract, slot)
                .expect("restored slot"),
            Hash256([0x99; 32])
        );
        assert_eq!(restored.best_header().expect("best header"), genesis.header);
        drop(restored);
        drop(storage);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn write_snapshot_round_trips_an_isolated_checkpoint() {
        let path = unique_test_dir("write-generation-snapshot");
        let snapshot = GenerationSnapshot {
            generation_id: 12,
            height: 42,
            block_hash: Hash256([0x11; 32]),
            state_root: Hash256([0x22; 32]),
            profile_fingerprint: "profile".into(),
            finalized_height: 36,
            native_accounts: BTreeMap::new(),
            evm_accounts: BTreeMap::new(),
            entries: vec![(b"checkpoint".to_vec(), b"verified".to_vec())],
        };

        let snapshot_path =
            SledStorage::write_snapshot(&path, &snapshot).expect("persist isolated snapshot");
        assert_eq!(
            SledStorage::load_snapshot(&snapshot_path).expect("reload isolated snapshot"),
            snapshot
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn execution_snapshot_excludes_archive_entries() {
        let path = unique_test_dir("execution-snapshot");
        let snapshot = ExecutionSnapshot {
            generation_id: 12,
            height: 42,
            block_hash: Hash256([0x11; 32]),
            state_root: Hash256([0x22; 32]),
            profile_fingerprint: "profile".into(),
            finalized_height: 36,
            native_accounts: BTreeMap::from([(Address([0x33; 20]), (Bix(7), 2))]),
            evm_accounts: BTreeMap::new(),
        };

        let snapshot_path = SledStorage::write_execution_snapshot(&path, &snapshot)
            .expect("persist execution snapshot");
        let bytes = fs::read(&snapshot_path).expect("snapshot bytes");
        assert!(!String::from_utf8_lossy(&bytes).contains("entries"));
        assert_eq!(
            SledStorage::load_execution_snapshot(&snapshot_path)
                .expect("reload execution snapshot"),
            snapshot
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn compact_execution_snapshot_is_preferred_over_newer_legacy_snapshot() {
        let path = unique_test_dir("execution-snapshot-preference");
        let compact = ExecutionSnapshot {
            generation_id: 12,
            height: 256,
            block_hash: Hash256([0x11; 32]),
            state_root: Hash256([0x22; 32]),
            profile_fingerprint: "profile".into(),
            finalized_height: 250,
            native_accounts: BTreeMap::new(),
            evm_accounts: BTreeMap::new(),
        };
        let legacy = GenerationSnapshot {
            generation_id: 12,
            height: 272,
            block_hash: Hash256([0x33; 32]),
            state_root: Hash256([0x44; 32]),
            profile_fingerprint: "profile".into(),
            finalized_height: 266,
            native_accounts: BTreeMap::new(),
            evm_accounts: BTreeMap::new(),
            entries: vec![(b"archive".to_vec(), vec![0x55; 1024])],
        };
        SledStorage::write_execution_snapshot(&path, &compact).expect("write compact snapshot");
        SledStorage::write_snapshot(&path, &legacy).expect("write legacy snapshot");

        let selected = SledStorage::latest_execution_snapshot_at_or_before(&path, 272, "profile")
            .expect("load preferred snapshot")
            .expect("snapshot exists");
        assert_eq!(selected, compact);
        fs::remove_dir_all(path).ok();
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blq-storage-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    #[test]
    fn sled_storage_bounds_and_reloads_orphan_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        let mut block = blq_primitives::genesis_block();
        block.header.number.0 = 1;
        block.header.parent_hash = blq_primitives::Hash256([7; 32]);
        storage.store_orphan_block(&block).expect("store orphan");
        assert_eq!(storage.orphan_blocks().expect("list orphans").len(), 1);
        storage
            .remove_orphan_block(block.header.hash())
            .expect("remove orphan");
        assert!(storage.orphan_blocks().expect("list orphans").is_empty());
    }

    #[test]
    fn sled_storage_persists_candidate_branch_work() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        let mut block = blq_primitives::genesis_block();
        block.header.number.0 = 1;
        block.header.parent_hash = blq_primitives::genesis_header().hash();
        let hash = block.header.hash();
        storage
            .store_candidate_block(&block, 123)
            .expect("store candidate");
        assert_eq!(storage.candidate_work(hash).expect("candidate work"), 123);
        assert_eq!(storage.block_by_hash(hash).expect("candidate block"), block);
    }

    #[test]
    fn suffix_publication_replaces_only_the_forked_canonical_height() {
        let path = unique_test_dir("suffix-publication");
        let mut storage = SledStorage::open(&path).expect("open storage");
        let genesis = blq_primitives::genesis_block();
        storage
            .insert_block(genesis.clone())
            .expect("insert genesis");
        let mut losing = genesis.clone();
        losing.header.number = BlockNumber(1);
        losing.header.parent_hash = genesis.header.hash();
        losing.header.timestamp_seconds = genesis.header.timestamp_seconds.saturating_add(30);
        losing.header.nonce = 1;
        storage
            .insert_block(losing.clone())
            .expect("insert losing block");
        let previous_manifest = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Active,
            canonical_height: losing.header.number.0,
            canonical_hash: losing.header.hash(),
            state_root: losing.header.state_root,
            profile_fingerprint: "profile".into(),
            finalized_height: 0,
            replay_checkpoint: None,
        };
        SledStorage::write_generation_manifest(&path, &previous_manifest)
            .expect("write previous manifest");
        SledStorage::write_generation_publication(&path, &previous_manifest)
            .expect("write previous publication");
        let mut winner = losing.clone();
        winner.header.nonce = 2;
        assert_ne!(winner.header.hash(), losing.header.hash());
        let target_manifest = GenerationManifest {
            canonical_hash: winner.header.hash(),
            state_root: winner.header.state_root,
            replay_checkpoint: Some(winner.header.number.0),
            ..previous_manifest.clone()
        };
        storage
            .publish_canonical_suffix(
                &genesis.header,
                &[winner.clone()],
                &storage.account_snapshot().expect("native snapshot"),
                &storage.evm_account_snapshot().expect("EVM snapshot"),
                (0, 0, 0),
                target_manifest.clone(),
            )
            .expect("publish fork suffix");
        assert_eq!(
            storage.block_by_number(0).expect("genesis retained"),
            genesis
        );
        assert_eq!(storage.block_by_number(1).expect("winner block"), winner);
        assert_eq!(
            SledStorage::load_generation_manifest(&path).expect("load target manifest"),
            Some(target_manifest.clone())
        );
        assert!(SledStorage::load_suffix_publication(&path)
            .expect("load suffix journal")
            .is_none());
        // Model a crash after the atomic Sled batch but before the derived
        // manifest refresh. Recovery must recognize the new canonical tip and
        // finish only the metadata publication on the next open.
        SledStorage::write_generation_manifest(&path, &previous_manifest)
            .expect("restore stale manifest");
        SledStorage::write_generation_publication(&path, &previous_manifest)
            .expect("restore stale publication");
        SledStorage::write_suffix_publication(
            &path,
            &SuffixPublicationRecord {
                previous_manifest,
                target_manifest: target_manifest.clone(),
            },
        )
        .expect("persist publication intent");
        drop(storage);
        let recovered = SledStorage::open(&path).expect("recover published suffix");
        assert_eq!(
            recovered
                .verify_generation_manifest()
                .expect("verified manifest"),
            target_manifest
        );
        assert!(SledStorage::load_suffix_publication(&path)
            .expect("load recovered suffix journal")
            .is_none());
        drop(recovered);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn published_branch_cleanup_removes_only_its_candidate_and_spool_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        let mut block = blq_primitives::genesis_block();
        block.header.number.0 = 1;
        block.header.parent_hash = blq_primitives::genesis_header().hash();
        let hash = block.header.hash();
        let tip = Hash256([0x5c; 32]);
        storage
            .store_candidate_block(&block, 123)
            .expect("store candidate");
        storage
            .store_recovery_block_unflushed(tip, &block, 123)
            .expect("store recovery body");

        storage
            .remove_candidate_blocks(&[hash])
            .expect("remove published candidate");
        storage
            .clear_recovery_blocks_for_tip(tip)
            .expect("clear published spool");

        assert!(matches!(
            storage.candidate_work(hash),
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            storage.recovery_block_by_hash(hash),
            Err(StorageError::NotFound)
        ));
        assert!(storage
            .recovery_blocks_for_tip(tip)
            .expect("empty spool")
            .is_empty());
    }

    #[test]
    fn recovery_spool_migrates_legacy_hash_index_without_refetching() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        let tip = Hash256([0x5a; 32]);
        let block = blq_primitives::genesis_block();
        let hash = block.header.hash();
        storage
            .store_recovery_block_unflushed(tip, &block, 42)
            .expect("store recovery body");
        // Model the index created by the predecessor build: a raw tip hash
        // rather than the body-key prefix used by the current format.
        storage
            .db
            .insert(
                format!("recovery:hash:{}", hash.to_hex()).as_bytes(),
                tip.0.as_slice(),
            )
            .expect("write legacy index");

        let (restored, work) = storage
            .recovery_block_by_hash(hash)
            .expect("migrate lookup");
        assert_eq!(restored, block);
        assert_eq!(work, 42);
        let index = storage
            .db
            .get(format!("recovery:hash:{}", hash.to_hex()).as_bytes())
            .expect("read index")
            .expect("index exists");
        assert!(std::str::from_utf8(&index)
            .expect("migrated index text")
            .starts_with("recovery:"));
        assert_eq!(
            storage
                .recovery_blocks_for_tip(tip)
                .expect("list recovery spool"),
            vec![(block, 42)]
        );
    }

    #[test]
    fn recovery_spool_rebuilds_a_missing_hash_index_without_refetching() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        let tip = Hash256([0x6b; 32]);
        let block = blq_primitives::genesis_block();
        let hash = block.header.hash();
        storage
            .store_recovery_block_unflushed(tip, &block, 77)
            .expect("store recovery body");
        storage
            .db
            .remove(format!("recovery:hash:{}", hash.to_hex()).as_bytes())
            .expect("remove index");

        let (restored, work) = storage
            .recovery_block_by_hash(hash)
            .expect("rebuild lookup");
        assert_eq!(restored, block);
        assert_eq!(work, 77);
        assert!(storage
            .db
            .get(format!("recovery:hash:{}", hash.to_hex()).as_bytes())
            .expect("read rebuilt index")
            .is_some());
    }

    #[test]
    fn pruning_never_removes_bodies_at_or_below_finalized_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut storage = SledStorage::open(dir.path()).expect("open storage");
        let genesis = blq_primitives::genesis_block();
        storage.insert_block(genesis.clone()).expect("genesis");
        let mut retained = genesis.clone();
        retained.header.number.0 = 1;
        retained.header.parent_hash = genesis.header.hash();
        storage
            .insert_block(retained.clone())
            .expect("retained block");
        let mut removable = retained.clone();
        removable.header.number.0 = 2;
        removable.header.parent_hash = retained.header.hash();
        storage
            .insert_block(removable.clone())
            .expect("removable block");

        storage
            .prune_old_blocks(1, 1)
            .expect("prune above finalized floor");

        assert!(storage.block_by_number(1).is_ok());
    }

    #[test]
    fn sled_storage_indexes_logs_and_rebuilds_on_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let address = Address([0x11; 20]);
        let topic = Hash256([0x22; 32]);
        let mut block = blq_primitives::genesis_block();
        block.receipts = vec![Receipt {
            transaction_hash: Hash256::ZERO,
            success: true,
            gas_used: 0,
            logs_root: logs_root(&[LogEntry {
                address,
                topics: vec![topic],
                data: vec![0xaa],
            }]),
            logs: vec![LogEntry {
                address,
                topics: vec![topic],
                data: vec![0xaa],
            }],
        }];
        {
            let mut storage = SledStorage::open(dir.path()).expect("open storage");
            storage.insert_block(block).expect("insert block");
            assert_eq!(
                storage
                    .indexed_log_block_numbers(0, 0, Some(&[address]), None)
                    .expect("address index"),
                [0].into_iter().collect()
            );
            assert_eq!(
                storage
                    .indexed_log_block_numbers(0, 0, None, Some(&[topic]))
                    .expect("topic index"),
                [0].into_iter().collect()
            );
            assert!(storage
                .indexed_log_block_numbers(1, 2, None, None)
                .expect("range index")
                .is_empty());
        }
        let storage = SledStorage::open(dir.path()).expect("reopen storage");
        assert_eq!(
            storage
                .indexed_log_block_numbers(0, 0, None, None)
                .expect("rebuilt index"),
            [0].into_iter().collect()
        );
    }

    #[test]
    fn generation_manifest_and_checkpoint_writes_are_atomic_and_reloadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generation = SledStorage::generation_path(dir.path(), 0);
        let manifest = GenerationManifest {
            generation_id: 0,
            status: GenerationStatus::Active,
            canonical_height: 12,
            canonical_hash: Hash256([1; 32]),
            state_root: Hash256([2; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 10,
            replay_checkpoint: None,
        };
        SledStorage::write_generation_manifest(&generation, &manifest)
            .expect("write generation manifest");
        assert_eq!(
            SledStorage::load_generation_manifest(&generation).expect("load manifest"),
            Some(manifest.clone())
        );

        let checkpoint = ReplayCheckpoint {
            generation_id: 0,
            height: 8,
            block_hash: Hash256([3; 32]),
            state_root: Hash256([4; 32]),
        };
        SledStorage::write_replay_checkpoint(&generation, &checkpoint).expect("write checkpoint");
        assert_eq!(
            SledStorage::load_replay_checkpoint(&generation).expect("load checkpoint"),
            Some(checkpoint)
        );
        SledStorage::retire_generation(&generation).expect("retire generation");
        assert_eq!(
            SledStorage::load_generation_manifest(&generation)
                .expect("load retired manifest")
                .expect("retired manifest")
                .status,
            GenerationStatus::Retired
        );
    }

    #[test]
    fn staging_generation_publishes_and_updates_active_pointer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = blq_primitives::genesis_block();
        let staging_manifest = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Staging,
            canonical_height: 0,
            canonical_hash: genesis.header.hash(),
            state_root: genesis.header.state_root,
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 0,
            replay_checkpoint: Some(0),
        };
        let staging = SledStorage::create_staging_generation(dir.path(), &staging_manifest)
            .expect("create staging generation");
        let mut staged = SledStorage::open(&staging).expect("open staging storage");
        staged
            .insert_block(genesis.clone())
            .expect("insert genesis");
        SledStorage::write_replay_checkpoint(
            &staging,
            &ReplayCheckpoint {
                generation_id: 1,
                height: 0,
                block_hash: genesis.header.hash(),
                state_root: genesis.header.state_root,
            },
        )
        .expect("write checkpoint");
        drop(staged);
        assert!(staging.exists());
        let verified = GenerationManifest {
            status: GenerationStatus::Verified,
            ..staging_manifest
        };
        let active = SledStorage::publish_staging_generation(dir.path(), 1, &verified)
            .expect("publish staging generation");
        assert!(active.exists());
        assert_eq!(
            SledStorage::load_active_generation(dir.path()).expect("load active pointer"),
            Some(1)
        );
        assert_eq!(
            SledStorage::load_generation_manifest(active)
                .expect("load active manifest")
                .expect("active manifest")
                .status,
            GenerationStatus::Verified
        );
    }

    #[test]
    fn verified_generation_repairs_a_stale_publication_after_canonical_extension() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("generations");
        let generation = SledStorage::generation_path(&root, 1);
        let mut storage = SledStorage::open(&generation).expect("open generation storage");
        let genesis = blq_primitives::genesis_block();
        storage
            .insert_block(genesis.clone())
            .expect("insert genesis");

        let published = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Verified,
            canonical_height: 0,
            canonical_hash: genesis.header.hash(),
            state_root: genesis.header.state_root,
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 0,
            replay_checkpoint: None,
        };
        SledStorage::write_generation_manifest(&generation, &published)
            .expect("write published manifest");
        SledStorage::write_generation_publication(&generation, &published)
            .expect("write publication record");

        let mut next = genesis;
        next.header.number = BlockNumber(1);
        next.header.parent_hash = published.canonical_hash;
        next.header.nonce = 1;
        storage
            .insert_block(next.clone())
            .expect("insert next block");
        let active = GenerationManifest {
            status: GenerationStatus::Active,
            canonical_height: 1,
            canonical_hash: next.header.hash(),
            state_root: next.header.state_root,
            finalized_height: 0,
            ..published
        };
        // Model a restart between a manifest update and its derived record.
        SledStorage::write_generation_manifest(&generation, &active)
            .expect("write active manifest");

        assert_eq!(
            storage
                .verify_generation_manifest()
                .expect("repair stale publication"),
            active
        );
        assert_eq!(
            SledStorage::load_generation_publication(&generation)
                .expect("load repaired publication")
                .expect("publication record")
                .manifest_checksum,
            SledStorage::manifest_checksum(&active).expect("manifest checksum")
        );
    }

    #[test]
    fn recovery_falls_back_to_previous_verified_generation_and_removes_staging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("generations");
        let previous = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Verified,
            canonical_height: 10,
            canonical_hash: Hash256([1; 32]),
            state_root: Hash256([2; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 8,
            replay_checkpoint: Some(9),
        };
        let active = GenerationManifest {
            generation_id: 2,
            status: GenerationStatus::Verified,
            canonical_height: 11,
            canonical_hash: Hash256([3; 32]),
            state_root: Hash256([4; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 9,
            replay_checkpoint: Some(10),
        };
        let staging = GenerationManifest {
            generation_id: 3,
            status: GenerationStatus::Staging,
            canonical_height: 12,
            canonical_hash: Hash256([5; 32]),
            state_root: Hash256([6; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 10,
            replay_checkpoint: Some(11),
        };
        SledStorage::write_generation_manifest(SledStorage::generation_path(&root, 1), &previous)
            .expect("write previous");
        SledStorage::write_generation_manifest(SledStorage::generation_path(&root, 2), &active)
            .expect("write active");
        SledStorage::write_generation_manifest(
            SledStorage::staging_generation_path(&root, 3),
            &staging,
        )
        .expect("write staging");
        SledStorage::write_active_generation(&root, 2).expect("write active pointer");

        let storage = SledStorage::open(dir.path()).expect("open storage");
        storage.recover_generation_state().expect("recover");

        assert_eq!(
            SledStorage::load_active_generation(&root).expect("load active"),
            Some(2)
        );
        assert!(!SledStorage::staging_generation_path(&root, 3).exists());
        assert_eq!(
            SledStorage::load_generation_manifest(SledStorage::generation_path(&root, 2))
                .expect("load active manifest")
                .expect("active manifest")
                .status,
            GenerationStatus::Verified
        );
    }

    #[test]
    fn recovery_restores_previous_verified_generation_when_active_manifest_is_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("generations");
        let previous = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Verified,
            canonical_height: 4,
            canonical_hash: Hash256([7; 32]),
            state_root: Hash256([8; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 2,
            replay_checkpoint: Some(3),
        };
        SledStorage::write_generation_manifest(SledStorage::generation_path(&root, 1), &previous)
            .expect("write previous");
        SledStorage::write_active_generation(&root, 99).expect("write corrupt active");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        storage.recover_generation_state().expect("recover");
        assert_eq!(
            SledStorage::load_active_generation(&root).expect("load active"),
            Some(1)
        );
    }

    #[test]
    fn recovery_rejects_active_generation_with_mismatched_checkpoint_and_tip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("generations");
        let genesis = blq_primitives::genesis_block();

        let previous_path = SledStorage::generation_path(&root, 1);
        let mut previous_storage = SledStorage::open(&previous_path).expect("open previous");
        previous_storage
            .insert_block(genesis.clone())
            .expect("insert previous genesis");
        let previous = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Verified,
            canonical_height: 0,
            canonical_hash: genesis.header.hash(),
            state_root: genesis.header.state_root,
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 0,
            replay_checkpoint: None,
        };
        SledStorage::write_generation_manifest(&previous_path, &previous)
            .expect("write previous manifest");
        drop(previous_storage);

        let broken_path = SledStorage::generation_path(&root, 2);
        let mut broken_storage = SledStorage::open(&broken_path).expect("open broken");
        broken_storage
            .insert_block(genesis.clone())
            .expect("insert broken genesis");
        let broken = GenerationManifest {
            generation_id: 2,
            status: GenerationStatus::Active,
            canonical_height: 7,
            canonical_hash: Hash256([7; 32]),
            state_root: Hash256([8; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 0,
            replay_checkpoint: Some(7),
        };
        SledStorage::write_generation_manifest(&broken_path, &broken)
            .expect("write broken manifest");
        drop(broken_storage);
        SledStorage::write_active_generation(&root, 2).expect("write active pointer");

        let _root_storage = SledStorage::open(dir.path()).expect("recover root storage");
        assert_eq!(
            SledStorage::load_active_generation(&root).expect("load active generation"),
            Some(1)
        );
        assert_eq!(
            SledStorage::load_generation_manifest(&broken_path)
                .expect("load broken manifest")
                .expect("broken manifest")
                .status,
            GenerationStatus::Failed
        );
    }

    #[test]
    fn candidate_tip_reports_highest_work() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        let mut block = blq_primitives::genesis_block();
        block.header.number.0 = 1;
        block.header.parent_hash = blq_primitives::genesis_header().hash();
        let first = block.clone();
        storage
            .store_candidate_block(&first, 10)
            .expect("store first candidate");
        let mut second = block;
        second.header.nonce = 2;
        storage
            .store_candidate_block(&second, 20)
            .expect("store second candidate");
        let tip = storage
            .latest_candidate_tip()
            .expect("candidate tip")
            .expect("candidate present");
        assert_eq!(tip.1, 20);
        assert_eq!(tip.0.hash(), second.header.hash());
    }

    #[test]
    fn candidate_tip_uses_lower_hash_for_equal_work() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        let mut first = blq_primitives::genesis_block();
        first.header.number.0 = 1;
        first.header.parent_hash = blq_primitives::genesis_header().hash();
        let mut second = first.clone();
        second.header.nonce = 2;
        storage
            .store_candidate_block(&first, 20)
            .expect("store first");
        storage
            .store_candidate_block(&second, 20)
            .expect("store second");
        let expected = if first.header.hash() < second.header.hash() {
            first.header.hash()
        } else {
            second.header.hash()
        };
        assert_eq!(
            storage
                .latest_candidate_tip()
                .expect("candidate tip")
                .expect("candidate present")
                .0
                .hash(),
            expected
        );
    }

    #[test]
    fn recovery_ignores_abandoned_staging_and_falls_back_to_previous_verified_generation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("generations");
        let previous = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Verified,
            canonical_height: 8,
            canonical_hash: Hash256([7; 32]),
            state_root: Hash256([8; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 6,
            replay_checkpoint: Some(8),
        };
        let staging = GenerationManifest {
            generation_id: 2,
            status: GenerationStatus::Staging,
            canonical_height: 9,
            canonical_hash: Hash256([9; 32]),
            state_root: Hash256([10; 32]),
            profile_fingerprint: "profile-test".to_string(),
            finalized_height: 7,
            replay_checkpoint: None,
        };
        SledStorage::write_generation_manifest(SledStorage::generation_path(&root, 1), &previous)
            .expect("write previous manifest");
        SledStorage::write_generation_manifest(
            SledStorage::staging_generation_path(&root, 2),
            &staging,
        )
        .expect("write staging manifest");
        SledStorage::write_active_generation(&root, 2).expect("write corrupt active pointer");
        let storage = SledStorage::open(dir.path()).expect("open storage");
        storage.recover_generation_state().expect("recover");
        assert_eq!(
            SledStorage::load_active_generation(&root).expect("load active"),
            Some(1)
        );
        assert!(SledStorage::staging_generation_path(&root, 2).exists() == false);
    }

    #[test]
    fn publication_retains_active_and_previous_verified_generations_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("generations");
        for generation_id in 1..=4 {
            let manifest = GenerationManifest {
                generation_id,
                status: GenerationStatus::Verified,
                canonical_height: generation_id * 10,
                canonical_hash: Hash256([generation_id as u8; 32]),
                state_root: Hash256([generation_id as u8 + 1; 32]),
                profile_fingerprint: "profile-test".to_string(),
                finalized_height: generation_id * 10 - 2,
                replay_checkpoint: Some(generation_id * 10),
            };
            let path = SledStorage::generation_path(&root, generation_id);
            SledStorage::write_generation_manifest(&path, &manifest).expect("write manifest");
        }
        SledStorage::prune_old_generations(&root).expect("prune generations");
        assert!(SledStorage::generation_path(&root, 4).exists());
        assert!(SledStorage::generation_path(&root, 3).exists());
        assert!(!SledStorage::generation_path(&root, 2).exists());
        assert!(!SledStorage::generation_path(&root, 1).exists());
    }
}
