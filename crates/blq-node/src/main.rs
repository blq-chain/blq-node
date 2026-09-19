#![recursion_limit = "256"]

use alloy_primitives::{keccak256, Signature as EthSignature, B256};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use blq_consensus::{
    block_reward_for_interval_bix, fee_split_for_utilization, next_base_fee_per_gas,
    next_block_difficulty_target, next_block_difficulty_target_v2, utilization_basis_points,
    validate_block_with_genesis_and_activation, validate_header_with_genesis,
    validate_transaction_fee,
};
use blq_evm::{RevmAccount, RevmBlockExecutor, RevmState};
use blq_mempool::Mempool;
use blq_network::{work_for_target, PeerId, PeerScoreBook};
use blq_primitives::{
    genesis_block, genesis_header, logs_root, parse_beneficiary, receipts_root, transactions_root,
    Address, Bix, Block, BlockHeader, Hash256, LogEntry, NodeMode, Receipt, Transaction,
    TransactionAccessListItem, TransactionSignature, MAINNET_CHAIN_ID, MAX_ACCESS_LIST_ENTRIES,
    MAX_ACCESS_LIST_STORAGE_KEYS, MAX_ACCESS_LIST_STORAGE_KEYS_PER_ENTRY, MAX_BLOCK_BYTES,
    MAX_TRANSACTION_PAYLOAD_BYTES,
};
use blq_rpc::{ChainInfo, RpcSnapshot};
use blq_storage::{
    state_root_from_accounts, ChainStorage, ExecutionSnapshot, FileStorage, GenerationManifest,
    GenerationSnapshot, GenerationStatus, ReplayCheckpoint, SledStorage,
};
use clap::{Parser, Subcommand};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned,
};
use secp256k1::{
    ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, PublicKey, Secp256k1, SecretKey,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::Shutdown,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TRANSFER_GAS: u64 = 21_000;
const MAX_EVM_CALL_GAS: u64 = 16_777_216;
const MAX_P2P_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_FEE_HISTORY_BLOCKS: u64 = 1024;
const MAX_RPC_BATCH_REQUESTS: usize = 20;
/// Filters are node-local convenience state. Keep their lifetime bounded so a
/// public RPC client cannot turn them into unbounded process memory.
const MAX_RPC_FILTERS: usize = 256;
const RPC_FILTER_TTL_SECONDS: u64 = 5 * 60;
const LIVENESS_DEGRADED_AFTER_SECONDS: u64 = 3 * blq_primitives::TARGET_BLOCK_TIME_SECONDS;
const LIVENESS_STALLED_AFTER_SECONDS: u64 = 10 * blq_primitives::TARGET_BLOCK_TIME_SECONDS;
const MAX_P2P_HEADERS: usize = 512;
const MAX_P2P_MESSAGES_PER_CONNECTION: usize = 1_024;
const MAX_TRANSACTION_GOSSIP_QUEUE: usize = 512;
const TRANSACTION_GOSSIP_WORKERS: usize = 2;
const TRANSACTION_GOSSIP_INVENTORY_TTL_SECONDS: u64 = 10 * 60;
const MAX_BLOCK_GOSSIP_QUEUE: usize = 64;
const BLOCK_GOSSIP_WORKERS: usize = 2;
const BLOCK_GOSSIP_INVENTORY_TTL_SECONDS: u64 = 2 * 60;
const MEMPOOL_TRANSACTION_EXPIRY_SECONDS: u64 = 2 * 60 * 60;
const MAX_P2P_BODY_REQUESTS_PER_CONNECTION: usize = 256;
// A recovery batch must be substantially larger than normal block production.
// At a 30-second target, 128 bodies per durable checkpoint leaves ample room
// for provider latency while avoiding a reconnect after every 16 bodies.
const SYNC_COMMIT_BATCH_SIZE: usize = 128;
const SYNC_CHECKPOINT_BATCH_SIZE: usize = 32;
const SYNC_RANGE_SIZE: usize = 128;
const RECOVERY_NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);
const RECOVERY_MIN_BATCH_BODIES: usize = 32;
const RECOVERY_MIN_BATCH_WINDOW: Duration = Duration::from_secs(20);
const MAX_DISCOVERY_PEERS: usize = 1_024;
const MAX_RELAY_NODES: usize = 1_024;
const MAX_RELAY_MESSAGES_PER_NODE: usize = 256;
const DEFAULT_MAX_SAVED_PEERS: usize = 32;
const MAX_SAVED_PEERS: usize = 512;
const MAX_ROUTES_PER_SAVED_PEER: usize = 4;
const P2P_PEER_CACHE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_LIVE_TIMESTAMP_FUTURE_DRIFT_SECONDS: u64 = 30;
// Confirmation depth is operational metadata for clients and retention. It
// is deliberately not a consensus checkpoint: PoW fork choice always follows
// cumulative work, including a deeper complete branch.
// A live fork is bounded so a malformed peer cannot make a node allocate an
// unbounded branch. The larger limit permits recovery from a legacy active
// generation that predates per-generation snapshots.
// A full node recovering from a long-lived partition must be able to replay
// the complete suffix from a verified snapshot. This remains bounded, but is
// large enough for the current 2,495 -> 7,581 recovery without forcing an
// unsafe genesis fallback or a manual database intervention.
const MAX_CANDIDATE_REPLAY_SUFFIX: usize = 8_192;
// Candidate bodies already reside in the durable recovery spool. The live
// publisher receives one resolved suffix in memory, so cap its serialized
// footprint before allocating the execution overlay. Canonical history before
// the fork ancestor is streamed from Sled one body at a time.
const MAX_CANDIDATE_REPLAY_BYTES: usize = 256 * 1024 * 1024;
const MIN_CANDIDATE_REPLAY_MEMORY_HEADROOM_BYTES: u64 = 768 * 1024 * 1024;
const MAX_LEGACY_SNAPSHOT_RECOVERY_BLOCKS: usize = 8_192;
const MIN_CANDIDATE_REPLAY_FREE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OPTIONAL_SERVICE_CONNECTIONS: usize = 128;
const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const P2P_READ_TIMEOUT: Duration = Duration::from_secs(30);
const P2P_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
// A peer can legitimately return the current tip body during routine
// reconciliation.  That is not sync progress and must not reset the retry
// backoff, otherwise already-synced nodes churn short-lived TLS sessions.
const P2P_SYNC_IDLE_RETRY_MAX_SECONDS: u64 = 30;
// A peer can be reachable by both a private mesh route and a public route.
// Prefer one authenticated route during normal operation, but leave the
// alternate route ready to take over promptly after a real connect failure.
const P2P_ROUTE_FAILOVER_WINDOW_SECONDS: u64 = 60;
// Inbound sockets exist to serve one bounded P2P exchange, not to become
// permanent idle leases.  Outbound sync owns its own 30-second deadline;
// keeping inbound handlers short prevents public churn from consuming the
// shared session budget needed for recovery providers.
const P2P_INBOUND_READ_TIMEOUT: Duration = Duration::from_secs(10);
// A range response is streamed as bounded body frames on the same session.
// Keep the connection alive long enough to finish one range; the per-read,
// request-count, byte, and recovery no-progress deadlines remain the guards.
const P2P_INBOUND_SESSION_MAX: Duration = Duration::from_secs(120);
// WebSocket subscriptions are long-lived, but an abandoned client must not
// retain an RPC handler forever. Successful client frames or notifications
// reset this deadline; idle clients reconnect through the normal backoff.
const RPC_WEBSOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
// A storage-blocked node must remain quiet enough that its own journal does
// not consume the remaining filesystem reserve. The state transition is still
// always logged; this interval only bounds repeated reminders while the
// reserve remains unavailable.
const MEMPOOL_PERSISTENCE_PRESSURE_LOG_INTERVAL: Duration = Duration::from_secs(5 * 60);
// Keep enough headroom for the single durable recovery session.  A node that
// has reached this limit is still able to finish its existing work, but it
// stops admitting more short-lived relay/discovery handlers that could starve
// the recovery cursor.
const P2P_SESSION_LIMIT: usize = 24;
/// Keep authenticated configured routes usable during public inbound churn.
/// A peer discovered on several addresses still has its own identity lease;
/// this reserve only prevents anonymous inbound handlers from consuming every
/// OS/P2P session before node-to-node recovery can connect.
const P2P_CONFIGURED_SESSION_RESERVE: usize = 6;
const P2P_UNTRUSTED_SESSION_LIMIT: usize =
    P2P_SESSION_LIMIT.saturating_sub(P2P_CONFIGURED_SESSION_RESERVE);
const P2P_CLOSE_WAIT_THRESHOLD: usize = P2P_SESSION_LIMIT;
// The node uses one bounded blocking handler per HTTP or WebSocket client.
// Keeping this close to the P2P budget prevents public RPC churn from
// exhausting the scheduler or file-descriptor table required for sync.
const DEFAULT_RPC_CONNECTIONS: usize = 64;
const FINALITY_CONFIRMATION_DEPTH: u64 = 6;
const P2P_IDENTITY_FILE: &str = "identity.key";
const REPLAY_CHECKPOINT_INTERVAL: usize = 16;
// Supply is a derived index, not consensus state. Persist it periodically so
// a restart can resume an archive backfill without delaying fork publication
// behind thousands of per-block database flushes.
const SUPPLY_BACKFILL_CHECKPOINT_INTERVAL: u64 = 256;

// Candidate replay is deliberately single-flight per node. A lagging peer can
// deliver many bodies from the same competing branch; replaying each arrival
// concurrently would starve the active RPC and P2P paths without improving
// fork-choice correctness.
static CANDIDATE_REPLAY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static BLOCK_IMPORT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
static SOCKET_COUNTER_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static REORG_IN_PROGRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// Snapshot bootstrap is the expensive legacy recovery path. Keep a separate
// lease because several completed range notifications can arrive while the
// bootstrap is still constructing its checkpoint.
static SNAPSHOT_BOOTSTRAP_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static SNAPSHOT_BOOTSTRAP_LEASE_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static ACTIVE_P2P_SESSIONS: AtomicUsize = AtomicUsize::new(0);
static CLOSING_P2P_SESSIONS: AtomicUsize = AtomicUsize::new(0);
static CLOSED_P2P_SESSIONS: AtomicU64 = AtomicU64::new(0);
static ACTIVE_RPC_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static CLOSING_RPC_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static CLOSED_RPC_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static LAST_RPC_HANDLER_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static LAST_P2P_HANDLER_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static SYNC_SESSION_STARTED_AT: AtomicU64 = AtomicU64::new(0);
static ACTIVE_SYNC_IDENTITIES: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
static ACTIVE_RECOVERY_JOBS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
static KNOWN_PEER_IDENTITIES: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
static CACHED_PEER_ROUTES: OnceLock<Mutex<BTreeMap<String, CachedPeerRoute>>> = OnceLock::new();
static P2P_ROUTE_FAILURES: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
static BRANCH_SYNC_CURSORS: OnceLock<Mutex<BTreeMap<String, BranchSyncCursor>>> = OnceLock::new();
// Cursor updates are made by primary, witness, watchdog, and failover
// sessions. They must serialize the temp-file replacement or one session can
// rename another session's `.tmp` file and lose durable recovery progress.
static BRANCH_SYNC_CURSOR_PERSIST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
// Multiple transport addresses can identify the same remote branch. Keep the
// recovery cursor keyed by tip hash so node 39 and node 43 do not each start a
// separate backwards walk for the same canonical branch.
static PEER_RECOVERY_KEYS: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
static UPSTREAM_TEMPLATE_SOURCES: OnceLock<Mutex<BTreeMap<Hash256, MiningUpstreamTemplate>>> =
    OnceLock::new();
static LOCAL_TEMPLATE_CACHE: OnceLock<Mutex<Option<LocalTemplateCache>>> = OnceLock::new();
static VALIDATED_MINING_UPSTREAMS: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
static TRANSACTION_GOSSIP_QUEUE: OnceLock<SyncSender<TransactionGossipJob>> = OnceLock::new();
static TRANSACTION_GOSSIP_INVENTORY: OnceLock<Mutex<BTreeMap<Hash256, u64>>> = OnceLock::new();
static TRANSACTION_GOSSIP_RECEIVED: AtomicU64 = AtomicU64::new(0);
static TRANSACTION_GOSSIP_RELAYED: AtomicU64 = AtomicU64::new(0);
static TRANSACTION_GOSSIP_FAILURES: AtomicU64 = AtomicU64::new(0);
static BLOCK_GOSSIP_QUEUE: OnceLock<SyncSender<BlockGossipJob>> = OnceLock::new();
static BLOCK_GOSSIP_INVENTORY: OnceLock<Mutex<BTreeMap<Hash256, u64>>> = OnceLock::new();
static BLOCK_GOSSIP_RELAYED: AtomicU64 = AtomicU64::new(0);
static BLOCK_GOSSIP_FAILURES: AtomicU64 = AtomicU64::new(0);
static BLOCK_GOSSIP_DEDUPLICATED: AtomicU64 = AtomicU64::new(0);
static LAST_BLOCK_GOSSIP_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
// Snapshotting and retention pruning are operational maintenance. They must
// not extend the synchronous response after a canonical block is committed.
static CANONICAL_MAINTENANCE_QUEUE: OnceLock<SyncSender<CanonicalMaintenanceJob>> = OnceLock::new();
static CANONICAL_MAINTENANCE_PENDING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static DISCOVERED_PEER_ROUTES: OnceLock<Mutex<BTreeMap<String, PeerRecord>>> = OnceLock::new();
static ACTIVE_DISCOVERY_ROUTES: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
const MAX_DISCOVERY_WORKERS: usize = 16;

#[derive(Clone)]
struct TransactionGossipJob {
    config: NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    transaction: Transaction,
}

#[derive(Clone)]
struct BlockGossipJob {
    config: NodeConfig,
    genesis_hash: Hash256,
    block: Block,
    source_peer: Option<String>,
}

#[derive(Clone)]
struct CanonicalMaintenanceJob {
    config: NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
}

#[derive(Clone, Debug)]
struct CandidateBranch {
    common_height: u64,
    common_hash: Hash256,
    suffix: Vec<Block>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BranchSyncCursor {
    tip_hash: Hash256,
    /// The recovery spool is immutable for the lifetime of a branch job.
    /// Providers keep extending their tip while a deep recovery is in
    /// progress, so using the latest tip hash as the spool namespace would
    /// strand already validated bodies on every new block.
    #[serde(default)]
    spool_tip_hash: Option<Hash256>,
    /// The signed hello height for this remote branch. It makes a branch walk
    /// durable evidence that local mining must stay upstream-backed even if
    /// the peer's short-lived status report expires mid-retrieval.
    #[serde(default)]
    tip_height: u64,
    next_hash: Hash256,
    #[serde(default)]
    consensus_profile: String,
    #[serde(default)]
    imported_bodies: u64,
    #[serde(default)]
    updated_at: u64,
    #[serde(default)]
    ancestor_height: Option<u64>,
    #[serde(default)]
    ancestor_hash: Option<Hash256>,
    /// The first recovered block above the proven ancestor identifies the
    /// branch independently of a moving tip.  It lets two providers share a
    /// job only after they have demonstrated they serve the same suffix.
    #[serde(default)]
    branch_root_hash: Option<Hash256>,
    #[serde(default)]
    next_height: u64,
    #[serde(default)]
    expected_parent_hash: Option<Hash256>,
    #[serde(default)]
    staged_height: u64,
    #[serde(default)]
    state: String,
    /// The provider which most recently received a recovery request. This is
    /// operational state only; branch selection remains consensus-driven.
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    requested_height: Option<u64>,
    #[serde(default)]
    requested_at: u64,
    #[serde(default)]
    last_progress_at: u64,
    #[serde(default)]
    provider_attempts: u32,
    #[serde(default)]
    last_failure: Option<String>,
    #[serde(default)]
    retry_after: u64,
    /// The authenticated identity serving the current bulk range. It is
    /// operational evidence only; consensus is still verified locally.
    #[serde(default)]
    primary_identity: Option<String>,
    /// A second authenticated identity used for bounded header cross-checks.
    #[serde(default)]
    witness_identity: Option<String>,
    #[serde(default = "default_provider_mode")]
    provider_mode: String,
    #[serde(default)]
    witness_sample_heights: Vec<u64>,
    #[serde(default)]
    primary_sample_hashes: BTreeMap<u64, Hash256>,
    #[serde(default)]
    witness_sample_hashes: BTreeMap<u64, Hash256>,
    #[serde(default)]
    witness_mismatch: Option<String>,
    /// A restart must prove the retained spool is contiguous before trusting
    /// its cursor. Older builds could checkpoint the cursor before all spool
    /// keys were durable.
    #[serde(default)]
    spool_verified: bool,
}

fn default_provider_mode() -> String {
    "single-provider".to_string()
}

fn cursor_spool_tip(cursor: &BranchSyncCursor) -> Hash256 {
    cursor.spool_tip_hash.unwrap_or(cursor.tip_hash)
}

#[derive(Clone, Debug)]
struct MiningUpstreamTemplate {
    endpoint: String,
    updated_at: u64,
}

#[derive(Clone)]
struct LocalTemplateCache {
    parent_hash: Hash256,
    beneficiary: Hash256,
    created_at: Instant,
    payload: serde_json::Value,
}

const LOCAL_TEMPLATE_CACHE_TTL: Duration = Duration::from_secs(5);

const MINING_UPSTREAM_TEMPLATE_TTL_SECONDS: u64 = 120;

const HASHRATE_TTL_SECONDS: u64 = 30;
const MAX_HASHRATE_WORKERS: usize = 256;
const MAX_HASHRATE_PER_WORKER: f64 = 1.0e12;

#[derive(Clone)]
struct MinerTelemetry {
    total_hashes: u64,
    elapsed_seconds: f64,
    hashrate: f64,
    updated_at: u64,
}

static MINER_TELEMETRY: OnceLock<Mutex<BTreeMap<String, MinerTelemetry>>> = OnceLock::new();

#[derive(Clone, Default)]
struct SyncProgress {
    current_height: u64,
    network_height: u64,
    active_peer: Option<String>,
    common_ancestor: Option<u64>,
    next_requested_height: u64,
    last_imported_height: u64,
    last_progress_at: u64,
    provider_state: &'static str,
    state: &'static str,
}

static SYNC_PROGRESS: OnceLock<Mutex<SyncProgress>> = OnceLock::new();

fn sync_progress() -> &'static Mutex<SyncProgress> {
    SYNC_PROGRESS.get_or_init(|| {
        Mutex::new(SyncProgress {
            provider_state: "available",
            state: "synced",
            ..Default::default()
        })
    })
}

fn record_sync_progress(peer: &str, current_height: u64, network_height: u64) {
    let now = unix_now();
    let mut progress = sync_progress()
        .lock()
        .expect("sync progress mutex poisoned");
    progress.current_height = current_height;
    progress.network_height = network_height.max(current_height);
    progress.active_peer = Some(peer.to_string());
    progress.next_requested_height = current_height.saturating_add(1);
    progress.last_imported_height = current_height;
    progress.last_progress_at = now;
    progress.provider_state = "available";
    progress.state = if progress.network_height > current_height {
        "syncing"
    } else {
        "synced"
    };
}

fn sync_session_made_progress(
    recovery_range_body: bool,
    canonical_height_before: Option<u64>,
    canonical_height_after: Option<u64>,
) -> bool {
    recovery_range_body
        || canonical_height_before
            .zip(canonical_height_after)
            .is_some_and(|(before, after)| after > before)
}

fn sync_retry_delay(
    confirmed_idle_match: bool,
    authenticated_session: bool,
    made_progress: bool,
    retry_delay_seconds: &mut u64,
) -> u64 {
    if confirmed_idle_match {
        *retry_delay_seconds = P2P_SYNC_IDLE_RETRY_MAX_SECONDS;
        return P2P_SYNC_IDLE_RETRY_MAX_SECONDS;
    }
    if authenticated_session && made_progress {
        *retry_delay_seconds = 1;
        return 1;
    }
    let delay = *retry_delay_seconds;
    *retry_delay_seconds = retry_delay_seconds
        .saturating_mul(2)
        .min(P2P_SYNC_IDLE_RETRY_MAX_SECONDS);
    delay
}

/// Keep the lock-free status fallback honest after an atomic generation
/// publication. `blq_status` deliberately avoids waiting behind storage work;
/// without this update it could report the pre-reorg height while miners and
/// P2P are already using the newly published canonical tip.
fn record_published_tip_progress(storage: &Arc<Mutex<NodeStorage>>) {
    let Some(best) = storage
        .lock()
        .ok()
        .and_then(|guard| guard.best_header().ok())
    else {
        return;
    };
    let mut progress = sync_progress()
        .lock()
        .expect("sync progress mutex poisoned");
    progress.current_height = best.number.0;
    progress.network_height = best.number.0;
    progress.active_peer = None;
    progress.common_ancestor = None;
    progress.next_requested_height = best.number.0.saturating_add(1);
    progress.last_imported_height = best.number.0;
    progress.last_progress_at = unix_now();
    progress.provider_state = "available";
    progress.state = "synced";
}

fn miner_telemetry() -> &'static Mutex<BTreeMap<String, MinerTelemetry>> {
    MINER_TELEMETRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn hashrate_snapshot() -> (Option<f64>, usize, Option<u64>, &'static str) {
    let now = unix_now();
    let mut workers = miner_telemetry().lock().expect("telemetry mutex poisoned");
    workers.retain(|_, worker| now.saturating_sub(worker.updated_at) <= HASHRATE_TTL_SECONDS);
    let count = workers.len();
    let total = workers.values().map(|worker| worker.hashrate).sum::<f64>();
    let latest = workers.values().map(|worker| worker.updated_at).max();
    if count == 0 {
        (None, 0, latest, "unavailable")
    } else {
        (Some(total), count, latest, "live")
    }
}

struct ReorgGuard {
    acquired: bool,
}
impl ReorgGuard {
    fn try_acquire() -> Option<Self> {
        REORG_IN_PROGRESS
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
            .then_some(Self { acquired: true })
    }
}
impl Drop for ReorgGuard {
    fn drop(&mut self) {
        if self.acquired {
            REORG_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct SnapshotBootstrapGuard {
    lease_path: PathBuf,
}
impl SnapshotBootstrapGuard {
    fn try_acquire(root: &Path) -> Result<Option<Self>> {
        let lease_path = root.join(".snapshot-bootstrap.lease");
        // A stale lease can only exist after a prior process exited.  Clean it
        // once per process before any recovery thread is admitted; thereafter
        // the exclusive file is the authoritative cross-thread lease.
        if !SNAPSHOT_BOOTSTRAP_LEASE_INITIALIZED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            match fs::remove_file(&lease_path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    SNAPSHOT_BOOTSTRAP_LEASE_INITIALIZED
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    return Err(err.into());
                }
            }
        }
        let acquired = SNAPSHOT_BOOTSTRAP_IN_PROGRESS
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok();
        if !acquired {
            return Ok(None);
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lease_path)
        {
            Ok(mut lease) => {
                use std::io::Write;
                writeln!(lease, "pid={}", std::process::id())?;
                Ok(Some(Self { lease_path }))
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                SNAPSHOT_BOOTSTRAP_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(None)
            }
            Err(err) => {
                SNAPSHOT_BOOTSTRAP_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
                Err(err.into())
            }
        }
    }
}
impl Drop for SnapshotBootstrapGuard {
    fn drop(&mut self) {
        SNAPSHOT_BOOTSTRAP_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
        let _ = fs::remove_file(&self.lease_path);
    }
}

#[derive(Clone, Debug)]
enum RpcFilterKind {
    Logs(serde_json::Value),
    Blocks,
    PendingTransactions,
}

#[derive(Clone, Debug)]
struct RpcFilter {
    kind: RpcFilterKind,
    last_block: u64,
    last_accessed_at: u64,
}

static RPC_FILTERS: OnceLock<Mutex<BTreeMap<u64, RpcFilter>>> = OnceLock::new();
static PEER_AGREEMENT: OnceLock<Arc<Mutex<PeerAgreement>>> = OnceLock::new();
const PEER_TIP_TTL_SECONDS: u64 = 90;

#[derive(Clone, Debug, Default)]
struct PeerTip {
    best_number: u64,
    best_hash: String,
    consensus_profile: String,
    last_seen: u64,
    body_verified: bool,
}

#[derive(Clone, Debug, Default)]
struct PeerAgreement {
    tips: BTreeMap<String, PeerTip>,
}

fn peer_agreement() -> Arc<Mutex<PeerAgreement>> {
    Arc::clone(PEER_AGREEMENT.get_or_init(|| Arc::new(Mutex::new(PeerAgreement::default()))))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn record_peer_tip(identity_public_key: &str, best_number: u64, best_hash: &str, profile: &str) {
    let state = peer_agreement();
    state
        .lock()
        .expect("peer agreement mutex poisoned")
        .tips
        .insert(
            identity_public_key.to_string(),
            PeerTip {
                best_number,
                best_hash: best_hash.to_string(),
                consensus_profile: profile.to_string(),
                last_seen: unix_now(),
                body_verified: true,
            },
        );
}

fn record_provisional_peer_tip(
    identity_public_key: &str,
    best_number: u64,
    best_hash: &str,
    profile: &str,
) {
    record_peer_tip(identity_public_key, best_number, best_hash, profile);
    if let Some(tip) = peer_agreement()
        .lock()
        .expect("peer agreement mutex poisoned")
        .tips
        .get_mut(identity_public_key)
    {
        tip.body_verified = false;
    }
}

fn mark_peer_body_verified(identity_public_key: &str) {
    let state = peer_agreement();
    let mut guard = state.lock().expect("peer agreement mutex poisoned");
    if let Some(tip) = guard.tips.get_mut(identity_public_key) {
        tip.body_verified = true;
        tip.last_seen = unix_now();
    }
}

fn record_verified_peer_tip(message: &P2pMessage) {
    if let P2pMessage::Hello {
        identity_public_key,
        best_number,
        best_hash,
        consensus_profile,
        ..
    } = message
    {
        record_provisional_peer_tip(
            identity_public_key,
            *best_number,
            best_hash,
            consensus_profile,
        );
    }
}

fn trusted_peer_quorum(
    config: &NodeConfig,
    local: &BlockHeader,
    genesis_hash: Hash256,
) -> (bool, usize, usize) {
    if config.network.trusted_peer_keys.is_empty() {
        return (true, 0, 0);
    }
    let profile = network_consensus_profile(config, genesis_hash);
    let state = peer_agreement();
    let state = state.lock().expect("peer agreement mutex poisoned");
    let reports = config
        .network
        .trusted_peer_keys
        .iter()
        .filter_map(|key| state.tips.get(key))
        .filter(|tip| {
            tip.body_verified && unix_now().saturating_sub(tip.last_seen) <= PEER_TIP_TTL_SECONDS
        })
        .collect::<Vec<_>>();
    let matching = reports
        .iter()
        .filter(|tip| {
            tip.best_number == local.number.0
                && tip.best_hash == local.hash().to_hex()
                && tip.consensus_profile == profile
        })
        .count();
    let compatible = reports
        .iter()
        .filter(|tip| tip.consensus_profile == profile)
        .collect::<Vec<_>>();
    let _conflicting = compatible.iter().any(|tip| {
        tip.best_number >= local.number.0
            && (tip.best_number != local.number.0 || tip.best_hash != local.hash().to_hex())
    });
    // Peer reports are advisory. A healthy node must remain able to mine when
    // peers are offline, still catching up, or have not reported a tip yet.
    // Only an active same-or-higher conflicting tip makes mining unsafe.
    // A valid peer tip is not an operator emergency. The node's cumulative
    // work fork choice resolves competing branches and stale submissions
    // cause miners to refresh. Keep the conflict signal for diagnostics, but
    // do not deadlock mining before fork choice can run.
    let safe = true;
    (safe, reports.len(), matching)
}

fn trusted_peer_status(
    config: &NodeConfig,
    local: &BlockHeader,
    genesis_hash: Hash256,
) -> Vec<serde_json::Value> {
    let profile = network_consensus_profile(config, genesis_hash);
    let state = peer_agreement();
    let state = state.lock().expect("peer agreement mutex poisoned");
    config
        .network
        .trusted_peer_keys
        .iter()
        .map(|key| {
            let Some(tip) = state.tips.get(key) else {
                return serde_json::json!({"peer": key, "status": "offline"});
            };
            let status = if unix_now().saturating_sub(tip.last_seen) > PEER_TIP_TTL_SECONDS {
                "offline"
            } else if tip.consensus_profile != profile {
                "incompatible"
            } else if !tip.body_verified {
                "body-unavailable"
            } else if tip.best_number < local.number.0 {
                "lagging"
            } else if tip.best_number == local.number.0 && tip.best_hash == local.hash().to_hex() {
                "matching"
            } else {
                "conflicting"
            };
            serde_json::json!({
                "peer": key,
                "status": status,
                "height": tip.best_number,
                "hash": tip.best_hash,
            })
        })
        .collect()
}
static NEXT_RPC_FILTER_ID: AtomicU64 = AtomicU64::new(1);

fn rpc_filters() -> &'static Mutex<BTreeMap<u64, RpcFilter>> {
    RPC_FILTERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct ActiveConnectionGuard(Arc<AtomicUsize>);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_connection(active: &AtomicUsize, limit: usize) -> bool {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < limit).then_some(count + 1)
        })
        .is_ok()
}

fn connect_tcp_session(endpoint: &str) -> Result<TcpStream> {
    let mut last_error = None;
    for address in endpoint.to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, P2P_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(P2P_READ_TIMEOUT))?;
                stream.set_write_timeout(Some(P2P_WRITE_TIMEOUT))?;
                return Ok(stream);
            }
            Err(err) => last_error = Some(err),
        }
    }
    match last_error {
        Some(err) => Err(err.into()),
        None => anyhow::bail!("no socket address resolved for {endpoint}"),
    }
}

fn active_sync_identities() -> &'static Mutex<BTreeSet<String>> {
    ACTIVE_SYNC_IDENTITIES.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn active_recovery_jobs() -> &'static Mutex<BTreeSet<String>> {
    ACTIVE_RECOVERY_JOBS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn known_peer_identities() -> &'static Mutex<BTreeMap<String, String>> {
    KNOWN_PEER_IDENTITIES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedPeerRoute {
    identity_public_key: String,
    routes: Vec<String>,
    last_success_epoch: u64,
    #[serde(default)]
    last_failure_epoch: Option<u64>,
    expires_at_epoch: u64,
}

fn cached_peer_routes() -> &'static Mutex<BTreeMap<String, CachedPeerRoute>> {
    CACHED_PEER_ROUTES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn p2p_route_failures() -> &'static Mutex<BTreeMap<String, u64>> {
    P2P_ROUTE_FAILURES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn peer_identity_path(config: &NodeConfig) -> PathBuf {
    Path::new(&config.node.data_dir).join("peer-identities.json")
}

fn peer_route_cache_path(config: &NodeConfig) -> PathBuf {
    Path::new(&config.node.data_dir).join("peer-routes.json")
}

fn normalize_peer_route(route: &str) -> Result<String> {
    Ok(route
        .parse::<SocketAddr>()
        .map_err(|err| anyhow::anyhow!("peer route is invalid: {err}"))?
        .to_string())
}

fn valid_cached_peer_identity(identity: &str) -> bool {
    identity.len() == 66
        && identity.is_ascii()
        && identity.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn cached_peer_route_is_valid(peer: &CachedPeerRoute) -> bool {
    valid_cached_peer_identity(&peer.identity_public_key)
        && !peer.routes.is_empty()
        && peer.routes.len() <= MAX_ROUTES_PER_SAVED_PEER
        && peer.expires_at_epoch >= unix_now()
        && peer
            .routes
            .iter()
            .all(|route| normalize_peer_route(route).is_ok())
}

fn trim_cached_peer_routes(routes: &mut BTreeMap<String, CachedPeerRoute>, limit: usize) {
    routes.retain(|identity, peer| {
        identity == &peer.identity_public_key && cached_peer_route_is_valid(peer)
    });
    while routes.len() > limit {
        let eviction = routes
            .iter()
            .min_by_key(|(identity, peer)| {
                (
                    peer.expires_at_epoch,
                    peer.last_success_epoch,
                    (*identity).clone(),
                )
            })
            .map(|(identity, _)| identity.clone());
        let Some(identity) = eviction else {
            break;
        };
        routes.remove(&identity);
    }
}

fn persist_cached_peer_routes(config: &NodeConfig) -> Result<()> {
    let path = peer_route_cache_path(config);
    let data = serde_json::to_vec_pretty(
        &*cached_peer_routes()
            .lock()
            .expect("cached peer routes mutex poisoned"),
    )?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, data)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn load_cached_peer_routes(config: &NodeConfig) {
    let path = peer_route_cache_path(config);
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    let loaded = match serde_json::from_slice::<BTreeMap<String, CachedPeerRoute>>(&bytes) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("could not load persisted peer route cache: {err}");
            return;
        }
    };
    let mut routes = cached_peer_routes()
        .lock()
        .expect("cached peer routes mutex poisoned");
    routes.extend(loaded);
    trim_cached_peer_routes(&mut routes, config.network.max_saved_peers);
    let identities = routes
        .values()
        .flat_map(|peer| {
            peer.routes
                .iter()
                .cloned()
                .map(move |route| (route, peer.identity_public_key.clone()))
        })
        .collect::<Vec<_>>();
    drop(routes);
    known_peer_identities()
        .lock()
        .expect("known peer identities mutex poisoned")
        .extend(identities);
}

fn cached_peer_endpoints() -> Vec<String> {
    cached_peer_routes()
        .lock()
        .expect("cached peer routes mutex poisoned")
        .values()
        .filter(|peer| cached_peer_route_is_valid(peer))
        .flat_map(|peer| peer.routes.iter().cloned())
        .collect()
}

fn remember_verified_peer_route(config: &NodeConfig, peer: &str, identity: &str) {
    let Ok(route) = normalize_peer_route(peer) else {
        return;
    };
    if !valid_cached_peer_identity(identity) {
        return;
    }
    let now = unix_now();
    let mut routes = cached_peer_routes()
        .lock()
        .expect("cached peer routes mutex poisoned");
    let entry = routes
        .entry(identity.to_string())
        .or_insert_with(|| CachedPeerRoute {
            identity_public_key: identity.to_string(),
            routes: Vec::new(),
            last_success_epoch: now,
            last_failure_epoch: None,
            expires_at_epoch: now.saturating_add(P2P_PEER_CACHE_TTL_SECONDS),
        });
    entry.routes.retain(|candidate| candidate != &route);
    entry.routes.push(route);
    entry
        .routes
        .sort_by_key(|candidate| (route_priority(candidate), candidate.clone()));
    entry.routes.truncate(MAX_ROUTES_PER_SAVED_PEER);
    entry.last_success_epoch = now;
    entry.last_failure_epoch = None;
    entry.expires_at_epoch = now.saturating_add(P2P_PEER_CACHE_TTL_SECONDS);
    trim_cached_peer_routes(&mut routes, config.network.max_saved_peers);
    drop(routes);
    if let Err(err) = persist_cached_peer_routes(config) {
        eprintln!("could not persist verified peer route for {peer}: {err}");
    }
}

/// Route aliases are operational metadata learned only from a signed Hello.
/// They are deliberately separate from peer scoring and consensus storage.
fn load_known_peer_identities(config: &NodeConfig) {
    let path = peer_identity_path(config);
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    match serde_json::from_slice::<BTreeMap<String, String>>(&bytes) {
        Ok(saved) => {
            known_peer_identities()
                .lock()
                .expect("known peer identities mutex poisoned")
                .extend(saved);
        }
        Err(err) => eprintln!("could not load persisted peer route identities: {err}"),
    }
}

fn persist_known_peer_identities(config: &NodeConfig) -> Result<()> {
    let path = peer_identity_path(config);
    let data = serde_json::to_vec_pretty(
        &*known_peer_identities()
            .lock()
            .expect("known peer identities mutex poisoned"),
    )?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, data)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn remember_verified_peer_identity(config: &NodeConfig, peer: &str, identity: &str) {
    let changed = known_peer_identities()
        .lock()
        .expect("known peer identities mutex poisoned")
        .insert(peer.to_string(), identity.to_string())
        .as_deref()
        != Some(identity);
    if changed {
        if let Err(err) = persist_known_peer_identities(config) {
            eprintln!("could not persist verified peer route identity for {peer}: {err}");
        }
    }
    remember_verified_peer_route(config, peer, identity);
}

fn route_priority(route: &str) -> u8 {
    let host = route
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(route);
    // Keep transport details out of the protocol: private direct routes are
    // local, public direct routes are WAN, and relay paths are last resort.
    if host.starts_with("100.")
        || host.starts_with("fd7a:")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
    {
        0
    } else {
        1
    }
}

fn preferred_peer_route(peer: &str) -> Option<String> {
    let identities = known_peer_identities()
        .lock()
        .expect("known peer identities mutex poisoned");
    let identity = identities.get(peer)?;
    identities
        .iter()
        .filter(|(_, candidate_identity)| *candidate_identity == identity)
        .map(|(route, _)| route.clone())
        .min_by_key(|route| (route_priority(route), route.clone()))
}

fn alternate_route_may_fail_over(peer: &str) -> bool {
    let Some(preferred) = preferred_peer_route(peer) else {
        return true;
    };
    if preferred == peer {
        return true;
    }
    let now = unix_now();
    p2p_route_failures()
        .lock()
        .expect("P2P route failure mutex poisoned")
        .get(&preferred)
        .is_some_and(|failed_at| {
            now.saturating_sub(*failed_at) <= P2P_ROUTE_FAILOVER_WINDOW_SECONDS
        })
}

fn record_p2p_route_connect_failure(peer: &str) {
    p2p_route_failures()
        .lock()
        .expect("P2P route failure mutex poisoned")
        .insert(peer.to_string(), unix_now());
}

fn clear_p2p_route_connect_failure(peer: &str) {
    p2p_route_failures()
        .lock()
        .expect("P2P route failure mutex poisoned")
        .remove(peer);
}

fn branch_sync_cursors() -> &'static Mutex<BTreeMap<String, BranchSyncCursor>> {
    BRANCH_SYNC_CURSORS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn branch_sync_cursor_persist_lock() -> &'static Mutex<()> {
    BRANCH_SYNC_CURSOR_PERSIST_LOCK.get_or_init(|| Mutex::new(()))
}

fn peer_recovery_keys() -> &'static Mutex<BTreeMap<String, String>> {
    PEER_RECOVERY_KEYS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn upstream_template_sources() -> &'static Mutex<BTreeMap<Hash256, MiningUpstreamTemplate>> {
    UPSTREAM_TEMPLATE_SOURCES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn validated_mining_upstreams() -> &'static Mutex<BTreeMap<String, u64>> {
    VALIDATED_MINING_UPSTREAMS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn branch_sync_cursor_path(config: &NodeConfig) -> PathBuf {
    Path::new(&config.node.data_dir).join("branch-sync-cursors.json")
}

fn persist_branch_sync_cursors(config: &NodeConfig) -> Result<()> {
    let _persist_guard = branch_sync_cursor_persist_lock()
        .lock()
        .expect("branch sync cursor persistence mutex poisoned");
    let path = branch_sync_cursor_path(config);
    let data = serde_json::to_vec_pretty(
        &*branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned"),
    )?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, data)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn load_branch_sync_cursors(config: &NodeConfig) {
    let path = branch_sync_cursor_path(config);
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    match serde_json::from_slice::<BTreeMap<String, BranchSyncCursor>>(&bytes) {
        Ok(saved) => {
            // Older releases persisted one reverse-walk cursor per transport
            // and later added a shared `branch:<tip>` cursor.  On restart the
            // stale transport entries could win status selection or obscure the
            // only cursor that can resume forward recovery.  Keep exactly one
            // recovery job per target tip.
            let normalized = normalize_branch_sync_cursors(saved);
            *branch_sync_cursors()
                .lock()
                .expect("branch sync cursor mutex poisoned") = normalized;
            if let Err(err) = persist_branch_sync_cursors(config) {
                eprintln!("could not normalize persisted branch sync cursor state: {err}");
            }
        }
        Err(err) => eprintln!("ignoring invalid persisted branch sync cursor state: {err}"),
    }
}

/// Older cursor normalization could discard a moving-tip job after it had
/// already persisted a valid spool beyond its original hello target. Recover
/// that derived metadata at startup from the retained bodies themselves. The
/// first spool body must join an exact local canonical parent and every later
/// body must be contiguous, so this does not select or alter a chain by
/// itself; ordinary cumulative-work replay still decides publication.
fn restore_orphaned_recovery_spools(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
) -> Result<()> {
    let known_spools = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .values()
        .map(cursor_spool_tip)
        .collect::<BTreeSet<_>>();
    let (tips, canonical, profile) = {
        let storage = storage.lock().expect("storage mutex poisoned");
        (
            storage.recovery_spool_tips()?,
            storage.canonical_blocks()?,
            network_consensus_profile(config, configured_genesis_hash(&storage)?),
        )
    };
    let canonical_height = canonical
        .last()
        .map(|block| block.header.number.0)
        .unwrap_or(0);
    let mut restored = 0usize;
    for spool_tip in tips {
        if known_spools.contains(&spool_tip) {
            continue;
        }
        let spool = storage
            .lock()
            .expect("storage mutex poisoned")
            .recovery_spool_blocks_for_tip(spool_tip)?;
        let Some((first, _)) = spool.first() else {
            continue;
        };
        let Some(ancestor_height) = first.header.number.0.checked_sub(1) else {
            continue;
        };
        let Some(ancestor) = canonical.get(ancestor_height as usize) else {
            continue;
        };
        if ancestor.header.hash() != first.header.parent_hash {
            continue;
        }
        let mut expected_height = first.header.number.0;
        let mut expected_parent = ancestor.header.hash();
        let mut branch_root = None;
        let mut imported = 0u64;
        for (block, _) in &spool {
            if block.header.number.0 != expected_height
                || block.header.parent_hash != expected_parent
            {
                break;
            }
            branch_root.get_or_insert_with(|| block.header.hash());
            expected_parent = block.header.hash();
            expected_height = expected_height.saturating_add(1);
            imported = imported.saturating_add(1);
        }
        let staged_height = expected_height.saturating_sub(1);
        if imported == 0 || staged_height <= canonical_height {
            continue;
        }
        let mut cursor = new_branch_sync_cursor(expected_parent, staged_height, profile.clone());
        cursor.spool_tip_hash = Some(spool_tip);
        cursor.ancestor_height = Some(ancestor_height);
        cursor.ancestor_hash = Some(ancestor.header.hash());
        cursor.branch_root_hash = branch_root;
        cursor.imported_bodies = imported;
        cursor.staged_height = staged_height;
        cursor.next_height = expected_height;
        cursor.expected_parent_hash = Some(expected_parent);
        cursor.state = "complete".to_string();
        cursor.provider_mode = "single-provider".to_string();
        cursor.spool_verified = true;
        cursor.updated_at = unix_now();
        branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned")
            .insert(recovery_cursor_key(expected_parent), cursor);
        restored = restored.saturating_add(1);
        eprintln!(
            "restored orphaned recovery spool {} through height {} above canonical height {}",
            spool_tip.to_hex(),
            staged_height,
            canonical_height
        );
    }
    if restored > 0 {
        persist_branch_sync_cursors(config)?;
    }
    Ok(())
}

fn normalize_branch_sync_cursors(
    saved: BTreeMap<String, BranchSyncCursor>,
) -> BTreeMap<String, BranchSyncCursor> {
    let mut normalized = BTreeMap::<String, BranchSyncCursor>::new();
    for cursor in saved.into_values() {
        let key = recovery_cursor_key(cursor.tip_hash);
        normalized
            .entry(key)
            .and_modify(|current| {
                let current_progress = (
                    current.ancestor_height.is_some(),
                    current.staged_height,
                    current.updated_at,
                );
                let candidate_progress = (
                    cursor.ancestor_height.is_some(),
                    cursor.staged_height,
                    cursor.updated_at,
                );
                if candidate_progress > current_progress {
                    *current = cursor.clone();
                }
            })
            .or_insert(cursor);
    }
    // A live provider can advance after its signed hello while it streams a
    // contiguous range.  Keep a cursor whose staged suffix has outrun that
    // hello tip: startup reconciliation derives its newer target from the
    // locally validated durable spool.  Dropping it here strands a complete
    // branch behind an obsolete target and forces an unnecessary refetch.
    for cursor in normalized.values_mut() {
        // Completion is derived from the durable forward cursor, not the last
        // connection outcome. Older nodes could record EOF after the final
        // body and incorrectly turn a complete job back into a retry.
        if cursor.ancestor_height.is_some()
            && cursor.tip_height > 0
            && cursor.next_height > cursor.tip_height
        {
            cursor.state = "complete".to_string();
            cursor.requested_height = None;
            cursor.requested_at = 0;
            cursor.last_failure = None;
            cursor.retry_after = 0;
        }
    }
    prune_duplicate_recovery_cursors(normalized)
}

/// Remove only metadata that is provably another name for the same durable
/// branch job.  The spool namespace plus ancestor/root identity is stronger
/// evidence than a peer address or a moving tip hash, so distinct forks are
/// never discarded here.
fn prune_duplicate_recovery_cursors(
    cursors: BTreeMap<String, BranchSyncCursor>,
) -> BTreeMap<String, BranchSyncCursor> {
    let mut selected = BTreeMap::<(Hash256, Hash256, Hash256, String), BranchSyncCursor>::new();
    let mut ungrouped = Vec::new();
    for cursor in cursors.into_values() {
        let (Some(ancestor), Some(root)) = (cursor.ancestor_hash, cursor.branch_root_hash) else {
            ungrouped.push(cursor);
            continue;
        };
        let identity = (
            cursor_spool_tip(&cursor),
            ancestor,
            root,
            cursor.consensus_profile.clone(),
        );
        selected
            .entry(identity)
            .and_modify(|current| {
                let current_progress = (
                    current.staged_height,
                    current.last_progress_at,
                    current.tip_height,
                );
                let candidate_progress = (
                    cursor.staged_height,
                    cursor.last_progress_at,
                    cursor.tip_height,
                );
                if candidate_progress > current_progress {
                    *current = cursor.clone();
                }
            })
            .or_insert(cursor);
    }
    let mut pruned = BTreeMap::new();
    for cursor in ungrouped.into_iter().chain(selected.into_values()) {
        pruned.insert(recovery_cursor_key(cursor.tip_hash), cursor);
    }
    pruned
}

fn recovery_cursor_progress_key(cursor: &BranchSyncCursor) -> (u8, u64, u64, u64) {
    let state = match cursor.state.as_str() {
        "replaying" => 5,
        "retrieving" => 4,
        "complete" => 3,
        "waiting-for-provider" => 2,
        _ => 1,
    };
    (
        state,
        cursor.staged_height,
        cursor.last_progress_at,
        cursor.tip_height,
    )
}

fn completed_recovery_tip() -> Option<Hash256> {
    branch_sync_cursors()
        .lock()
        .ok()?
        .values()
        .filter(|cursor| {
            cursor.state == "complete"
                && cursor.ancestor_height.is_some()
                && cursor.tip_height > 0
                && cursor.staged_height <= cursor.tip_height
                && cursor.next_height > cursor.tip_height
        })
        .max_by_key(|cursor| recovery_cursor_progress_key(cursor))
        .map(|cursor| cursor.tip_hash)
}

fn recovery_tip_is_replaying(tip_hash: Hash256) -> bool {
    branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .get(&recovery_cursor_key(tip_hash))
        .is_some_and(|cursor| cursor.state == "replaying")
}

fn any_recovery_replay_is_active() -> bool {
    branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .values()
        .any(|cursor| cursor.state == "replaying")
}

/// Only an incomplete forward range is allowed to hold the exclusive provider
/// lease. A completed cursor is waiting for publication, not for more bodies;
/// treating it as an active provider job can permanently defer every healthy
/// route after a losing candidate or interrupted publication.
fn recovery_cursor_requires_provider(cursor: &BranchSyncCursor) -> bool {
    cursor.ancestor_height.is_some()
        && cursor.tip_height > 0
        && cursor.next_height <= cursor.tip_height
        && matches!(
            cursor.state.as_str(),
            "retrieving" | "waiting-for-provider" | "pending-retrieval"
        )
}

fn reject_completed_recovery(config: &NodeConfig, tip_hash: Hash256, reason: &str) {
    let key = recovery_cursor_key(tip_hash);
    if let Some(cursor) = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .get_mut(&key)
    {
        cursor.state = "rejected".to_string();
        cursor.last_failure = Some(reason.to_string());
        cursor.retry_after = 0;
        cursor.updated_at = unix_now();
    }
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist rejected recovery cursor: {err}");
    }
    prune_finalized_recovery_cursors(config, 0);
}

fn recovery_tip_ready_for_publication(tip_hash: Hash256) -> bool {
    let key = recovery_cursor_key(tip_hash);
    let Ok(cursors) = branch_sync_cursors().lock() else {
        return false;
    };
    let Some(cursor) = cursors.get(&key) else {
        // Locally observed, fully validated forks without a recovery cursor
        // retain the normal consensus path.
        return true;
    };
    cursor.provider_mode == "single-provider" || cursor.provider_mode == "cross-checked"
}

fn set_recovery_state_for_tip(config: &NodeConfig, tip_hash: Hash256, state: &str) {
    let key = recovery_cursor_key(tip_hash);
    if let Some(cursor) = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .get_mut(&key)
    {
        cursor.state = state.to_string();
        cursor.updated_at = unix_now();
    }
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist recovery state transition: {err}");
    }
}

/// A published recovery branch is now canonical. Retain neither its cursor
/// nor its duplicate spool bodies: keeping either makes a later restart
/// attempt to replay a branch that has already been atomically selected.
fn finalize_published_recovery(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    tip_hash: Hash256,
) {
    let (key, spool_tip) = {
        let cursors = branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned");
        let key = recovery_cursor_key(tip_hash);
        let Some(cursor) = cursors.get(&key) else {
            return;
        };
        (key, cursor_spool_tip(cursor))
    };
    if let Err(error) = storage
        .lock()
        .expect("storage mutex poisoned")
        .clear_recovery_spool_for_tip(spool_tip)
    {
        eprintln!("published recovery could not clear its spool: {error}");
        return;
    }
    branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .remove(&key);
    peer_recovery_keys()
        .lock()
        .expect("peer recovery keys mutex poisoned")
        .retain(|_, value| value != &key);
    if let Err(error) = persist_branch_sync_cursors(config) {
        eprintln!("published recovery could not clear its durable cursor: {error}");
    }
}

fn restore_completed_candidate(
    storage: &NodeStorage,
    tip_hash: Hash256,
) -> Result<(BlockHeader, u128)> {
    // Candidate indexes are derived data and may be cleaned while the durable
    // recovery spool is retained. Parent traversal below reads the spool
    // directly; rebuilding the ordinary candidate index here turns a large
    // restart recovery into quadratic database work.
    let spool_tip = branch_sync_cursors()
        .lock()
        .ok()
        .and_then(|cursors| {
            cursors
                .get(&recovery_cursor_key(tip_hash))
                .map(cursor_spool_tip)
        })
        .unwrap_or(tip_hash);
    let tip = storage
        .recovery_spool_block_by_hash(tip_hash)
        .or_else(|_| storage.recovery_spool_block_by_hash(spool_tip))
        .map(|(block, _)| block)
        .or_else(|_| storage.block_by_hash(tip_hash))?;
    let branch = candidate_branch_from_storage(storage, &tip)?;
    let ancestor_work = canonical_work_through_node_storage(storage, branch.common_height)?;
    let work = branch.suffix.iter().fold(ancestor_work, |total, block| {
        total.saturating_add(work_for_target(block.header.difficulty_target))
    });
    // Candidate bodies can outlive their work index after a restart cleanup.
    // Recreate the exact tip index from the complete durable branch so the
    // normal fork-choice and isolated publication path can resume.
    storage.store_candidate_block(&tip, work)?;
    Ok((tip.header, work))
}

fn reset_completed_recovery_for_refetch(config: &NodeConfig, tip_hash: Hash256) {
    let key = recovery_cursor_key(tip_hash);
    let removed = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .remove(&key);
    if removed.is_some() {
        // A cursor marked complete without its durable spool has no proven
        // next parent. Rewinding counters to its old ancestor can satisfy
        // `next_height > tip_height` immediately and creates a permanent
        // complete/empty loop. Drop only this derived cursor and let the next
        // authenticated hello perform a fresh locator exchange.
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys mutex poisoned")
            .retain(|_, value| value != &key);
        eprintln!(
            "discarded completed recovery cursor {} with no retained spool; rediscovering locator",
            tip_hash.to_hex()
        );
    }
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist completed recovery refetch: {err}");
    }
}

fn has_durable_recovery_job() -> bool {
    branch_sync_cursors()
        .lock()
        .map(|cursors| {
            cursors
                .values()
                .any(|cursor| cursor.ancestor_height.is_some())
        })
        .unwrap_or(false)
}

fn new_branch_sync_cursor(
    tip_hash: Hash256,
    tip_height: u64,
    consensus_profile: String,
) -> BranchSyncCursor {
    BranchSyncCursor {
        tip_hash,
        spool_tip_hash: Some(tip_hash),
        tip_height,
        next_hash: tip_hash,
        consensus_profile,
        imported_bodies: 0,
        updated_at: unix_now(),
        ancestor_height: None,
        ancestor_hash: None,
        branch_root_hash: None,
        next_height: 0,
        expected_parent_hash: None,
        staged_height: 0,
        state: "pending-ancestor".to_string(),
        provider: None,
        requested_height: None,
        requested_at: 0,
        last_progress_at: 0,
        provider_attempts: 0,
        last_failure: None,
        retry_after: 0,
        primary_identity: None,
        witness_identity: None,
        provider_mode: default_provider_mode(),
        witness_sample_heights: Vec::new(),
        primary_sample_hashes: BTreeMap::new(),
        witness_sample_hashes: BTreeMap::new(),
        witness_mismatch: None,
        spool_verified: false,
    }
}

fn cursor_key(peer: &str) -> String {
    if let Some(key) = peer_recovery_keys()
        .lock()
        .expect("peer recovery keys mutex poisoned")
        .get(peer)
        .cloned()
    {
        return key;
    }
    known_peer_identities()
        .lock()
        .expect("known peer identities mutex poisoned")
        .get(peer)
        .cloned()
        .unwrap_or_else(|| peer.to_string())
}

fn recovery_cursor_key(tip_hash: Hash256) -> String {
    format!("branch:{}", tip_hash.to_hex())
}

/// Recover the durable branch job after a process restart. Peer-to-job route
/// bindings are deliberately in-memory, so the persisted cursor itself must
/// be discoverable from authenticated identity/provider evidence.
fn durable_forward_cursor_key(
    peer: &str,
    consensus_profile: &str,
    _finalized_floor: u64,
) -> Option<String> {
    let route_key = cursor_key(peer);
    let identity = known_peer_identities()
        .lock()
        .ok()
        .and_then(|identities| identities.get(peer).cloned());
    let cursors = branch_sync_cursors().lock().ok()?;
    if cursors.get(&route_key).is_some_and(|cursor| {
        cursor.ancestor_height.is_some() && cursor.consensus_profile == consensus_profile
    }) {
        return Some(route_key);
    }
    cursors
        .iter()
        .filter(|(_, cursor)| {
            cursor.ancestor_height.is_some()
                && cursor.consensus_profile == consensus_profile
                && (cursor.provider.as_deref() == Some(peer)
                    || identity.as_deref() == cursor.primary_identity.as_deref())
        })
        .max_by_key(|(_, cursor)| recovery_cursor_progress_key(cursor))
        .map(|(key, _)| key.clone())
        // A forward cursor represents a branch, not its first transport
        // route.  A second compatible identity must be able to take over the
        // exact persisted range after the first provider disconnects.  The
        // older route-only lookup created a fresh cursor for that second
        // provider, which then raced the real recovery job and repeatedly
        // rejected correct bodies from either branch.
        .or_else(|| {
            cursors
                .iter()
                .filter(|(_, cursor)| {
                    cursor.ancestor_height.is_some()
                        && cursor.consensus_profile == consensus_profile
                        && cursor.next_height > 0
                        && matches!(
                            cursor.state.as_str(),
                            "retrieving" | "waiting-for-provider" | "complete" | "replaying"
                        )
                })
                .max_by_key(|(_, cursor)| recovery_cursor_progress_key(cursor))
                .map(|(key, _)| key.clone())
        })
}

fn set_peer_recovery_key(peer: &str, tip_hash: Hash256) {
    peer_recovery_keys()
        .lock()
        .expect("peer recovery keys mutex poisoned")
        .insert(peer.to_string(), recovery_cursor_key(tip_hash));
}

/// The reported finalized height is a retention/client marker, not a PoW
/// checkpoint. Keep deep recovery jobs until normal fork choice publishes or
/// rejects them; otherwise a node loops by rediscovering the same branch.
fn prune_finalized_recovery_cursors(config: &NodeConfig, _finalized_floor: u64) {
    let (removed, retained_keys) = {
        let mut cursors = branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned");
        let before = cursors.len();
        cursors.retain(|_, cursor| !matches!(cursor.state.as_str(), "published" | "rejected"));
        (
            before.saturating_sub(cursors.len()),
            cursors.keys().cloned().collect::<BTreeSet<_>>(),
        )
    };
    if removed > 0 {
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys mutex poisoned")
            .retain(|_, key| retained_keys.contains(key));
        eprintln!("pruned {removed} terminal recovery cursor(s)");
        if let Err(err) = persist_branch_sync_cursors(config) {
            eprintln!("could not persist finalized recovery cursor cleanup: {err}");
        }
    }
}

/// A provider tip is a moving target.  Once a forward recovery has proven a
/// common ancestor, a newer signed tip from that same authenticated provider
/// is an extension of the *recovery job*, not a fresh job.  Retargeting keeps
/// the durable spool, staged parent chain, and checkpoint intact.
fn coalesce_advancing_recovery_job(
    peer: &str,
    identity: &str,
    tip_hash: Hash256,
    tip_height: u64,
    consensus_profile: &str,
    ancestor_height: u64,
    ancestor_hash: Hash256,
    branch_root_hash: Option<Hash256>,
) -> String {
    let incoming_key = cursor_key(peer);
    let target_key = recovery_cursor_key(tip_hash);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    let existing_key = cursors
        .iter()
        .filter(|(key, cursor)| {
            **key != incoming_key
                && cursor.ancestor_height == Some(ancestor_height)
                && cursor.ancestor_hash == Some(ancestor_hash)
                && cursor.consensus_profile == consensus_profile
                && (cursor.primary_identity.as_deref() == Some(identity)
                    || (branch_root_hash.is_some() && cursor.branch_root_hash == branch_root_hash))
                && cursor.staged_height >= ancestor_height
                && cursor.tip_height <= tip_height
                && !matches!(
                    cursor.state.as_str(),
                    "published" | "rejected" | "conflicting"
                )
        })
        .max_by_key(|(_, cursor)| (cursor.staged_height, cursor.last_progress_at))
        .map(|(key, _)| key.clone());

    let Some(existing_key) = existing_key else {
        return incoming_key;
    };
    let Some(mut job) = cursors.remove(&existing_key) else {
        return incoming_key;
    };
    // The initial target owns the durable recovery namespace.  Preserve it
    // even when the provider advances through many later tip hashes.
    job.spool_tip_hash = Some(cursor_spool_tip(&job));
    job.tip_hash = tip_hash;
    job.tip_height = tip_height;
    job.provider = Some(peer.to_string());
    job.primary_identity = Some(identity.to_string());
    job.updated_at = unix_now();
    job.requested_height = None;
    job.requested_at = 0;
    job.last_failure = None;
    job.retry_after = 0;
    job.witness_sample_heights.clear();
    job.primary_sample_hashes.clear();
    job.witness_sample_hashes.clear();
    job.witness_mismatch = None;
    if job.next_height <= job.tip_height {
        job.state = "retrieving".to_string();
    }
    cursors.remove(&incoming_key);
    cursors.insert(target_key.clone(), job);
    drop(cursors);

    let mut peer_keys = peer_recovery_keys()
        .lock()
        .expect("peer recovery key mutex poisoned");
    for key in peer_keys.values_mut() {
        if *key == existing_key || *key == incoming_key {
            *key = target_key.clone();
        }
    }
    peer_keys.insert(peer.to_string(), target_key.clone());
    target_key
}

/// An independent route first proves the first suffix block through normal
/// local validation.  Only then can it attach to a job created by another
/// identity; this avoids treating two forks with the same ancestor as one.
fn coalesce_recovery_job_after_branch_root(peer: &str, identity: &str) -> bool {
    let incoming_key = cursor_key(peer);
    let incoming = branch_sync_cursors()
        .lock()
        .ok()
        .and_then(|cursors| cursors.get(&incoming_key).cloned());
    let Some(incoming) = incoming else {
        return false;
    };
    let (Some(ancestor_height), Some(ancestor_hash), Some(branch_root_hash)) = (
        incoming.ancestor_height,
        incoming.ancestor_hash,
        incoming.branch_root_hash,
    ) else {
        return false;
    };
    let target = coalesce_advancing_recovery_job(
        peer,
        identity,
        incoming.tip_hash,
        incoming.tip_height,
        &incoming.consensus_profile,
        ancestor_height,
        ancestor_hash,
        Some(branch_root_hash),
    );
    branch_sync_cursors()
        .lock()
        .ok()
        .and_then(|cursors| cursors.get(&target).map(cursor_spool_tip))
        .is_some_and(|spool_tip| spool_tip != incoming.tip_hash)
}

fn migrate_branch_sync_cursor(config: &NodeConfig, peer: &str, identity: &str) {
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    if let Some(cursor) = cursors.remove(peer) {
        cursors
            .entry(identity.to_string())
            .and_modify(|known| {
                if cursor.updated_at > known.updated_at {
                    *known = cursor.clone();
                }
            })
            .or_insert(cursor);
    }
    drop(cursors);
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist migrated branch sync cursor: {err}");
    }
}

fn clear_branch_sync_cursor(config: &NodeConfig, peer: &str) {
    let key = cursor_key(peer);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    // A lagging or already-matching peer must not erase the shared forward
    // job merely because *that one route* has nothing to offer. Publication
    // owns cleanup for proven recovery jobs.
    if cursors
        .get(&key)
        .is_some_and(|cursor| cursor.ancestor_height.is_none())
    {
        cursors.remove(&key);
    }
    drop(cursors);
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist cleared branch sync cursor: {err}");
    }
}

/// A peer that now matches the active tip proves that a route's completed
/// cursor is obsolete when that cursor tip is already canonical locally.
/// It also retires an unstarted cursor for a lower, non-canonical advertised
/// tip: that cursor has no validated branch work and cannot be allowed to
/// keep status or P2P scheduling in a false recovery state.
fn clear_canonical_recovery_cursor(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    _peer: &str,
) {
    // Route bindings disappear on restart, so a matching hello cannot rely on
    // `cursor_key(peer)` to find a persisted branch job. Retire every cursor
    // whose exact tip is already canonical instead.
    let candidates = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .iter()
        .map(|(key, cursor)| (key.clone(), cursor.clone()))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return;
    }
    let (canonical, stale_unstarted_keys) = {
        let storage = storage.lock().expect("storage mutex poisoned");
        let best = match storage.best_header() {
            Ok(best) => best,
            Err(_) => return,
        };
        let mut canonical = Vec::new();
        let mut stale_unstarted_keys = BTreeSet::new();
        for (key, cursor) in &candidates {
            if storage
                .block_by_number(cursor.tip_height)
                .ok()
                .is_some_and(|block| block.header.hash() == cursor.tip_hash)
            {
                canonical.push((key.clone(), cursor_spool_tip(cursor)));
            } else if cursor.tip_height < best.number.0
                && cursor.ancestor_height.is_none()
                && cursor.staged_height == 0
                && cursor.imported_bodies == 0
                && cursor.next_height == 0
            {
                stale_unstarted_keys.insert(key.clone());
            }
        }
        (canonical, stale_unstarted_keys)
    };
    if canonical.is_empty() && stale_unstarted_keys.is_empty() {
        return;
    }
    for (_, spool_tip) in &canonical {
        if let Err(error) = storage
            .lock()
            .expect("storage mutex poisoned")
            .clear_recovery_spool_for_tip(*spool_tip)
        {
            // Cursor removal is still required: it is derived metadata and a
            // failed spool cleanup must not resurrect a canonical branch job.
            eprintln!("could not clear canonical recovery spool: {error}");
        }
    }
    let canonical_keys = canonical
        .iter()
        .map(|(key, _)| key.clone())
        .chain(stale_unstarted_keys)
        .collect::<std::collections::BTreeSet<_>>();
    branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .retain(|key, _| !canonical_keys.contains(key));
    peer_recovery_keys()
        .lock()
        .expect("peer recovery key mutex poisoned")
        .retain(|_, value| !canonical_keys.contains(value));
    if let Err(error) = persist_branch_sync_cursors(config) {
        eprintln!("could not clear canonical recovery cursor: {error}");
    }
}

fn advance_branch_sync_cursor(config: &NodeConfig, peer: &str, next_hash: Hash256) {
    let key = cursor_key(peer);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    if let Some(cursor) = cursors.get_mut(&key) {
        cursor.next_hash = next_hash;
        cursor.imported_bodies = cursor.imported_bodies.saturating_add(1);
        cursor.updated_at = unix_now();
    } else {
        cursors.insert(key, new_branch_sync_cursor(next_hash, 0, String::new()));
    }
    drop(cursors);
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist advanced branch sync cursor: {err}");
    }
}

fn record_forward_recovery_progress(config: &NodeConfig, peer: &str, block: &Block) -> bool {
    let key = cursor_key(peer);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    let Some(cursor) = cursors.get_mut(&key) else {
        return false;
    };
    if cursor.ancestor_height.is_none() {
        return false;
    }
    if cursor.next_height != 0 && block.header.number.0 != cursor.next_height {
        return false;
    }
    if let Some(expected_parent) = cursor.expected_parent_hash {
        if block.header.parent_hash != expected_parent {
            return false;
        }
    }
    if cursor.branch_root_hash.is_none()
        && cursor
            .ancestor_height
            .is_some_and(|ancestor| block.header.number.0 == ancestor.saturating_add(1))
    {
        cursor.branch_root_hash = Some(block.header.hash());
    }
    cursor.imported_bodies = cursor.imported_bodies.saturating_add(1);
    cursor.staged_height = block.header.number.0;
    cursor.next_height = block.header.number.0.saturating_add(1);
    cursor.expected_parent_hash = Some(block.header.hash());
    cursor.updated_at = unix_now();
    cursor.last_progress_at = cursor.updated_at;
    // A range response contains sequential bodies after one request. Advance
    // the durable expectation with each accepted body instead of clearing it
    // after the first one, otherwise every remaining body in the same range
    // is indistinguishable from an unrelated stale response.
    cursor.requested_height = Some(cursor.next_height);
    cursor.last_failure = None;
    cursor.retry_after = 0;
    let complete = cursor.next_height > cursor.tip_height;
    cursor.state = if complete {
        "complete".to_string()
    } else {
        "retrieving".to_string()
    };
    // Recovery durability is a bounded checkpoint contract: persisting every
    // imported block makes a large fork I/O-bound and can fall behind normal
    // block production. A crash can at most repeat one 32-body range, whose
    // bodies are independently revalidated before use.
    let checkpoint = complete || cursor.imported_bodies % SYNC_CHECKPOINT_BATCH_SIZE as u64 == 0;
    drop(cursors);
    if checkpoint {
        if let Err(err) = persist_branch_sync_cursors(config) {
            eprintln!("could not persist forward recovery checkpoint: {err}");
        }
    }
    complete
}

fn record_recovery_request(config: &NodeConfig, peer: &str, height: u64) {
    let key = cursor_key(peer);
    if let Some(cursor) = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .get_mut(&key)
    {
        if cursor.next_height > cursor.tip_height || cursor.state == "complete" {
            return;
        }
        cursor.provider = Some(peer.to_string());
        cursor.requested_height = Some(height);
        cursor.requested_at = unix_now();
        cursor.updated_at = cursor.requested_at;
        cursor.state = "retrieving".to_string();
        cursor.witness_sample_heights =
            recovery_witness_sample_heights(cursor.tip_hash, height, cursor.tip_height);
        cursor.primary_sample_hashes.clear();
        cursor.witness_sample_hashes.clear();
        cursor.witness_mismatch = None;
        if cursor.witness_identity.is_some() {
            cursor.provider_mode = "waiting-for-witness".to_string();
        }
    }
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist recovery request: {err}");
    }
}

/// A P2P session can carry ordinary relay traffic as well as a response to a
/// recovery range request. Only consume a body through the recovery importer
/// when it is the exact next body in the durable cursor. `requested_height`
/// is useful for deadlines and observability, but cannot be an admission
/// requirement: it is intentionally cleared during provider failover and is
/// not persisted for every body in a range. A restarted session can therefore
/// legitimately receive the exact next body before that diagnostic field is
/// repopulated.
fn is_expected_recovery_body(peer: &str, block: &Block) -> bool {
    let cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    cursors
        .get(&cursor_key(peer))
        .or_else(|| {
            cursors
                .values()
                .find(|cursor| cursor.provider.as_deref() == Some(peer))
        })
        .is_some_and(|cursor| {
            cursor.ancestor_height.is_some()
                && matches!(cursor.state.as_str(), "retrieving" | "waiting-for-provider")
                && block.header.number.0 == cursor.next_height
                && cursor.expected_parent_hash == Some(block.header.parent_hash)
        })
}

fn reconcile_recovery_cursor_to_canonical_prefix(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    peer: &str,
) {
    let Ok(local) = storage
        .lock()
        .ok()
        .and_then(|storage| storage.best_header().ok())
        .ok_or(())
    else {
        return;
    };
    let changed = {
        let mut cursors = match branch_sync_cursors().lock() {
            Ok(cursors) => cursors,
            Err(_) => return,
        };
        let key = cursor_key(peer);
        let key = if cursors.contains_key(&key) {
            Some(key)
        } else {
            cursors
                .iter()
                .find(|(_, cursor)| cursor.provider.as_deref() == Some(peer))
                .map(|(key, _)| key.clone())
        };
        let Some(key) = key else {
            return;
        };
        let cursor = cursors
            .get_mut(&key)
            .expect("recovery cursor key disappeared");
        if cursor.ancestor_height.is_some()
            && cursor.next_height <= local.number.0
            && local.number.0 < cursor.tip_height
        {
            cursor.next_height = local.number.0.saturating_add(1);
            cursor.expected_parent_hash = Some(local.hash());
            cursor.requested_height = None;
            cursor.last_failure = None;
            cursor.updated_at = unix_now();
            true
        } else {
            false
        }
    };
    if changed {
        let _ = persist_branch_sync_cursors(config);
    }
}

fn is_canonical_next_body(storage: &Arc<Mutex<NodeStorage>>, block: &Block) -> bool {
    storage
        .lock()
        .ok()
        .and_then(|storage| storage.best_header().ok())
        .is_some_and(|parent| {
            block.header.number.0 == parent.number.0.saturating_add(1)
                && block.header.parent_hash == parent.hash()
        })
}

fn is_canonical_body(storage: &Arc<Mutex<NodeStorage>>, block: &Block) -> bool {
    storage
        .lock()
        .ok()
        .and_then(|storage| storage.block_by_number(block.header.number.0).ok())
        .is_some_and(|canonical| canonical.header.hash() == block.header.hash())
}

fn reset_recovery_cursor_for_fork(config: &NodeConfig, peer: &str) {
    let (changed, reset_key) = {
        let mut cursors = match branch_sync_cursors().lock() {
            Ok(cursors) => cursors,
            Err(_) => return,
        };
        let key = cursor_key(peer);
        let key = if cursors.contains_key(&key) {
            Some(key)
        } else {
            cursors
                .iter()
                .find(|(_, cursor)| cursor.provider.as_deref() == Some(peer))
                .map(|(key, _)| key.clone())
        };
        let Some(key) = key else { return };
        let cursor = cursors
            .get_mut(&key)
            .expect("recovery cursor key disappeared");
        if cursor.ancestor_height.is_some() {
            cursor.ancestor_height = None;
            cursor.ancestor_hash = None;
            cursor.expected_parent_hash = None;
            cursor.next_height = 0;
            cursor.requested_height = None;
            cursor.state = "pending-ancestor".to_string();
            cursor.last_failure = None;
            cursor.updated_at = unix_now();
            (true, Some(key))
        } else {
            (false, None)
        }
    };
    if changed {
        // Route bindings are transport-local state.  Remove every binding for
        // this job so an already-connected alternate route cannot continue
        // using the pre-reset ancestor/parent expectations.
        if let Some(reset_key) = reset_key {
            peer_recovery_keys()
                .lock()
                .expect("peer recovery keys mutex poisoned")
                .retain(|_, value| value != &reset_key);
        }
        let _ = persist_branch_sync_cursors(config);
    }
}

/// A response at the exact durable height with a different parent cannot
/// extend this recovery branch. This is a provider-route mismatch, not proof
/// that the durable branch is bad: another compatible provider may still
/// serve the exact cursor. Callers must fail over without rejecting the job.
fn recovery_body_conflicts_with_cursor(peer: &str, block: &Block) -> bool {
    branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .get(&cursor_key(peer))
        .is_some_and(|cursor| {
            cursor.ancestor_height.is_some()
                && cursor.next_height == block.header.number.0
                && cursor
                    .expected_parent_hash
                    .is_some_and(|expected| expected != block.header.parent_hash)
        })
}

/// A forward range session owns one ordered body stream. Header announcements
/// and one-off `BlockNotFound` replies are sideband gossip: neither can be a
/// response to `GetBlockRange`, which emits only `BlockBody` frames. Letting
/// them enter normal gossip handling can create a `GetBlockByHash` request and
/// then tear down an otherwise healthy bulk recovery session.
fn is_recovery_sideband_message(message: &P2pMessage) -> bool {
    matches!(
        message,
        P2pMessage::NewHeader { .. } | P2pMessage::BlockNotFound { .. }
    )
}

/// The primary transfers complete bodies.  A witness only confirms two
/// deterministic interior heights plus the range boundaries, which avoids a
/// second full download while making the provider unable to choose samples.
fn recovery_witness_sample_heights(tip: Hash256, from: u64, tip_height: u64) -> Vec<u64> {
    let end = from
        .saturating_add(SYNC_RANGE_SIZE.saturating_sub(1) as u64)
        .min(tip_height);
    if from > end {
        return Vec::new();
    }
    let span = end.saturating_sub(from).saturating_add(1);
    let offsets = [tip.0[0] as u64 % span, tip.0[1] as u64 % span];
    let mut heights = vec![from, end];
    heights.extend(
        offsets
            .into_iter()
            .map(|offset| from.saturating_add(offset)),
    );
    heights.sort_unstable();
    heights.dedup();
    heights
}

fn register_recovery_peer_role(
    config: &NodeConfig,
    peer: &str,
    identity: &str,
    tip_hash: Hash256,
    primary: bool,
) -> Option<Vec<u64>> {
    let key = recovery_cursor_key(tip_hash);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    let cursor = cursors.get_mut(&key)?;
    if primary {
        cursor.primary_identity = Some(identity.to_string());
        cursor.provider = Some(peer.to_string());
        if cursor.witness_identity.as_deref() == Some(identity) {
            cursor.witness_identity = None;
            cursor.witness_sample_heights.clear();
            cursor.primary_sample_hashes.clear();
            cursor.witness_sample_hashes.clear();
            cursor.witness_mismatch = None;
        }
        if cursor.witness_identity.is_none() {
            cursor.provider_mode = "single-provider".to_string();
        }
    } else if cursor.primary_identity.as_deref() != Some(identity)
        && cursor.witness_identity.as_deref() != Some(identity)
    {
        cursor.witness_identity = Some(identity.to_string());
        cursor.provider_mode = "waiting-for-witness".to_string();
    }
    let is_witness = cursor.witness_identity.as_deref() == Some(identity);
    let heights = if is_witness {
        if cursor.witness_sample_heights.is_empty() {
            cursor.witness_sample_heights = recovery_witness_sample_heights(
                cursor.tip_hash,
                cursor.next_height,
                cursor.tip_height,
            );
            cursor.witness_sample_heights.clone()
        } else {
            cursor.witness_sample_heights.clone()
        }
    } else {
        Vec::new()
    };
    drop(cursors);
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist recovery provider role: {err}");
    }
    (!heights.is_empty()).then_some(heights)
}

/// A peer behind the selected recovery tip cannot witness that tip. Keep the
/// fully validated primary branch usable in explicit single-provider mode
/// instead of letting an unrelated stale peer block publication forever.
fn remove_stale_recovery_witness(config: &NodeConfig, tip_hash: Hash256, identity: &str) -> bool {
    let key = recovery_cursor_key(tip_hash);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    let Some(cursor) = cursors.get_mut(&key) else {
        return false;
    };
    if cursor.witness_identity.as_deref() != Some(identity) {
        return false;
    }
    cursor.witness_identity = None;
    cursor.witness_sample_heights.clear();
    cursor.primary_sample_hashes.clear();
    cursor.witness_sample_hashes.clear();
    cursor.witness_mismatch = None;
    cursor.provider_mode = "single-provider".to_string();
    if cursor.next_height > cursor.tip_height {
        cursor.state = "complete".to_string();
    }
    cursor.updated_at = unix_now();
    drop(cursors);
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist stale witness removal: {err}");
    }
    true
}

fn record_primary_witness_sample(config: &NodeConfig, peer: &str, block: &Block) -> Result<bool> {
    let key = cursor_key(peer);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    let Some(cursor) = cursors.get_mut(&key) else {
        return Ok(false);
    };
    if !cursor
        .witness_sample_heights
        .contains(&block.header.number.0)
    {
        return Ok(false);
    }
    let hash = block.header.hash();
    cursor
        .primary_sample_hashes
        .insert(block.header.number.0, hash);
    if let Some(witness_hash) = cursor.witness_sample_hashes.get(&block.header.number.0) {
        if *witness_hash != hash {
            let reason = format!(
                "witness header mismatch at height {}: primary {} != witness {}",
                block.header.number.0,
                hash.to_hex(),
                witness_hash.to_hex()
            );
            cursor.provider_mode = "conflicting".to_string();
            cursor.witness_mismatch = Some(reason.clone());
            cursor.state = "conflicting".to_string();
            drop(cursors);
            persist_branch_sync_cursors(config)?;
            anyhow::bail!("{reason}");
        }
    }
    let all_samples_match = cursor.witness_sample_heights.iter().all(|height| {
        matches!(
            (cursor.primary_sample_hashes.get(height), cursor.witness_sample_hashes.get(height)),
            (Some(primary), Some(witness)) if primary == witness
        )
    });
    if all_samples_match && cursor.witness_identity.is_some() {
        cursor.provider_mode = "cross-checked".to_string();
    }
    let ready = cursor.next_height > cursor.tip_height
        && matches!(
            cursor.provider_mode.as_str(),
            "single-provider" | "cross-checked"
        );
    if ready {
        cursor.state = "complete".to_string();
    }
    drop(cursors);
    persist_branch_sync_cursors(config)?;
    Ok(ready)
}

fn record_witness_headers(
    config: &NodeConfig,
    tip_hash: Hash256,
    identity: &str,
    headers: Vec<BlockHeader>,
) -> Result<bool> {
    let key = recovery_cursor_key(tip_hash);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    let cursor = cursors
        .get_mut(&key)
        .ok_or_else(|| anyhow::anyhow!("witness response has no recovery job"))?;
    if cursor.witness_identity.as_deref() != Some(identity) {
        anyhow::bail!("witness response came from an unselected peer identity");
    }
    for header in headers {
        if !cursor.witness_sample_heights.contains(&header.number.0) {
            anyhow::bail!("witness returned an unrequested header height");
        }
        let hash = header.hash();
        if let Some(primary_hash) = cursor.primary_sample_hashes.get(&header.number.0) {
            if *primary_hash != hash {
                let reason = format!(
                    "witness header mismatch at height {}: primary {} != witness {}",
                    header.number.0,
                    primary_hash.to_hex(),
                    hash.to_hex()
                );
                cursor.provider_mode = "conflicting".to_string();
                cursor.witness_mismatch = Some(reason.clone());
                cursor.state = "conflicting".to_string();
                drop(cursors);
                persist_branch_sync_cursors(config)?;
                anyhow::bail!("{reason}");
            }
        }
        cursor.witness_sample_hashes.insert(header.number.0, hash);
    }
    let all_samples_match = cursor.witness_sample_heights.iter().all(|height| {
        matches!(
            (cursor.primary_sample_hashes.get(height), cursor.witness_sample_hashes.get(height)),
            (Some(primary), Some(witness)) if primary == witness
        )
    });
    if all_samples_match {
        cursor.provider_mode = "cross-checked".to_string();
    }
    // A prior publication attempt may have marked the completed job
    // `waiting-for-witness`. Completion is structural, not a transient UI
    // state: the durable cursor has consumed every body through the tip.
    let complete = cursor.next_height > cursor.tip_height;
    if complete && all_samples_match {
        cursor.state = "complete".to_string();
    }
    drop(cursors);
    persist_branch_sync_cursors(config)?;
    Ok(complete && all_samples_match)
}

fn record_recovery_failure(config: &NodeConfig, peer: &str, reason: impl Into<String>) {
    let key = cursor_key(peer);
    let mut cursors = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned");
    let failure_key = if cursors.contains_key(&key) {
        Some(key)
    } else {
        cursors
            .iter()
            .find(|(_, cursor)| cursor.provider.as_deref() == Some(peer))
            .map(|(key, _)| key.clone())
    };
    if let Some(failure_key) = failure_key {
        let cursor = cursors
            .get_mut(&failure_key)
            .expect("recovery cursor disappeared before failure recording");
        // Short-lived P2P sessions often end with EOF immediately after a
        // final response. Completion must stay terminal for publication.
        if cursor.next_height > cursor.tip_height
            || matches!(
                cursor.state.as_str(),
                "complete" | "replaying" | "published"
            )
        {
            return;
        }
        cursor.provider = Some(peer.to_string());
        cursor.provider_attempts = cursor.provider_attempts.saturating_add(1);
        cursor.last_failure = Some(reason.into());
        cursor.retry_after = unix_now().saturating_add(1u64 << cursor.provider_attempts.min(5));
        cursor.requested_height = None;
        cursor.requested_at = 0;
        cursor.updated_at = unix_now();
        cursor.state = "waiting-for-provider".to_string();
    }
    drop(cursors);
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist recovery failure: {err}");
    }
}

fn recovery_locator(storage: &Arc<Mutex<NodeStorage>>) -> Result<Vec<String>> {
    let storage = storage.lock().expect("storage mutex poisoned");
    let mut locator = Vec::new();
    let mut height = storage.best_header()?.number.0;
    let mut step = 1u64;
    loop {
        let block = storage.block_by_number(height)?;
        locator.push(block.header.hash().to_hex());
        if height == 0 {
            break;
        }
        height = height.saturating_sub(step);
        if locator.len() >= 10 {
            step = step.saturating_mul(2);
        }
    }
    Ok(locator)
}

/// A parent walk starts at the signed remote tip and moves back exactly one
/// block per verified body. This gives us a safe numeric fallback when a peer
/// incorrectly misses an otherwise retained canonical body by hash.
fn branch_cursor_next_height(peer: &str) -> Option<u64> {
    let key = cursor_key(peer);
    let cursors = branch_sync_cursors().lock().ok()?;
    let cursor = cursors.get(&key)?;
    // A forward recovery owns an explicit contiguous cursor.  The historical
    // reverse-walk estimate is only valid before locator discovery.
    cursor
        .ancestor_height
        .map(|_| cursor.next_height)
        .or_else(|| cursor.tip_height.checked_sub(cursor.imported_bodies))
}

fn forward_recovery_context(peer: &str) -> Option<(Hash256, u64, Hash256)> {
    let key = cursor_key(peer);
    let cursors = branch_sync_cursors().lock().ok()?;
    let cursor = cursors.get(&key)?;
    Some((
        // A provider's advertised tip can advance while the forward recovery
        // is in flight.  The cursor follows that tip, but its spool namespace
        // deliberately remains fixed so every retained body stays visible to
        // restart reconciliation and parent lookup.
        cursor_spool_tip(cursor),
        cursor.next_height,
        cursor.expected_parent_hash?,
    ))
}

/// Reconcile the cursor with the job-scoped durable spool once after startup
/// (and again after a local parent lookup failure).  A broken checkpoint is a
/// local recovery-cache problem, not a peer fault: rewind only to the proven
/// common ancestor and refetch forward in bounded ranges.
fn reconcile_forward_recovery_spool(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    peer: &str,
) -> Result<()> {
    let key = cursor_key(peer);
    let cursor = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .get(&key)
        .cloned();
    let Some(cursor) = cursor else {
        return Ok(());
    };
    let (Some(ancestor_height), Some(ancestor_hash)) =
        (cursor.ancestor_height, cursor.ancestor_hash)
    else {
        return Ok(());
    };
    let spool_tip = cursor_spool_tip(&cursor);
    let ancestor_is_currently_usable = storage
        .lock()
        .expect("storage mutex poisoned")
        .block_by_number(ancestor_height)
        .map(|block| block.header.hash() == ancestor_hash)
        .unwrap_or(false);
    if !ancestor_is_currently_usable {
        // A cursor can survive a local publication, generation cleanup, or
        // pruning decision that removes the body it previously used as an
        // anchor. Its old common ancestor is no longer proof that the next
        // provider range joins the active chain. Discard only this derived
        // recovery cache and force a fresh locator exchange; canonical chain
        // data is never touched.
        storage
            .lock()
            .expect("storage mutex poisoned")
            .clear_recovery_spool_for_tip(spool_tip)?;
        {
            let mut cursors = branch_sync_cursors()
                .lock()
                .expect("branch sync cursor mutex poisoned");
            let current = cursors.get_mut(&key).ok_or_else(|| {
                anyhow::anyhow!("recovery cursor disappeared during ancestor validation")
            })?;
            current.ancestor_height = None;
            current.ancestor_hash = None;
            current.branch_root_hash = None;
            current.next_height = 0;
            current.expected_parent_hash = None;
            current.staged_height = 0;
            current.imported_bodies = 0;
            current.spool_verified = false;
            current.state = "pending-retrieval".to_string();
            current.requested_height = None;
            current.requested_at = 0;
            current.last_failure = Some(
                "saved recovery ancestor is not retained canonical history; rediscovering locator"
                    .to_string(),
            );
            current.updated_at = unix_now();
        }
        persist_branch_sync_cursors(config)?;
        eprintln!(
            "recovery cursor for {peer} discarded its stale ancestor at height {ancestor_height}; rediscovering common ancestor"
        );
        return Ok(());
    }
    // A verified spool still needs reconciliation when a moving provider
    // streamed bodies beyond the tip advertised in the hello that created
    // this job.  Those bodies are locally validated and contiguous, so their
    // final hash is the job's new safe target; do not leave publication tied
    // to the old signed tip.
    if cursor.spool_verified && cursor.staged_height <= cursor.tip_height {
        return Ok(());
    }
    let (canonical_ancestor, spool) = {
        let storage = storage.lock().expect("storage mutex poisoned");
        // Versions before the stable-spool fix wrote newly received bodies
        // under the moving advertised tip.  Merge that one legacy namespace
        // into the job's fixed spool before deriving the cursor, so upgrading
        // does not make a node redownload or loop over an already validated
        // suffix after each provider hello.
        if cursor.tip_hash != spool_tip {
            let moved = storage.recovery_spool_blocks_for_tip(cursor.tip_hash)?;
            if !moved.is_empty() {
                for (block, work) in moved {
                    storage.store_recovery_spool_block(spool_tip, &block, work)?;
                }
                storage.flush_sync_batch()?;
            }
        }
        (
            storage.block_by_number(ancestor_height)?,
            storage.recovery_spool_blocks_for_tip(spool_tip)?,
        )
    };
    if canonical_ancestor.header.hash() != ancestor_hash {
        anyhow::bail!("recovery cursor ancestor is no longer canonical");
    }

    let mut next_height = ancestor_height.saturating_add(1);
    let mut expected_parent = ancestor_hash;
    let mut branch_root_hash = None;
    for (block, _) in spool {
        if block.header.number.0 < next_height {
            continue;
        }
        if block.header.number.0 != next_height || block.header.parent_hash != expected_parent {
            break;
        }
        if branch_root_hash.is_none() && block.header.number.0 == ancestor_height.saturating_add(1)
        {
            branch_root_hash = Some(block.header.hash());
        }
        expected_parent = block.header.hash();
        next_height = next_height.saturating_add(1);
    }
    let imported = next_height.saturating_sub(ancestor_height.saturating_add(1));
    let staged_height = next_height.saturating_sub(1);
    let target_advanced = staged_height > cursor.tip_height;
    let repaired = next_height != cursor.next_height
        || cursor.expected_parent_hash != Some(expected_parent)
        || cursor.imported_bodies != imported
        || target_advanced;
    let replacement_key = target_advanced.then(|| recovery_cursor_key(expected_parent));
    {
        let mut cursors = branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned");
        let mut current = cursors
            .remove(&key)
            .ok_or_else(|| anyhow::anyhow!("recovery cursor disappeared during spool repair"))?;
        current.next_height = next_height;
        current.staged_height = staged_height;
        current.expected_parent_hash = Some(expected_parent);
        current.imported_bodies = imported;
        current.branch_root_hash = branch_root_hash;
        current.spool_verified = true;
        current.updated_at = unix_now();
        if target_advanced {
            current.tip_hash = expected_parent;
            current.tip_height = staged_height;
        }
        let complete = current.next_height > current.tip_height;
        if repaired {
            current.state = if complete {
                "complete".to_string()
            } else {
                "retrieving".to_string()
            };
            current.requested_height = None;
            current.requested_at = 0;
            current.last_failure = Some(
                "recovery spool checkpoint was incomplete; resumed from last contiguous body"
                    .to_string(),
            );
        }
        let replacement_key = replacement_key.unwrap_or_else(|| key.clone());
        cursors.insert(replacement_key.clone(), current);
        if replacement_key != key {
            let mut peer_keys = peer_recovery_keys()
                .lock()
                .expect("peer recovery keys mutex poisoned");
            for value in peer_keys.values_mut() {
                if *value == key {
                    *value = replacement_key.clone();
                }
            }
        }
    }
    persist_branch_sync_cursors(config)?;
    if repaired {
        if target_advanced {
            eprintln!(
                "recovery spool reconciled for {peer}: advanced durable target to height {staged_height}"
            );
        } else {
            eprintln!(
                "recovery spool reconciled for {peer}: resuming forward range at height {next_height}"
            );
        }
    }
    Ok(())
}

fn recovery_progress_timed_out(has_recovery_job: bool, elapsed: Duration) -> bool {
    has_recovery_job && elapsed >= RECOVERY_NO_PROGRESS_TIMEOUT
}

/// A durable branch has exactly one ordered range provider. A route that
/// advertises a different moving tip may still become a failover provider once
/// the active session ends, but must not start a second range while that lease
/// is held. Otherwise both streams race the shared cursor and invalidate one
/// another as stale responses.
fn recovery_provider_is_deferred(
    active_tip: Hash256,
    peer_tip: Hash256,
    holds_provider_lease: bool,
) -> bool {
    !holds_provider_lease && peer_tip != active_tip
}

fn mark_recovery_spool_unverified(config: &NodeConfig, peer: &str, reason: &str) {
    let key = cursor_key(peer);
    if let Some(cursor) = branch_sync_cursors()
        .lock()
        .expect("branch sync cursor mutex poisoned")
        .get_mut(&key)
    {
        cursor.spool_verified = false;
        cursor.last_failure = Some(reason.to_string());
        cursor.updated_at = unix_now();
    }
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist recovery spool repair request: {err}");
    }
}

fn branch_cursor_next_hash(peer: &str) -> Option<Hash256> {
    let key = cursor_key(peer);
    branch_sync_cursors()
        .lock()
        .ok()?
        .get(&key)
        // Forward recovery validates the ordered height/parent sequence in
        // `record_forward_recovery_progress`; its next body is not the old
        // reverse-walk hash stored for backwards-compatible cursors.
        .and_then(|cursor| (cursor.ancestor_height.is_none()).then_some(cursor.next_hash))
}

fn branch_cursor_target_height(peer: &str) -> u64 {
    let key = cursor_key(peer);
    branch_sync_cursors()
        .lock()
        .ok()
        .and_then(|cursors| cursors.get(&key).map(|cursor| cursor.tip_height))
        .unwrap_or(0)
}

/// Returns durable branch retrieval evidence that has not yet become part of
/// the local canonical chain. A cursor is intentionally conservative when it
/// was created by an older binary without a recorded height: failing closed is
/// safer than accidentally extending a known stale branch after restart.
fn unresolved_branch_cursor(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
) -> Option<BranchSyncCursor> {
    let guard = storage.lock().ok()?;
    let local = guard.best_header().ok()?;
    let canonical = guard.canonical_blocks().ok()?;
    let local_profile = configured_genesis_hash(&guard)
        .map(|genesis| network_consensus_profile(config, genesis))
        .unwrap_or_else(|_| network_consensus_profile(config, genesis_header().hash()));
    let cursors = branch_sync_cursors().lock().ok()?;
    cursors
        .values()
        .filter(|cursor| {
            if matches!(
                cursor.state.as_str(),
                "published" | "rejected" | "conflicting"
            ) {
                return false;
            }
            let already_canonical = canonical
                .iter()
                .any(|block| block.header.hash() == cursor.tip_hash);
            !already_canonical
                && cursor.tip_hash != local.hash()
                && (cursor.tip_height == 0 || cursor.tip_height >= local.number.0)
                && (cursor.consensus_profile.is_empty()
                    || cursor.consensus_profile == local_profile)
        })
        // A freshly advertised moving tip may have no staged bodies yet.
        // Prefer the branch that has actually made durable forward progress;
        // this is the job operators and miners need to see.
        .max_by_key(|cursor| recovery_cursor_progress_key(cursor))
        .cloned()
}

fn sync_peer_identity_is_active(peer: &str) -> bool {
    let Some(identity) = known_peer_identities()
        .lock()
        .expect("known peer identities mutex poisoned")
        .get(peer)
        .cloned()
    else {
        return false;
    };
    active_sync_identities()
        .lock()
        .expect("active sync identities mutex poisoned")
        .contains(&identity)
}

fn p2p_session_status() -> serde_json::Value {
    let active = ACTIVE_P2P_SESSIONS.load(Ordering::Acquire);
    let started_at = SYNC_SESSION_STARTED_AT.load(Ordering::Acquire);
    let now = unix_now();
    let last_p2p_error = last_p2p_handler_error()
        .lock()
        .ok()
        .and_then(|error| error.clone());
    let last_rpc_error = last_rpc_handler_error()
        .lock()
        .ok()
        .and_then(|error| error.clone());
    let last_block_gossip_error = LAST_BLOCK_GOSSIP_ERROR
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|error| error.clone());
    serde_json::json!({
        "activeP2pConnections": active,
        "cachedPeerCount": cached_peer_routes()
            .lock()
            .map(|routes| routes.len())
            .unwrap_or(0),
        "closingP2pConnections": CLOSING_P2P_SESSIONS.load(Ordering::Acquire),
        "closedP2pSessions": CLOSED_P2P_SESSIONS.load(Ordering::Acquire),
        "activeRpcConnections": ACTIVE_RPC_CONNECTIONS.load(Ordering::Acquire),
        "closingRpcConnections": CLOSING_RPC_CONNECTIONS.load(Ordering::Acquire),
        "closedRpcConnections": CLOSED_RPC_CONNECTIONS.load(Ordering::Acquire),
        "lastP2pHandlerError": last_p2p_error,
        "lastRpcHandlerError": last_rpc_error,
        "blockAnnouncementsRelayed": BLOCK_GOSSIP_RELAYED.load(Ordering::Relaxed),
        "blockAnnouncementFailures": BLOCK_GOSSIP_FAILURES.load(Ordering::Relaxed),
        "blockAnnouncementsDeduplicated": BLOCK_GOSSIP_DEDUPLICATED.load(Ordering::Relaxed),
        "lastBlockAnnouncementError": last_block_gossip_error,
        "closeWaitThreshold": P2P_CLOSE_WAIT_THRESHOLD,
        "syncSessionAge": if started_at == 0 { serde_json::Value::Null } else { serde_json::json!(now.saturating_sub(started_at)) },
        "degraded": active >= P2P_CLOSE_WAIT_THRESHOLD,
    })
}

struct SyncIdentityLease(Option<String>);

impl SyncIdentityLease {
    fn acquire(identity: &str) -> Option<Self> {
        let mut active = active_sync_identities()
            .lock()
            .expect("active sync identities mutex poisoned");
        if !active.insert(identity.to_string()) {
            return None;
        }
        Some(Self(Some(identity.to_string())))
    }
}

impl Drop for SyncIdentityLease {
    fn drop(&mut self) {
        if let Some(identity) = self.0.take() {
            active_sync_identities()
                .lock()
                .expect("active sync identities mutex poisoned")
                .remove(&identity);
        }
    }
}

/// A node imports at most one forward recovery range at a time. The cursor key
/// follows a moving provider tip, so it cannot itself be the lease key: moving
/// it would allow a second route to acquire a differently named lease for the
/// same spool and race the ordered body stream.
const FORWARD_RECOVERY_LEASE_KEY: &str = "forward-recovery";

struct RecoveryJobLease(Option<String>);

impl RecoveryJobLease {
    fn acquire(_job: &str) -> Option<Self> {
        let mut active = active_recovery_jobs()
            .lock()
            .expect("active recovery jobs mutex poisoned");
        active
            .insert(FORWARD_RECOVERY_LEASE_KEY.to_string())
            .then(|| Self(Some(FORWARD_RECOVERY_LEASE_KEY.to_string())))
    }
}

impl Drop for RecoveryJobLease {
    fn drop(&mut self) {
        if let Some(job) = self.0.take() {
            active_recovery_jobs()
                .lock()
                .expect("active recovery jobs mutex poisoned")
                .remove(&job);
        }
    }
}

/// Force a full-duplex close when a short-lived network handler exits.
///
/// Relying on `Drop` alone can leave the peer side in CLOSE-WAIT when a
/// cloned reader still owns the socket.  Keeping the shutdown in one guard
/// makes every success, timeout, EOF, and error path behave identically.
struct SocketShutdownGuard(Option<TcpStream>);

impl SocketShutdownGuard {
    fn new(stream: &TcpStream) -> Result<Self> {
        let stream = stream.try_clone()?;
        if !try_acquire_connection(&ACTIVE_P2P_SESSIONS, P2P_SESSION_LIMIT) {
            let _ = stream.shutdown(Shutdown::Both);
            anyhow::bail!("P2P session capacity reached");
        }
        Ok(Self(Some(stream)))
    }
}

/// JSON-RPC has its own listener-level admission counter.  It must close its
/// socket on every exit path without consuming a P2P lease, otherwise P2P
/// churn can make the public RPC endpoint unavailable.
struct RpcSocketShutdownGuard(Option<TcpStream>);

impl RpcSocketShutdownGuard {
    fn new(stream: &TcpStream) -> Result<Self> {
        Ok(Self(Some(stream.try_clone()?)))
    }
}

impl Drop for RpcSocketShutdownGuard {
    fn drop(&mut self) {
        if let Some(stream) = self.0.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for SocketShutdownGuard {
    fn drop(&mut self) {
        CLOSING_P2P_SESSIONS.fetch_add(1, Ordering::AcqRel);
        if let Some(stream) = self.0.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        CLOSING_P2P_SESSIONS.fetch_sub(1, Ordering::AcqRel);
        ACTIVE_P2P_SESSIONS.fetch_sub(1, Ordering::AcqRel);
        CLOSED_P2P_SESSIONS.fetch_add(1, Ordering::AcqRel);
    }
}

struct P2pShutdownGuard<T: ShutdownTransport>(Option<T>);

struct InboundAddressLease {
    addresses: Arc<Mutex<HashSet<String>>>,
    address: String,
}

impl Drop for InboundAddressLease {
    fn drop(&mut self) {
        self.addresses
            .lock()
            .expect("inbound address lease mutex poisoned")
            .remove(&self.address);
    }
}

fn try_acquire_inbound_address(
    addresses: &Arc<Mutex<HashSet<String>>>,
    address: String,
) -> Option<InboundAddressLease> {
    let mut active = addresses
        .lock()
        .expect("inbound address lease mutex poisoned");
    if !active.insert(address.clone()) {
        return None;
    }
    Some(InboundAddressLease {
        addresses: Arc::clone(addresses),
        address,
    })
}

fn admit_p2p_transport<T: ShutdownTransport>(
    mut stream: T,
    active_sessions: &AtomicUsize,
    limit: usize,
) -> Result<T> {
    if !try_acquire_connection(active_sessions, limit) {
        stream.shutdown_transport();
        anyhow::bail!("P2P session capacity reached");
    }
    Ok(stream)
}

impl<T: ShutdownTransport> P2pShutdownGuard<T> {
    fn new(stream: T) -> Result<Self> {
        Ok(Self(Some(admit_p2p_transport(
            stream,
            &ACTIVE_P2P_SESSIONS,
            P2P_UNTRUSTED_SESSION_LIMIT,
        )?)))
    }

    fn new_configured(stream: T) -> Result<Self> {
        Ok(Self(Some(admit_p2p_transport(
            stream,
            &ACTIVE_P2P_SESSIONS,
            P2P_SESSION_LIMIT,
        )?)))
    }
}

impl<T: ShutdownTransport + Read> Read for P2pShutdownGuard<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0
            .as_mut()
            .expect("shutdown guard present")
            .read(buffer)
    }
}

impl<T: ShutdownTransport + Write> Write for P2pShutdownGuard<T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .as_mut()
            .expect("shutdown guard present")
            .write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.as_mut().expect("shutdown guard present").flush()
    }
}

trait ShutdownTransport {
    fn shutdown_transport(&mut self);
}

impl ShutdownTransport for StreamOwned<ClientConnection, TcpStream> {
    fn shutdown_transport(&mut self) {
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}

impl ShutdownTransport for StreamOwned<ServerConnection, TcpStream> {
    fn shutdown_transport(&mut self) {
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}

impl<T: ShutdownTransport> Drop for P2pShutdownGuard<T> {
    fn drop(&mut self) {
        CLOSING_P2P_SESSIONS.fetch_add(1, Ordering::AcqRel);
        if let Some(mut stream) = self.0.take() {
            stream.shutdown_transport();
        }
        CLOSING_P2P_SESSIONS.fetch_sub(1, Ordering::AcqRel);
        ACTIVE_P2P_SESSIONS.fetch_sub(1, Ordering::AcqRel);
        CLOSED_P2P_SESSIONS.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct AnyServerCertificateVerifier;

impl ServerCertVerifier for AnyServerCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn certificate_fingerprint(certificate: &[u8]) -> String {
    hex::encode(keccak256(certificate).0)
}

fn build_server_tls_config() -> Result<(Arc<ServerConfig>, String)> {
    let certified = rcgen::generate_simple_self_signed(vec!["blq".to_string()])?;
    let certificate_bytes = certified.cert.der().to_vec();
    let certificate = CertificateDer::from(certificate_bytes.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)?;
    Ok((
        Arc::new(config),
        certificate_fingerprint(&certificate_bytes),
    ))
}

fn build_client_tls_config() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyServerCertificateVerifier))
            .with_no_client_auth(),
    )
}

fn connect_p2p_tls(peer: &str) -> Result<(StreamOwned<ClientConnection, TcpStream>, String)> {
    let stream = connect_tcp_session(peer)?;
    let server_name = ServerName::try_from("blq")
        .map_err(|err| anyhow::anyhow!("invalid P2P TLS server name: {err}"))?;
    let connection = ClientConnection::new(build_client_tls_config(), server_name)?;
    let mut stream = StreamOwned::new(connection, stream);
    if let Err(error) = stream.conn.complete_io(&mut stream.sock) {
        let _ = stream.sock.shutdown(Shutdown::Both);
        return Err(error.into());
    }
    let certificate_hash = {
        let certificate = stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or_else(|| anyhow::anyhow!("P2P TLS peer did not provide a certificate"))?;
        certificate_fingerprint(certificate.as_ref())
    };
    Ok((stream, certificate_hash))
}

struct NodeIdentity {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl NodeIdentity {
    fn load_or_create(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join(P2P_IDENTITY_FILE);
        let mut secret_bytes = [0u8; 32];
        if path.exists() {
            let bytes = fs::read(&path)?;
            if bytes.len() != secret_bytes.len() {
                anyhow::bail!("P2P identity key has invalid length");
            }
            secret_bytes.copy_from_slice(&bytes);
        } else {
            loop {
                getrandom::fill(&mut secret_bytes)?;
                if SecretKey::from_byte_array(secret_bytes).is_ok() {
                    break;
                }
            }
            fs::write(&path, secret_bytes)?;
        }
        #[cfg(unix)]
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        let secret_key = SecretKey::from_byte_array(secret_bytes)
            .map_err(|err| anyhow::anyhow!("invalid P2P identity key: {err}"))?;
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.serialize())
    }

    fn sign(&self, payload: &[u8]) -> String {
        let digest = keccak256(payload);
        let message = Message::from_digest(digest.0);
        let signature = Secp256k1::new().sign_ecdsa_recoverable(message, &self.secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut encoded = [0u8; 65];
        encoded[..64].copy_from_slice(&compact);
        encoded[64] = i32::from(recovery_id) as u8;
        hex::encode(encoded)
    }
}

fn p2p_hello_payload(
    node_mode: NodeMode,
    best_number: u64,
    best_hash: &str,
    consensus_profile: &str,
    identity_public_key: &str,
    tls_certificate_hash: &str,
) -> Vec<u8> {
    format!(
        "BLQ-P2P-HELLO-v3|{}|{}|{}|{}|{}|{}",
        node_mode.as_str(),
        best_number,
        best_hash,
        consensus_profile,
        identity_public_key,
        tls_certificate_hash,
    )
    .into_bytes()
}

fn consensus_profile() -> String {
    consensus_profile_for_genesis(genesis_header().hash())
}

fn consensus_profile_for_genesis(genesis_hash: Hash256) -> String {
    format!(
        "blq-consensus-v2|chain={}|genesis={}|pow={}|target_time={}|deadband=15..45|adjustment_cap=25|issuance=elapsed-time-0.1-blq-per-minute",
        MAINNET_CHAIN_ID,
        genesis_hash.to_hex(),
        genesis_header().pow_algorithm,
        blq_primitives::TARGET_BLOCK_TIME_SECONDS,
    )
}

/// The storage fingerprint intentionally stays genesis-only so existing
/// snapshots remain valid across a scheduled hard-fork. Network peers,
/// however, must agree on every active consensus schedule before exchanging
/// blocks or miner work.
fn network_consensus_profile(config: &NodeConfig, genesis_hash: Hash256) -> String {
    let activation = config
        .node
        .block_size_activation_height
        .map(|height| height.to_string())
        .unwrap_or_else(|| "disabled".to_string());
    let block_time_v2 = config
        .node
        .block_time_v2_activation_height
        .map(|height| height.to_string())
        .unwrap_or_else(|| "disabled".to_string());
    format!(
        "{}|block_size_activation_height={activation}|block_time_v2_activation_height={block_time_v2}|block_time_v2_target=15|block_time_v2_window=16|block_time_v2_fast_median=3|block_time_v2_slow_interval=60",
        consensus_profile_for_genesis(genesis_hash)
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_p2p_identity(
    node_mode: NodeMode,
    best_number: u64,
    best_hash: &str,
    remote_consensus_profile: &str,
    identity_public_key: &str,
    identity_signature: &str,
    tls_certificate_hash: &str,
    expected_tls_certificate_hash: Option<&str>,
    trusted_identity_keys: Option<&[String]>,
) -> Result<()> {
    verify_p2p_identity_for_profile(
        node_mode,
        best_number,
        best_hash,
        remote_consensus_profile,
        identity_public_key,
        identity_signature,
        tls_certificate_hash,
        expected_tls_certificate_hash,
        trusted_identity_keys,
        &consensus_profile(),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_p2p_identity_with_profile(
    node_mode: NodeMode,
    best_number: u64,
    best_hash: &str,
    remote_consensus_profile: &str,
    identity_public_key: &str,
    identity_signature: &str,
    tls_certificate_hash: &str,
    expected_tls_certificate_hash: Option<&str>,
    trusted_identity_keys: Option<&[String]>,
    expected_profile: &str,
) -> Result<()> {
    verify_p2p_identity_for_profile(
        node_mode,
        best_number,
        best_hash,
        remote_consensus_profile,
        identity_public_key,
        identity_signature,
        tls_certificate_hash,
        expected_tls_certificate_hash,
        trusted_identity_keys,
        expected_profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_p2p_identity_for_profile(
    node_mode: NodeMode,
    best_number: u64,
    best_hash: &str,
    remote_consensus_profile: &str,
    identity_public_key: &str,
    identity_signature: &str,
    tls_certificate_hash: &str,
    expected_tls_certificate_hash: Option<&str>,
    trusted_identity_keys: Option<&[String]>,
    expected_profile: &str,
) -> Result<()> {
    if remote_consensus_profile != expected_profile {
        anyhow::bail!("consensus profile mismatch");
    }
    if let Some(expected) = expected_tls_certificate_hash {
        if tls_certificate_hash != expected {
            anyhow::bail!("P2P hello certificate fingerprint does not match TLS peer");
        }
    }
    let public_key_bytes = hex::decode(identity_public_key)?;
    let public_key = PublicKey::from_slice(&public_key_bytes)?;
    if let Some(trusted) = trusted_identity_keys {
        if !trusted
            .iter()
            .any(|key| key.eq_ignore_ascii_case(identity_public_key))
        {
            anyhow::bail!("P2P identity key is not trusted by this node");
        }
    }
    let signature_bytes = hex::decode(identity_signature)?;
    if signature_bytes.len() != 65 {
        anyhow::bail!("P2P identity signature has invalid length");
    }
    let recovery_id = RecoveryId::try_from(signature_bytes[64] as i32)?;
    let signature = RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id)?;
    let digest = keccak256(p2p_hello_payload(
        node_mode,
        best_number,
        best_hash,
        remote_consensus_profile,
        identity_public_key,
        tls_certificate_hash,
    ));
    Secp256k1::new().verify_ecdsa(
        Message::from_digest(digest.0),
        &signature.to_standard(),
        &public_key,
    )?;
    Ok(())
}

#[derive(Debug, Parser)]
#[command(name = "blq-node")]
#[command(about = "Block public node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    FullNode {
        #[arg(long)]
        config: Option<String>,
    },
    PartialNode {
        #[arg(long)]
        config: Option<String>,
    },
    PublicNode {
        #[arg(long)]
        config: Option<String>,
    },
    Genesis,
    GenesisManifest {
        #[arg(long)]
        out: String,
    },
    Status {
        #[arg(long)]
        config: Option<String>,
    },
    PeerUnban {
        #[arg(long)]
        config: Option<String>,
        #[arg(long, conflicts_with = "peer_id", required_unless_present = "peer_id")]
        peer: Option<String>,
        #[arg(long, conflicts_with = "peer", required_unless_present = "peer")]
        peer_id: Option<String>,
    },
    PeerUnbanAll {
        #[arg(long)]
        config: Option<String>,
    },
    ClearOrphans {
        #[arg(long)]
        config: Option<String>,
    },
    StorageStatus {
        #[arg(long)]
        config: Option<String>,
    },
    SyncStatus {
        #[arg(long)]
        config: Option<String>,
    },
    ImportBlock {
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        path: String,
    },
    ImportHeader {
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        path: String,
    },
    Rollback {
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        height: u64,
    },
    SnapshotRecovery {
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        height: u64,
    },
    DiscoveryServer {
        #[arg(long)]
        bind: String,
    },
    RelayNode {
        #[arg(long)]
        bind: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::FullNode { config } => run_node(config, NodeMode::Full),
        Command::PartialNode { config } => run_node(config, NodeMode::Partial),
        Command::PublicNode { config } => run_node(config, None),
        Command::Genesis => print_genesis(),
        Command::GenesisManifest { out } => mine_genesis_manifest(&out),
        Command::Status { config } => print_status(config),
        Command::PeerUnban {
            config,
            peer,
            peer_id,
        } => peer_unban(config, peer, peer_id),
        Command::PeerUnbanAll { config } => peer_unban_all(config),
        Command::ClearOrphans { config } => clear_orphans(config),
        Command::StorageStatus { config } | Command::SyncStatus { config } => print_status(config),
        Command::ImportBlock { config, path } => import_block(config, path),
        Command::ImportHeader { config, path } => import_header(config, path),
        Command::Rollback { config, height } => rollback_node(config, height),
        Command::SnapshotRecovery { config, height } => recover_snapshot(config, height),
        Command::DiscoveryServer { bind } => run_discovery_server(&bind),
        Command::RelayNode { bind } => run_relay_node(&bind),
    }
}

/// Offline-only escape hatch for legacy databases created before periodic
/// snapshots. It never changes the active generation: it verifies the local
/// canonical prefix into a separate verified generation and saves a snapshot
/// at the requested ancestor for the normal fork-choice path to consume.
fn recover_snapshot(config: Option<String>, height: u64) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let storage = NodeStorage::open(&config)?;
    verify_expected_genesis(&config, &storage)?;
    let canonical = storage.canonical_blocks()?;
    let target = canonical.get(height as usize).ok_or_else(|| {
        anyhow::anyhow!("snapshot recovery height is absent from canonical storage")
    })?;
    let root = Path::new(&config.node.data_dir).join("generations");
    let available = filesystem_free_bytes(Path::new(&config.node.data_dir)).unwrap_or(0);
    let required = config
        .node
        .filesystem_reserve_bytes
        .saturating_add(MIN_CANDIDATE_REPLAY_FREE_BYTES);
    if available < required {
        anyhow::bail!("snapshot recovery deferred: insufficient filesystem budget");
    }
    let mut generation_id = SledStorage::load_active_generation(&root)?
        .unwrap_or(0)
        .saturating_add(1);
    while SledStorage::generation_path(&root, generation_id).exists()
        || SledStorage::staging_generation_path(&root, generation_id).exists()
    {
        generation_id = generation_id.saturating_add(1);
    }
    let path = SledStorage::generation_path(&root, generation_id);
    let result = (|| -> Result<()> {
        let mut recovered = NodeStorage::Full(SledStorage::open(&path)?);
        replay_canonical_chain(
            &mut recovered,
            &canonical[..=height as usize],
            config.node.block_size_activation_height,
            config.node.block_time_v2_activation_height,
        )?;
        let best = recovered.best_header()?;
        if best.hash() != target.header.hash() || best.state_root != target.header.state_root {
            anyhow::bail!("snapshot recovery canonical verification failed");
        }
        let profile = consensus_profile_for_genesis(configured_genesis_hash(&storage)?);
        let NodeStorage::Full(full) = &recovered else {
            unreachable!();
        };
        full.create_snapshot(
            &path,
            generation_id,
            height,
            best.hash(),
            profile.clone(),
            finalized_height(height),
        )?;
        SledStorage::write_generation_manifest(
            &path,
            &GenerationManifest {
                generation_id,
                status: GenerationStatus::Verified,
                canonical_height: height,
                canonical_hash: best.hash(),
                state_root: best.state_root,
                profile_fingerprint: profile,
                finalized_height: finalized_height(height),
                replay_checkpoint: Some(height),
            },
        )?;
        println!(
            "snapshot recovery created verified generation {generation_id} at height {height}"
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&path);
    }
    result
}

fn rollback_node(config: Option<String>, height: u64) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let mut storage = NodeStorage::open(&config)?;
    verify_expected_genesis(&config, &storage)?;
    let canonical = storage.canonical_blocks()?;
    let current = canonical
        .last()
        .ok_or_else(|| anyhow::anyhow!("cannot roll back an empty chain"))?;
    if height >= current.header.number.0 {
        anyhow::bail!(
            "rollback height {} is not below current height {}",
            height,
            current.header.number.0
        );
    }
    let replacement = canonical
        .into_iter()
        .take((height as usize).saturating_add(1))
        .collect::<Vec<_>>();
    let target = replacement
        .last()
        .ok_or_else(|| anyhow::anyhow!("rollback target is empty"))?;
    storage.clear_canonical_state()?;
    if let Err(err) = replay_canonical_chain(
        &mut storage,
        &replacement,
        config.node.block_size_activation_height,
        config.node.block_time_v2_activation_height,
    ) {
        let _ = storage.clear_canonical_state();
        return Err(err);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "rolledBack": true,
            "height": target.header.number.0,
            "hash": target.header.hash().to_hex(),
            "stateRoot": target.header.state_root.to_hex(),
        }))?
    );
    Ok(())
}

fn run_node(config: Option<String>, mode_override: impl Into<Option<NodeMode>>) -> Result<()> {
    let mut config = NodeConfig::load(config.as_deref())?;
    if let Some(mode) = mode_override.into() {
        config.node.mode = mode;
    }
    load_branch_sync_cursors(&config);
    let storage = Arc::new(Mutex::new(NodeStorage::open(&config)?));
    start_canonical_maintenance_worker();
    {
        let mut storage = storage.lock().expect("storage mutex poisoned");
        if storage.is_empty() {
            initialize_genesis_for_config(&mut storage, config.node.mode, &config)?;
        }
        verify_expected_genesis(&config, &storage)?;
        storage.backfill_rewards()?;
        if let NodeStorage::Full(full) = &*storage {
            backfill_supply_storage(full)?;
        }
        ensure_storage_cap(&config, &storage)?;
    }
    restore_orphaned_recovery_spools(&config, &storage)?;
    let best_header = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?;
    {
        let mut progress = sync_progress()
            .lock()
            .expect("sync progress mutex poisoned");
        progress.current_height = best_header.number.0;
        progress.network_height = best_header.number.0;
        progress.last_imported_height = best_header.number.0;
        progress.state = "synced";
    }
    let mempool_path = Path::new(&config.node.data_dir).join("mempool.json");
    let restored =
        Mempool::load(&mempool_path, best_header.base_fee_per_gas).unwrap_or_else(|err| {
            eprintln!("mempool could not be restored: {err}");
            Mempool::default()
        });
    let mut validated_mempool = Mempool::default();
    for transaction in restored.pending() {
        if validate_transaction_against_current_state(
            &storage,
            transaction,
            best_header.base_fee_per_gas,
        )
        .is_ok()
        {
            let _ = validated_mempool.add(transaction.clone(), best_header.base_fee_per_gas);
        }
    }
    let mempool = Arc::new(Mutex::new(validated_mempool));
    start_mempool_persistence(
        mempool_path,
        Arc::clone(&mempool),
        config.node.filesystem_reserve_bytes,
    );
    let info = ChainInfo::from_header(config.node.mode, &best_header);
    println!("{}", serde_json::to_string_pretty(&info)?);
    report_storage_usage(&config, &storage.lock().expect("storage mutex poisoned"))?;
    if config.node.mining_enabled {
        eprintln!("mining is configured on but miner startup is intentionally disabled");
    }
    if config.rpc.enabled {
        start_rpc_server(&config, Arc::clone(&storage), Arc::clone(&mempool));
    } else {
        eprintln!("rpc disabled; set [rpc].enabled = true to serve read-only JSON-RPC");
    }
    start_candidate_recovery(&config, Arc::clone(&storage));
    eprintln!("{} node initialized", config.node.mode.as_str());
    if config.network.enabled {
        start_optional_services(&config);
        run_p2p(config, storage, mempool)?;
    } else {
        eprintln!("networking disabled; enable [network] for p2p sync");
    }
    Ok(())
}

fn start_canonical_maintenance_worker() {
    CANONICAL_MAINTENANCE_QUEUE.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<CanonicalMaintenanceJob>(8);
        thread::spawn(move || canonical_maintenance_worker(receiver));
        sender
    });
}

fn schedule_canonical_maintenance(config: &NodeConfig, storage: &Arc<Mutex<NodeStorage>>) {
    if CANONICAL_MAINTENANCE_PENDING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let sender = CANONICAL_MAINTENANCE_QUEUE.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<CanonicalMaintenanceJob>(8);
        thread::spawn(move || canonical_maintenance_worker(receiver));
        sender
    });
    if sender
        .try_send(CanonicalMaintenanceJob {
            config: config.clone(),
            storage: Arc::clone(storage),
        })
        .is_err()
    {
        CANONICAL_MAINTENANCE_PENDING.store(false, Ordering::Release);
    }
}

fn canonical_maintenance_worker(receiver: Receiver<CanonicalMaintenanceJob>) {
    while let Ok(job) = receiver.recv() {
        // The immediate next template has priority over filesystem work.
        thread::sleep(Duration::from_millis(25));
        CANONICAL_MAINTENANCE_PENDING.store(false, Ordering::Release);
        let storage = job.storage.lock().expect("storage mutex poisoned");
        if let Err(err) = write_periodic_snapshot(&job.config, &storage) {
            eprintln!("periodic generation snapshot failed: {err}");
        }
        if job.config.node.pruning_enabled() {
            match prune_floor(&job.config, &storage).and_then(|floor| {
                storage
                    .prune_old_blocks(job.config.node.max_storage_bytes, floor)
                    .map_err(Into::into)
            }) {
                Ok(()) => {}
                Err(err) => eprintln!("canonical maintenance pruning failed: {err}"),
            }
        }
    }
}

fn invalidate_local_template_cache() {
    LOCAL_TEMPLATE_CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("local template cache mutex poisoned")
        .take();
}

fn start_candidate_recovery(config: &NodeConfig, storage: Arc<Mutex<NodeStorage>>) {
    if config.node.mode != NodeMode::Full {
        return;
    }
    // A historical snapshot bootstrap has already claimed the only recovery
    // workspace. New gossip notifications must not repeatedly rebuild the
    // same candidate branch just to discover that the bootstrap lease is busy.
    let bootstrap_lease = Path::new(&config.node.data_dir)
        .join("generations")
        .join(".snapshot-bootstrap.lease");
    if SNAPSHOT_BOOTSTRAP_IN_PROGRESS.load(std::sync::atomic::Ordering::SeqCst)
        || bootstrap_lease.exists()
    {
        return;
    }
    // Do this before any staging cleanup. A second candidate notification may
    // refer to an older cursor while the selected tip is replaying; deleting
    // staging in that path forces the live worker back to its snapshot.
    if any_recovery_replay_is_active() {
        return;
    }
    // Claim ownership before any staging cleanup. A newly completed range can
    // otherwise delete the generation currently being replayed by another
    // recovery invocation.
    let Some(reorg_guard) = ReorgGuard::try_acquire() else {
        return;
    };
    if let Err(err) = remove_abandoned_staging_generations(config) {
        eprintln!("candidate recovery could not clean abandoned staging: {err}");
    }
    let completed_tip = completed_recovery_tip();
    // A completed spool can be announced again by every healthy peer hello.
    // The replay is deliberately isolated and may take longer than those
    // sessions, so treating each announcement as fresh work restarts branch
    // assembly and starves the one staging generation that must finish.
    // Startup normalization changes an interrupted `replaying` cursor back
    // to `complete`, which makes this latch crash-safe rather than sticky.
    if let Some(tip_hash) = completed_tip {
        if recovery_tip_is_replaying(tip_hash) {
            return;
        }
    }
    if let Some(tip_hash) = completed_tip {
        // Old cursors could retain the same authenticated identity as both
        // primary and witness after routes were reassigned. That is not an
        // independent cross-check; fall back to the explicitly supported
        // single-provider mode instead of leaving a complete recovery stuck.
        let key = recovery_cursor_key(tip_hash);
        let mut repaired = false;
        if let Some(cursor) = branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned")
            .get_mut(&key)
        {
            if cursor.primary_identity.is_some()
                && cursor.primary_identity == cursor.witness_identity
            {
                cursor.witness_identity = None;
                cursor.witness_sample_heights.clear();
                cursor.primary_sample_hashes.clear();
                cursor.witness_sample_hashes.clear();
                cursor.witness_mismatch = None;
                cursor.provider_mode = "single-provider".to_string();
                cursor.updated_at = unix_now();
                repaired = true;
            } else if cursor.witness_identity.is_some() && cursor.witness_sample_heights.is_empty()
            {
                // A completed job restored after a restart can predate the
                // per-range witness samples.  It still contains bodies that
                // this node has fully validated, but has no pending audit to
                // wait for.  Make that degraded confidence explicit rather
                // than allowing an empty audit set to block publication
                // forever. New ranges continue to request witnesses.
                cursor.witness_identity = None;
                cursor.primary_sample_hashes.clear();
                cursor.witness_sample_hashes.clear();
                cursor.witness_mismatch = None;
                cursor.provider_mode = "single-provider".to_string();
                cursor.updated_at = unix_now();
                repaired = true;
            } else if cursor.witness_identity.is_some()
                && cursor.next_height > cursor.tip_height
                && cursor.last_progress_at > 0
                && unix_now().saturating_sub(cursor.last_progress_at) >= 30
            {
                // Cross-check when an independent peer can answer, but do not
                // make one lagging or deferred session a permanent publication
                // veto. The complete primary branch has already undergone full
                // local validation; surface the reduced confidence explicitly.
                cursor.witness_identity = None;
                cursor.witness_sample_heights.clear();
                cursor.primary_sample_hashes.clear();
                cursor.witness_sample_hashes.clear();
                cursor.witness_mismatch = None;
                cursor.provider_mode = "single-provider".to_string();
                cursor.updated_at = unix_now();
                repaired = true;
            }
        }
        if repaired {
            if let Err(err) = persist_branch_sync_cursors(config) {
                eprintln!("could not persist repaired recovery witness role: {err}");
            }
            eprintln!(
                "candidate recovery ignored a duplicate witness identity; continuing in single-provider mode"
            );
        }
    }
    if let Some(tip_hash) = completed_tip {
        if !recovery_tip_ready_for_publication(tip_hash) {
            set_recovery_state_for_tip(config, tip_hash, "waiting-for-witness");
            eprintln!(
                "candidate recovery has a complete branch but is waiting for bounded witness checks"
            );
            return;
        }
    }
    let candidate = {
        let storage_guard = storage.lock().expect("storage mutex poisoned");
        let preferred = completed_tip.and_then(|hash| {
            match restore_completed_candidate(&storage_guard, hash) {
                Ok(candidate) => Some(candidate),
                Err(err) => {
                    eprintln!("candidate recovery could not restore completed tip: {err}");
                    reset_completed_recovery_for_refetch(config, hash);
                    None
                }
            }
        });
        let (header, work) = match preferred
            .or_else(|| storage_guard.latest_candidate_tip().ok().flatten())
        {
            Some(candidate) => candidate,
            None => {
                if !has_durable_recovery_job() {
                    if let Err(err) = clear_obsolete_candidates(&storage_guard) {
                        eprintln!("candidate recovery could not clear obsolete candidates: {err}");
                    }
                }
                if let Err(err) = remove_abandoned_staging_generations(config) {
                    eprintln!("candidate recovery could not clean abandoned staging: {err}");
                }
                return;
            }
        };
        let canonical_tip = match storage_guard.best_header() {
            Ok(header) => header,
            Err(err) => {
                eprintln!("candidate recovery could not read canonical tip: {err}");
                return;
            }
        };
        let canonical_work =
            match canonical_work_through_node_storage(&storage_guard, canonical_tip.number.0) {
                Ok(work) => work,
                Err(err) => {
                    eprintln!("candidate recovery could not read canonical work: {err}");
                    return;
                }
            };
        if work <= canonical_work {
            if completed_tip.is_some_and(|tip_hash| tip_hash == header.hash()) {
                // A completed spool can become obsolete while the local tip
                // advances. Retire it before returning so later peer hellos
                // resume normal branch retrieval instead of re-evaluating it.
                reject_completed_recovery(
                    config,
                    header.hash(),
                    "completed recovery no longer outranks canonical work",
                );
            }
            if let Err(err) = clear_obsolete_candidates(&storage_guard) {
                eprintln!("candidate recovery could not clear obsolete candidates: {err}");
            }
            if let Err(err) = remove_abandoned_staging_generations(config) {
                eprintln!("candidate recovery could not clean abandoned staging: {err}");
            }
            return;
        }
        match storage_guard
            .recovery_spool_block_by_hash(header.hash())
            .map(|(block, _)| block)
            .or_else(|_| storage_guard.block_by_hash(header.hash()))
        {
            Ok(block) => Some((block, canonical_tip)),
            Err(err) => {
                eprintln!("candidate recovery missing tip body: {err}");
                None
            }
        }
    };
    let Some((tip, canonical_tip)) = candidate else {
        return;
    };
    eprintln!(
        "candidate recovery selected tip {} at height {} over canonical height {}",
        tip.header.hash().to_hex(),
        tip.header.number.0,
        canonical_tip.number.0
    );
    let config = config.clone();
    // Publish the durable admission state before the worker starts.  A peer
    // hello can arrive between `spawn` and the first worker instruction; if
    // it observes `complete` in that gap it can attempt a second replay and
    // remove the first worker's staging generation during its setup.
    set_recovery_state_for_tip(&config, tip.header.hash(), "replaying");
    thread::spawn(move || {
        // Keep this lease alive until the recovery thread exits.  Candidate
        // notifications can arrive while snapshot bootstrap is still busy.
        // The explicit drop below prevents an unused binding from ending the
        // lease before staged replay and publication have completed.
        let reorg_guard = reorg_guard;
        eprintln!("candidate recovery assembling replacement branch");
        let branch = {
            let storage_guard = storage.lock().expect("storage mutex poisoned");
            match candidate_branch_from_storage(&storage_guard, &tip) {
                Ok(branch) => branch,
                Err(err) => {
                    set_recovery_state_for_tip(&config, tip.header.hash(), "waiting-for-provider");
                    if err.to_string().contains("candidate rejected") {
                        if let Err(quarantine_error) = storage_guard
                            .quarantine_candidate_tip(tip.header.hash(), &err.to_string())
                        {
                            eprintln!("candidate recovery could not quarantine rejected candidate: {quarantine_error}");
                        }
                    }
                    eprintln!("candidate recovery waiting for a safe branch: {err}");
                    return;
                }
            }
        };
        eprintln!(
            "candidate recovery assembled suffix of {} blocks above ancestor {}; starting staged replay",
            branch.suffix.len(),
            branch.common_height
        );
        // A forward sync that starts exactly at the active canonical tip is
        // not a reorganization. Import it through the normal validated
        // canonical path so node 201 does not spend its limited memory
        // rebuilding a staging generation for an ordinary catch-up.
        let direct_extension = {
            let storage_guard = storage.lock().expect("storage mutex poisoned");
            let canonical_tip = storage_guard.best_header().ok();
            canonical_tip.is_some_and(|tip| {
                tip.number.0 == branch.common_height
                    && tip.hash() == branch.common_hash
                    && branch
                        .suffix
                        .first()
                        .is_some_and(|block| block.header.parent_hash == tip.hash())
            })
        };
        if direct_extension {
            eprintln!(
                "candidate recovery is a direct extension; importing {} block(s) canonically",
                branch.suffix.len()
            );
            for (batch_index, batch) in branch.suffix.chunks(32).enumerate() {
                if let Err(err) = import_direct_recovery_batch(&config, &storage, batch) {
                    set_recovery_state_for_tip(&config, tip.header.hash(), "complete");
                    eprintln!("direct recovery import deferred; active chain unchanged: {err}");
                    return;
                }
                let committed = ((batch_index + 1) * 32).min(branch.suffix.len());
                eprintln!(
                    "candidate recovery committed direct batch: {}/{} blocks (height {})",
                    committed,
                    branch.suffix.len(),
                    batch
                        .last()
                        .map(|block| block.header.number.0)
                        .unwrap_or(canonical_tip.number.0)
                );
            }
            finalize_published_recovery(&config, &storage, tip.header.hash());
            eprintln!("candidate recovery published the direct canonical extension");
            drop(reorg_guard);
            return;
        }
        if let Err(err) = stage_and_publish_candidate(&config, &storage, branch) {
            if err
                .to_string()
                .contains("candidate recovery bootstrap already in progress")
            {
                eprintln!(
                    "candidate recovery bootstrap is already running; keeping the active job"
                );
                return;
            }
            if err
                .to_string()
                .contains("candidate replay superseded by current canonical work")
            {
                reject_completed_recovery(
                    &config,
                    tip.header.hash(),
                    "candidate replay superseded by current canonical work",
                );
            } else {
                set_recovery_state_for_tip(&config, tip.header.hash(), "complete");
            }
            eprintln!("candidate recovery deferred; active chain unchanged: {err}");
        } else {
            finalize_published_recovery(&config, &storage, tip.header.hash());
            eprintln!("candidate recovery published the highest-work stored branch");
        }
        drop(reorg_guard);
    });
}

// Direct recovery is already parent-ordered and does not need the gossip
// importer’s per-body snapshot, pruning, orphan drain, or relay work.
fn import_direct_recovery_batch(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    blocks: &[Block],
) -> Result<()> {
    let _import_guard = BLOCK_IMPORT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("block import mutex poisoned");
    let mut storage_guard = storage.lock().expect("storage mutex poisoned");
    // Disk accounting and generation cleanup are batch guards. Running them
    // for every body defeats the bounded importer and can look like a sync
    // stall on archive nodes.
    ensure_storage_cap(config, &storage_guard)?;
    for block in blocks {
        let parent = storage_guard.best_header()?;
        if block.header.parent_hash != parent.hash() || block.header.number.0 != parent.number.0 + 1
        {
            anyhow::bail!("direct recovery batch lost contiguous parent linkage");
        }
        validate_block_for_storage(config, &storage_guard, &parent, block)?;
        validate_difficulty_target(
            &storage_guard,
            &parent,
            &block.header,
            config.node.block_time_v2_activation_height,
        )?;
        validate_state_root(&storage_guard, block)?;
        storage_guard.insert_block(block.clone())?;
    }
    write_periodic_snapshot(config, &storage_guard)?;
    if config.node.pruning_enabled() {
        let floor = prune_floor(config, &storage_guard)?;
        storage_guard.prune_old_blocks(config.node.max_storage_bytes, floor)?;
    }
    Ok(())
}

fn clear_obsolete_candidates(storage: &NodeStorage) -> Result<()> {
    match storage {
        NodeStorage::Full(storage) => Ok(storage.clear_candidate_blocks()?),
        NodeStorage::Partial(_) => Ok(()),
    }
}

fn remove_abandoned_staging_generations(config: &NodeConfig) -> Result<()> {
    let root = Path::new(&config.node.data_dir).join("generations");
    let Some(active_id) = SledStorage::load_active_generation(&root)? else {
        return Ok(());
    };
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id_text) = name
            .strip_prefix("generation-")
            .and_then(|value| value.strip_suffix(".staging"))
        else {
            continue;
        };
        let Ok(generation_id) = id_text.parse::<u64>() else {
            continue;
        };
        if generation_id != active_id {
            SledStorage::remove_staging_generation(&root, generation_id)?;
        }
    }
    Ok(())
}

fn print_genesis() -> Result<()> {
    let header = genesis_header();
    println!(
        "{}",
        serde_json::to_string_pretty(&ChainInfo::from_header(NodeMode::Full, &header))?
    );
    Ok(())
}

fn print_status(config: Option<String>) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let mut storage = NodeStorage::open(&config)?;
    if storage.is_empty() {
        initialize_genesis_for_config(&mut storage, config.node.mode, &config)?;
    }
    verify_expected_genesis(&config, &storage)?;
    storage.backfill_rewards()?;
    let best = storage.best_header()?;
    let (mining_safe, available_peers, matching_peers) =
        trusted_peer_quorum(&config, &best, configured_genesis_hash(&storage)?);
    let info = ChainInfo::from_header(config.node.mode, &best);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "chain": info,
            "storage": storage_status(&config, &storage)?,
            "consensusProfile": network_consensus_profile(&config, configured_genesis_hash(&storage)?),
            "blockSizeActivationHeight": config.node.block_size_activation_height,
            "blockTimeV2ActivationHeight": config.node.block_time_v2_activation_height,
            "blockTimeTargetSeconds": active_block_time_target_seconds(&config, best.number.0),
            "canonicalTip": {
                "number": best.number.0,
                "hash": best.hash().to_hex(),
            },
            "finalizedHeight": finalized_height(best.number.0),
            "peerAgreement": {
                "available": available_peers,
                "matching": matching_peers,
                "peers": trusted_peer_status(&config, &best, configured_genesis_hash(&storage)?),
            },
            "cumulativeWork": canonical_work(&storage.canonical_blocks()?).to_string(),
            "miningSafe": mining_safe,
        }))?
    );
    Ok(())
}

fn peer_unban(config: Option<String>, peer: Option<String>, peer_id: Option<String>) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let score_path = Path::new(&config.node.data_dir).join("peer-scores.json");
    let mut scores = PeerScoreBook::load(&score_path)
        .map_err(|err| anyhow::anyhow!("could not load peer scores: {err}"))?;
    let (target, peer_id) = match (peer, peer_id) {
        (Some(peer), None) => (peer.clone(), PeerId::from_advertised_address(&peer)),
        (None, Some(peer_id)) => {
            let hash = Hash256::from_hex(&peer_id)
                .map_err(|err| anyhow::anyhow!("invalid --peer-id: {err:?}"))?;
            (peer_id, PeerId(hash))
        }
        _ => anyhow::bail!("provide exactly one of --peer or --peer-id"),
    };
    let score = scores.clear_ban(peer_id).clone();
    scores
        .save(&score_path)
        .map_err(|err| anyhow::anyhow!("could not save peer scores: {err}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "peer": target,
            "score": score.score,
            "consecutiveFailures": score.consecutive_failures,
            "banned": score.banned,
            "scoreFile": score_path,
        }))?
    );
    Ok(())
}

fn peer_unban_all(config: Option<String>) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let score_path = Path::new(&config.node.data_dir).join("peer-scores.json");
    let mut scores = PeerScoreBook::load(&score_path)
        .map_err(|err| anyhow::anyhow!("could not load peer scores: {err}"))?;
    let cleared = scores.clear_all_bans();
    scores
        .save(&score_path)
        .map_err(|err| anyhow::anyhow!("could not save peer scores: {err}"))?;
    println!(
        "{}",
        serde_json::json!({
            "clearedEntries": cleared,
            "scoreFile": score_path,
            "chainDataChanged": false,
        })
    );
    Ok(())
}

fn clear_orphans(config: Option<String>) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let storage = NodeStorage::open(&config)?;
    let cleared = match storage {
        NodeStorage::Full(storage) => storage.clear_orphan_blocks()?,
        NodeStorage::Partial(_) => 0,
    };
    println!(
        "{}",
        serde_json::json!({
            "clearedOrphans": cleared,
            "chainDataChanged": false,
        })
    );
    Ok(())
}

fn import_block(config: Option<String>, path: String) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let mut storage = NodeStorage::open(&config)?;
    if storage.is_empty() {
        initialize_genesis_for_config(&mut storage, config.node.mode, &config)?;
    }
    verify_expected_genesis(&config, &storage)?;
    storage.backfill_rewards()?;
    let parent = storage.best_header()?;
    let block: blq_primitives::Block = serde_json::from_str(&fs::read_to_string(path)?)?;
    validate_block_for_storage(&config, &storage, &parent, &block)
        .map_err(|err| anyhow::anyhow!("validate block {} failed: {err}", block.header.number.0))?;
    validate_difficulty_target(
        &storage,
        &parent,
        &block.header,
        config.node.block_time_v2_activation_height,
    )
    .map_err(|err| {
        anyhow::anyhow!(
            "validate difficulty {} failed: {err}",
            block.header.number.0
        )
    })?;
    validate_state_root(&storage, &block)
        .map_err(|err| anyhow::anyhow!("validate state {} failed: {err}", block.header.number.0))?;
    ensure_storage_cap(&config, &storage)?;
    let hash = block.header.hash().to_hex();
    let number = block.header.number.0;
    storage.insert_block(block)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "imported": true,
            "number": number,
            "hash": hash,
        }))?
    );
    Ok(())
}

fn import_header(config: Option<String>, path: String) -> Result<()> {
    let config = NodeConfig::load(config.as_deref())?;
    let mut storage = NodeStorage::open(&config)?;
    if storage.is_empty() {
        initialize_genesis_for_config(&mut storage, NodeMode::Partial, &config)?;
    }
    verify_expected_genesis(&config, &storage)?;
    let parent = storage.best_header()?;
    let header: BlockHeader = serde_json::from_str(&fs::read_to_string(path)?)?;
    validate_header_for_storage(&storage, &parent, &header)?;
    if header.parent_hash != parent.hash() {
        anyhow::bail!("header parent hash does not match current best header");
    }
    validate_difficulty_target(
        &storage,
        &parent,
        &header,
        config.node.block_time_v2_activation_height,
    )?;
    ensure_storage_cap(&config, &storage)?;
    let hash = header.hash().to_hex();
    let number = header.number.0;
    storage.insert_header(header)?;
    relay_best_header(&config, &storage)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "imported": true,
            "nodeMode": "partial",
            "number": number,
            "hash": hash,
        }))?
    );
    Ok(())
}

fn start_rpc_server(
    config: &NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
) {
    let config = config.clone();
    thread::spawn(move || {
        if let Err(err) = run_rpc_server(config, storage, mempool) {
            eprintln!("json-rpc server failed: {err}");
        }
    });
}

fn start_mempool_persistence(
    path: std::path::PathBuf,
    mempool: Arc<Mutex<Mempool>>,
    filesystem_reserve_bytes: u64,
) {
    thread::spawn(move || {
        let mut reserve_unavailable = false;
        let mut last_reserve_warning = None;
        loop {
            thread::sleep(Duration::from_secs(5));
            let free = filesystem_free_bytes(&path);
            if free.is_some_and(|free| free < filesystem_reserve_bytes) {
                let now = Instant::now();
                if !reserve_unavailable
                    || should_log_mempool_persistence_pressure(last_reserve_warning, now)
                {
                    eprintln!(
                    "mempool persistence paused: filesystem reserve is unavailable (free {} bytes, reserve {} bytes)",
                    free.unwrap_or(0),
                    filesystem_reserve_bytes
                );
                    last_reserve_warning = Some(now);
                }
                reserve_unavailable = true;
                continue;
            }
            if reserve_unavailable {
                eprintln!("mempool persistence resumed: filesystem reserve is available");
                reserve_unavailable = false;
                last_reserve_warning = None;
            }
            let mempool = mempool.lock().expect("mempool mutex poisoned");
            if let Err(err) = mempool.save(&path) {
                eprintln!("mempool could not be persisted: {err}");
            }
        }
    });
}

fn should_log_mempool_persistence_pressure(last_warning: Option<Instant>, now: Instant) -> bool {
    last_warning.map_or(true, |last| {
        now.saturating_duration_since(last) >= MEMPOOL_PERSISTENCE_PRESSURE_LOG_INTERVAL
    })
}

fn run_rpc_server(
    config: NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
) -> Result<()> {
    let bind = config.rpc.bind.clone();
    let listener = TcpListener::bind(bind)?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    eprintln!("JSON-RPC listening on http://{}", config.rpc.bind);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(error) => {
                record_rpc_handler_error(&anyhow::anyhow!(error.to_string()));
                eprintln!("json-rpc accept failed: {error}; retrying");
                thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        if !try_acquire_connection(&active_connections, config.rpc.max_connections) {
            let _ = reject_rpc_connection(stream);
            continue;
        }
        stream.set_read_timeout(Some(P2P_INBOUND_READ_TIMEOUT))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let config = config.clone();
        let storage = Arc::clone(&storage);
        let mempool = Arc::clone(&mempool);
        let active_connections = Arc::clone(&active_connections);
        thread::spawn(move || {
            let _connection_guard = RpcConnectionGuard::new(active_connections);
            if let Err(err) = handle_connection(stream, &config, storage, mempool) {
                if !is_expected_rpc_disconnect(&err) {
                    record_rpc_handler_error(&err);
                    eprintln!("json-rpc connection failed: {err}");
                }
            }
        });
    }
    Ok(())
}

fn reject_rpc_connection(mut stream: TcpStream) -> Result<()> {
    let body = rpc_error(
        serde_json::Value::Null,
        -32005,
        "RPC connection limit reached",
    );
    let response = format!(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\nretry-after: 1\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    config: &NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
) -> Result<()> {
    let _shutdown = RpcSocketShutdownGuard::new(&stream)?;
    let (headers, body) = read_http_request(&mut stream)?;
    if headers
        .lines()
        .next()
        .is_some_and(|line| line.starts_with("OPTIONS "))
    {
        let response = format!(
            "HTTP/1.1 204 No Content\r\n{}content-length: 0\r\nconnection: close\r\n\r\n",
            rpc_cors_headers()
        );
        stream.write_all(response.as_bytes())?;
        stream.shutdown(Shutdown::Both)?;
        return Ok(());
    }
    if headers
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case("upgrade: websocket"))
    {
        return run_websocket_connection(stream, config, storage, mempool, &headers);
    }
    if let Some((method, path)) = http_request_method_and_path(&headers) {
        if method == "GET" {
            let (status, response_body) = if path == "/" {
                ("200 OK", http_node_status_body(config, &storage))
            } else {
                (
                    "404 Not Found",
                    serde_json::json!({
                        "error": "not found",
                        "health": "/",
                        "rpc": "POST /",
                    })
                    .to_string(),
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\n{}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                rpc_cors_headers(),
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes())?;
            stream.shutdown(Shutdown::Both)?;
            return Ok(());
        }
    }
    let response_body = handle_json_rpc_request(config, &storage, &mempool, &body);
    let response = format!(
        "HTTP/1.1 200 OK\r\n{}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        rpc_cors_headers(),
        response_body.len(),
        response_body
    );
    stream.write_all(response.as_bytes())?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn rpc_cors_headers() -> &'static str {
    "access-control-allow-origin: *\r\naccess-control-allow-methods: GET, POST, OPTIONS\r\naccess-control-allow-headers: content-type\r\naccess-control-max-age: 600\r\n"
}

fn http_request_method_and_path(headers: &str) -> Option<(&str, &str)> {
    let mut parts = headers.lines().next()?.split_whitespace();
    Some((parts.next()?, parts.next()?))
}

fn http_node_status_body(config: &NodeConfig, storage: &Arc<Mutex<NodeStorage>>) -> String {
    let node_info = serde_json::from_str::<serde_json::Value>(&rpc_node_info(
        serde_json::Value::Null,
        config,
        storage,
    ))
    .ok()
    .and_then(|response| response.get("result").cloned())
    .unwrap_or(serde_json::Value::Null);
    let field = |name| {
        node_info
            .get(name)
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    serde_json::json!({
        "service": "BLQ node",
        "status": "online",
        "rpc": "POST /",
        "chain": {
            "chainId": field("chainId"),
            "genesisHash": field("genesisHash"),
            "consensusProfile": field("consensusProfile"),
            "currentHeight": field("currentHeight"),
            "networkHeight": field("networkHeight"),
        },
        "health": {
            "nodeMode": field("nodeMode"),
            "syncState": field("syncState"),
            "status": field("status"),
            "activity": field("activity"),
            "isSyncing": field("isSyncing"),
            "isMining": field("isMining"),
            "templateServing": field("templateServing"),
            "miningMode": field("miningMode"),
            "peerCount": field("peerCount"),
            "hashrate": field("hashrate"),
            "hashrateUnit": field("hashrateUnit"),
            "activeMinerCount": field("activeMinerCount"),
            "hashrateStatus": field("hashrateStatus"),
            "lastCanonicalBlockAt": field("lastCanonicalBlockAt"),
            "blockAgeSeconds": field("blockAgeSeconds"),
            "liveness": field("liveness"),
        },
    })
    .to_string()
}

fn read_http_request(stream: &mut TcpStream) -> Result<(String, String)> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    let (header_end, content_length) = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            anyhow::bail!("empty HTTP request");
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 1024 * 1024 {
            anyhow::bail!("HTTP request is too large");
        }
        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = parse_content_length(&headers).unwrap_or(0);
            break (header_end, content_length);
        }
    };
    let header_text = String::from_utf8_lossy(&request[..header_end]).to_string();
    let body_start = header_end;
    while request.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 1024 * 1024 {
            anyhow::bail!("HTTP request is too large");
        }
    }
    let available = request.len().saturating_sub(body_start);
    if available < content_length {
        anyhow::bail!("HTTP request body ended before content-length");
    }
    Ok((
        header_text,
        String::from_utf8_lossy(&request[body_start..body_start + content_length]).to_string(),
    ))
}

#[derive(Clone, Debug)]
struct WsSubscription {
    kind: String,
    filter: Option<serde_json::Value>,
    last_block: u64,
    pending_seen: BTreeSet<Hash256>,
    beneficiary: Option<Hash256>,
    last_mining_parent: Option<String>,
}

fn websocket_accept(headers: &str) -> Result<String> {
    let key = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("sec-websocket-key")
                .then_some(value.trim())
        })
        .ok_or_else(|| anyhow::anyhow!("websocket key is missing"))?;
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    Ok(BASE64.encode(digest.finalize()))
}

fn write_websocket_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    if payload.len() > 2 * 1024 * 1024 {
        anyhow::bail!("websocket payload is too large");
    }
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x81);
    match payload.len() {
        0..=125 => frame.push(payload.len() as u8),
        126..=65_535 => {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn websocket_is_idle(last_activity: Instant) -> bool {
    last_activity.elapsed() >= RPC_WEBSOCKET_IDLE_TIMEOUT
}

fn read_websocket_frame(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 2];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(err)
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut =>
        {
            return Ok(None)
        }
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(Some(Vec::new())),
        Err(err) => return Err(err.into()),
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut length = (header[1] & 0x7f) as usize;
    if length == 126 {
        let mut bytes = [0u8; 2];
        stream.read_exact(&mut bytes)?;
        length = u16::from_be_bytes(bytes) as usize;
    } else if length == 127 {
        let mut bytes = [0u8; 8];
        stream.read_exact(&mut bytes)?;
        length = usize::try_from(u64::from_be_bytes(bytes))?;
    }
    if length > 2 * 1024 * 1024 {
        anyhow::bail!("websocket frame is too large");
    }
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    match opcode {
        0x1 => Ok(Some(payload)),
        0x8 => Ok(Some(Vec::new())),
        0x9 => {
            let mut pong = vec![0x8a, payload.len() as u8];
            pong.extend_from_slice(&payload);
            stream.write_all(&pong)?;
            stream.flush()?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn websocket_subscription_result(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    subscription: &mut WsSubscription,
) -> Result<Vec<serde_json::Value>> {
    let latest = current_block_number(storage)?;
    let from = subscription.last_block.saturating_add(1);
    if subscription.kind == "newHeads" {
        if from > latest {
            return Ok(Vec::new());
        }
        let storage = storage.lock().expect("storage mutex poisoned");
        let mut results = Vec::new();
        for number in from..=latest {
            if let Ok(header) = storage.header_by_number(blq_primitives::BlockNumber(number)) {
                results.push(serde_json::json!({
                    "number": format!("0x{:x}", header.number.0),
                    "hash": format!("0x{}", header.hash().to_hex()),
                    "parentHash": format!("0x{}", header.parent_hash.to_hex()),
                    "timestamp": format!("0x{:x}", header.timestamp_seconds),
                }));
            }
        }
        subscription.last_block = latest;
        return Ok(results);
    }
    if subscription.kind == "newPendingTransactions" {
        return Ok(mempool
            .lock()
            .expect("mempool mutex poisoned")
            .pending()
            .iter()
            .filter_map(|transaction| {
                let hash = transaction.rpc_hash();
                subscription
                    .pending_seen
                    .insert(hash)
                    .then(|| serde_json::json!(format!("0x{}", hash.to_hex())))
            })
            .collect());
    }
    if subscription.kind == "mining" {
        let latest = current_block_number(storage)?;
        let upstream_mode = mining_upstream_required(config, storage);
        if latest < subscription.last_block {
            subscription.last_block = latest;
            return Ok(Vec::new());
        }
        if latest == subscription.last_block && !upstream_mode {
            return Ok(Vec::new());
        }
        let beneficiary = subscription.beneficiary.unwrap_or(Hash256::ZERO);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "blq_getBlockTemplate",
            "params": [beneficiary.to_hex()],
        });
        let response = rpc_block_template(serde_json::json!(0), config, storage, mempool, &request);
        let parsed: serde_json::Value = serde_json::from_str(&response)?;
        subscription.last_block = latest;
        if let Some(result) = parsed.get("result") {
            let parent = result
                .get("parentHash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            if upstream_mode && subscription.last_mining_parent.as_deref() == Some(parent.as_str())
            {
                return Ok(Vec::new());
            }
            subscription.last_mining_parent = Some(parent);
            return Ok(vec![serde_json::json!({
                "type": "mining.notify",
                "jobId": format!("{}-{}", latest, result.get("parentHash").and_then(serde_json::Value::as_str).unwrap_or_default()),
                "height": result.get("height").cloned().unwrap_or(serde_json::Value::Null),
                "parentHash": result.get("parentHash").cloned().unwrap_or(serde_json::Value::Null),
                "templateGeneration": result.get("templateGeneration").cloned().unwrap_or(serde_json::Value::Null),
                "target": result.get("target").cloned().unwrap_or(serde_json::Value::Null),
                "algorithm": result.get("powAlgorithm").cloned().unwrap_or(serde_json::Value::Null),
                "template": result.get("block").cloned().unwrap_or(serde_json::Value::Null),
                "genesisHash": result.get("genesisHash").cloned().unwrap_or(serde_json::Value::Null),
            })]);
        }
        return Ok(Vec::new());
    }
    if subscription.kind == "logs" {
        if from > latest {
            return Ok(Vec::new());
        }
        let filter = subscription
            .filter
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let result = log_filter_result(config, storage, filter, from, latest)?;
        subscription.last_block = latest;
        return Ok(result.as_array().cloned().unwrap_or_default());
    }
    anyhow::bail!("unsupported websocket subscription")
}

fn run_websocket_connection(
    mut stream: TcpStream,
    config: &NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
    headers: &str,
) -> Result<()> {
    let accept = websocket_accept(headers)?;
    stream.write_all(
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    // Keep enough time for a complete client frame; read_exact must not consume
    // a partial header and then discard it when a short timeout expires.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut subscriptions = BTreeMap::<String, WsSubscription>::new();
    let mut last_activity = Instant::now();
    loop {
        if let Some(frame) = read_websocket_frame(&mut stream)? {
            if frame.is_empty() {
                return Ok(());
            }
            last_activity = Instant::now();
            let request: serde_json::Value = serde_json::from_slice(&frame)?;
            let id = request
                .get("id")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            match request.get("method").and_then(serde_json::Value::as_str) {
                Some("eth_subscribe") => {
                    let params = request.get("params").and_then(serde_json::Value::as_array);
                    let kind = params
                        .and_then(|values| values.first())
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("missing subscription kind"))?;
                    if !matches!(
                        kind,
                        "newHeads" | "logs" | "newPendingTransactions" | "mining"
                    ) {
                        write_websocket_frame(
                            &mut stream,
                            rpc_error(id, -32602, "unsupported websocket subscription").as_bytes(),
                        )?;
                        continue;
                    }
                    let subscription_id =
                        format!("0x{:x}", NEXT_RPC_FILTER_ID.fetch_add(1, Ordering::Relaxed));
                    let filter = params.and_then(|values| values.get(1)).cloned();
                    let beneficiary = if kind == "mining" {
                        let token = params
                            .and_then(|values| values.get(2))
                            .and_then(serde_json::Value::as_str);
                        let expected = config.rpc.mining_token.as_deref();
                        if let Some(expected) = expected {
                            if token != Some(expected) {
                                write_websocket_frame(
                                    &mut stream,
                                    rpc_error(
                                        id,
                                        -32001,
                                        "mining subscription authentication failed",
                                    )
                                    .as_bytes(),
                                )?;
                                continue;
                            }
                        }
                        filter
                            .as_ref()
                            .and_then(serde_json::Value::as_str)
                            .and_then(|value| parse_beneficiary(value).ok())
                    } else {
                        None
                    };
                    subscriptions.insert(
                        subscription_id.clone(),
                        WsSubscription {
                            kind: kind.to_string(),
                            filter,
                            last_block: if kind == "mining" {
                                current_block_number(&storage)?.saturating_sub(1)
                            } else {
                                current_block_number(&storage)?
                            },
                            pending_seen: BTreeSet::new(),
                            beneficiary,
                            last_mining_parent: None,
                        },
                    );
                    write_websocket_frame(
                        &mut stream,
                        rpc_result(id, serde_json::json!(subscription_id)).as_bytes(),
                    )?;
                }
                Some("eth_unsubscribe") => {
                    let subscription_id = request
                        .get("params")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|values| values.first())
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    let removed = subscriptions.remove(subscription_id).is_some();
                    write_websocket_frame(
                        &mut stream,
                        rpc_result(id, serde_json::json!(removed)).as_bytes(),
                    )?;
                }
                Some(_) => {
                    let response = handle_json_rpc_value(config, &storage, &mempool, &request);
                    if !response.is_empty() {
                        write_websocket_frame(&mut stream, response.as_bytes())?;
                    }
                }
                None => write_websocket_frame(
                    &mut stream,
                    rpc_error(id, -32600, "invalid request").as_bytes(),
                )?,
            }
        }
        let ids: Vec<String> = subscriptions.keys().cloned().collect();
        for subscription_id in ids {
            let Some(subscription) = subscriptions.get_mut(&subscription_id) else {
                continue;
            };
            for result in websocket_subscription_result(config, &storage, &mempool, subscription)? {
                let notification = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_subscription",
                    "params": {"subscription": subscription_id, "result": result}
                });
                write_websocket_frame(&mut stream, notification.to_string().as_bytes())?;
                last_activity = Instant::now();
            }
        }
        if websocket_is_idle(last_activity) {
            return Ok(());
        }
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            request
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

fn handle_json_rpc_request(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    body: &str,
) -> String {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return rpc_error(serde_json::Value::Null, -32700, "parse error"),
    };
    if let Some(requests) = parsed.as_array() {
        if requests.is_empty() || requests.len() > MAX_RPC_BATCH_REQUESTS {
            return rpc_error(serde_json::Value::Null, -32600, "invalid request batch");
        }
        let responses = requests
            .iter()
            .filter_map(|request| {
                if !is_valid_json_rpc_envelope(request) {
                    return Some(rpc_error(
                        request
                            .get("id")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        -32600,
                        "invalid request",
                    ));
                }
                let response = handle_json_rpc_value(config, storage, mempool, request);
                if is_json_rpc_notification(request) {
                    None
                } else {
                    Some(response)
                }
            })
            .map(|response| {
                serde_json::from_str::<serde_json::Value>(&response).unwrap_or_else(|_| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32603, "message": "invalid RPC response"}
                    })
                })
            })
            .collect::<Vec<_>>();
        return serde_json::to_string(&responses).unwrap_or_else(|_| {
            rpc_error(
                serde_json::Value::Null,
                -32603,
                "could not encode batch response",
            )
        });
    }
    if !is_valid_json_rpc_envelope(&parsed) {
        return rpc_error(serde_json::Value::Null, -32600, "invalid request");
    }
    if is_json_rpc_notification(&parsed) {
        handle_json_rpc_value(config, storage, mempool, &parsed);
        return String::new();
    }
    handle_json_rpc_value(config, storage, mempool, &parsed)
}

fn is_valid_json_rpc_envelope(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("jsonrpc").and_then(serde_json::Value::as_str) == Some("2.0")
        && object
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some()
}

fn is_json_rpc_notification(value: &serde_json::Value) -> bool {
    value
        .as_object()
        .map(|object| !object.contains_key("id"))
        .unwrap_or(false)
}

fn handle_json_rpc_value(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    parsed: &serde_json::Value,
) -> String {
    if !is_valid_json_rpc_envelope(parsed) {
        return rpc_error(
            parsed.get("id").cloned().unwrap_or(serde_json::Value::Null),
            -32600,
            "invalid request",
        );
    }
    let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = parsed
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if !rpc_method_allowed_by_policy(
        config.rpc.public_read_only,
        config.rpc.mining_api_enabled,
        method,
    ) {
        return rpc_error(id, -32601, "method not available on read-only RPC");
    }
    // Keep the public RPC view on the live branch while this node retrieves a
    // verified stronger branch in the background. Operational status remains
    // local so callers can still see that the node is recovering.
    if is_upstream_read_method(method) && mining_upstream_required(config, storage) {
        return match proxy_read_rpc(config, storage, method, parsed) {
            Ok(result) => rpc_result(id, result),
            Err(err) => rpc_error(
                id,
                -32002,
                &format!("read RPC upstream unavailable; retrying: {err}"),
            ),
        };
    }
    if matches!(
        method,
        "blq_submitBlock" | "blq_sendTransaction" | "eth_sendRawTransaction"
    ) {
        let storage_guard = storage.lock().expect("storage mutex poisoned");
        if let Err(err) = ensure_storage_cap(config, &storage_guard) {
            return rpc_error(id, -32000, &format!("node storage blocked: {err}"));
        }
    }
    match method {
        "blq_getBlockTemplate" => rpc_block_template(id, config, storage, mempool, parsed),
        "blq_submitBlock" => rpc_submit_block(id, config, storage, mempool, parsed),
        "blq_reportHashrate" => rpc_report_hashrate(id, parsed),
        "blq_nodeInfo" | "blq_health" => rpc_node_info(id, config, storage),
        "blq_supply" => rpc_supply(id, storage),
        "blq_status" => rpc_status(id, config, storage),
        "blq_pendingTransactions" => rpc_pending_transactions(id, mempool),
        "blq_sendTransaction" => rpc_send_transaction(id, config, storage, mempool, parsed),
        "eth_blockNumber" => {
            let height = match storage
                .lock()
                .expect("storage mutex poisoned")
                .best_header()
            {
                Ok(header) => header.number.0,
                Err(_) => 0,
            };
            rpc_result(id, serde_json::json!(format!("0x{:x}", height)))
        }
        "eth_sendRawTransaction" => rpc_send_raw_transaction(id, config, storage, mempool, parsed),
        "eth_getBalance" => rpc_get_balance(id, config, storage, parsed),
        "eth_getBlockByNumber" => rpc_get_block_by_number(id, config, storage, parsed),
        "eth_getBlockByHash" => rpc_get_block_by_hash(id, config, storage, parsed),
        "eth_getBlockTransactionCountByNumber" => {
            rpc_get_block_transaction_count_by_number(id, config, storage, parsed)
        }
        "eth_getBlockTransactionCountByHash" => {
            rpc_get_block_transaction_count_by_hash(id, config, storage, parsed)
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            rpc_get_transaction_by_block_number_and_index(id, config, storage, parsed)
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            rpc_get_transaction_by_block_hash_and_index(id, config, storage, parsed)
        }
        "eth_getBlockReceipts" => rpc_get_block_receipts(id, config, storage, parsed),
        "eth_getTransactionCount" => rpc_get_transaction_count(id, config, storage, parsed),
        "eth_getTransactionByHash" => rpc_get_transaction_by_hash(id, config, storage, parsed),
        "eth_getTransactionReceipt" => rpc_get_transaction_receipt(id, config, storage, parsed),
        "eth_getCode" => rpc_get_code(id, config, storage, parsed),
        "eth_getStorageAt" => rpc_get_storage_at(id, config, storage, parsed),
        "eth_estimateGas" => rpc_estimate_gas(id, config, storage, parsed),
        "eth_call" => rpc_eth_call(id, config, storage, parsed),
        "eth_getLogs" => rpc_get_logs(id, config, storage, parsed),
        "eth_feeHistory" => rpc_fee_history(id, config, storage, parsed),
        "eth_newFilter" => rpc_new_filter(id, storage, parsed),
        "eth_newBlockFilter" => rpc_new_block_filter(id, storage),
        "eth_newPendingTransactionFilter" => rpc_new_pending_filter(id, storage),
        "eth_getFilterChanges" => rpc_get_filter_changes(id, config, storage, mempool, parsed),
        "eth_getFilterLogs" => rpc_get_filter_logs(id, config, storage, parsed),
        "eth_uninstallFilter" => rpc_uninstall_filter(id, parsed),
        _ => {
            let best_header = match storage
                .lock()
                .expect("storage mutex poisoned")
                .best_header()
            {
                Ok(header) => header,
                Err(err) => return rpc_error(id, -32000, &err.to_string()),
            };
            let snapshot = RpcSnapshot {
                best_header,
                node_mode: config.node.mode,
            };
            let body = match serde_json::to_string(parsed) {
                Ok(body) => body,
                Err(err) => return rpc_error(id, -32603, &err.to_string()),
            };
            snapshot.handle_json_rpc(&body)
        }
    }
}

fn rpc_method_allowed_by_policy(
    public_read_only: bool,
    mining_api_enabled: bool,
    method: &str,
) -> bool {
    if public_read_only
        && mining_api_enabled
        && matches!(method, "blq_getBlockTemplate" | "blq_submitBlock")
    {
        return true;
    }
    !public_read_only
        || !matches!(
            method,
            "blq_getBlockTemplate" | "blq_submitBlock" | "blq_sendTransaction"
        )
}

fn rpc_report_hashrate(id: serde_json::Value, parsed: &serde_json::Value) -> String {
    let params = parsed
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let params = params.as_object().cloned().or_else(|| {
        params
            .as_array()
            .and_then(|items| items.first())
            .and_then(|item| item.as_object())
            .cloned()
    });
    let Some(params) = params else {
        return rpc_error(id, -32602, "invalid hashrate parameters");
    };
    let beneficiary = params
        .get("beneficiary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let worker_id = params
        .get("workerId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let total_hashes = params
        .get("totalHashes")
        .and_then(serde_json::Value::as_u64);
    let elapsed = params
        .get("elapsedSeconds")
        .and_then(serde_json::Value::as_f64);
    let threads = params.get("threads").and_then(serde_json::Value::as_u64);
    if beneficiary.is_empty()
        || beneficiary.len() > 128
        || worker_id.is_empty()
        || worker_id.len() > 128
        || total_hashes.is_none()
        || elapsed.is_none()
        || threads.is_none()
    {
        return rpc_error(id, -32602, "invalid hashrate parameters");
    }
    let total_hashes = total_hashes.unwrap();
    let elapsed = elapsed.unwrap();
    let threads = threads.unwrap();
    if !elapsed.is_finite()
        || elapsed <= 0.0
        || elapsed > 31_536_000.0
        || threads == 0
        || threads > 4096
    {
        return rpc_error(id, -32602, "invalid hashrate sample");
    }
    let key = format!("{beneficiary}|{worker_id}");
    let now = unix_now();
    let mut workers = miner_telemetry().lock().expect("telemetry mutex poisoned");
    if !workers.contains_key(&key) && workers.len() >= MAX_HASHRATE_WORKERS {
        return rpc_error(id, -32000, "hashrate worker limit reached");
    }
    let rate = if let Some(previous) = workers.get(&key) {
        if total_hashes < previous.total_hashes || elapsed <= previous.elapsed_seconds {
            return rpc_error(id, -32602, "hashrate counter rollback");
        }
        let rate =
            (total_hashes - previous.total_hashes) as f64 / (elapsed - previous.elapsed_seconds);
        if !rate.is_finite() || rate > MAX_HASHRATE_PER_WORKER {
            return rpc_error(id, -32602, "hashrate sample exceeds limit");
        }
        rate
    } else {
        0.0
    };
    workers.insert(
        key,
        MinerTelemetry {
            total_hashes,
            elapsed_seconds: elapsed,
            hashrate: rate,
            updated_at: now,
        },
    );
    drop(workers);
    let (hashrate, active, updated, status) = hashrate_snapshot();
    rpc_result(
        id,
        serde_json::json!({"accepted": true, "hashrate": hashrate, "activeMinerCount": active, "hashrateUpdatedAt": updated, "hashrateStatus": status}),
    )
}

fn filter_id_from_params(parsed: &serde_json::Value) -> Result<u64> {
    let value = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing filter id"))?;
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|_| anyhow::anyhow!("invalid filter id"))
}

fn current_block_number(storage: &Arc<Mutex<NodeStorage>>) -> Result<u64> {
    Ok(storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?
        .number
        .0)
}

fn prune_expired_rpc_filters(filters: &mut BTreeMap<u64, RpcFilter>, now: u64) {
    filters
        .retain(|_, filter| now.saturating_sub(filter.last_accessed_at) <= RPC_FILTER_TTL_SECONDS);
}

fn new_rpc_filter(kind: RpcFilterKind, last_block: u64) -> Result<String> {
    let now = unix_now();
    let mut filters = rpc_filters().lock().expect("rpc filter mutex poisoned");
    prune_expired_rpc_filters(&mut filters, now);
    if filters.len() >= MAX_RPC_FILTERS {
        anyhow::bail!("RPC filter limit reached; uninstall an existing filter or retry later");
    }
    let id = NEXT_RPC_FILTER_ID.fetch_add(1, Ordering::Relaxed);
    filters.insert(
        id,
        RpcFilter {
            kind,
            last_block,
            last_accessed_at: now,
        },
    );
    Ok(serde_json::json!(format!("0x{id:x}")).to_string())
}

fn rpc_filter_by_id(filter_id: u64) -> Result<RpcFilter> {
    let now = unix_now();
    let mut filters = rpc_filters().lock().expect("rpc filter mutex poisoned");
    prune_expired_rpc_filters(&mut filters, now);
    let filter = filters
        .get_mut(&filter_id)
        .ok_or_else(|| anyhow::anyhow!("filter not found or expired"))?;
    filter.last_accessed_at = now;
    Ok(filter.clone())
}

fn rpc_new_filter(
    id: serde_json::Value,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let filter = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .cloned()
        .filter(|value| value.is_object())
        .unwrap_or_else(|| serde_json::json!({}));
    let latest = match current_block_number(storage) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    match new_rpc_filter(RpcFilterKind::Logs(filter), latest) {
        Ok(filter_id) => rpc_result(
            id,
            serde_json::from_str(&filter_id).unwrap_or(serde_json::Value::Null),
        ),
        Err(err) => rpc_error(id, -32005, &err.to_string()),
    }
}

fn rpc_new_block_filter(id: serde_json::Value, storage: &Arc<Mutex<NodeStorage>>) -> String {
    let latest = match current_block_number(storage) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    match new_rpc_filter(RpcFilterKind::Blocks, latest) {
        Ok(filter_id) => rpc_result(
            id,
            serde_json::from_str(&filter_id).unwrap_or(serde_json::Value::Null),
        ),
        Err(err) => rpc_error(id, -32005, &err.to_string()),
    }
}

fn rpc_new_pending_filter(id: serde_json::Value, storage: &Arc<Mutex<NodeStorage>>) -> String {
    let latest = match current_block_number(storage) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    match new_rpc_filter(RpcFilterKind::PendingTransactions, latest) {
        Ok(filter_id) => rpc_result(
            id,
            serde_json::from_str(&filter_id).unwrap_or(serde_json::Value::Null),
        ),
        Err(err) => rpc_error(id, -32005, &err.to_string()),
    }
}

fn log_filter_result(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mut filter: serde_json::Value,
    from: u64,
    to: u64,
) -> Result<serde_json::Value> {
    let object = filter
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("log filter must be an object"))?;
    object.insert("fromBlock".into(), serde_json::json!(format!("0x{from:x}")));
    object.insert("toBlock".into(), serde_json::json!(format!("0x{to:x}")));
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getLogs", "params": [filter]
    });
    let response = rpc_get_logs(serde_json::json!(1), config, storage, &request);
    let value: serde_json::Value = serde_json::from_str(&response)?;
    value
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!(value.to_string()))
}

fn rpc_get_filter_changes(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    parsed: &serde_json::Value,
) -> String {
    let filter_id = match filter_id_from_params(parsed) {
        Ok(value) => value,
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    let latest = match current_block_number(storage) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let filter = match rpc_filter_by_id(filter_id) {
        Ok(filter) => filter,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let from = filter.last_block.saturating_add(1);
    if from > latest {
        return rpc_result(id, serde_json::json!([]));
    }
    let result = match filter.kind {
        RpcFilterKind::Blocks => {
            let storage = storage.lock().expect("storage mutex poisoned");
            let hashes = (from..=latest)
                .filter_map(|number| {
                    storage
                        .header_by_number(blq_primitives::BlockNumber(number))
                        .ok()
                })
                .map(|header| serde_json::json!(format!("0x{}", header.hash().to_hex())))
                .collect();
            Ok(serde_json::Value::Array(hashes))
        }
        RpcFilterKind::PendingTransactions => Ok(serde_json::Value::Array(
            mempool
                .lock()
                .expect("mempool mutex poisoned")
                .pending()
                .iter()
                .map(|transaction| {
                    serde_json::json!(format!("0x{}", transaction.rpc_hash().to_hex()))
                })
                .collect(),
        )),
        RpcFilterKind::Logs(filter) => log_filter_result(config, storage, filter, from, latest),
    };
    match result {
        Ok(result) => {
            let now = unix_now();
            let mut filters = rpc_filters().lock().expect("rpc filter mutex poisoned");
            prune_expired_rpc_filters(&mut filters, now);
            if let Some(entry) = filters.get_mut(&filter_id) {
                entry.last_block = latest;
                entry.last_accessed_at = now;
            }
            rpc_result(id, result)
        }
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_get_filter_logs(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let filter_id = match filter_id_from_params(parsed) {
        Ok(value) => value,
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    let filter = match rpc_filter_by_id(filter_id) {
        Ok(RpcFilter {
            kind: RpcFilterKind::Logs(filter),
            last_block,
            ..
        }) => (filter, last_block),
        Ok(_) => return rpc_error(id, -32602, "filter is not a log filter"),
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let latest = match current_block_number(storage) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    match log_filter_result(config, storage, filter.0, 0, latest) {
        Ok(result) => rpc_result(id, result),
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_uninstall_filter(id: serde_json::Value, parsed: &serde_json::Value) -> String {
    let filter_id = match filter_id_from_params(parsed) {
        Ok(value) => value,
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    let now = unix_now();
    let mut filters = rpc_filters().lock().expect("rpc filter mutex poisoned");
    prune_expired_rpc_filters(&mut filters, now);
    rpc_result(id, serde_json::json!(filters.remove(&filter_id).is_some()))
}

fn sync_progress_info(storage: &Arc<Mutex<NodeStorage>>) -> (u64, u64) {
    let progress_height = sync_progress()
        .lock()
        .map(|progress| progress.current_height)
        .unwrap_or(0);
    let current_height = storage
        .try_lock()
        .ok()
        .and_then(|s| s.best_header().ok())
        .map(|h| h.number.0)
        .unwrap_or(progress_height);
    let network_height = peer_agreement()
        .lock()
        .map(|guard| {
            guard
                .tips
                .values()
                .filter(|tip| {
                    tip.body_verified
                        && unix_now().saturating_sub(tip.last_seen) <= PEER_TIP_TTL_SECONDS
                })
                .map(|tip| tip.best_number)
                .max()
                .unwrap_or(current_height)
        })
        .unwrap_or(current_height)
        .max(current_height);
    (current_height, network_height)
}

// This is strictly operational telemetry. Consensus never reads wall-clock
// time; it only helps operators distinguish a serving template endpoint from
// an actively producing chain.
fn canonical_liveness(storage: &Arc<Mutex<NodeStorage>>) -> (Option<u64>, u64, &'static str) {
    let Some(header) = storage
        .try_lock()
        .ok()
        .and_then(|guard| guard.best_header().ok())
    else {
        return (None, 0, "unknown");
    };
    if header.number.0 == 0 {
        return (Some(header.timestamp_seconds), 0, "unknown");
    }
    let age = unix_now().saturating_sub(header.timestamp_seconds);
    let state = if age >= LIVENESS_STALLED_AFTER_SECONDS {
        "stalled"
    } else if age >= LIVENESS_DEGRADED_AFTER_SECONDS {
        "degraded"
    } else {
        "healthy"
    };
    (Some(header.timestamp_seconds), age, state)
}

/// Operational status must never queue behind a replay, import, or slow
/// storage maintenance task. Template admission still uses the stricter
/// `mining_upstream_required` path below; this helper only reports the best
/// immediately available status.
fn mining_upstream_required_for_status(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
) -> bool {
    if config.rpc.mining_upstreams.is_empty() {
        return false;
    }
    if branch_sync_cursors()
        .lock()
        .map(|cursors| {
            cursors.values().any(|cursor| {
                cursor.ancestor_height.is_some()
                    && !matches!(cursor.state.as_str(), "published" | "rejected")
            })
        })
        .unwrap_or(false)
    {
        return true;
    }
    let Ok(guard) = storage.try_lock() else {
        return false;
    };
    let Ok(local) = guard.best_header() else {
        return false;
    };
    let genesis = configured_genesis_hash(&guard).unwrap_or_else(|_| genesis_header().hash());
    let profile = network_consensus_profile(config, genesis);
    peer_agreement()
        .lock()
        .map(|peers| {
            peers.tips.values().any(|tip| {
                tip.body_verified
                    && unix_now().saturating_sub(tip.last_seen) <= PEER_TIP_TTL_SECONDS
                    && tip.consensus_profile == profile
                    && (tip.best_number > local.number.0
                        || (tip.best_number == local.number.0
                            && tip.best_hash != local.hash().to_hex()))
            })
        })
        .unwrap_or(false)
}

// Sync progress is diagnostic. A live PoW miner keeps working on the active
// canonical tip while this value advances in the background; fork choice uses
// only complete, validated branches and cumulative work.
fn format_sync_paused_message(storage: &Arc<Mutex<NodeStorage>>, action: &str) -> String {
    let (current, network) = sync_progress_info(storage);
    if network > current {
        let remaining = network - current;
        format!(
            "node is re-synchronizing canonical chain (current height: {current}, network height: {network}, {remaining} blocks remaining); {action}"
        )
    } else {
        format!(
            "node is re-synchronizing canonical chain (current height: {current}, network height: {network}); {action}"
        )
    }
}

fn parse_http_endpoint(endpoint: &str) -> Result<(String, u16, String)> {
    let authority_and_path = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("mining upstream must use http://"))?;
    let (authority, path) = authority_and_path
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((authority_and_path, "/".to_string()));
    let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_string(), port.parse::<u16>()?)
    } else {
        (authority.to_string(), 80)
    };
    Ok((host, port, path))
}

fn rpc_call_upstream(
    endpoint: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let (host, port, path) = parse_http_endpoint(endpoint)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let mut stream = connect_tcp_session(&format!("{host}:{port}"))?;
    // Mining/read upstream calls are short-lived. Ensure an error while
    // parsing the response cannot leave the TCP half-close around until the
    // operating system reaps it.
    let _shutdown = RpcSocketShutdownGuard::new(&stream)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response_body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response from mining upstream"))?;
    let value: serde_json::Value = serde_json::from_str(response_body)?;
    if let Some(error) = value.get("error") {
        anyhow::bail!("upstream {method} failed: {error}");
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("upstream {method} response missing result"))
}

fn validate_mining_upstream(
    config: &NodeConfig,
    endpoint: &str,
    genesis_hash: Hash256,
) -> Result<()> {
    let info = rpc_call_upstream(endpoint, "blq_nodeInfo", serde_json::json!([]))?;
    if info.get("chainId").and_then(serde_json::Value::as_u64) != Some(MAINNET_CHAIN_ID) {
        anyhow::bail!("upstream reported the wrong chain ID");
    }
    let expected_genesis = genesis_hash.to_hex();
    if info.get("genesisHash").and_then(serde_json::Value::as_str)
        != Some(expected_genesis.as_str())
    {
        anyhow::bail!("upstream reported a different genesis hash");
    }
    let profile = info
        .get("consensusProfile")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let expected_profile = network_consensus_profile(config, genesis_hash);
    if profile != expected_profile {
        anyhow::bail!("upstream reported an incompatible consensus profile");
    }
    Ok(())
}

fn mining_upstream_required(config: &NodeConfig, storage: &Arc<Mutex<NodeStorage>>) -> bool {
    if config.rpc.mining_upstreams.is_empty() {
        return false;
    }
    // A branch cursor is durable, body-backed retrieval state. Do not let a
    // transient peer-tip TTL expiry turn a lagging node back into a local
    // miner before that branch has been published or rejected.
    if branch_sync_cursors()
        .lock()
        .map(|cursors| cursors.values().any(recovery_cursor_requires_provider))
        .unwrap_or(false)
    {
        return true;
    }
    if unresolved_branch_cursor(config, storage).is_some() {
        return true;
    }
    let Ok(guard) = storage.lock() else {
        return false;
    };
    let Ok(local) = guard.best_header() else {
        return false;
    };
    let genesis = configured_genesis_hash(&guard).unwrap_or_else(|_| genesis_header().hash());
    let profile = network_consensus_profile(config, genesis);
    let verified_peer_ahead = peer_agreement()
        .lock()
        .map(|peers| {
            peers.tips.values().any(|tip| {
                tip.body_verified
                    && unix_now().saturating_sub(tip.last_seen) <= PEER_TIP_TTL_SECONDS
                    && tip.consensus_profile == profile
                    && (tip.best_number > local.number.0
                        || (tip.best_number == local.number.0
                            && tip.best_hash != local.hash().to_hex()))
            })
        })
        .unwrap_or(false);
    let local_work =
        canonical_work_through_node_storage(&guard, local.number.0).unwrap_or_default();
    let winning_candidate = guard
        .latest_candidate_tip()
        .ok()
        .flatten()
        .is_some_and(|(_, work)| work >= local_work);
    verified_peer_ahead || winning_candidate
}

fn minimum_upstream_template_height(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
) -> Result<u64> {
    let local_height = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?
        .number
        .0;
    // A retrieved remote tip at height N can only safely supply work for
    // height N + 1 or later. This rejects a healthy-but-stale upstream before
    // it can pull miners backwards onto an older branch.
    Ok(unresolved_branch_cursor(config, storage)
        .map(|cursor| cursor.tip_height.saturating_add(1))
        .filter(|height| *height > 0)
        .unwrap_or_else(|| local_height.saturating_add(1)))
}

fn proxy_mining_template(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> Result<serde_json::Value> {
    let genesis = {
        let guard = storage.lock().expect("storage mutex poisoned");
        configured_genesis_hash(&guard).unwrap_or_else(|_| genesis_header().hash())
    };
    let params = parsed
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let minimum_height = minimum_upstream_template_height(config, storage)?;
    let mut failures = Vec::new();
    let mut selected: Option<(u64, String, Hash256, serde_json::Value)> = None;
    for endpoint in &config.rpc.mining_upstreams {
        let now = unix_now();
        let identity_valid = validated_mining_upstreams()
            .lock()
            .expect("validated mining upstream mutex poisoned")
            .get(endpoint)
            .is_some_and(|expires_at| *expires_at > now);
        let validation = if identity_valid {
            Ok(())
        } else {
            validate_mining_upstream(config, endpoint, genesis).map(|_| {
                validated_mining_upstreams()
                    .lock()
                    .expect("validated mining upstream mutex poisoned")
                    .insert(
                        endpoint.clone(),
                        now.saturating_add(MINING_UPSTREAM_TEMPLATE_TTL_SECONDS),
                    );
            })
        };
        match validation
            .and_then(|_| rpc_call_upstream(endpoint, "blq_getBlockTemplate", params.clone()))
        {
            Ok(template) => {
                let height = template
                    .get("height")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("upstream template missing height"))?;
                if height < minimum_height {
                    failures.push(format!(
                        "{endpoint}: stale template height {height}, require at least {minimum_height}"
                    ));
                    continue;
                }
                let parent = template
                    .get("parentHash")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("upstream template missing parent hash"))
                    .and_then(|value| {
                        Hash256::from_hex(value)
                            .map_err(|err| anyhow::anyhow!("invalid upstream parent hash: {err:?}"))
                    })?;
                if selected
                    .as_ref()
                    .is_none_or(|(selected_height, _, _, _)| height > *selected_height)
                {
                    selected = Some((height, endpoint.clone(), parent, template));
                }
            }
            Err(err) => {
                validated_mining_upstreams()
                    .lock()
                    .expect("validated mining upstream mutex poisoned")
                    .remove(endpoint);
                failures.push(format!("{endpoint}: {err}"));
            }
        }
    }
    if let Some((_, endpoint, parent, mut template)) = selected {
        upstream_template_sources()
            .lock()
            .expect("upstream template mutex poisoned")
            .insert(
                parent,
                MiningUpstreamTemplate {
                    endpoint: endpoint.clone(),
                    updated_at: unix_now(),
                },
            );
        if let Some(object) = template.as_object_mut() {
            object.insert("templateSource".to_string(), serde_json::json!("upstream"));
            object.insert("miningUpstream".to_string(), serde_json::json!(endpoint));
        }
        return Ok(template);
    }
    anyhow::bail!(
        "no compatible mining upstream is available at height {minimum_height}: {}",
        failures.join("; ")
    )
}

fn proxy_mined_block(
    block: &Block,
    parsed: &serde_json::Value,
) -> Result<Option<serde_json::Value>> {
    let source = upstream_template_sources()
        .lock()
        .expect("upstream template mutex poisoned")
        .get(&block.header.parent_hash)
        .cloned();
    let Some(source) = source else {
        return Ok(None);
    };
    if unix_now().saturating_sub(source.updated_at) > MINING_UPSTREAM_TEMPLATE_TTL_SECONDS {
        upstream_template_sources()
            .lock()
            .expect("upstream template mutex poisoned")
            .remove(&block.header.parent_hash);
        return Ok(None);
    }
    let params = parsed
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    rpc_call_upstream(&source.endpoint, "blq_submitBlock", params).map(Some)
}

fn is_upstream_read_method(method: &str) -> bool {
    matches!(
        method,
        "blq_supply"
            | "eth_blockNumber"
            | "eth_getBalance"
            | "eth_getBlockByNumber"
            | "eth_getBlockByHash"
            | "eth_getBlockTransactionCountByNumber"
            | "eth_getBlockTransactionCountByHash"
            | "eth_getTransactionByBlockNumberAndIndex"
            | "eth_getTransactionByBlockHashAndIndex"
            | "eth_getBlockReceipts"
            | "eth_getTransactionCount"
            | "eth_getTransactionByHash"
            | "eth_getTransactionReceipt"
            | "eth_getCode"
            | "eth_getStorageAt"
            | "eth_estimateGas"
            | "eth_call"
            | "eth_getLogs"
            | "eth_feeHistory"
    )
}

fn proxy_read_rpc(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    method: &str,
    parsed: &serde_json::Value,
) -> Result<serde_json::Value> {
    let genesis = {
        let guard = storage.lock().expect("storage mutex poisoned");
        configured_genesis_hash(&guard).unwrap_or_else(|_| genesis_header().hash())
    };
    let params = parsed
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let mut failures = Vec::new();
    for endpoint in &config.rpc.mining_upstreams {
        match validate_mining_upstream(config, endpoint, genesis)
            .and_then(|_| rpc_call_upstream(endpoint, method, params.clone()))
        {
            Ok(result) => return Ok(result),
            Err(err) => failures.push(format!("{endpoint}: {err}")),
        }
    }
    anyhow::bail!(
        "no compatible read RPC upstream is available: {}",
        failures.join("; ")
    )
}

fn rpc_block_template(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    parsed: &serde_json::Value,
) -> String {
    // A node that has verified a stronger remote branch must not keep its
    // miners extending the known-stale local tip. It serves compatible work
    // from a synchronized peer until local fork choice catches up.
    if mining_upstream_required(config, storage) {
        return match proxy_mining_template(config, storage, parsed) {
            Ok(template) => rpc_result(id, template),
            Err(err) => rpc_error(
                id,
                -32002,
                &format!("mining upstream unavailable; retrying: {err}"),
            ),
        };
    }
    let beneficiary = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| parse_beneficiary(value).ok())
        .unwrap_or(Hash256::ZERO);
    let locked_storage = storage.lock().expect("storage mutex poisoned");
    let parent = match locked_storage.best_header() {
        Ok(header) => header,
        Err(err) => {
            let msg = if err.to_string().contains("was not found") {
                format_sync_paused_message(storage, "template paused")
            } else {
                err.to_string()
            };
            return rpc_error(id, -32000, &msg);
        }
    };
    if let Some(cached) = LOCAL_TEMPLATE_CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("local template cache mutex poisoned")
        .as_ref()
        .filter(|cached| {
            cached.parent_hash == parent.hash()
                && cached.beneficiary == beneficiary
                && cached.created_at.elapsed() < LOCAL_TEMPLATE_CACHE_TTL
        })
        .cloned()
    {
        return rpc_result(id, cached.payload);
    }
    let (mining_safe, available_peers, matching_peers) = trusted_peer_quorum(
        config,
        &parent,
        configured_genesis_hash(&locked_storage).unwrap_or_else(|_| genesis_header().hash()),
    );
    if !mining_safe {
        return rpc_error(
            id,
            -32001,
            &format!(
                "mining is unsafe: competing peer tip detected ({matching_peers} matching of {available_peers} available)"
            ),
        );
    }
    let template_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_else(|_| parent.timestamp_seconds.saturating_add(1))
        .max(parent.timestamp_seconds.saturating_add(1));
    let mut template = blq_miner::build_empty_template_with_genesis(
        &parent,
        beneficiary,
        // Use wall-clock time only when proposing work. Consensus validates
        // the timestamp carried by the submitted block deterministically.
        template_timestamp,
        configured_genesis_hash(&locked_storage).unwrap_or_else(|_| genesis_header().hash()),
    );
    match expected_difficulty_target(
        &locked_storage,
        &parent,
        &template.header,
        config.node.block_time_v2_activation_height,
    ) {
        Ok(target) => {
            template.header.difficulty_target = target;
            template.target = target;
        }
        Err(err) => {
            let msg = if err.to_string().contains("was not found") {
                format_sync_paused_message(storage, "template paused")
            } else {
                err.to_string()
            };
            return rpc_error(id, -32000, &msg);
        }
    }
    let transactions = {
        let mut mempool = mempool.lock().expect("mempool mutex poisoned");
        mempool.remove_expired(unix_now(), MEMPOOL_TRANSACTION_EXPIRY_SECONDS);
        mempool.remove_stale_nonces(|address| locked_storage.nonce(address).unwrap_or(0));
        mempool.drain_for_block(template.header.gas_limit)
    };
    let native_only = transactions
        .iter()
        .all(|transaction| !is_evm_transaction(transaction));
    let (generation_id, genesis_hash) = (
        locked_storage
            .generation_status()
            .ok()
            .and_then(|generation| generation.get("activeId").cloned())
            .unwrap_or(serde_json::Value::Null),
        configured_genesis_hash(&locked_storage).unwrap_or_else(|_| genesis_header().hash()),
    );
    let block_result = if native_only {
        let accounts = locked_storage.account_snapshot();
        drop(locked_storage);
        accounts.and_then(|accounts| {
            let block = build_stateful_block_from_accounts(
                &accounts,
                template.clone().into_unsealed_block(),
                transactions,
                parent.timestamp_seconds,
            )?;
            if block.canonical_bytes().len() > MAX_BLOCK_BYTES {
                anyhow::bail!("block template cannot fit within the 2 MiB consensus limit");
            }
            Ok(block)
        })
    } else {
        build_bounded_stateful_block(
            &locked_storage,
            template.clone().into_unsealed_block(),
            transactions,
        )
    };
    let block = match block_result {
        Ok(block) => block,
        Err(err) => {
            let msg = if err.to_string().contains("was not found") {
                format_sync_paused_message(storage, "template paused")
            } else {
                err.to_string()
            };
            return rpc_error(id, -32000, &msg);
        }
    };
    template.header = block.header.clone();
    template.transactions = block.transactions.clone();
    let payload = serde_json::json!({
        "templateMode": "stateful",
        "generationId": generation_id,
        "pendingTransactionsIncluded": template.transactions.len(),
        "height": template.header.number.0,
        "parentHash": template.header.parent_hash.to_hex(),
        "templateGeneration": template.header.number.0,
        "target": template.target.to_hex(),
        "powAlgorithm": template.pow_algorithm,
        "powEpoch": template.pow_epoch,
        "epochSeed": template.epoch_seed.to_hex(),
        "genesisHash": genesis_hash.to_hex(),
        "templateTimestamp": template.header.timestamp_seconds,
        "beneficiaryAddress": template.header.beneficiary_address().to_hex(),
        "beneficiaryWord": template.header.beneficiary.to_hex(),
        "block": block,
    });
    LOCAL_TEMPLATE_CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("local template cache mutex poisoned")
        .replace(LocalTemplateCache {
            parent_hash: parent.hash(),
            beneficiary,
            created_at: Instant::now(),
            payload: payload.clone(),
        });
    rpc_result(id, payload)
}

fn build_bounded_stateful_block(
    storage: &NodeStorage,
    template: Block,
    mut transactions: Vec<Transaction>,
) -> Result<Block> {
    loop {
        let block = build_stateful_block(storage, template.clone(), transactions.clone())?;
        if block.canonical_bytes().len() <= MAX_BLOCK_BYTES {
            return Ok(block);
        }
        if transactions.pop().is_none() {
            anyhow::bail!("block template cannot fit within the 2 MiB consensus limit");
        }
    }
}

fn rpc_pending_transactions(id: serde_json::Value, mempool: &Arc<Mutex<Mempool>>) -> String {
    const MAX_PENDING_TRANSACTIONS: usize = 256;
    const MAX_PENDING_RESPONSE_BYTES: usize = 256 * 1024;
    let now = unix_now();
    let pending = {
        let mut mempool = mempool.lock().expect("mempool mutex poisoned");
        mempool.remove_expired(now, MEMPOOL_TRANSACTION_EXPIRY_SECONDS);
        mempool.pending_with_age(now)
    };
    let mut items = Vec::new();
    for (transaction, age_seconds) in pending.into_iter().take(MAX_PENDING_TRANSACTIONS) {
        items.push(serde_json::json!({
            "hash": format!("0x{}", transaction.rpc_hash().to_hex()),
            "sender": transaction.from.to_hex(),
            "recipient": transaction.to.map(|address| address.to_hex()),
            "value": format!("0x{:x}", transaction.value.0),
            "maxFeePerGas": format!("0x{:x}", transaction.max_fee_per_gas.0),
            "maxPriorityFeePerGas": format!("0x{:x}", transaction.max_priority_fee_per_gas.0),
            "gasLimit": format!("0x{:x}", transaction.gas_limit),
            "nonce": format!("0x{:x}", transaction.nonce),
            "ageSeconds": age_seconds,
        }));
    }
    while serde_json::to_vec(&items)
        .map(|body| body.len() > MAX_PENDING_RESPONSE_BYTES)
        .unwrap_or(true)
    {
        if items.pop().is_none() {
            break;
        }
    }
    rpc_result(id, serde_json::Value::Array(items))
}

fn rpc_submit_block(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    parsed: &serde_json::Value,
) -> String {
    // See rpc_block_template: sync and candidate replay do not make a valid
    // local PoW tip unusable. Fork choice resolves concurrent work by total
    // cumulative work after all candidate bodies validate.
    if config.node.mode != NodeMode::Full {
        return rpc_error(id, -32000, "only full nodes accept blocks");
    }
    let Some(block_value) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
    else {
        return rpc_error(id, -32602, "missing block parameter");
    };
    let block: Block = match serde_json::from_value(block_value.clone()) {
        Ok(block) => block,
        Err(err) => return rpc_error(id, -32602, &format!("invalid block: {err}")),
    };
    if let Err(err) = validate_live_timestamp_admission(&block.header) {
        return rpc_error(id, -32000, &err.to_string());
    }
    if let Err(err) =
        validate_block_transaction_auth(config.node.require_signed_transactions, &block)
    {
        return rpc_error(id, -32000, &err.to_string());
    }
    match proxy_mined_block(&block, parsed) {
        Ok(Some(mut result)) => {
            if let Some(object) = result.as_object_mut() {
                object.insert("templateSource".to_string(), serde_json::json!("upstream"));
            }
            return rpc_result(id, result);
        }
        Ok(None) => {}
        Err(err) => {
            return rpc_error(
                id,
                -32002,
                &format!("mining upstream submission failed; retrying: {err}"),
            )
        }
    }
    let hash = block.header.hash().to_hex();
    let number = block.header.number.0;
    let accepted_block = block.clone();
    let included_hashes = block
        .transactions
        .iter()
        .map(Transaction::hash)
        .collect::<Vec<_>>();
    let storage_arc = Arc::clone(storage);
    {
        let mut storage = storage.lock().expect("storage mutex poisoned");
        let parent = match storage.best_header() {
            Ok(header) => header,
            Err(err) => {
                let msg = if err.to_string().contains("was not found") {
                    format_sync_paused_message(&storage_arc, "submission paused")
                } else {
                    err.to_string()
                };
                return rpc_error(id, -32000, &msg);
            }
        };
        if storage.header_by_hash(block.header.hash()).is_ok() {
            return rpc_result(
                id,
                serde_json::json!({
                    "accepted": true,
                    "duplicate": true,
                    "canonical": block.header.hash() == parent.hash(),
                    "number": block.header.number.0,
                    "hash": hash,
                    "currentNumber": parent.number.0,
                    "currentHash": parent.hash().to_hex(),
                }),
            );
        }
        if block.header.parent_hash != parent.hash() || block.header.number.0 != parent.number.0 + 1
        {
            let replacement = match queue_competing_block_pending(
                &mut storage,
                &block,
                config.node.require_signed_transactions,
            ) {
                Ok(replacement) => replacement,
                Err(err) => return rpc_error(id, -32000, &err.to_string()),
            };
            if let Err(err) = drain_orphan_blocks(config, &mut storage) {
                return rpc_error(id, -32000, &err.to_string());
            }
            let pending = replacement.is_some();
            drop(storage);
            if let Some(replacement) = replacement {
                if let Err(err) = stage_and_publish_candidate(config, &storage_arc, replacement) {
                    return rpc_error(id, -32000, &err.to_string());
                }
            }
            let genesis_hash = {
                let storage = storage_arc.lock().expect("storage mutex poisoned");
                configured_genesis_hash(&storage).unwrap_or_else(|_| genesis_header().hash())
            };
            enqueue_block_gossip(config, genesis_hash, &block, None);
            let storage = storage_arc.lock().expect("storage mutex poisoned");
            let current = match storage.best_header() {
                Ok(header) => header,
                Err(err) => {
                    let msg = if err.to_string().contains("was not found") {
                        "node is re-synchronizing canonical chain; submission paused".to_string()
                    } else {
                        err.to_string()
                    };
                    return rpc_error(id, -32000, &msg);
                }
            };
            let canonical = current.hash() == block.header.hash();
            let stale = !canonical && current.number.0 >= number;
            return rpc_result(
                id,
                serde_json::json!({
                    "accepted": true,
                    "canonical": canonical,
                    "pending": pending && !stale,
                    "stale": stale,
                    "number": block.header.number.0,
                    "hash": hash,
                    "currentNumber": current.number.0,
                    "currentHash": current.hash().to_hex(),
                }),
            );
        }
        if let Err(err) = validate_block_for_storage(config, &storage, &parent, &block) {
            return rpc_error(id, -32000, &err.to_string());
        }
        if let Err(err) = validate_difficulty_target(
            &storage,
            &parent,
            &block.header,
            config.node.block_time_v2_activation_height,
        ) {
            return rpc_error(id, -32000, &err.to_string());
        }
        if let Err(err) = validate_state_root(&storage, &block) {
            return rpc_error(id, -32000, &err.to_string());
        }
        if let Err(err) = ensure_storage_cap(config, &storage) {
            return rpc_error(id, -32000, &err.to_string());
        }
        if let Err(err) = storage.insert_block(block) {
            return rpc_error(id, -32000, &err.to_string());
        }
        invalidate_local_template_cache();
    }
    mempool
        .lock()
        .expect("mempool mutex poisoned")
        .remove_included(&included_hashes);
    schedule_canonical_maintenance(config, &storage_arc);
    let genesis_hash = {
        let storage = storage_arc.lock().expect("storage mutex poisoned");
        configured_genesis_hash(&storage).unwrap_or_else(|_| genesis_header().hash())
    };
    enqueue_block_gossip(config, genesis_hash, &accepted_block, None);
    rpc_result(
        id,
        serde_json::json!({
            "accepted": true,
            "number": number,
            "hash": hash,
            "activeHeight": number,
            "activeHash": hash,
            "candidateHeight": serde_json::Value::Null,
            "candidateHash": serde_json::Value::Null,
            "stale": false,
            "duplicate": false,
            "canonical": true,
        }),
    )
}

fn format_bix(bix: Bix) -> String {
    const BIX_PER_BLQ: u128 = blq_primitives::BIX_PER_BLQ;
    let whole = bix.0 / BIX_PER_BLQ;
    let fractional = (bix.0 % BIX_PER_BLQ) / (BIX_PER_BLQ / 1000);
    format!("{whole}.{fractional:03}")
}

fn rpc_supply(id: serde_json::Value, storage: &Arc<Mutex<NodeStorage>>) -> String {
    let mut storage_guard = storage.lock().expect("storage mutex poisoned");
    if let NodeStorage::Full(storage) = &mut *storage_guard {
        if let Err(err) = backfill_supply_storage(storage) {
            return rpc_error(id, -32000, &err.to_string());
        }
    }
    let best = match storage_guard.best_header() {
        Ok(header) => header,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let (indexed_to, total, burned) = match &*storage_guard {
        NodeStorage::Full(storage) => match storage.supply_totals() {
            Ok(value) => value,
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
        NodeStorage::Partial(_) => {
            return rpc_error(id, -32000, "supply is unavailable on partial storage")
        }
    };
    let circulating = total.saturating_sub(burned);
    rpc_result(
        id,
        serde_json::json!({
            "indexedTo": indexed_to,
            "bestBlock": best.number.0,
            "totalSupply": format_bix(Bix(total)),
            "circulatingSupply": format_bix(Bix(circulating)),
            "totalBurned": format_bix(Bix(burned)),
        }),
    )
}

fn rpc_status(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
) -> String {
    // Status is an operational endpoint. It must not queue behind a long
    // validation/replay batch and make a recovering node look dead.
    let cursor = branch_sync_cursors().lock().ok().and_then(|cursors| {
        cursors
            .values()
            .max_by_key(|cursor| cursor.updated_at)
            .cloned()
    });
    let progress = sync_progress()
        .lock()
        .expect("sync progress mutex poisoned")
        .clone();
    let Ok(storage_guard) = storage.try_lock() else {
        return rpc_result(
            id,
            serde_json::json!({
                "storageBusy": true,
                "activeTip": serde_json::Value::Null,
                "currentHeight": progress.current_height,
                "targetHeight": cursor.as_ref().map(|cursor| cursor.tip_height).unwrap_or(progress.network_height),
                "recoveryState": cursor.as_ref().map(|cursor| cursor.state.clone()).unwrap_or_else(|| "idle".to_string()),
                "recoveryProvider": cursor.as_ref().and_then(|cursor| cursor.provider.clone()),
                "requestedBlock": cursor.as_ref().and_then(|cursor| cursor.requested_height),
                "lastProgressAt": cursor.as_ref().map(|cursor| cursor.last_progress_at).filter(|value| *value > 0),
                "recoveryFailure": cursor.as_ref().and_then(|cursor| cursor.last_failure.clone()),
                "p2p": p2p_session_status(),
            }),
        );
    };
    let generation = match storage_guard.generation_status() {
        Ok(value) => value,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let best = match storage_guard.best_header() {
        Ok(header) => header,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let candidate = storage_guard
        .latest_candidate_tip()
        .ok()
        .flatten()
        .map(|(header, work)| {
            serde_json::json!({
                "height": header.number.0,
                "hash": header.hash().to_hex(),
                "work": work.to_string(),
            })
        });
    let upstream_required = mining_upstream_required(config, storage);
    rpc_result(
        id,
        serde_json::json!({
            "generationId": generation["activeId"].clone(),
            "activeTip": {
                "height": best.number.0,
                "hash": best.hash().to_hex(),
                "stateRoot": best.state_root.to_hex(),
            },
            "candidateTip": candidate.as_ref().map(|candidate| candidate.clone()).unwrap_or(serde_json::Value::Null),
            "candidateWork": candidate.as_ref().and_then(|candidate| candidate.get("work")).cloned().unwrap_or(serde_json::Value::Null),
            "branchImportedBodies": cursor.as_ref().map(|cursor| cursor.imported_bodies).unwrap_or(0),
            "cursorNextHash": cursor.as_ref().map(|cursor| cursor.next_hash.to_hex()),
            "cursorTipHeight": cursor.as_ref().map(|cursor| cursor.tip_height),
            "cursorTipHash": cursor.as_ref().map(|cursor| cursor.tip_hash.to_hex()),
            "recoveryAncestorHeight": cursor.as_ref().and_then(|cursor| cursor.ancestor_height),
            "stagedHeight": cursor.as_ref().map(|cursor| cursor.staged_height).unwrap_or(best.number.0),
            "targetHeight": cursor.as_ref().map(|cursor| cursor.tip_height).unwrap_or(best.number.0),
            "recoveryState": cursor.as_ref().map(|cursor| cursor.state.clone()).unwrap_or_else(|| "idle".to_string()),
            "recoveryProvider": cursor.as_ref().and_then(|cursor| cursor.provider.clone()),
            "providerMode": cursor.as_ref().map(|cursor| cursor.provider_mode.clone()).unwrap_or_else(|| "single-provider".to_string()),
            "primaryProviderIdentity": cursor.as_ref().and_then(|cursor| cursor.primary_identity.clone()),
            "witnessIdentity": cursor.as_ref().and_then(|cursor| cursor.witness_identity.clone()),
            "witnessSampleHeights": cursor.as_ref().map(|cursor| cursor.witness_sample_heights.clone()).unwrap_or_default(),
            "witnessMismatch": cursor.as_ref().and_then(|cursor| cursor.witness_mismatch.clone()),
            "requestedBlock": cursor.as_ref().and_then(|cursor| cursor.requested_height),
            "requestedAt": cursor.as_ref().map(|cursor| cursor.requested_at).filter(|value| *value > 0),
            "lastProgressAt": cursor.as_ref().map(|cursor| cursor.last_progress_at).filter(|value| *value > 0),
            "providerAttempts": cursor.as_ref().map(|cursor| cursor.provider_attempts).unwrap_or(0),
            "retryAfter": cursor.as_ref().map(|cursor| cursor.retry_after).filter(|value| *value > 0),
            "recoveryFailure": cursor.as_ref().and_then(|cursor| cursor.last_failure.clone()),
            "recoveryProgress": cursor.as_ref().map(|cursor| serde_json::json!({
                "completed": cursor.staged_height.saturating_sub(cursor.ancestor_height.unwrap_or(cursor.staged_height)),
                "total": cursor.tip_height.saturating_sub(cursor.ancestor_height.unwrap_or(cursor.tip_height)),
            })).unwrap_or(serde_json::Value::Null),
            "upstreamRequired": upstream_required,
            "miningMode": if upstream_required { "upstream" } else { "local" },
            "replayProgress": generation["replayCheckpoint"].clone(),
            "replayStatus": generation["status"].clone(),
            "publicationPending": generation["publicationPending"].clone(),
            "miningSafety": {
                "safe": !config.rpc.public_read_only,
                "reason": if config.rpc.public_read_only {
                    "read-only profile"
                } else if upstream_required {
                    "local branch retrieval is active; templates are sourced from a verified upstream"
                } else {
                    "ok"
                },
            },
            "p2p": p2p_session_status(),
        }),
    )
}

fn rpc_node_info(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
) -> String {
    // `blq_nodeInfo` must remain truthful when recovery or block import holds
    // the storage mutex. Native configs pin the chain identity, so use that
    // configured value only as the nonblocking fallback.
    let configured_genesis_hash = config
        .node
        .expected_genesis_hash
        .as_deref()
        .and_then(|value| Hash256::from_hex(value).ok())
        .unwrap_or_else(|| genesis_header().hash());
    let configured_genesis_hex = configured_genesis_hash.to_hex();
    let (hashrate, active_miners, hashrate_updated_at, hashrate_status) = hashrate_snapshot();
    let (current_height, network_height) = sync_progress_info(storage);
    let (last_canonical_block_at, block_age_seconds, liveness) = canonical_liveness(storage);
    let progress = sync_progress()
        .lock()
        .expect("sync progress mutex poisoned")
        .clone();
    let remaining = network_height.saturating_sub(current_height);
    let peer_count = peer_agreement().lock().map(|g| g.tips.len()).unwrap_or(0);
    let explorer_provider_count = DISCOVERED_PEER_ROUTES
        .get()
        .and_then(|routes| {
            routes
                .lock()
                .ok()
                .map(|routes| routes.values().filter(|peer| peer.explorer_share).count())
        })
        .unwrap_or(0);
    let stale_peer_targets = peer_agreement()
        .lock()
        .map(|g| {
            g.tips
                .iter()
                .filter(|(_, tip)| {
                    !tip.body_verified
                        || unix_now().saturating_sub(tip.last_seen) > PEER_TIP_TTL_SECONDS
                })
                .map(|(peer, tip)| {
                    serde_json::json!({
                        "peer": peer,
                        "height": tip.best_number,
                        "hash": tip.best_hash,
                        "state": if tip.body_verified { "expired" } else { "body-unavailable" },
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let (genesis_hash, candidate) = storage
        .try_lock()
        .ok()
        .map(|guard| {
            let genesis_hash = guard
                .header_by_number(blq_primitives::BlockNumber(0))
                .map(|header| header.hash().to_hex())
                .unwrap_or_else(|_| configured_genesis_hex.clone());
            let candidate = guard
                .latest_candidate_tip()
                .ok()
                .flatten()
                .map(|(header, work)| {
                    serde_json::json!({
                        "height": header.number.0,
                        "hash": header.hash().to_hex(),
                        "work": work.to_string(),
                    })
                });
            (genesis_hash, candidate)
        })
        .unwrap_or_else(|| (configured_genesis_hex, None));

    let is_reorg = REORG_IN_PROGRESS.load(std::sync::atomic::Ordering::SeqCst);
    let mining_configured = config.node.mining_enabled
        && (!config.rpc.public_read_only || config.rpc.mining_api_enabled);
    let upstream_mode = mining_upstream_required_for_status(config, storage);
    let cursor = branch_sync_cursors().lock().ok().and_then(|cursors| {
        cursors
            .values()
            .max_by_key(|cursor| cursor.updated_at)
            .cloned()
    });
    let is_syncing = remaining > 1;
    let is_mining = active_miners > 0;
    // Stale peer advertisements are diagnostic-only once the local canonical
    // tip is current. Report a provider wait only for a live, unfinished
    // recovery cursor; otherwise a healthy synced node would contradict
    // itself with `status=synced` and `syncState=waiting-for-provider`.
    let waiting_for_provider =
        !is_reorg && !is_syncing && cursor_waiting_for_provider(cursor.as_ref(), current_height);

    // An intentionally idle, synchronized node is not stalled merely because
    // no miner has produced a block. Keep wall-clock liveness available as a
    // separate telemetry field, but do not turn it into a release failure.
    let production_stalled = liveness == "stalled" && (mining_configured || upstream_mode);
    let status_str = if is_reorg {
        "resyncing"
    } else if is_syncing {
        "syncing"
    } else if upstream_mode {
        "mining"
    } else if is_mining {
        "mining"
    } else if production_stalled {
        "stalled"
    } else {
        "synced"
    };

    let sync_state = if waiting_for_provider {
        "waiting-for-provider"
    } else if is_syncing {
        "syncing"
    } else {
        "synced"
    };

    let activity_str = if is_reorg {
        format!(
            "Re-synchronizing canonical chain state at block {} / {} ({} blocks remaining)",
            current_height, network_height, remaining
        )
    } else if waiting_for_provider {
        format!(
            "Waiting for a provider to serve peer history; local tip remains usable at height {}",
            current_height
        )
    } else if is_syncing {
        format!(
            "Syncing with P2P network (block {} / {}, {} blocks remaining)",
            current_height, network_height, remaining
        )
    } else if upstream_mode {
        format!(
            "Mining through a synchronized upstream while local branch retrieval continues from height {}",
            current_height
        )
    } else if is_mining {
        format!(
            "{} active miner telemetry session(s) on template #{}",
            active_miners,
            current_height + 1
        )
    } else if production_stalled {
        format!(
            "No canonical block has been produced for {} seconds; template service is {}",
            block_age_seconds,
            if mining_configured {
                "ready"
            } else {
                "disabled"
            }
        )
    } else {
        format!("Fully synchronized & Idle at height {}", current_height)
    };

    rpc_result(
        id,
        serde_json::json!({
            "chainId": 707070,
            "genesisHash": genesis_hash,
            "consensusProfile": network_consensus_profile(
                config,
                Hash256::from_hex(&genesis_hash).unwrap_or(configured_genesis_hash)
            ),
            "blockSizeActivationHeight": config.node.block_size_activation_height,
            "blockTimeV2ActivationHeight": config.node.block_time_v2_activation_height,
            "blockTimeTargetSeconds": active_block_time_target_seconds(config, current_height),
            "rpcEndpoint": config.node.advertise_rpc.as_deref(),
            "websocketEndpoint": config.node.advertise_websocket.as_deref(),
            "p2pEndpoint": config.node.advertise_p2p.as_deref(),
            "nodeMode": config.node.mode.as_str(),
            "miningEnabled": mining_configured,
            "templateServing": mining_configured,
            "miningMode": if upstream_mode { "upstream" } else { "local" },
            "upstreamRequired": upstream_mode,
            "templateSource": if upstream_mode { "upstream" } else { "local" },
            "miningUpstream": if upstream_mode {
                config.rpc.mining_upstreams.first().cloned()
            } else {
                None
            },
            "currentHeight": current_height,
            "networkHeight": network_height,
            "networkHeightSource": if network_height > current_height { "verified-peer" } else { "local-tip" },
            "stalePeerTargets": stale_peer_targets,
            "syncState": sync_state,
            "lastImportedHeight": current_height,
            "branchImportedBodies": cursor.as_ref().map(|cursor| cursor.imported_bodies).unwrap_or(0),
            "cursorNextHash": cursor.as_ref().map(|cursor| cursor.next_hash.to_hex()),
            "cursorTipHeight": cursor.as_ref().map(|cursor| cursor.tip_height),
            "cursorTipHash": cursor.as_ref().map(|cursor| cursor.tip_hash.to_hex()),
            "recoveryAncestorHeight": cursor.as_ref().and_then(|cursor| cursor.ancestor_height),
            "stagedHeight": cursor.as_ref().map(|cursor| cursor.staged_height).unwrap_or(current_height),
            "targetHeight": cursor.as_ref().map(|cursor| cursor.tip_height).unwrap_or(current_height),
            "recoveryState": cursor.as_ref().map(|cursor| cursor.state.clone()).unwrap_or_else(|| "idle".to_string()),
            "recoveryProvider": cursor.as_ref().and_then(|cursor| cursor.provider.clone()),
            "providerMode": cursor.as_ref().map(|cursor| cursor.provider_mode.clone()).unwrap_or_else(|| "single-provider".to_string()),
            "primaryProviderIdentity": cursor.as_ref().and_then(|cursor| cursor.primary_identity.clone()),
            "witnessIdentity": cursor.as_ref().and_then(|cursor| cursor.witness_identity.clone()),
            "witnessSampleHeights": cursor.as_ref().map(|cursor| cursor.witness_sample_heights.clone()).unwrap_or_default(),
            "witnessMismatch": cursor.as_ref().and_then(|cursor| cursor.witness_mismatch.clone()),
            "requestedBlock": cursor.as_ref().and_then(|cursor| cursor.requested_height),
            "requestedAt": cursor.as_ref().map(|cursor| cursor.requested_at).filter(|value| *value > 0),
            "lastProgressAt": cursor.as_ref().map(|cursor| cursor.last_progress_at).filter(|value| *value > 0),
            "providerAttempts": cursor.as_ref().map(|cursor| cursor.provider_attempts).unwrap_or(0),
            "retryAfter": cursor.as_ref().map(|cursor| cursor.retry_after).filter(|value| *value > 0),
            "recoveryFailure": cursor.as_ref().and_then(|cursor| cursor.last_failure.clone()),
            "recoveryProgress": cursor.as_ref().map(|cursor| serde_json::json!({
                "completed": cursor.staged_height.saturating_sub(cursor.ancestor_height.unwrap_or(cursor.staged_height)),
                "total": cursor.tip_height.saturating_sub(cursor.ancestor_height.unwrap_or(cursor.tip_height)),
            })).unwrap_or(serde_json::Value::Null),
            "candidateTip": candidate.as_ref().map(|candidate| candidate.clone()).unwrap_or(serde_json::Value::Null),
            "candidateWork": candidate.as_ref().and_then(|candidate| candidate.get("work")).cloned().unwrap_or(serde_json::Value::Null),
            "syncRemainingBlocks": remaining,
            "peerCount": peer_count,
            "explorer": serde_json::json!({
                "indexEnabled": config.explorer.index_enabled(config.node.storage_mode),
                "sharingEnabled": config.explorer.share_enabled(config.node.storage_mode),
                "relayEnabled": config.explorer.relay,
                "providerCount": explorer_provider_count,
            }),
            "status": status_str,
            "activity": activity_str,
            "isSyncing": is_syncing,
            "isMining": is_mining,
            "lastCanonicalBlockAt": last_canonical_block_at,
            "blockAgeSeconds": block_age_seconds,
            "liveness": liveness,
            "hashrate": hashrate,
            "hashrateUnit": "H/s",
            "activeMinerCount": active_miners,
            "hashrateUpdatedAt": hashrate_updated_at,
            "hashrateStatus": hashrate_status,
            "verifiedNetworkHeight": progress.network_height.max(network_height),
            "activePeer": progress.active_peer,
            "commonAncestor": progress.common_ancestor,
            "nextRequestedHeight": cursor
                .as_ref()
                .filter(|cursor| cursor.ancestor_height.is_some())
                .map(|cursor| cursor.next_height)
                .unwrap_or_else(|| progress.next_requested_height.max(current_height.saturating_add(1))),
            "lastProgressAt": if progress.last_progress_at == 0 { serde_json::Value::Null } else { serde_json::json!(progress.last_progress_at) },
            "providerState": progress.provider_state,
            "p2p": p2p_session_status(),
            "transactionGossip": serde_json::json!({
                "received": TRANSACTION_GOSSIP_RECEIVED.load(Ordering::Relaxed),
                "relayed": TRANSACTION_GOSSIP_RELAYED.load(Ordering::Relaxed),
                "failures": TRANSACTION_GOSSIP_FAILURES.load(Ordering::Relaxed),
                "inventorySize": TRANSACTION_GOSSIP_INVENTORY
                    .get()
                    .and_then(|inventory| inventory.lock().ok().map(|entries| entries.len()))
                    .unwrap_or(0),
                "queueCapacity": MAX_TRANSACTION_GOSSIP_QUEUE,
            }),
        }),
    )
}

fn cursor_waiting_for_provider(cursor: Option<&BranchSyncCursor>, current_height: u64) -> bool {
    cursor.is_some_and(|cursor| {
        cursor.tip_height > current_height
            && matches!(
                cursor.state.as_str(),
                "pending-retrieval" | "retrieving" | "waiting-for-provider"
            )
    })
}

fn rpc_get_balance(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let historical_number = match resolve_state_block_tag(storage, parsed, 1) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let Some(address) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Address::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid address parameter");
    };
    let balance = match historical_number {
        Some(number) => match load_historical_evm_state(config, storage, number) {
            Ok(state) => match u128::try_from(
                state
                    .account(alloy_primitives::Address::from(address.0))
                    .balance,
            ) {
                Ok(balance) => Bix(balance),
                Err(_) => return rpc_error(id, -32000, "historical EVM balance exceeds BLQ range"),
            },
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
        None => match storage
            .lock()
            .expect("storage mutex poisoned")
            .balance(address)
        {
            Ok(balance) => balance,
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
    };
    rpc_result(id, serde_json::json!(format!("0x{:x}", balance.0)))
}

fn rpc_get_transaction_count(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let historical_number = match resolve_state_block_tag(storage, parsed, 1) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let Some(address) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Address::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid address parameter");
    };
    let nonce = match historical_number {
        Some(number) => match load_historical_evm_state(config, storage, number) {
            Ok(state) => {
                state
                    .account(alloy_primitives::Address::from(address.0))
                    .nonce
            }
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
        None => match storage
            .lock()
            .expect("storage mutex poisoned")
            .nonce(address)
        {
            Ok(nonce) => nonce,
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
    };
    rpc_result(id, serde_json::json!(format!("0x{:x}", nonce)))
}

fn resolve_state_block_tag(
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
    index: usize,
) -> Result<Option<u64>> {
    let tag = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.get(index))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("latest");
    let latest = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?
        .number
        .0;
    match tag {
        "latest" | "safe" | "finalized" | "pending" => Ok(None),
        "earliest" => Ok(Some(0)),
        _ => {
            let number = parse_hex_u64(tag)?;
            if number == latest {
                Ok(None)
            } else if number < latest {
                Ok(Some(number))
            } else {
                anyhow::bail!("requested EVM state block is ahead of the chain tip")
            }
        }
    }
}

const MAX_RPC_BODY_FETCH_PEERS: usize = 2;
const MAX_RPC_BODY_FETCH_MESSAGES: usize = 8;
const MAX_RPC_REMOTE_LOG_BLOCKS: usize = 64;
const MAX_HISTORICAL_EVM_REPLAY_BLOCKS: u64 = 4_096;
const EVM_STATE_SNAPSHOT_INTERVAL: u64 = 256;
// A generation replay checkpoint contains only executable state. It is
// intentionally much less frequent than the old 16-block full-archive
// snapshots, which embedded the complete Sled keyspace and grew without
// bound on archive nodes.
const EXECUTION_SNAPSHOT_INTERVAL: u64 = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RpcTransactionData {
    receipt: Receipt,
    header: BlockHeader,
    transaction_index: usize,
    transaction: Transaction,
}

fn load_rpc_block(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    number: u64,
) -> Result<Option<Block>> {
    {
        let storage = storage.lock().expect("storage mutex poisoned");
        match storage.block_by_number(number) {
            Ok(block) => return Ok(Some(block)),
            Err(blq_storage::StorageError::NotFound) => {}
            Err(err) => return Err(err.into()),
        }
    }

    let expected_hash = {
        let storage = storage.lock().expect("storage mutex poisoned");
        match storage.header_by_number(blq_primitives::BlockNumber(number)) {
            Ok(header) => header.hash(),
            Err(blq_storage::StorageError::NotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        }
    };
    for peer in historical_peers(config)
        .into_iter()
        .take(MAX_RPC_BODY_FETCH_PEERS)
    {
        match fetch_rpc_block_body(config, storage, &peer, number, expected_hash) {
            Ok(block) => return Ok(Some(block)),
            Err(err) => eprintln!("historical RPC body fetch from {peer} failed: {err}"),
        }
    }
    Ok(None)
}

fn fetch_rpc_block_body(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    peer: &str,
    number: u64,
    expected_hash: Hash256,
) -> Result<Block> {
    let (mut stream, peer_tls_certificate_hash) = connect_p2p_tls(peer)?;
    stream.sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    send_p2p_message(
        &mut stream,
        &hello_message(config, storage, &peer_tls_certificate_hash)?,
    )?;
    let mut reader = BufReader::new(P2pShutdownGuard::new_configured(stream)?);
    let mut line = String::new();
    if !read_p2p_line(&mut reader, &mut line)? {
        anyhow::bail!("P2P peer closed before hello");
    }
    let hello: P2pMessage = serde_json::from_str(line.trim())?;
    let expected_profile = {
        let storage = storage.lock().expect("storage mutex poisoned");
        network_consensus_profile(config, configured_genesis_hash(&storage)?)
    };
    match hello {
        P2pMessage::Hello {
            node_mode,
            best_number,
            best_hash,
            consensus_profile,
            identity_public_key,
            identity_signature,
            tls_certificate_hash,
        } => verify_p2p_identity_with_profile(
            node_mode,
            best_number,
            &best_hash,
            &consensus_profile,
            &identity_public_key,
            &identity_signature,
            &tls_certificate_hash,
            Some(&peer_tls_certificate_hash),
            (!config.network.trusted_peer_keys.is_empty())
                .then_some(config.network.trusted_peer_keys.as_slice()),
            &expected_profile,
        )?,
        _ => anyhow::bail!("P2P peer did not send hello first"),
    }
    send_p2p_message(
        reader.get_mut(),
        &P2pMessage::GetBlockByHash {
            hash: expected_hash.to_hex(),
        },
    )?;
    for _ in 0..MAX_RPC_BODY_FETCH_MESSAGES {
        line.clear();
        if !read_p2p_line(&mut reader, &mut line)? {
            break;
        }
        match serde_json::from_str(line.trim())? {
            P2pMessage::BlockBody { block }
                if block.header.number.0 == number && block.header.hash() == expected_hash =>
            {
                return Ok(block);
            }
            P2pMessage::BlockBody { .. } => anyhow::bail!("P2P peer returned an unexpected block"),
            P2pMessage::BlockNotFound { hash } if hash == expected_hash.to_hex() => {
                anyhow::bail!("block {} was not found", hash)
            }
            P2pMessage::Hello { .. } => anyhow::bail!("P2P peer sent duplicate hello"),
            _ => {}
        }
    }
    anyhow::bail!("P2P peer did not return the requested block body")
}

fn load_historical_evm_state(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    number: u64,
) -> Result<RevmState> {
    let snapshot = {
        let storage = storage.lock().expect("storage mutex poisoned");
        match &*storage {
            NodeStorage::Full(storage) => storage.evm_state_snapshot_at_or_before(number)?,
            NodeStorage::Partial(_) => {
                anyhow::bail!("historical EVM state is unavailable on partial storage")
            }
        }
    };
    let (start, mut state) = match snapshot {
        Some((height, snapshot)) => (height, revm_state_from_snapshot(&snapshot)),
        None if number <= MAX_HISTORICAL_EVM_REPLAY_BLOCKS => (0, RevmState::default()),
        None => anyhow::bail!(
            "historical EVM snapshot is unavailable beyond {} blocks",
            MAX_HISTORICAL_EVM_REPLAY_BLOCKS
        ),
    };
    for height in start.saturating_add(1)..=number {
        let block = load_rpc_block(config, storage, height)?
            .ok_or_else(|| anyhow::anyhow!("historical block body unavailable at {height}"))?;
        let parent_timestamp = if height == 0 {
            0
        } else {
            load_rpc_block(config, storage, height - 1)?
                .map(|parent| parent.header.timestamp_seconds)
                .unwrap_or(0)
        };
        if block.transactions.iter().any(is_evm_transaction) {
            state =
                simulate_evm_state_transition_from_state(state, &block, parent_timestamp)?.state;
        } else {
            let accounts = accounts_from_revm_state(&state)?;
            let (next_accounts, _, _) =
                simulate_state_transition_from_accounts(accounts, &block, parent_timestamp)?;
            apply_accounts_to_revm_state(&mut state, &next_accounts);
        }
    }
    Ok(state)
}

fn revm_state_from_snapshot(snapshot: &blq_storage::EvmStateSnapshot) -> RevmState {
    let mut state = RevmState::default();
    for (address, (balance, nonce, code, slots)) in snapshot {
        let storage = slots
            .iter()
            .map(|(slot, value)| {
                (
                    alloy_primitives::U256::from_be_bytes(slot.0),
                    alloy_primitives::U256::from_be_bytes(value.0),
                )
            })
            .collect();
        state.put_account(
            alloy_primitives::Address::from(address.0),
            RevmAccount {
                nonce: *nonce,
                balance: alloy_primitives::U256::from(balance.0),
                code: code.clone(),
                storage,
            },
        );
    }
    state
}

fn rpc_evm_state_at(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    historical_number: Option<u64>,
) -> Result<(BlockHeader, RevmState)> {
    match historical_number {
        Some(number) => {
            let header = storage
                .lock()
                .expect("storage mutex poisoned")
                .header_by_number(blq_primitives::BlockNumber(number))?;
            let state = load_historical_evm_state(config, storage, number)?;
            Ok((header, state))
        }
        None => {
            let storage = storage.lock().expect("storage mutex poisoned");
            Ok((storage.best_header()?, storage.evm_state()?))
        }
    }
}

fn accounts_from_revm_state(
    state: &RevmState,
) -> Result<std::collections::BTreeMap<Address, (Bix, u64)>> {
    state
        .accounts
        .iter()
        .map(|(address, account)| {
            let balance = u128::try_from(account.balance)
                .map_err(|_| anyhow::anyhow!("historical EVM balance exceeds BLQ range"))?;
            Ok((Address(address.into_array()), (Bix(balance), account.nonce)))
        })
        .collect()
}

fn apply_accounts_to_revm_state(
    state: &mut RevmState,
    accounts: &std::collections::BTreeMap<Address, (Bix, u64)>,
) {
    for (address, (balance, nonce)) in accounts {
        let mut account = state.account(alloy_primitives::Address::from(address.0));
        account.balance = alloy_primitives::U256::from(balance.0);
        account.nonce = *nonce;
        state.put_account(alloy_primitives::Address::from(address.0), account);
    }
}

fn load_rpc_transaction(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    hash: Hash256,
) -> Result<Option<RpcTransactionData>> {
    for peer in historical_peers(config)
        .into_iter()
        .take(MAX_RPC_BODY_FETCH_PEERS)
    {
        match fetch_rpc_transaction(config, storage, &peer, hash) {
            Ok(Some(data)) => return Ok(Some(data)),
            Ok(None) => {}
            Err(err) => eprintln!("historical RPC transaction fetch from {peer} failed: {err}"),
        }
    }
    Ok(None)
}

fn historical_peers(config: &NodeConfig) -> Vec<String> {
    let mut advertised = Vec::new();
    if config.node.historical_peer_fallback {
        if let Ok(discovered) = discover_peer_records(config) {
            advertised.extend(discovered);
        }
        if let Some(routes) = DISCOVERED_PEER_ROUTES.get() {
            advertised.extend(
                routes
                    .lock()
                    .expect("discovered peer routes poisoned")
                    .values()
                    .cloned(),
            );
        }
    }

    // An authenticated archive/share advertisement is preferred for an
    // historical lookup. Older compatible peers did not send the capability
    // fields, so an archive retained range remains a backwards-compatible
    // provider hint. Every response is still anchored to a local canonical
    // header or transaction hash before the caller accepts it.
    advertised.retain(|peer| {
        validate_peer_record(peer).is_ok()
            && peer_route_is_fresh(peer)
            && (peer.explorer_share
                || (peer.storage_mode == StorageMode::Archive && peer.retained_to_height > 0))
    });
    advertised.sort_by_key(|peer| {
        (
            !peer.explorer_share,
            route_priority(&peer.address),
            peer.address.clone(),
        )
    });

    let mut peers = advertised
        .into_iter()
        .flat_map(|peer| {
            std::iter::once(peer.address)
                .chain(peer.alternate_addresses.into_iter())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    peers.extend(config.network.bootstrap_peers.iter().cloned());
    if config.node.historical_peer_fallback {
        peers.extend(cached_peer_endpoints());
    }
    let mut seen = BTreeSet::new();
    peers.retain(|peer| seen.insert(peer.clone()));
    peers
}

fn load_rpc_transaction_for_rpc(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    hash: Hash256,
) -> Result<Option<RpcTransactionData>> {
    if config.node.mode == NodeMode::Full {
        Ok(None)
    } else {
        load_rpc_transaction(config, storage, hash)
    }
}

fn fetch_rpc_transaction(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    peer: &str,
    hash: Hash256,
) -> Result<Option<RpcTransactionData>> {
    let (mut stream, peer_tls_certificate_hash) = connect_p2p_tls(peer)?;
    stream.sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    send_p2p_message(
        &mut stream,
        &hello_message(config, storage, &peer_tls_certificate_hash)?,
    )?;
    let mut reader = BufReader::new(P2pShutdownGuard::new_configured(stream)?);
    let mut line = String::new();
    if !read_p2p_line(&mut reader, &mut line)? {
        anyhow::bail!("P2P peer closed before hello");
    }
    let hello: P2pMessage = serde_json::from_str(line.trim())?;
    let expected_profile = {
        let storage = storage.lock().expect("storage mutex poisoned");
        network_consensus_profile(config, configured_genesis_hash(&storage)?)
    };
    match hello {
        P2pMessage::Hello {
            node_mode,
            best_number,
            best_hash,
            consensus_profile,
            identity_public_key,
            identity_signature,
            tls_certificate_hash,
        } => verify_p2p_identity_with_profile(
            node_mode,
            best_number,
            &best_hash,
            &consensus_profile,
            &identity_public_key,
            &identity_signature,
            &tls_certificate_hash,
            Some(&peer_tls_certificate_hash),
            (!config.network.trusted_peer_keys.is_empty())
                .then_some(config.network.trusted_peer_keys.as_slice()),
            &expected_profile,
        )?,
        _ => anyhow::bail!("P2P peer did not send hello first"),
    }
    send_p2p_message(
        reader.get_mut(),
        &P2pMessage::GetTransaction {
            hash: hash.to_hex(),
        },
    )?;
    for _ in 0..MAX_RPC_BODY_FETCH_MESSAGES {
        line.clear();
        if !read_p2p_line(&mut reader, &mut line)? {
            break;
        }
        match serde_json::from_str(line.trim())? {
            P2pMessage::Transaction { data } => {
                let Some(data) = data else {
                    return Ok(None);
                };
                if data.transaction.rpc_hash() != hash && data.transaction.hash() != hash {
                    anyhow::bail!("P2P peer returned a different transaction");
                }
                if data.receipt.transaction_hash != hash
                    && data.receipt.transaction_hash != data.transaction.hash()
                {
                    anyhow::bail!("P2P peer returned a mismatched transaction receipt");
                }
                let expected_header = storage
                    .lock()
                    .expect("storage mutex poisoned")
                    .header_by_number(data.header.number);
                if let Ok(expected_header) = expected_header {
                    if expected_header.hash() != data.header.hash() {
                        anyhow::bail!("P2P peer returned a mismatched transaction block");
                    }
                }
                return Ok(Some(data));
            }
            P2pMessage::Hello { .. } => anyhow::bail!("P2P peer sent duplicate hello"),
            _ => {}
        }
    }
    anyhow::bail!("P2P peer did not return the requested transaction")
}

fn rpc_get_block_by_number(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(tag) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
    else {
        return rpc_error(id, -32602, "missing block number parameter");
    };
    let include_transactions = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.get(1))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let latest = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.number.0,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let number = match parse_block_tag(tag, latest) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32602, &err),
    };
    match load_rpc_block(config, storage, number) {
        Ok(Some(block)) => rpc_result(id, block_to_rpc_json(&block, include_transactions)),
        Ok(None) => rpc_result(id, serde_json::Value::Null),
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_get_block_by_hash(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(hash) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Hash256::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid block hash parameter");
    };
    let include_transactions = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.get(1))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let number = match storage
        .lock()
        .expect("storage mutex poisoned")
        .header_by_hash(hash)
    {
        Ok(header) => header,
        Err(blq_storage::StorageError::NotFound) => return rpc_result(id, serde_json::Value::Null),
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    }
    .number
    .0;
    match load_rpc_block(config, storage, number) {
        Ok(Some(block)) if block.header.hash() == hash => {
            rpc_result(id, block_to_rpc_json(&block, include_transactions))
        }
        Ok(Some(_)) | Ok(None) => rpc_result(id, serde_json::Value::Null),
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_get_block_transaction_count_by_number(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(tag) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
    else {
        return rpc_error(id, -32602, "missing block number parameter");
    };
    let latest = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.number.0,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let number = match parse_block_tag(tag, latest) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32602, &err),
    };
    match load_rpc_block(config, storage, number) {
        Ok(Some(block)) => rpc_result(
            id,
            serde_json::json!(format!("0x{:x}", block.transactions.len())),
        ),
        Ok(None) => rpc_result(id, serde_json::Value::Null),
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_get_block_transaction_count_by_hash(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(hash) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Hash256::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid block hash parameter");
    };
    let number = match storage
        .lock()
        .expect("storage mutex poisoned")
        .header_by_hash(hash)
    {
        Ok(header) => header,
        Err(blq_storage::StorageError::NotFound) => return rpc_result(id, serde_json::Value::Null),
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    }
    .number
    .0;
    match load_rpc_block(config, storage, number) {
        Ok(Some(block)) => rpc_result(
            id,
            serde_json::json!(format!("0x{:x}", block.transactions.len())),
        ),
        Ok(None) => rpc_result(id, serde_json::Value::Null),
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_get_transaction_by_block_number_and_index(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(params) = parsed.get("params").and_then(serde_json::Value::as_array) else {
        return rpc_error(id, -32602, "missing transaction lookup parameters");
    };
    let Some(tag) = params.first().and_then(serde_json::Value::as_str) else {
        return rpc_error(id, -32602, "missing block number parameter");
    };
    let Some(index) = params.get(1).and_then(serde_json::Value::as_str) else {
        return rpc_error(id, -32602, "missing transaction index parameter");
    };
    let latest = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.number.0,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let number = match parse_block_tag(tag, latest) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32602, &err),
    };
    let index = match parse_hex_u64(index) {
        Ok(index) => index,
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    rpc_transaction_at_block_index(id, config, storage, number, index)
}

fn rpc_get_transaction_by_block_hash_and_index(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(params) = parsed.get("params").and_then(serde_json::Value::as_array) else {
        return rpc_error(id, -32602, "missing transaction lookup parameters");
    };
    let Some(hash) = params
        .first()
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Hash256::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid block hash parameter");
    };
    let Some(index) = params.get(1).and_then(serde_json::Value::as_str) else {
        return rpc_error(id, -32602, "missing transaction index parameter");
    };
    let index = match parse_hex_u64(index) {
        Ok(index) => index,
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    let number = match storage
        .lock()
        .expect("storage mutex poisoned")
        .header_by_hash(hash)
    {
        Ok(header) => header.number.0,
        Err(blq_storage::StorageError::NotFound) => return rpc_result(id, serde_json::Value::Null),
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    rpc_transaction_at_block_index_with_hash(id, config, storage, number, index, hash)
}

fn rpc_transaction_at_block_index(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    number: u64,
    index: u64,
) -> String {
    rpc_transaction_at_block_index_with_hash(id, config, storage, number, index, Hash256::ZERO)
}

fn rpc_transaction_at_block_index_with_hash(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    number: u64,
    index: u64,
    expected_hash: Hash256,
) -> String {
    let block = match load_rpc_block(config, storage, number) {
        Ok(Some(block))
            if expected_hash == Hash256::ZERO || block.header.hash() == expected_hash =>
        {
            block
        }
        Ok(Some(_)) => return rpc_result(id, serde_json::Value::Null),
        Ok(None) => return rpc_result(id, serde_json::Value::Null),
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let Some(transaction) = block.transactions.get(index as usize) else {
        return rpc_result(id, serde_json::Value::Null);
    };
    let mut transaction_value = transaction_to_rpc_json(transaction);
    if let Some(object) = transaction_value.as_object_mut() {
        object.insert(
            "blockHash".to_string(),
            serde_json::json!(format!("0x{}", block.header.hash().to_hex())),
        );
        object.insert(
            "blockNumber".to_string(),
            serde_json::json!(format!("0x{:x}", block.header.number.0)),
        );
        object.insert(
            "transactionIndex".to_string(),
            serde_json::json!(format!("0x{:x}", index)),
        );
    }
    rpc_result(id, transaction_value)
}

fn rpc_get_block_receipts(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(tag) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
    else {
        return rpc_error(id, -32602, "missing block parameter");
    };
    let latest = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.number.0,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let (number, expected_hash) = if tag.len() == 66 {
        let hash = match Hash256::from_hex(tag) {
            Ok(hash) => hash,
            Err(err) => return rpc_error(id, -32602, &format!("invalid block hash: {err:?}")),
        };
        let number = match storage
            .lock()
            .expect("storage mutex poisoned")
            .header_by_hash(hash)
        {
            Ok(header) => header.number.0,
            Err(blq_storage::StorageError::NotFound) => {
                return rpc_result(id, serde_json::Value::Null)
            }
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        };
        (number, hash)
    } else {
        let number = match parse_block_tag(tag, latest) {
            Ok(number) => number,
            Err(err) => return rpc_error(id, -32602, &err),
        };
        (number, Hash256::ZERO)
    };
    let block = match load_rpc_block(config, storage, number) {
        Ok(Some(block))
            if expected_hash == Hash256::ZERO || block.header.hash() == expected_hash =>
        {
            block
        }
        Ok(Some(_)) | Ok(None) => return rpc_result(id, serde_json::Value::Null),
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let mut cumulative_gas_used = 0u64;
    let receipts = block
        .transactions
        .iter()
        .zip(block.receipts.iter())
        .enumerate()
        .map(|(index, (transaction, receipt))| {
            cumulative_gas_used = cumulative_gas_used.saturating_add(receipt.gas_used);
            receipt_to_rpc_json(
                receipt,
                &block.header,
                index,
                transaction,
                cumulative_gas_used,
            )
        })
        .collect::<Vec<_>>();
    rpc_result(id, serde_json::Value::Array(receipts))
}

fn rpc_fee_history(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(params) = parsed.get("params").and_then(serde_json::Value::as_array) else {
        return rpc_error(id, -32602, "missing fee history parameters");
    };
    let Some(count_text) = params.first().and_then(serde_json::Value::as_str) else {
        return rpc_error(id, -32602, "invalid fee history block count");
    };
    let count = match parse_hex_u64(count_text) {
        Ok(value) if (1..=MAX_FEE_HISTORY_BLOCKS).contains(&value) => value,
        Ok(_) => return rpc_error(id, -32602, "fee history block count is out of bounds"),
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    let Some(newest_text) = params.get(1).and_then(serde_json::Value::as_str) else {
        return rpc_error(id, -32602, "missing fee history newest block");
    };
    let latest = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.number.0,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let newest = match parse_block_tag(newest_text, latest) {
        Ok(number) if number <= latest => number,
        Ok(_) => return rpc_error(id, -32602, "newest block is beyond the canonical tip"),
        Err(err) => return rpc_error(id, -32602, &err),
    };
    let Some(oldest) = newest
        .checked_add(1)
        .and_then(|value| value.checked_sub(count))
    else {
        return rpc_error(id, -32602, "fee history range underflows genesis");
    };
    let percentiles = match params.get(2) {
        None => Vec::new(),
        Some(value) => {
            let Some(values) = value.as_array() else {
                return rpc_error(id, -32602, "reward percentiles must be an array");
            };
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let Some(value) = value.as_f64() else {
                    return rpc_error(id, -32602, "reward percentile must be a number");
                };
                if !(0.0..=100.0).contains(&value)
                    || parsed.last().is_some_and(|previous| value < *previous)
                {
                    return rpc_error(id, -32602, "reward percentiles must be sorted 0..100");
                }
                parsed.push(value);
            }
            parsed
        }
    };
    let mut blocks = Vec::with_capacity(count as usize);
    for number in oldest..=newest {
        match load_rpc_block(config, storage, number) {
            Ok(Some(block)) => blocks.push(block),
            Ok(None) => return rpc_result(id, serde_json::Value::Null),
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        }
    }
    let mut base_fees = blocks
        .iter()
        .map(|block| serde_json::json!(format!("0x{:x}", block.header.base_fee_per_gas.0)))
        .collect::<Vec<_>>();
    let next_base_fee = blocks
        .last()
        .map(|block| next_base_fee_per_gas(&block.header).0)
        .unwrap_or_default();
    base_fees.push(serde_json::json!(format!("0x{:x}", next_base_fee)));
    let gas_used_ratio = blocks
        .iter()
        .map(|block| {
            if block.header.gas_limit == 0 {
                0.0
            } else {
                block.header.gas_used as f64 / block.header.gas_limit as f64
            }
        })
        .collect::<Vec<_>>();
    let reward = if percentiles.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Array(
            blocks
                .iter()
                .map(|block| {
                    let mut tips = block
                        .transactions
                        .iter()
                        .zip(block.receipts.iter())
                        .map(|(transaction, receipt)| {
                            let effective = transaction.max_fee_per_gas.0.min(
                                block
                                    .header
                                    .base_fee_per_gas
                                    .0
                                    .saturating_add(transaction.max_priority_fee_per_gas.0),
                            );
                            (
                                effective.saturating_sub(block.header.base_fee_per_gas.0),
                                receipt.gas_used,
                            )
                        })
                        .filter(|(_, gas)| *gas > 0)
                        .collect::<Vec<_>>();
                    tips.sort_by_key(|(tip, _)| *tip);
                    let total_gas = block.header.gas_used.max(1);
                    serde_json::Value::Array(
                        percentiles
                            .iter()
                            .map(|percentile| {
                                let target =
                                    ((total_gas as f64 * percentile / 100.0).ceil() as u64).max(1);
                                let mut cumulative = 0u64;
                                let tip = tips
                                    .iter()
                                    .find_map(|(tip, gas)| {
                                        cumulative = cumulative.saturating_add(*gas);
                                        (cumulative >= target).then_some(*tip)
                                    })
                                    .unwrap_or(0);
                                serde_json::json!(format!("0x{:x}", tip))
                            })
                            .collect(),
                    )
                })
                .collect(),
        )
    };
    rpc_result(
        id,
        serde_json::json!({
            "oldestBlock": format!("0x{:x}", oldest),
            "baseFeePerGas": base_fees,
            "gasUsedRatio": gas_used_ratio,
            "reward": reward,
        }),
    )
}

fn rpc_get_code(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let historical_number = match resolve_state_block_tag(storage, parsed, 1) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let Some(params) = parsed.get("params").and_then(serde_json::Value::as_array) else {
        return rpc_error(id, -32602, "eth_getCode requires address and block tag");
    };
    let Some(address) = params
        .first()
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Address::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid address parameter");
    };
    let code = match historical_number {
        Some(number) => match load_historical_evm_state(config, storage, number) {
            Ok(state) => {
                state
                    .account(alloy_primitives::Address::from(address.0))
                    .code
            }
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
        None => match storage
            .lock()
            .expect("storage mutex poisoned")
            .evm_code(address)
        {
            Ok(code) => code,
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
    };
    rpc_result(id, serde_json::json!(format!("0x{}", hex::encode(code))))
}

fn rpc_get_storage_at(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let historical_number = match resolve_state_block_tag(storage, parsed, 2) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let Some(params) = parsed.get("params").and_then(serde_json::Value::as_array) else {
        return rpc_error(
            id,
            -32602,
            "eth_getStorageAt requires address, position, and block tag",
        );
    };
    let Some(address) = params
        .first()
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Address::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid address parameter");
    };
    let Some(slot) = params
        .get(1)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Hash256::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid storage position");
    };
    let value = match historical_number {
        Some(number) => match load_historical_evm_state(config, storage, number) {
            Ok(state) => state
                .account(alloy_primitives::Address::from(address.0))
                .storage
                .get(&alloy_primitives::U256::from_be_bytes(slot.0))
                .copied()
                .map(|value| Hash256(value.to_be_bytes()))
                .unwrap_or(Hash256::ZERO),
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
        None => match storage
            .lock()
            .expect("storage mutex poisoned")
            .evm_storage_at(address, slot)
        {
            Ok(value) => value,
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        },
    };
    rpc_result(id, serde_json::json!(format!("0x{}", value.to_hex())))
}

fn transaction_to_rpc_with_metadata(data: &RpcTransactionData) -> serde_json::Value {
    let mut result = transaction_to_rpc_json(&data.transaction);
    if let Some(object) = result.as_object_mut() {
        object.insert(
            "blockHash".to_string(),
            serde_json::json!(format!("0x{}", data.header.hash().to_hex())),
        );
        object.insert(
            "blockNumber".to_string(),
            serde_json::json!(format!("0x{:x}", data.header.number.0)),
        );
        object.insert(
            "transactionIndex".to_string(),
            serde_json::json!(format!("0x{:x}", data.transaction_index)),
        );
    }
    result
}

fn rpc_get_transaction_by_hash(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(hash) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Hash256::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid transaction hash");
    };
    let local = storage
        .lock()
        .expect("storage mutex poisoned")
        .indexed_transaction_receipt_by_hash(hash);
    match local {
        Ok((receipt, header, transaction_index, transaction)) => rpc_result(
            id,
            transaction_to_rpc_with_metadata(&RpcTransactionData {
                receipt,
                header,
                transaction_index,
                transaction,
            }),
        ),
        Err(blq_storage::StorageError::NotFound) => {
            let pending = storage
                .lock()
                .expect("storage mutex poisoned")
                .transaction_by_hash(hash);
            match pending {
                Ok(transaction) => rpc_result(id, transaction_to_rpc_json(&transaction)),
                Err(blq_storage::StorageError::NotFound) => {
                    match load_rpc_transaction_for_rpc(config, storage, hash) {
                        Ok(Some(data)) => rpc_result(id, transaction_to_rpc_with_metadata(&data)),
                        Ok(None) => rpc_result(id, serde_json::Value::Null),
                        Err(err) => rpc_error(id, -32000, &err.to_string()),
                    }
                }
                Err(err) => rpc_error(id, -32000, &err.to_string()),
            }
        }
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_get_transaction_receipt(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(hash) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Hash256::from_hex(value).ok())
    else {
        return rpc_error(id, -32602, "missing or invalid transaction hash");
    };
    let data = match storage
        .lock()
        .expect("storage mutex poisoned")
        .indexed_transaction_receipt_by_hash(hash)
    {
        Ok((receipt, header, transaction_index, transaction)) => Some(RpcTransactionData {
            receipt,
            header,
            transaction_index,
            transaction,
        }),
        Err(blq_storage::StorageError::NotFound) => {
            match load_rpc_transaction_for_rpc(config, storage, hash) {
                Ok(data) => data,
                Err(err) => return rpc_error(id, -32000, &err.to_string()),
            }
        }
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let receipt = match data {
        Some(data) => {
            let block = match load_rpc_block(config, storage, data.header.number.0) {
                Ok(Some(block)) => block,
                Ok(None) => return rpc_error(id, -32000, "transaction block body unavailable"),
                Err(err) => return rpc_error(id, -32000, &err.to_string()),
            };
            let cumulative_gas_used = block
                .receipts
                .iter()
                .take(data.transaction_index.saturating_add(1))
                .map(|receipt| receipt.gas_used)
                .sum();
            receipt_to_rpc_json(
                &data.receipt,
                &data.header,
                data.transaction_index,
                &data.transaction,
                cumulative_gas_used,
            )
        }
        None => serde_json::Value::Null,
    };
    rpc_result(id, receipt)
}

fn rpc_estimate_gas(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(call) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_object)
    else {
        return rpc_error(id, -32602, "missing call object");
    };
    let to = match call
        .get("to")
        .and_then(serde_json::Value::as_str)
        .map(Address::from_hex)
        .transpose()
    {
        Ok(to) => to,
        Err(err) => return rpc_error(id, -32602, &format!("invalid to address: {err:?}")),
    };
    let from = match call
        .get("from")
        .and_then(serde_json::Value::as_str)
        .map(Address::from_hex)
        .transpose()
    {
        Ok(Some(from)) => from,
        Ok(None) => Address([0; 20]),
        Err(err) => return rpc_error(id, -32602, &format!("invalid from address: {err:?}")),
    };
    let data = match call
        .get("data")
        .or_else(|| call.get("input"))
        .and_then(serde_json::Value::as_str)
        .map(decode_hex)
        .transpose()
    {
        Ok(data) => data.unwrap_or_default(),
        Err(err) => return rpc_error(id, -32602, &format!("invalid call data: {err}")),
    };
    let value = match call
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(parse_hex_u128)
        .transpose()
    {
        Ok(value) => value.unwrap_or(0),
        Err(err) => return rpc_error(id, -32602, &format!("invalid call value: {err}")),
    };
    let requested_limit = match call
        .get("gas")
        .and_then(serde_json::Value::as_str)
        .map(parse_hex_u64)
        .transpose()
    {
        Ok(limit) => limit,
        Err(err) => return rpc_error(id, -32602, &format!("invalid gas: {err}")),
    };
    let historical_number = match resolve_state_block_tag(storage, parsed, 1) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let (header, state) = match rpc_evm_state_at(config, storage, historical_number) {
        Ok(state) => state,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    if let Some(to) = to {
        if data.is_empty()
            && value == 0
            && state
                .account(alloy_primitives::Address::from(to.0))
                .code
                .is_empty()
        {
            return rpc_result(id, serde_json::json!(format!("0x{:x}", TRANSFER_GAS)));
        }
    }
    let max_gas = requested_limit
        .unwrap_or(header.gas_limit.min(MAX_EVM_CALL_GAS))
        .min(header.gas_limit);
    if max_gas > MAX_EVM_CALL_GAS {
        return rpc_error(id, -32602, "gas exceeds the EVM execution cap");
    }
    if max_gas < TRANSFER_GAS {
        return rpc_error(id, -32000, "gas limit is below the intrinsic transfer gas");
    }
    let nonce = state.account(alloy_primitives::Address::from(from.0)).nonce;
    let transaction = |gas_limit| Transaction {
        chain_id: blq_primitives::MAINNET_CHAIN_ID,
        transaction_type: 2,
        nonce,
        from,
        to,
        value: Bix(value),
        gas_limit,
        max_fee_per_gas: header.base_fee_per_gas,
        max_priority_fee_per_gas: Bix(0),
        payload: data.clone(),
        access_list: Vec::new(),
        signature: None,
        external_hash: None,
    };
    let mut low = TRANSFER_GAS;
    let mut high = max_gas;
    let mut successful_gas = None;
    while low <= high {
        let candidate = low.saturating_add(high).saturating_div(2);
        let mut executor = RevmBlockExecutor::new(state.clone());
        match executor.execute_transaction(&header, &transaction(candidate)) {
            Ok(output) if output.success => {
                // The gas consumed by REVM is not necessarily a sufficient
                // transaction limit at the boundary. Return the candidate
                // that actually completed successfully, not the reported
                // usage value, which can be one unit below the limit needed.
                successful_gas = Some(candidate);
                high = candidate.saturating_sub(1);
            }
            Ok(output) if output.gas_used >= candidate => {
                low = candidate.saturating_add(1);
            }
            Ok(_) => {
                return rpc_error(id, -32000, "EVM execution reverted");
            }
            Err(err) if is_gas_limit_failure(&err) => {
                low = candidate.saturating_add(1);
            }
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        }
    }
    match successful_gas {
        Some(gas) => rpc_result(id, serde_json::json!(format!("0x{:x}", gas))),
        None => rpc_error(id, -32000, "gas required exceeds allowance or always fails"),
    }
}

fn is_gas_limit_failure(error: &blq_evm::EvmError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("gas floor") || message.contains("out of gas") || message.contains("gas limit")
}

fn rpc_eth_call(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(call) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_object)
    else {
        return rpc_error(id, -32602, "missing call object");
    };
    let to = match call
        .get("to")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("eth_call to must be a hex address"))
                .and_then(|value| {
                    Address::from_hex(value)
                        .map_err(|err| anyhow::anyhow!("invalid eth_call to address: {err:?}"))
                })
        })
        .transpose()
    {
        Ok(to) => to,
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    let from = call
        .get("from")
        .and_then(serde_json::Value::as_str)
        .map(Address::from_hex)
        .transpose()
        .map_err(|_| ())
        .ok()
        .flatten()
        .unwrap_or(Address([0; 20]));
    let data = match call
        .get("data")
        .or_else(|| call.get("input"))
        .and_then(serde_json::Value::as_str)
        .map(decode_hex)
        .transpose()
    {
        Ok(data) => data.unwrap_or_default(),
        Err(err) => return rpc_error(id, -32602, &format!("invalid call data: {err}")),
    };
    let value = match call
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(parse_hex_u128)
        .transpose()
    {
        Ok(value) => value.unwrap_or(0),
        Err(err) => return rpc_error(id, -32602, &format!("invalid call value: {err}")),
    };
    let gas_limit = match call
        .get("gas")
        .and_then(serde_json::Value::as_str)
        .map(parse_hex_u64)
        .transpose()
    {
        Ok(gas) => gas.unwrap_or(MAX_EVM_CALL_GAS),
        Err(err) => return rpc_error(id, -32602, &format!("invalid call gas: {err}")),
    };
    let historical_number = match resolve_state_block_tag(storage, parsed, 1) {
        Ok(number) => number,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let (header, mut state) = match rpc_evm_state_at(config, storage, historical_number) {
        Ok(state) => state,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    if gas_limit > MAX_EVM_CALL_GAS || gas_limit > header.gas_limit {
        return rpc_error(
            id,
            -32602,
            "gas exceeds the EVM execution cap or block limit",
        );
    }
    let nonce = state.account(alloy_primitives::Address::from(from.0)).nonce;
    let caller = alloy_primitives::Address::from(from.0);
    let required_balance = alloy_primitives::U256::from(value).saturating_add(
        alloy_primitives::U256::from(gas_limit)
            .saturating_mul(alloy_primitives::U256::from(header.base_fee_per_gas.0)),
    );
    let mut caller_account = state.account(caller);
    if caller_account.balance < required_balance {
        caller_account.balance = required_balance;
        state.put_account(caller, caller_account);
    }
    let transaction = Transaction {
        chain_id: blq_primitives::MAINNET_CHAIN_ID,
        transaction_type: 2,
        nonce,
        from,
        to,
        value: Bix(value),
        gas_limit,
        max_fee_per_gas: header.base_fee_per_gas,
        max_priority_fee_per_gas: Bix(0),
        payload: data,
        access_list: Vec::new(),
        signature: None,
        external_hash: None,
    };
    let mut executor = RevmBlockExecutor::new(std::mem::take(&mut state));
    match executor.execute_transaction(&header, &transaction) {
        Ok(output) if output.success => rpc_result(
            id,
            serde_json::json!(format!("0x{}", hex::encode(output.output))),
        ),
        Ok(output) => rpc_error(
            id,
            -32000,
            &format!(
                "EVM call failed after {} gas: 0x{}",
                output.gas_used,
                hex::encode(output.output)
            ),
        ),
        Err(err) => rpc_error(id, -32000, &err.to_string()),
    }
}

fn rpc_get_logs(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    parsed: &serde_json::Value,
) -> String {
    const MAX_LOG_BLOCK_RANGE: u64 = 2_000;
    let Some(filter) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_object)
    else {
        return rpc_error(id, -32602, "eth_getLogs requires a filter object");
    };
    let latest = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.number.0,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let block_numbers = if let Some(block_hash) = filter.get("blockHash") {
        if filter.contains_key("fromBlock") || filter.contains_key("toBlock") {
            return rpc_error(
                id,
                -32602,
                "eth_getLogs blockHash cannot be combined with a block range",
            );
        }
        let Some(block_hash) = block_hash.as_str() else {
            return rpc_error(id, -32602, "eth_getLogs blockHash must be a hex hash");
        };
        let block_hash = match Hash256::from_hex(block_hash) {
            Ok(hash) => hash,
            Err(err) => return rpc_error(id, -32602, &format!("invalid blockHash: {err:?}")),
        };
        match storage
            .lock()
            .expect("storage mutex poisoned")
            .header_by_hash(block_hash)
        {
            Ok(header) => vec![header.number.0],
            Err(blq_storage::StorageError::NotFound) => Vec::new(),
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        }
    } else {
        let from = match parse_log_block_tag(filter.get("fromBlock"), latest) {
            Ok(number) => number,
            Err(err) => return rpc_error(id, -32602, &err),
        };
        let to = match parse_log_block_tag(filter.get("toBlock"), latest) {
            Ok(number) => number,
            Err(err) => return rpc_error(id, -32602, &err),
        };
        if to < from || to.saturating_sub(from) > MAX_LOG_BLOCK_RANGE {
            return rpc_error(
                id,
                -32602,
                "eth_getLogs block range is invalid or too large",
            );
        }
        (from..=to).collect()
    };
    let address_filter = filter.get("address");
    let topic_filter = filter.get("topics").and_then(serde_json::Value::as_array);
    let address_candidates = indexed_log_addresses(address_filter);
    let topic_candidates = indexed_log_topics(topic_filter);
    let indexed_numbers = match storage
        .lock()
        .expect("storage mutex poisoned")
        .indexed_log_block_numbers(
            block_numbers.first().copied().unwrap_or(0),
            block_numbers.last().copied().unwrap_or(0),
            address_candidates.as_deref(),
            topic_candidates.as_deref(),
        ) {
        Ok(numbers) => numbers,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    let mut remote_fetches = 0usize;
    let mut logs = Vec::new();
    for number in block_numbers {
        let local_block = storage
            .lock()
            .expect("storage mutex poisoned")
            .block_by_number(number);
        let block = match local_block {
            Ok(_) if !indexed_numbers.contains(&number) => continue,
            Ok(block) => block,
            Err(blq_storage::StorageError::NotFound) => {
                remote_fetches = remote_fetches.saturating_add(1);
                if remote_fetches > MAX_RPC_REMOTE_LOG_BLOCKS {
                    return rpc_error(
                        id,
                        -32000,
                        "historical log query exceeds the remote body fetch limit",
                    );
                }
                match load_rpc_block(config, storage, number) {
                    Ok(Some(block)) => block,
                    Ok(None) => {
                        return rpc_error(id, -32000, "historical log block body unavailable")
                    }
                    Err(err) => return rpc_error(id, -32000, &err.to_string()),
                }
            }
            Err(err) => return rpc_error(id, -32000, &err.to_string()),
        };
        for (transaction_index, (transaction, receipt)) in block
            .transactions
            .iter()
            .zip(block.receipts.iter())
            .enumerate()
        {
            for (log_index, log) in receipt.logs.iter().enumerate() {
                if !log_address_matches(address_filter, log.address) {
                    continue;
                }
                if !log_topics_match(topic_filter, &log.topics) {
                    continue;
                }
                logs.push(log_to_rpc_json(
                    log,
                    receipt,
                    &block.header,
                    transaction_index,
                    log_index,
                ));
                if let Some(entry) = logs.last_mut().and_then(serde_json::Value::as_object_mut) {
                    entry.insert(
                        "transactionHash".to_string(),
                        serde_json::json!(format!("0x{}", transaction.rpc_hash().to_hex())),
                    );
                }
            }
        }
    }
    rpc_result(id, serde_json::Value::Array(logs))
}

fn parse_log_block_tag(value: Option<&serde_json::Value>, latest: u64) -> Result<u64, String> {
    let tag = value
        .and_then(serde_json::Value::as_str)
        .unwrap_or("latest");
    parse_block_tag(tag, latest)
}

fn parse_block_tag(tag: &str, latest: u64) -> Result<u64, String> {
    match tag {
        "latest" | "safe" | "finalized" | "pending" => Ok(latest),
        "earliest" => Ok(0),
        _ => parse_hex_u64(tag).map_err(|err| err.to_string()),
    }
}

fn log_address_matches(filter: Option<&serde_json::Value>, address: Address) -> bool {
    let Some(filter) = filter else { return true };
    if let Some(value) = filter.as_str() {
        return Address::from_hex(value)
            .map(|candidate| candidate == address)
            .unwrap_or(false);
    }
    filter
        .as_array()
        .map(|values| {
            values.iter().any(|value| {
                value
                    .as_str()
                    .and_then(|value| Address::from_hex(value).ok())
                    .map(|candidate| candidate == address)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn indexed_log_addresses(filter: Option<&serde_json::Value>) -> Option<Vec<Address>> {
    let filter = filter?;
    if let Some(value) = filter.as_str() {
        return Some(Address::from_hex(value).ok().into_iter().collect());
    }
    Some(
        filter
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(|value| Address::from_hex(value).ok())
                    .collect()
            })
            .unwrap_or_default(),
    )
}

fn indexed_log_topics(filter: Option<&Vec<serde_json::Value>>) -> Option<Vec<Hash256>> {
    let filter = filter?;
    for expected in filter {
        if expected.is_null() {
            continue;
        }
        if let Some(value) = expected.as_str() {
            return Some(Hash256::from_hex(value).ok().into_iter().collect());
        }
        return Some(
            expected
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .filter_map(|value| Hash256::from_hex(value).ok())
                        .collect()
                })
                .unwrap_or_default(),
        );
    }
    None
}

fn log_topics_match(filter: Option<&Vec<serde_json::Value>>, topics: &[Hash256]) -> bool {
    let Some(filter) = filter else { return true };
    filter.iter().enumerate().all(|(index, expected)| {
        let Some(actual) = topics.get(index) else {
            return false;
        };
        if expected.is_null() {
            return true;
        }
        if let Some(value) = expected.as_str() {
            return Hash256::from_hex(value)
                .map(|candidate| candidate == *actual)
                .unwrap_or(false);
        }
        expected
            .as_array()
            .map(|values| {
                values.iter().any(|value| {
                    value
                        .as_str()
                        .and_then(|value| Hash256::from_hex(value).ok())
                        .map(|candidate| candidate == *actual)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    })
}

fn block_to_rpc_json(block: &Block, include_transactions: bool) -> serde_json::Value {
    let transactions = if include_transactions {
        serde_json::Value::Array(
            block
                .transactions
                .iter()
                .enumerate()
                .map(|(transaction_index, transaction)| {
                    let mut value = transaction_to_rpc_json(transaction);
                    if let Some(object) = value.as_object_mut() {
                        object.insert(
                            "blockHash".to_string(),
                            serde_json::json!(format!("0x{}", block.header.hash().to_hex())),
                        );
                        object.insert(
                            "blockNumber".to_string(),
                            serde_json::json!(format!("0x{:x}", block.header.number.0)),
                        );
                        object.insert(
                            "transactionIndex".to_string(),
                            serde_json::json!(format!("0x{:x}", transaction_index)),
                        );
                    }
                    value
                })
                .collect(),
        )
    } else {
        serde_json::Value::Array(
            block
                .transactions
                .iter()
                .map(|transaction| {
                    serde_json::json!(format!("0x{}", transaction.rpc_hash().to_hex()))
                })
                .collect(),
        )
    };
    serde_json::json!({
        "number": format!("0x{:x}", block.header.number.0),
        "hash": format!("0x{}", block.header.hash().to_hex()),
        "parentHash": format!("0x{}", block.header.parent_hash.to_hex()),
        "stateRoot": format!("0x{}", block.header.state_root.to_hex()),
        "transactionsRoot": format!("0x{}", block.header.transactions_root.to_hex()),
        "receiptsRoot": format!("0x{}", block.header.receipts_root.to_hex()),
        "miner": block.header.beneficiary_address().to_hex(),
        "difficulty": format!("0x{}", block.header.difficulty_target.to_hex()),
        "gasLimit": format!("0x{:x}", block.header.gas_limit),
        "gasUsed": format!("0x{:x}", block.header.gas_used),
        "timestamp": format!("0x{:x}", block.header.timestamp_seconds),
        "baseFeePerGas": format!("0x{:x}", block.header.base_fee_per_gas.0),
        "mixHash": format!("0x{}", block.header.mix_hash.to_hex()),
        "nonce": format!("0x{:016x}", block.header.nonce),
        "transactions": transactions,
        "uncles": [],
        "logsBloom": block_logs_bloom_hex(block),
        "extraData": "0x",
        "sha3Uncles": format!("0x{}", Hash256::ZERO.to_hex()),
    })
}

fn block_logs_bloom_hex(block: &Block) -> String {
    let logs = block
        .receipts
        .iter()
        .flat_map(|receipt| receipt.logs.iter())
        .cloned()
        .collect::<Vec<_>>();
    logs_bloom_hex(&logs)
}

fn transaction_to_rpc_json(transaction: &Transaction) -> serde_json::Value {
    let (r, s, y_parity) = transaction
        .signature
        .as_ref()
        .map(|signature| {
            (
                format!("0x{}", hex::encode(signature.r.0)),
                format!("0x{}", hex::encode(signature.s.0)),
                u64::from(signature.y_parity),
            )
        })
        .unwrap_or_else(|| ("0x0".to_string(), "0x0".to_string(), 0));
    serde_json::json!({
        "hash": format!("0x{}", transaction.rpc_hash().to_hex()),
        "chainId": format!("0x{:x}", transaction.chain_id),
        "nonce": format!("0x{:x}", transaction.nonce),
        "from": transaction.from.to_hex(),
        "to": transaction.to.map(Address::to_hex),
        "value": format!("0x{:x}", transaction.value.0),
        "gas": format!("0x{:x}", transaction.gas_limit),
        "maxFeePerGas": format!("0x{:x}", transaction.max_fee_per_gas.0),
        "maxPriorityFeePerGas": format!("0x{:x}", transaction.max_priority_fee_per_gas.0),
        "gasPrice": format!("0x{:x}", transaction.max_fee_per_gas.0),
        "input": format!("0x{}", hex::encode(&transaction.payload)),
        "accessList": transaction.access_list.iter().map(|item| serde_json::json!({
            "address": item.address.to_hex(),
            "storageKeys": item.storage_keys.iter().map(|key| format!("0x{}", key.to_hex())).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "type": format!("0x{:x}", transaction.transaction_type),
        "r": r,
        "s": s,
        "v": format!("0x{:x}", y_parity),
        "yParity": format!("0x{:x}", y_parity),
    })
}

fn receipt_to_rpc_json(
    receipt: &Receipt,
    header: &BlockHeader,
    transaction_index: usize,
    transaction: &Transaction,
    cumulative_gas_used: u64,
) -> serde_json::Value {
    let logs = receipt
        .logs
        .iter()
        .enumerate()
        .map(|(log_index, log)| log_to_rpc_json(log, receipt, header, transaction_index, log_index))
        .collect::<Vec<_>>();
    let contract_address = if transaction.to.is_none() && receipt.success {
        Some(create_contract_address(transaction.from, transaction.nonce).to_hex())
    } else {
        None
    };
    serde_json::json!({
        "transactionHash": format!("0x{}", receipt.transaction_hash.to_hex()),
        "transactionIndex": format!("0x{:x}", transaction_index),
        "blockHash": format!("0x{}", header.hash().to_hex()),
        "blockNumber": format!("0x{:x}", header.number.0),
        "from": transaction.from.to_hex(),
        "to": transaction.to.map(|address| address.to_hex()),
        "cumulativeGasUsed": format!("0x{:x}", cumulative_gas_used),
        "gasUsed": format!("0x{:x}", receipt.gas_used),
        "effectiveGasPrice": format!(
            "0x{:x}",
            transaction.max_fee_per_gas.0.min(
                header
                    .base_fee_per_gas
                    .0
                    .saturating_add(transaction.max_priority_fee_per_gas.0),
            )
        ),
        "contractAddress": contract_address,
        "logs": logs,
        "logsBloom": logs_bloom_hex(&receipt.logs),
        "status": if receipt.success { "0x1" } else { "0x0" },
        "type": format!("0x{:x}", transaction.transaction_type)
    })
}

fn create_contract_address(sender: Address, nonce: u64) -> Address {
    let mut payload = Vec::with_capacity(32);
    payload.push(0x94);
    payload.extend_from_slice(&sender.0);
    let nonce_bytes = nonce.to_be_bytes();
    let first = nonce_bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(nonce_bytes.len());
    let nonce_bytes = &nonce_bytes[first..];
    if nonce_bytes.is_empty() {
        payload.push(0x80);
    } else if nonce_bytes.len() == 1 && nonce_bytes[0] < 0x80 {
        payload.extend_from_slice(nonce_bytes);
    } else {
        payload.push(0x80 + nonce_bytes.len() as u8);
        payload.extend_from_slice(nonce_bytes);
    }
    let mut encoded = Vec::with_capacity(payload.len() + 2);
    if payload.len() < 56 {
        encoded.push(0xc0 + payload.len() as u8);
    } else {
        unreachable!("CREATE address RLP payload is bounded");
    }
    encoded.extend_from_slice(&payload);
    let hash = keccak256(encoded);
    Address(hash.0[12..].try_into().expect("keccak hash has 32 bytes"))
}

fn logs_bloom_hex(logs: &[LogEntry]) -> String {
    let alloy_logs = logs
        .iter()
        .map(|log| {
            alloy_primitives::Log::new_unchecked(
                alloy_primitives::Address::from(log.address.0),
                log.topics
                    .iter()
                    .map(|topic| alloy_primitives::B256::from(topic.0))
                    .collect(),
                alloy_primitives::Bytes::copy_from_slice(&log.data),
            )
        })
        .collect::<Vec<_>>();
    let bloom = alloy_primitives::logs_bloom(alloy_logs.iter());
    format!("0x{}", hex::encode(bloom.data()))
}

fn log_to_rpc_json(
    log: &LogEntry,
    receipt: &Receipt,
    header: &BlockHeader,
    transaction_index: usize,
    log_index: usize,
) -> serde_json::Value {
    serde_json::json!({
        "address": log.address.to_hex(),
        "topics": log.topics.iter().map(|topic| format!("0x{}", topic.to_hex())).collect::<Vec<_>>(),
        "data": format!("0x{}", hex::encode(&log.data)),
        "blockNumber": format!("0x{:x}", header.number.0),
        "transactionHash": format!("0x{}", receipt.transaction_hash.to_hex()),
        "transactionIndex": format!("0x{:x}", transaction_index),
        "blockHash": format!("0x{}", header.hash().to_hex()),
        "logIndex": format!("0x{:x}", log_index),
        "removed": false
    })
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    let trimmed = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("hex quantity must start with 0x"))?;
    Ok(u64::from_str_radix(trimmed, 16)?)
}

fn parse_hex_u128(value: &str) -> Result<u128> {
    let trimmed = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("hex quantity must start with 0x"))?;
    Ok(u128::from_str_radix(trimmed, 16)?)
}

fn rpc_send_transaction(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(value) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
    else {
        return rpc_error(id, -32602, "missing transaction parameter");
    };
    let transaction: Transaction = match serde_json::from_value(value.clone()) {
        Ok(transaction) => transaction,
        Err(err) => return rpc_error(id, -32602, &format!("invalid transaction: {err}")),
    };
    if transaction.signature.is_none() {
        return rpc_error(id, -32602, "structured transaction requires a signature");
    }
    if let Err(err) = verify_transaction_signature(&transaction) {
        return rpc_error(id, -32602, &err.to_string());
    }
    if let Err(err) = validate_transfer_transaction_shape(&transaction) {
        return rpc_error(id, -32602, &err.to_string());
    }
    let base_fee = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.base_fee_per_gas,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    if let Err(err) = validate_transaction_fee(&transaction, base_fee) {
        return rpc_error(id, -32000, &err.to_string());
    }
    let pending = mempool.lock().expect("mempool mutex poisoned");
    if let Err(err) = validate_transaction_against_current_state_with_pending(
        storage,
        &transaction,
        base_fee,
        Some(&pending),
    ) {
        return rpc_error(id, -32000, &err.to_string());
    }
    drop(pending);
    let hash = transaction.hash();
    let relay_transaction = transaction.clone();
    if let Err(err) = mempool
        .lock()
        .expect("mempool mutex poisoned")
        .add(transaction, base_fee)
    {
        return rpc_error(id, -32000, &err.to_string());
    }
    relay_transaction_async(config, storage, relay_transaction);
    rpc_result(id, serde_json::json!(format!("0x{}", hash.to_hex())))
}

fn rpc_send_raw_transaction(
    id: serde_json::Value,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    parsed: &serde_json::Value,
) -> String {
    let Some(raw) = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .and_then(|params| params.first())
        .and_then(serde_json::Value::as_str)
    else {
        return rpc_error(id, -32602, "missing raw transaction parameter");
    };
    let transaction = match decode_raw_transaction(raw) {
        Ok(transaction) => transaction,
        Err(err) => return rpc_error(id, -32602, &err.to_string()),
    };
    if transaction.to.is_none() && transaction.payload.is_empty() {
        return rpc_error(
            id,
            -32602,
            "contract creation transaction requires init code",
        );
    }
    let base_fee = match storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
    {
        Ok(header) => header.base_fee_per_gas,
        Err(err) => return rpc_error(id, -32000, &err.to_string()),
    };
    if let Err(err) = validate_transaction_fee(&transaction, base_fee) {
        return rpc_error(id, -32000, &err.to_string());
    }
    let pending = mempool.lock().expect("mempool mutex poisoned");
    if let Err(err) = validate_transaction_against_current_state_with_pending(
        storage,
        &transaction,
        base_fee,
        Some(&pending),
    ) {
        return rpc_error(id, -32000, &err.to_string());
    }
    drop(pending);
    let rpc_hash = transaction.rpc_hash();
    let relay_transaction = transaction.clone();
    if let Err(err) = mempool
        .lock()
        .expect("mempool mutex poisoned")
        .add(transaction, base_fee)
    {
        return rpc_error(id, -32000, &err.to_string());
    }
    relay_transaction_async(config, storage, relay_transaction);
    rpc_result(id, serde_json::json!(format!("0x{}", rpc_hash.to_hex())))
}

fn decode_raw_transaction(raw: &str) -> Result<Transaction> {
    let raw_bytes = decode_hex(raw)?;
    match raw_bytes.first().copied() {
        Some(0x01) => decode_eip2930_transaction(&raw_bytes),
        Some(0x02) => decode_eip1559_transaction(&raw_bytes),
        Some(value) if value >= 0xc0 => decode_legacy_transaction(&raw_bytes),
        _ => anyhow::bail!("unsupported raw transaction type"),
    }
}

fn decode_eip1559_transaction(raw_bytes: &[u8]) -> Result<Transaction> {
    let raw_hash = keccak256(raw_bytes);
    let mut payload = decode_rlp_list(&raw_bytes[1..])?;
    let signing_payload = encode_typed_signing_payload(payload, 9, 0x02)?;
    let chain_id = rlp_take_u64(&mut payload)?;
    validate_raw_chain_id(chain_id)?;
    let nonce = rlp_take_u64(&mut payload)?;
    let max_priority_fee_per_gas = rlp_take_u128(&mut payload)?;
    let max_fee_per_gas = rlp_take_u128(&mut payload)?;
    let gas_limit = rlp_take_u64(&mut payload)?;
    let to = rlp_take_optional_address(&mut payload)?;
    let value = rlp_take_u128(&mut payload)?;
    let input = rlp_take_bytes(&mut payload)?;
    if input.len() > MAX_TRANSACTION_PAYLOAD_BYTES {
        anyhow::bail!("transaction payload exceeds the maximum size");
    }
    let access_list = rlp_decode_access_list(&mut payload)?;
    let y_parity = rlp_take_u64(&mut payload)?;
    if y_parity > 1 {
        anyhow::bail!("invalid EIP-1559 signature parity");
    }
    let r = rlp_take_word(&mut payload)?;
    let s = rlp_take_word(&mut payload)?;
    if !payload.is_empty() {
        anyhow::bail!("raw transaction has trailing RLP fields");
    }
    let signature =
        EthSignature::from_scalars_and_parity(B256::from(r), B256::from(s), y_parity == 1);
    reject_high_s_signature(&signature)?;
    let signer = signature
        .recover_address_from_prehash(&keccak256(signing_payload))
        .map_err(|err| anyhow::anyhow!("could not recover transaction signer: {err}"))?;
    Ok(Transaction {
        chain_id,
        transaction_type: 2,
        nonce,
        from: Address(signer.into_array()),
        to,
        value: Bix(value),
        gas_limit,
        max_fee_per_gas: Bix(max_fee_per_gas),
        max_priority_fee_per_gas: Bix(max_priority_fee_per_gas),
        payload: input,
        access_list,
        signature: Some(TransactionSignature {
            y_parity: y_parity == 1,
            r: Hash256(r),
            s: Hash256(s),
        }),
        external_hash: Some(Hash256(raw_hash.into())),
    })
}

fn decode_eip2930_transaction(raw_bytes: &[u8]) -> Result<Transaction> {
    let raw_hash = keccak256(raw_bytes);
    let mut payload = decode_rlp_list(&raw_bytes[1..])?;
    let signing_payload = encode_typed_signing_payload(payload, 8, 0x01)?;
    let chain_id = rlp_take_u64(&mut payload)?;
    validate_raw_chain_id(chain_id)?;
    let nonce = rlp_take_u64(&mut payload)?;
    let gas_price = rlp_take_u128(&mut payload)?;
    let gas_limit = rlp_take_u64(&mut payload)?;
    let to = rlp_take_optional_address(&mut payload)?;
    let value = rlp_take_u128(&mut payload)?;
    let input = rlp_take_bytes(&mut payload)?;
    if input.len() > MAX_TRANSACTION_PAYLOAD_BYTES {
        anyhow::bail!("transaction payload exceeds the maximum size");
    }
    let access_list = rlp_decode_access_list(&mut payload)?;
    let y_parity = rlp_take_u64(&mut payload)?;
    if y_parity > 1 {
        anyhow::bail!("invalid EIP-2930 signature parity");
    }
    let r = rlp_take_word(&mut payload)?;
    let s = rlp_take_word(&mut payload)?;
    if !payload.is_empty() {
        anyhow::bail!("raw transaction has trailing RLP fields");
    }
    let signature =
        EthSignature::from_scalars_and_parity(B256::from(r), B256::from(s), y_parity == 1);
    reject_high_s_signature(&signature)?;
    let signer = signature
        .recover_address_from_prehash(&keccak256(signing_payload))
        .map_err(|err| anyhow::anyhow!("could not recover transaction signer: {err}"))?;
    Ok(Transaction {
        chain_id,
        transaction_type: 1,
        nonce,
        from: Address(signer.into_array()),
        to,
        value: Bix(value),
        gas_limit,
        max_fee_per_gas: Bix(gas_price),
        max_priority_fee_per_gas: Bix(0),
        payload: input,
        access_list,
        signature: Some(TransactionSignature {
            y_parity: y_parity == 1,
            r: Hash256(r),
            s: Hash256(s),
        }),
        external_hash: Some(Hash256(raw_hash.into())),
    })
}

fn decode_legacy_transaction(raw_bytes: &[u8]) -> Result<Transaction> {
    let raw_hash = keccak256(raw_bytes);
    let mut payload = decode_rlp_list(raw_bytes)?;
    let mut signing_fields = Vec::with_capacity(9);
    for _ in 0..6 {
        signing_fields.push(rlp_take_raw(&mut payload)?.to_vec());
    }
    let nonce = decode_u64_field(&signing_fields[0])?;
    let gas_price = decode_u128_field(&signing_fields[1])?;
    let gas_limit = decode_u64_field(&signing_fields[2])?;
    let mut to_input = signing_fields[3].as_slice();
    let to = rlp_take_optional_address(&mut to_input)?;
    if !to_input.is_empty() {
        anyhow::bail!("invalid legacy recipient field");
    }
    let value = decode_u128_field(&signing_fields[4])?;
    let input = decode_bytes_field(&signing_fields[5])?;
    if input.len() > MAX_TRANSACTION_PAYLOAD_BYTES {
        anyhow::bail!("transaction payload exceeds the maximum size");
    }
    let v = rlp_take_u64(&mut payload)?;
    let r = rlp_take_word(&mut payload)?;
    let s = rlp_take_word(&mut payload)?;
    if !payload.is_empty() {
        anyhow::bail!("raw transaction has trailing RLP fields");
    }
    let (chain_id, y_parity, signing_payload) = match v {
        27 | 28 => anyhow::bail!(
            "unprotected legacy transactions are disabled; use EIP-155 chain ID {}",
            MAINNET_CHAIN_ID
        ),
        value if value >= 35 => {
            let adjusted = value - 35;
            let chain_id = adjusted / 2;
            let parity = adjusted % 2;
            signing_fields.push(rlp_encode_u64(chain_id));
            signing_fields.push(rlp_encode_bytes(&[]));
            signing_fields.push(rlp_encode_bytes(&[]));
            (chain_id, parity == 1, encode_rlp_list(&signing_fields))
        }
        _ => anyhow::bail!("invalid legacy signature v value"),
    };
    validate_raw_chain_id(chain_id)?;
    let signature = EthSignature::from_scalars_and_parity(B256::from(r), B256::from(s), y_parity);
    reject_high_s_signature(&signature)?;
    let signer = signature
        .recover_address_from_prehash(&keccak256(signing_payload))
        .map_err(|err| anyhow::anyhow!("could not recover transaction signer: {err}"))?;
    Ok(Transaction {
        chain_id,
        transaction_type: 0,
        nonce,
        from: Address(signer.into_array()),
        to,
        value: Bix(value),
        gas_limit,
        max_fee_per_gas: Bix(gas_price),
        max_priority_fee_per_gas: Bix(0),
        payload: input,
        access_list: Vec::new(),
        signature: Some(TransactionSignature {
            y_parity,
            r: Hash256(r),
            s: Hash256(s),
        }),
        external_hash: Some(Hash256(raw_hash.into())),
    })
}

fn validate_raw_chain_id(chain_id: u64) -> Result<()> {
    if chain_id != MAINNET_CHAIN_ID {
        anyhow::bail!(
            "transaction chain ID {} does not match network {}",
            chain_id,
            MAINNET_CHAIN_ID
        );
    }
    Ok(())
}

fn reject_high_s_signature(signature: &EthSignature) -> Result<()> {
    if signature.normalize_s().is_some() {
        anyhow::bail!("high-s transaction signatures are not accepted")
    }
    Ok(())
}

fn verify_transaction_signature(transaction: &Transaction) -> Result<()> {
    let signature = transaction
        .signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("transaction gossip requires a signature"))?;
    let signature = EthSignature::from_scalars_and_parity(
        B256::from(signature.r.0),
        B256::from(signature.s.0),
        signature.y_parity,
    );
    reject_high_s_signature(&signature)?;
    let recovered = signature
        .recover_address_from_prehash(&keccak256(transaction_signing_payload(transaction)?))
        .map_err(|err| anyhow::anyhow!("could not recover transaction signer: {err}"))?;
    if recovered.into_array() != transaction.from.0 {
        anyhow::bail!("transaction signature does not match sender");
    }
    if let Some(external_hash) = transaction.external_hash {
        let wire_hash = Hash256(keccak256(transaction_signed_bytes(transaction)?).0);
        if external_hash != wire_hash {
            anyhow::bail!("transaction external hash does not match signed payload");
        }
    }
    Ok(())
}

fn transaction_signing_payload(transaction: &Transaction) -> Result<Vec<u8>> {
    let recipient = transaction
        .to
        .map(|address| address.0.to_vec())
        .unwrap_or_default();
    let access_list = encode_access_list(&transaction.access_list);
    match transaction.transaction_type {
        1 => Ok(encode_typed_rlp(
            0x01,
            &[
                rlp_encode_u64(transaction.chain_id),
                rlp_encode_u64(transaction.nonce),
                rlp_encode_u128(transaction.max_fee_per_gas.0),
                rlp_encode_u64(transaction.gas_limit),
                rlp_encode_bytes(&recipient),
                rlp_encode_u128(transaction.value.0),
                rlp_encode_bytes(&transaction.payload),
                access_list,
            ]
            .concat(),
        )),
        2 => blq_primitives::eip1559_signing_payload(transaction).map_err(anyhow::Error::msg),
        0 => {
            let fields = [
                rlp_encode_u64(transaction.nonce),
                rlp_encode_u128(transaction.max_fee_per_gas.0),
                rlp_encode_u64(transaction.gas_limit),
                rlp_encode_bytes(&recipient),
                rlp_encode_u128(transaction.value.0),
                rlp_encode_bytes(&transaction.payload),
                rlp_encode_u64(transaction.chain_id),
                rlp_encode_bytes(&[]),
                rlp_encode_bytes(&[]),
            ];
            Ok(encode_rlp_list(&fields))
        }
        value => anyhow::bail!("unsupported transaction type {value}"),
    }
}

fn encode_access_list(access_list: &[TransactionAccessListItem]) -> Vec<u8> {
    let entries = access_list
        .iter()
        .map(|item| {
            let keys = encode_rlp_list(
                &item
                    .storage_keys
                    .iter()
                    .map(|key| rlp_encode_bytes(&key.0))
                    .collect::<Vec<_>>(),
            );
            encode_rlp_list(&[rlp_encode_bytes(&item.address.0), keys])
        })
        .collect::<Vec<_>>();
    encode_rlp_list(&entries)
}

fn transaction_signed_bytes(transaction: &Transaction) -> Result<Vec<u8>> {
    let recipient = transaction
        .to
        .map(|address| address.0.to_vec())
        .unwrap_or_default();
    let access_list = encode_access_list(&transaction.access_list);
    let signature = transaction
        .signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("transaction gossip requires a signature"))?;
    let r = rlp_encode_word(signature.r.0);
    let s = rlp_encode_word(signature.s.0);
    match transaction.transaction_type {
        1 => Ok(encode_typed_rlp(
            0x01,
            &[
                rlp_encode_u64(transaction.chain_id),
                rlp_encode_u64(transaction.nonce),
                rlp_encode_u128(transaction.max_fee_per_gas.0),
                rlp_encode_u64(transaction.gas_limit),
                rlp_encode_bytes(&recipient),
                rlp_encode_u128(transaction.value.0),
                rlp_encode_bytes(&transaction.payload),
                access_list,
                rlp_encode_u64(u64::from(signature.y_parity)),
                r,
                s,
            ]
            .concat(),
        )),
        2 => blq_primitives::eip1559_signed_bytes(transaction).map_err(anyhow::Error::msg),
        0 => {
            let fields = [
                rlp_encode_u64(transaction.nonce),
                rlp_encode_u128(transaction.max_fee_per_gas.0),
                rlp_encode_u64(transaction.gas_limit),
                rlp_encode_bytes(&recipient),
                rlp_encode_u128(transaction.value.0),
                rlp_encode_bytes(&transaction.payload),
                rlp_encode_u64(
                    transaction
                        .chain_id
                        .saturating_mul(2)
                        .saturating_add(35)
                        .saturating_add(u64::from(signature.y_parity)),
                ),
                r,
                s,
            ];
            Ok(encode_rlp_list(&fields))
        }
        value => anyhow::bail!("unsupported transaction type {value}"),
    }
}

fn encode_typed_signing_payload(
    payload: &[u8],
    field_count: usize,
    transaction_type: u8,
) -> Result<Vec<u8>> {
    let mut rest = payload;
    let mut fields = Vec::new();
    for _ in 0..field_count {
        fields.push(rlp_take_raw(&mut rest)?.to_vec());
    }
    if rest.is_empty() {
        anyhow::bail!("raw transaction is missing signature fields");
    }
    Ok(encode_typed_rlp(transaction_type, &fields.concat()))
}

fn rlp_decode_access_list(input: &mut &[u8]) -> Result<Vec<TransactionAccessListItem>> {
    let (list, mut entries) = rlp_take_item(input)?;
    if !list {
        anyhow::bail!("access list must be an RLP list");
    }
    let mut access_list = Vec::new();
    let mut total_storage_keys = 0usize;
    while !entries.is_empty() {
        if access_list.len() >= MAX_ACCESS_LIST_ENTRIES {
            anyhow::bail!("transaction access list exceeds the maximum size");
        }
        let entry = rlp_take_raw(&mut entries)?;
        let mut entry_payload = decode_rlp_list(entry)?;
        let address = rlp_take_bytes(&mut entry_payload)?;
        if address.len() != 20 {
            anyhow::bail!("access-list address must be 20 bytes");
        }
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&address);
        let (storage_list, mut keys) = rlp_take_item(&mut entry_payload)?;
        if !storage_list || !entry_payload.is_empty() {
            anyhow::bail!("invalid access-list storage keys");
        }
        let mut storage_keys = Vec::new();
        while !keys.is_empty() {
            if storage_keys.len() >= MAX_ACCESS_LIST_STORAGE_KEYS_PER_ENTRY
                || total_storage_keys >= MAX_ACCESS_LIST_STORAGE_KEYS
            {
                anyhow::bail!("transaction access list exceeds the maximum size");
            }
            let key = rlp_take_bytes(&mut keys)?;
            if key.len() != 32 {
                anyhow::bail!("access-list storage key must be 32 bytes");
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key);
            storage_keys.push(Hash256(key_bytes));
            total_storage_keys += 1;
        }
        access_list.push(TransactionAccessListItem {
            address: Address(address_bytes),
            storage_keys,
        });
    }
    Ok(access_list)
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    Ok(hex::decode(trimmed)?)
}

fn decode_bytes_field(field: &[u8]) -> Result<Vec<u8>> {
    let mut input = field;
    let bytes = rlp_take_bytes(&mut input)?;
    if !input.is_empty() {
        anyhow::bail!("RLP field has trailing bytes");
    }
    Ok(bytes)
}

fn decode_u64_field(field: &[u8]) -> Result<u64> {
    let mut input = field;
    let value = rlp_take_u64(&mut input)?;
    if !input.is_empty() {
        anyhow::bail!("RLP integer field has trailing bytes");
    }
    Ok(value)
}

fn decode_u128_field(field: &[u8]) -> Result<u128> {
    let mut input = field;
    let value = rlp_take_u128(&mut input)?;
    if !input.is_empty() {
        anyhow::bail!("RLP integer field has trailing bytes");
    }
    Ok(value)
}

fn decode_rlp_list(bytes: &[u8]) -> Result<&[u8]> {
    let mut input = bytes;
    let (list, payload) = rlp_take_item(&mut input)?;
    if !input.is_empty() {
        anyhow::bail!("raw transaction has trailing bytes");
    }
    if !list {
        anyhow::bail!("raw transaction payload must be an RLP list");
    }
    Ok(payload)
}

fn rlp_take_raw<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let start = *input;
    let _ = rlp_take_item(input)?;
    let consumed = start.len() - input.len();
    Ok(&start[..consumed])
}

fn rlp_take_item<'a>(input: &mut &'a [u8]) -> Result<(bool, &'a [u8])> {
    let original = *input;
    let Some((&prefix, rest)) = original.split_first() else {
        anyhow::bail!("unexpected end of RLP input");
    };
    match prefix {
        0x00..=0x7f => {
            *input = rest;
            Ok((false, &original[..1]))
        }
        0x80..=0xb7 => {
            let len = (prefix - 0x80) as usize;
            if rest.len() < len {
                anyhow::bail!("short RLP string");
            }
            let (payload, tail) = rest.split_at(len);
            *input = tail;
            Ok((false, payload))
        }
        0xb8..=0xbf => {
            let len_of_len = (prefix - 0xb7) as usize;
            let (len, after_len) = rlp_decode_length(rest, len_of_len)?;
            if after_len.len() < len {
                anyhow::bail!("short RLP long string");
            }
            let (payload, tail) = after_len.split_at(len);
            *input = tail;
            Ok((false, payload))
        }
        0xc0..=0xf7 => {
            let len = (prefix - 0xc0) as usize;
            if rest.len() < len {
                anyhow::bail!("short RLP list");
            }
            let (payload, tail) = rest.split_at(len);
            *input = tail;
            Ok((true, payload))
        }
        0xf8..=0xff => {
            let len_of_len = (prefix - 0xf7) as usize;
            let (len, after_len) = rlp_decode_length(rest, len_of_len)?;
            if after_len.len() < len {
                anyhow::bail!("short RLP long list");
            }
            let (payload, tail) = after_len.split_at(len);
            *input = tail;
            Ok((true, payload))
        }
    }
}

fn rlp_decode_length(input: &[u8], len_of_len: usize) -> Result<(usize, &[u8])> {
    if len_of_len == 0 || len_of_len > 8 || input.len() < len_of_len {
        anyhow::bail!("invalid RLP length");
    }
    let (len_bytes, rest) = input.split_at(len_of_len);
    let mut len = 0usize;
    for byte in len_bytes {
        len = len
            .checked_mul(256)
            .and_then(|value| value.checked_add(*byte as usize))
            .ok_or_else(|| anyhow::anyhow!("RLP length overflow"))?;
    }
    Ok((len, rest))
}

fn rlp_take_bytes(input: &mut &[u8]) -> Result<Vec<u8>> {
    let (list, payload) = rlp_take_item(input)?;
    if list {
        anyhow::bail!("expected RLP bytes");
    }
    Ok(payload.to_vec())
}

fn rlp_take_u64(input: &mut &[u8]) -> Result<u64> {
    let value = rlp_take_u128(input)?;
    Ok(u64::try_from(value)?)
}

fn rlp_take_u128(input: &mut &[u8]) -> Result<u128> {
    let bytes = rlp_take_bytes(input)?;
    if bytes.len() > 16 {
        anyhow::bail!("integer does not fit in u128");
    }
    if bytes.len() > 1 && bytes.first() == Some(&0) {
        anyhow::bail!("non-canonical RLP integer encoding");
    }
    let mut value = 0u128;
    for byte in bytes {
        value = (value << 8) | byte as u128;
    }
    Ok(value)
}

fn rlp_take_word(input: &mut &[u8]) -> Result<[u8; 32]> {
    let bytes = rlp_take_bytes(input)?;
    if bytes.len() > 32 {
        anyhow::bail!("signature scalar is longer than 32 bytes");
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn rlp_take_optional_address(input: &mut &[u8]) -> Result<Option<Address>> {
    let bytes = rlp_take_bytes(input)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 20 {
        anyhow::bail!("transaction recipient must be empty or 20 bytes");
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(Some(Address(out)))
}

fn rlp_encode_list_payload(payload: &[u8], out: &mut Vec<u8>) {
    rlp_encode_header(0xc0, payload.len(), out);
    out.extend_from_slice(payload);
}

fn encode_typed_rlp(transaction_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![transaction_type];
    rlp_encode_list_payload(payload, &mut out);
    out
}

fn encode_rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let payload = fields.concat();
    let mut out = Vec::new();
    rlp_encode_list_payload(&payload, &mut out);
    out
}

fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = Vec::new();
    rlp_encode_header(0x80, bytes.len(), &mut out);
    out.extend_from_slice(bytes);
    out
}

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return rlp_encode_bytes(&[]);
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    rlp_encode_bytes(&bytes[first..])
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return rlp_encode_bytes(&[]);
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(15);
    rlp_encode_bytes(&bytes[first..])
}

fn rlp_encode_word(value: [u8; 32]) -> Vec<u8> {
    let first = value.iter().position(|byte| *byte != 0).unwrap_or(31);
    if value.iter().all(|byte| *byte == 0) {
        return rlp_encode_bytes(&[]);
    }
    rlp_encode_bytes(&value[first..])
}

fn rlp_encode_header(offset: u8, len: usize, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + len as u8);
        return;
    }
    let mut len_bytes = Vec::new();
    let mut value = len;
    while value > 0 {
        len_bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    len_bytes.reverse();
    out.push(offset + 55 + len_bytes.len() as u8);
    out.extend_from_slice(&len_bytes);
}

fn validate_transaction_against_current_state(
    storage: &Arc<Mutex<NodeStorage>>,
    transaction: &Transaction,
    base_fee: Bix,
) -> Result<()> {
    validate_transaction_against_current_state_with_pending(storage, transaction, base_fee, None)
}

fn validate_transaction_against_current_state_with_pending(
    storage: &Arc<Mutex<NodeStorage>>,
    transaction: &Transaction,
    base_fee: Bix,
    pending: Option<&Mempool>,
) -> Result<()> {
    let storage = storage.lock().expect("storage mutex poisoned");
    let expected_nonce = storage.nonce(transaction.from)?;
    let queued_sequence = transaction.nonce > expected_nonce
        && pending.is_some_and(|mempool| {
            mempool.has_nonce_chain(transaction.from, expected_nonce, transaction.nonce)
        });
    if expected_nonce != transaction.nonce && !queued_sequence {
        anyhow::bail!(
            "invalid nonce for {}: expected {}, got {}",
            transaction.from.to_hex(),
            expected_nonce,
            transaction.nonce
        );
    }
    let effective_gas_price = transaction.max_fee_per_gas.0.min(
        base_fee
            .0
            .saturating_add(transaction.max_priority_fee_per_gas.0),
    );
    let fee = (transaction.gas_limit as u128).saturating_mul(effective_gas_price);
    let required = transaction.value.0.saturating_add(fee);
    let balance = storage.balance(transaction.from)?.0;
    if balance < required {
        anyhow::bail!(
            "insufficient balance for {}: required {}, available {}",
            transaction.from.to_hex(),
            required,
            balance
        );
    }
    Ok(())
}

fn rpc_result(id: serde_json::Value, result: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
    .to_string()
}

fn rpc_error(id: serde_json::Value, code: i64, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
    .to_string()
}

#[derive(Clone, Debug, Deserialize)]
struct NodeConfig {
    node: NodeSection,
    rpc: RpcSection,
    network: NetworkSection,
    #[serde(default)]
    explorer: ExplorerSection,
    discovery: ServiceSection,
    relay: ServiceSection,
}

/// Explorer configuration controls derived operational data only. It never
/// participates in consensus, fork choice, or block validation.
#[derive(Clone, Debug, Deserialize)]
struct ExplorerSection {
    #[serde(default)]
    index: Option<bool>,
    #[serde(default)]
    share: Option<bool>,
    #[serde(default = "default_true")]
    relay: bool,
}

impl Default for ExplorerSection {
    fn default() -> Self {
        Self {
            index: None,
            share: None,
            relay: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct NodeSection {
    mode: NodeMode,
    data_dir: String,
    mining_enabled: bool,
    #[serde(default)]
    advertise_rpc: Option<String>,
    #[serde(default)]
    advertise_websocket: Option<String>,
    #[serde(default)]
    advertise_p2p: Option<String>,
    max_storage_bytes: u64,
    #[serde(default = "default_filesystem_reserve_bytes")]
    filesystem_reserve_bytes: u64,
    #[serde(default = "default_prune_trigger_percent")]
    prune_trigger_percent: u8,
    #[serde(default)]
    storage_mode: StorageMode,
    #[serde(default)]
    prune_history: bool,
    #[serde(default = "default_true")]
    retain_snapshots: bool,
    #[serde(default = "default_true")]
    retain_finalized_checkpoints: bool,
    #[serde(default = "default_true")]
    historical_peer_fallback: bool,
    #[serde(default)]
    required_pow_algorithm: Option<String>,
    #[serde(default)]
    expected_genesis_hash: Option<String>,
    #[serde(default)]
    genesis_manifest: Option<String>,
    #[serde(default)]
    require_signed_transactions: bool,
    /// First height subject to the coordinated 2 MiB block-size rollout.
    #[serde(default)]
    block_size_activation_height: Option<u64>,
    /// First height governed by the 15-second median cadence controller.
    #[serde(default)]
    block_time_v2_activation_height: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum StorageMode {
    #[default]
    Archive,
    Pruned,
}

impl NodeSection {
    fn pruning_enabled(&self) -> bool {
        self.storage_mode == StorageMode::Pruned || self.prune_history
    }
}

impl ExplorerSection {
    fn index_enabled(&self, storage_mode: StorageMode) -> bool {
        self.index.unwrap_or(storage_mode == StorageMode::Archive)
    }

    fn share_enabled(&self, storage_mode: StorageMode) -> bool {
        self.share
            .unwrap_or(storage_mode == StorageMode::Archive && self.index_enabled(storage_mode))
            && self.index_enabled(storage_mode)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RpcSection {
    enabled: bool,
    bind: String,
    #[serde(default)]
    public_read_only: bool,
    #[serde(default = "default_rpc_connections")]
    max_connections: usize,
    #[serde(default)]
    mining_token: Option<String>,
    /// Compatible RPC endpoints used only to source miner work while this
    /// node has a verified higher branch still being synchronized.
    #[serde(default)]
    mining_upstreams: Vec<String>,
    #[serde(default)]
    mining_api_enabled: bool,
}

fn default_rpc_connections() -> usize {
    DEFAULT_RPC_CONNECTIONS
}

fn default_true() -> bool {
    true
}

fn default_filesystem_reserve_bytes() -> u64 {
    512 * 1024 * 1024
}

fn default_prune_trigger_percent() -> u8 {
    75
}

fn initialize_genesis(storage: &mut NodeStorage, node_mode: NodeMode) -> Result<()> {
    match node_mode {
        NodeMode::Full => storage.insert_block(genesis_block())?,
        NodeMode::Partial => storage.insert_header(genesis_header())?,
    }
    Ok(())
}

fn initialize_genesis_for_config(
    storage: &mut NodeStorage,
    node_mode: NodeMode,
    config: &NodeConfig,
) -> Result<()> {
    let (header, _) = genesis_from_config(config)?;
    match node_mode {
        NodeMode::Full => storage.insert_block(Block {
            header,
            transactions: Vec::new(),
            receipts: Vec::new(),
        })?,
        NodeMode::Partial => storage.insert_header(header)?,
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GenesisManifest {
    chain_id: u64,
    pow_algorithm: String,
    hash: String,
    header: BlockHeader,
}

fn load_genesis_manifest(path: &str) -> Result<GenesisManifest> {
    let bytes = std::fs::read(path)
        .map_err(|err| anyhow::anyhow!("read genesis manifest {path}: {err}"))?;
    let manifest: GenesisManifest = serde_json::from_slice(&bytes)
        .map_err(|err| anyhow::anyhow!("parse genesis manifest {path}: {err}"))?;
    if manifest.chain_id != blq_primitives::MAINNET_CHAIN_ID {
        anyhow::bail!("genesis manifest chain id does not match BLQ");
    }
    if manifest.pow_algorithm != manifest.header.pow_algorithm {
        anyhow::bail!("genesis manifest algorithm does not match its header");
    }
    if manifest.hash != manifest.header.hash().to_hex() {
        anyhow::bail!("genesis manifest hash does not match its header");
    }
    Ok(manifest)
}

fn genesis_from_config(config: &NodeConfig) -> Result<(BlockHeader, Option<String>)> {
    if let Some(path) = config.node.genesis_manifest.as_deref() {
        let manifest = load_genesis_manifest(path)?;
        return Ok((manifest.header, Some(manifest.hash)));
    }
    Ok((genesis_header(), None))
}

fn mine_genesis_manifest(path: &str) -> Result<()> {
    let mut header = genesis_header();
    let target = header.difficulty_target;
    for nonce in 0..=u64::MAX {
        header.nonce = nonce;
        let result = blq_pow::blq_rx_hash(&header, blq_primitives::Hash256::ZERO);
        if blq_consensus::satisfies_pow(result.final_hash, target) {
            header.mix_hash = result.mix_hash;
            let manifest = GenesisManifest {
                chain_id: blq_primitives::MAINNET_CHAIN_ID,
                pow_algorithm: header.pow_algorithm.clone(),
                hash: header.hash().to_hex(),
                header,
            };
            let json = serde_json::to_vec_pretty(&manifest)?;
            std::fs::write(path, json)
                .map_err(|err| anyhow::anyhow!("write genesis manifest {path}: {err}"))?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
            return Ok(());
        }
    }
    unreachable!("u64 nonce space exhausted")
}

fn verify_expected_genesis(config: &NodeConfig, storage: &NodeStorage) -> Result<()> {
    let (configured_header, manifest_hash) = genesis_from_config(config)?;
    if let Some(hash) = manifest_hash {
        let actual = storage
            .header_by_number(blq_primitives::BlockNumber(0))?
            .hash();
        if actual.to_hex() != hash {
            anyhow::bail!("configured genesis manifest does not match stored genesis");
        }
        let pow = blq_pow::blq_rx_hash(&configured_header, blq_primitives::Hash256::ZERO);
        if configured_header.mix_hash != pow.mix_hash
            || !blq_consensus::satisfies_pow(pow.final_hash, configured_header.difficulty_target)
        {
            anyhow::bail!("configured genesis manifest has invalid proof of work");
        }
    }
    let expected = config.node.expected_genesis_hash.as_ref();
    if config.node.required_pow_algorithm.as_deref() == Some("BLQ-RX/2") && expected.is_none() {
        anyhow::bail!("native mainnet config must set expected_genesis_hash");
    }
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected = Hash256::from_hex(expected)
        .map_err(|err| anyhow::anyhow!("invalid expected_genesis_hash: {err:?}"))?;
    let actual = storage
        .header_by_number(blq_primitives::BlockNumber(0))?
        .hash();
    if actual != expected {
        anyhow::bail!(
            "configured genesis hash {} does not match stored genesis {}",
            expected.to_hex(),
            actual.to_hex()
        );
    }
    Ok(())
}

fn storage_status(config: &NodeConfig, storage: &NodeStorage) -> Result<serde_json::Value> {
    let used = storage.disk_usage_bytes()?;
    let max = config.node.max_storage_bytes;
    let generation = storage.generation_status()?;
    let retained_from = storage.oldest_body_height()?.unwrap_or(0);
    let retained_to = storage.best_header()?.number.0;
    let snapshot_heights = storage.snapshot_heights()?;
    let filesystem_free = filesystem_free_bytes(Path::new(&config.node.data_dir));
    let filesystem_blocked =
        filesystem_free.is_some_and(|free| free < config.node.filesystem_reserve_bytes);
    let pressure = if filesystem_blocked {
        "blocked"
    } else if max == 0 {
        "normal"
    } else if used >= max {
        "blocked"
    } else if used.saturating_mul(100) >= max.saturating_mul(85) {
        "near_limit"
    } else if used.saturating_mul(100)
        >= max.saturating_mul(config.node.prune_trigger_percent as u64)
    {
        "pruning"
    } else {
        "normal"
    };
    Ok(serde_json::json!({
        "dataDir": config.node.data_dir,
        "storageMode": config.node.storage_mode,
        "usedBytes": used,
        "quotaBytes": max,
        "maxBytes": max,
        "limited": max > 0,
        "retainedFromHeight": retained_from,
        "retainedToHeight": retained_to,
        "snapshotHeights": snapshot_heights,
        "historicalFallback": config.node.historical_peer_fallback,
        "archivePeers": config.network.bootstrap_peers,
        "diskPressure": pressure,
        "filesystemFreeBytes": filesystem_free.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
        "filesystemReserveBytes": config.node.filesystem_reserve_bytes,
        "pruneTriggerPercent": config.node.prune_trigger_percent,
        "generation": generation,
    }))
}

fn configured_genesis_hash(storage: &NodeStorage) -> Result<Hash256> {
    if let Ok(header) = storage.header_by_number(blq_primitives::BlockNumber(0)) {
        return Ok(header.hash());
    }
    Ok(genesis_header().hash())
}

fn validate_block_for_storage(
    config: &NodeConfig,
    storage: &NodeStorage,
    parent: &BlockHeader,
    block: &Block,
) -> Result<()> {
    validate_block_with_genesis_and_activation(
        parent,
        block,
        configured_genesis_hash(storage)?,
        config.node.block_size_activation_height,
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn validate_header_for_storage(
    storage: &NodeStorage,
    parent: &BlockHeader,
    header: &BlockHeader,
) -> Result<()> {
    validate_header_with_genesis(parent, header, configured_genesis_hash(storage)?)
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn report_storage_usage(config: &NodeConfig, storage: &NodeStorage) -> Result<()> {
    let status = storage_status(config, storage)?;
    eprintln!("storage: {}", serde_json::to_string(&status)?);
    Ok(())
}

fn ensure_storage_cap(config: &NodeConfig, storage: &NodeStorage) -> Result<()> {
    let max = config.node.max_storage_bytes;
    if config.node.pruning_enabled() {
        let root = Path::new(&config.node.data_dir).join("generations");
        let floor = prune_floor(config, storage)?;
        SledStorage::prune_old_generations(&root)?;
        SledStorage::prune_old_snapshots(&root, floor.saturating_sub(64))?;
    }
    let filesystem_free = filesystem_free_bytes(Path::new(&config.node.data_dir));
    if filesystem_free.is_some_and(|free| free < config.node.filesystem_reserve_bytes) {
        if config.node.pruning_enabled() {
            storage.prune_old_blocks(max, prune_floor(config, storage)?)?;
        }
        let free_after = filesystem_free_bytes(Path::new(&config.node.data_dir));
        if free_after.is_some_and(|free| free < config.node.filesystem_reserve_bytes) {
            anyhow::bail!(
                "filesystem reserve unavailable: free {} bytes, reserve {} bytes; node is storage-blocked",
                free_after.unwrap_or(0),
                config.node.filesystem_reserve_bytes
            );
        }
    }
    if max == 0 {
        return Ok(());
    }
    let used = storage.disk_usage_bytes()?;
    if config.node.pruning_enabled()
        && used.saturating_mul(100) >= max.saturating_mul(config.node.prune_trigger_percent as u64)
    {
        storage.prune_old_blocks(max, prune_floor(config, storage)?)?;
    }
    let used = storage.disk_usage_bytes()?;
    if used >= max {
        anyhow::bail!(
            "node storage cap reached: used {} bytes, max {} bytes",
            used,
            max
        );
    }
    Ok(())
}

fn filesystem_free_bytes(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
        if result != 0 {
            return None;
        }
        let stats = unsafe { stats.assume_init() };
        Some((stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_memory_limit(contents: &str) -> Option<u64> {
    let value = contents.trim();
    if value.is_empty() || value == "max" {
        None
    } else {
        value.parse().ok()
    }
}

fn candidate_replay_memory_headroom_available(
    current: Option<u64>,
    high: Option<u64>,
    maximum: Option<u64>,
) -> bool {
    let limit = match (high, maximum) {
        (Some(high), Some(maximum)) => Some(high.min(maximum)),
        (Some(limit), None) | (None, Some(limit)) => Some(limit),
        (None, None) => None,
    };
    match (current, limit) {
        (Some(current), Some(limit)) => {
            current.saturating_add(MIN_CANDIDATE_REPLAY_MEMORY_HEADROOM_BYTES) <= limit
        }
        _ => true,
    }
}

fn ensure_candidate_replay_memory_headroom() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let current = fs::read_to_string("/sys/fs/cgroup/memory.current")
            .ok()
            .and_then(|value| parse_cgroup_memory_limit(&value));
        let high = fs::read_to_string("/sys/fs/cgroup/memory.high")
            .ok()
            .and_then(|value| parse_cgroup_memory_limit(&value));
        let maximum = fs::read_to_string("/sys/fs/cgroup/memory.max")
            .ok()
            .and_then(|value| parse_cgroup_memory_limit(&value));
        if !candidate_replay_memory_headroom_available(current, high, maximum) {
            anyhow::bail!(
                "candidate replay deferred: cgroup memory headroom is below {} bytes",
                MIN_CANDIDATE_REPLAY_MEMORY_HEADROOM_BYTES
            );
        }
    }
    Ok(())
}

fn prune_floor(config: &NodeConfig, storage: &NodeStorage) -> Result<u64> {
    if !config.node.retain_finalized_checkpoints {
        return Ok(0);
    }
    Ok(storage
        .generation_status()?
        .get("finalizedHeight")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0))
}

#[derive(Clone, Debug, Deserialize)]
struct NetworkSection {
    enabled: bool,
    listen: String,
    advertise_addr: Option<String>,
    bootstrap_peers: Vec<String>,
    #[serde(default = "default_max_saved_peers")]
    max_saved_peers: usize,
    #[serde(default = "default_max_inbound_peers")]
    max_inbound_peers: usize,
    discovery_servers: Vec<String>,
    relay_servers: Vec<String>,
    #[serde(default)]
    trusted_peer_keys: Vec<String>,
}

fn default_max_saved_peers() -> usize {
    DEFAULT_MAX_SAVED_PEERS
}

fn default_max_inbound_peers() -> usize {
    P2P_UNTRUSTED_SESSION_LIMIT
}

#[derive(Clone, Debug, Deserialize)]
struct ServiceSection {
    enabled: bool,
    bind: String,
}

enum NodeStorage {
    Full(SledStorage),
    Partial(FileStorage),
}

impl NodeStorage {
    fn begin_sync_batch(&self) {
        if let Self::Full(storage) = self {
            storage.begin_batch();
        }
    }

    fn flush_sync_batch(&self) -> Result<()> {
        if let Self::Full(storage) = self {
            storage.flush_batch()?;
        }
        Ok(())
    }

    fn end_sync_batch(&self) -> Result<()> {
        if let Self::Full(storage) = self {
            storage.end_batch()?;
        }
        Ok(())
    }

    fn generation_work(storage: &SledStorage) -> Result<(u128, BlockHeader)> {
        let best = storage.best_header()?;
        let mut work = 0u128;
        for height in 0..=best.number.0 {
            let header = storage.header_by_number(blq_primitives::BlockNumber(height))?;
            work = work.saturating_add(work_for_target(header.difficulty_target));
        }
        Ok((work, best))
    }

    // A publication record is derived from a verified generation manifest.
    // Older nodes could leave it stale after extending the active chain,
    // causing an otherwise valid generation to be marked Failed at restart.
    // Reconsider only those failed generations that fully validate again,
    // then apply normal cumulative-work selection before changing the active
    // pointer. Corrupt or lower-work generations remain quarantined.
    fn restore_failed_publication_generations(
        config: &NodeConfig,
        generations: &Path,
    ) -> Result<()> {
        if !generations.exists() {
            return Ok(());
        }
        let expected_profile = consensus_profile_for_genesis(
            config
                .node
                .expected_genesis_hash
                .as_deref()
                .and_then(|hash| Hash256::from_hex(hash).ok())
                .unwrap_or_else(|| genesis_header().hash()),
        );
        let active_id = SledStorage::load_active_generation(generations)?;
        let mut best = active_id.and_then(|id| {
            let path = SledStorage::generation_path(generations, id);
            let storage = SledStorage::open(&path).ok()?;
            validate_generation_storage_for_config(config, &storage).ok()?;
            let work = Self::generation_work(&storage).ok()?;
            Some((id, work.0, work.1.hash()))
        });

        for entry in fs::read_dir(generations)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(generation_id) = name
                .strip_prefix("generation-")
                .filter(|_| !name.ends_with(".staging"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            let path = entry.path();
            let Some(failed_manifest) = SledStorage::load_generation_manifest(&path)? else {
                continue;
            };
            if failed_manifest.status != GenerationStatus::Failed
                || failed_manifest.profile_fingerprint != expected_profile
            {
                continue;
            }
            let Some(record) = SledStorage::load_generation_publication(&path)? else {
                continue;
            };
            if record.generation_id != generation_id {
                continue;
            }

            // Make the original status recoverable only while we validate it.
            // Any failed check restores the explicit quarantine marker.
            let mut recovered_manifest = failed_manifest.clone();
            recovered_manifest.status = GenerationStatus::Verified;
            SledStorage::write_generation_manifest(&path, &recovered_manifest)?;
            let recovered = (|| -> Result<(u128, Hash256)> {
                let storage = SledStorage::open(&path)?;
                validate_generation_storage_for_config(config, &storage)?;
                let (work, tip) = Self::generation_work(&storage)?;
                Ok((work, tip.hash()))
            })();
            let Ok((work, hash)) = recovered else {
                SledStorage::write_generation_manifest(&path, &failed_manifest)?;
                continue;
            };
            let wins = best
                .map(|(_, best_work, best_hash)| {
                    work > best_work || (work == best_work && hash < best_hash)
                })
                .unwrap_or(true);
            if wins {
                best = Some((generation_id, work, hash));
            }
        }

        if let Some((generation_id, _, _)) = best {
            if active_id != Some(generation_id) {
                SledStorage::activate_generation(generations, generation_id)?;
                eprintln!(
                    "restored validated generation {} after repairing stale publication metadata",
                    generation_id
                );
            }
        }
        Ok(())
    }

    fn open(config: &NodeConfig) -> Result<Self> {
        match config.node.mode {
            NodeMode::Full => {
                let configured = Path::new(&config.node.data_dir);
                let generations = configured.join("generations");
                Self::restore_failed_publication_generations(config, &generations)?;
                let active_id = SledStorage::load_active_generation(&generations)?;
                let mut candidates = Vec::new();
                if let Some(id) = active_id {
                    candidates.push((id, SledStorage::generation_path(&generations, id)));
                }
                if let Ok(entries) = fs::read_dir(&generations) {
                    let mut discovered = entries
                        .filter_map(|entry| entry.ok())
                        .filter_map(|entry| {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            let id = name
                                .strip_prefix("generation-")
                                .filter(|_| !name.ends_with(".staging"))?
                                .parse::<u64>()
                                .ok()?;
                            Some((id, entry.path()))
                        })
                        .collect::<Vec<_>>();
                    discovered.sort_by_key(|(id, _)| std::cmp::Reverse(*id));
                    candidates.extend(discovered);
                }
                candidates.dedup_by(|left, right| left.0 == right.0);

                for (generation_id, storage_path) in candidates {
                    match SledStorage::open(&storage_path) {
                        Ok(storage) => {
                            match validate_generation_storage_for_config(config, &storage) {
                                Ok(()) => {
                                    if active_id != Some(generation_id) {
                                        eprintln!(
                                    "active generation was invalid; selecting verified generation {}",
                                    generation_id
                                );
                                        SledStorage::activate_generation(
                                            &generations,
                                            generation_id,
                                        )?;
                                    }
                                    let storage = Self::compact_active_generation_if_over_quota(
                                        config,
                                        &generations,
                                        generation_id,
                                        storage,
                                    )?;
                                    ensure_generation_manifest(config, &storage)?;
                                    return Ok(Self::Full(storage));
                                }
                                Err(err) => {
                                    eprintln!(
                                        "ignoring invalid generation {} during startup: {}",
                                        generation_id, err
                                    );
                                    if let Err(mark_err) =
                                        SledStorage::fail_generation(&storage_path)
                                    {
                                        eprintln!(
                                            "could not quarantine invalid generation {}: {}",
                                            generation_id, mark_err
                                        );
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!(
                                "ignoring invalid generation {} during startup: {}",
                                generation_id, err
                            );
                            if let Err(mark_err) = SledStorage::fail_generation(&storage_path) {
                                eprintln!(
                                    "could not quarantine unreadable generation {}: {}",
                                    generation_id, mark_err
                                );
                            }
                        }
                    }
                }

                // A generation can be physically unreadable after an
                // interrupted host write. Periodic BLQ snapshots contain the
                // complete validated keyspace, so recover into a new verified
                // generation before ever falling back to the legacy root DB.
                // The damaged generation is retained untouched for forensics;
                // this is an automatic local storage repair, not a chain
                // rollback or a manual branch selection.
                if let Some(storage) =
                    Self::restore_latest_generation_snapshot(config, &generations)?
                {
                    return Ok(Self::Full(storage));
                }

                let storage = SledStorage::open(configured)?;
                if storage.is_empty() {
                    return Ok(Self::Full(storage));
                }
                validate_generation_storage_for_config(config, &storage)?;
                ensure_generation_manifest(config, &storage)?;
                Ok(Self::Full(storage))
            }
            NodeMode::Partial => Ok(Self::Partial(FileStorage::open(&config.node.data_dir)?)),
        }
    }

    fn restore_latest_generation_snapshot(
        config: &NodeConfig,
        generations: &Path,
    ) -> Result<Option<SledStorage>> {
        if !generations.exists() {
            return Ok(None);
        }
        let expected_profile = consensus_profile_for_genesis(
            config
                .node
                .expected_genesis_hash
                .as_deref()
                .and_then(|hash| Hash256::from_hex(hash).ok())
                .unwrap_or_else(|| genesis_header().hash()),
        );
        let mut snapshots = Vec::new();
        let mut highest_generation = 0u64;
        for entry in fs::read_dir(generations)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name
                .strip_prefix("generation-")
                .filter(|_| !name.ends_with(".staging"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            highest_generation = highest_generation.max(id);
            let Ok(files) = fs::read_dir(entry.path()) else {
                continue;
            };
            for file in files.flatten() {
                let file_name = file.file_name().to_string_lossy().into_owned();
                if !file_name.starts_with("snapshot-") || !file_name.ends_with(".json") {
                    continue;
                }
                match SledStorage::load_snapshot(file.path()) {
                    Ok(snapshot) if snapshot.profile_fingerprint == expected_profile => {
                        snapshots.push(snapshot);
                    }
                    Ok(_) => {}
                    Err(err) => eprintln!(
                        "ignoring unreadable generation snapshot {}: {}",
                        file.path().display(),
                        err
                    ),
                }
            }
        }
        snapshots.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.height));
        for snapshot in snapshots {
            let mut generation_id = highest_generation.saturating_add(1);
            while SledStorage::generation_path(generations, generation_id).exists()
                || SledStorage::staging_generation_path(generations, generation_id).exists()
            {
                generation_id = generation_id.saturating_add(1);
            }
            let manifest = GenerationManifest {
                generation_id,
                status: GenerationStatus::Staging,
                canonical_height: snapshot.height,
                canonical_hash: snapshot.block_hash,
                state_root: snapshot.state_root,
                profile_fingerprint: snapshot.profile_fingerprint.clone(),
                finalized_height: snapshot.finalized_height,
                replay_checkpoint: Some(snapshot.height),
            };
            let staging =
                match SledStorage::open_staging_from_snapshot(generations, &manifest, &snapshot) {
                    Ok(path) => path,
                    Err(err) => {
                        eprintln!(
                            "could not restore generation snapshot at height {}: {}",
                            snapshot.height, err
                        );
                        continue;
                    }
                };
            let verified_manifest = GenerationManifest {
                status: GenerationStatus::Verified,
                ..manifest
            };
            if let Err(err) = SledStorage::write_replay_checkpoint(
                &staging,
                &ReplayCheckpoint {
                    generation_id,
                    height: snapshot.height,
                    block_hash: snapshot.block_hash,
                    state_root: snapshot.state_root,
                },
            )
            .and_then(|_| SledStorage::write_generation_manifest(&staging, &verified_manifest))
            {
                eprintln!("could not mark restored generation for validation: {err}");
                let _ = SledStorage::remove_staging_generation(generations, generation_id);
                continue;
            }
            let restored = match SledStorage::open(&staging) {
                Ok(storage) => storage,
                Err(err) => {
                    eprintln!("restored generation could not open: {err}");
                    let _ = SledStorage::remove_staging_generation(generations, generation_id);
                    continue;
                }
            };
            let validation = validate_generation_storage_for_config(config, &restored);
            drop(restored);
            if let Err(err) = validation {
                eprintln!("restored generation snapshot validation failed: {err}");
                let _ = SledStorage::remove_staging_generation(generations, generation_id);
                continue;
            }
            if let Err(err) = SledStorage::publish_staging_generation(
                generations,
                generation_id,
                &verified_manifest,
            ) {
                eprintln!("could not publish restored generation snapshot: {err}");
                let _ = SledStorage::remove_staging_generation(generations, generation_id);
                continue;
            }
            eprintln!(
                "recovered verified generation {} from snapshot at height {}",
                generation_id, snapshot.height
            );
            return SledStorage::open(SledStorage::generation_path(generations, generation_id))
                .map(Some)
                .map_err(Into::into);
        }
        Ok(None)
    }

    /// Sled keeps obsolete value pages until a fresh database is written. A
    /// pruned node can therefore exceed its BLQ quota even after safe logical
    /// pruning. Rebuild the *verified active generation* from its complete
    /// snapshot on startup, then atomically publish the equivalent compact
    /// generation. This is storage maintenance only: the snapshot must prove
    /// the same canonical height, hash, roots, and consensus profile.
    fn compact_active_generation_if_over_quota(
        config: &NodeConfig,
        generations: &Path,
        active_id: u64,
        storage: SledStorage,
    ) -> Result<SledStorage> {
        let quota = config.node.max_storage_bytes;
        if quota == 0 || !config.node.pruning_enabled() || storage.disk_usage_bytes()? < quota {
            return Ok(storage);
        }

        let manifest = storage.verify_generation_manifest()?;
        let snapshot = SledStorage::latest_snapshot_at_or_before(
            storage.data_dir(),
            manifest.canonical_height,
            &manifest.profile_fingerprint,
        )?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "pruned active generation exceeds quota but has no verified snapshot for compaction"
            )
        })?;
        if snapshot.height != manifest.canonical_height
            || snapshot.block_hash != manifest.canonical_hash
            || snapshot.state_root != manifest.state_root
            || snapshot.profile_fingerprint != manifest.profile_fingerprint
        {
            anyhow::bail!(
                "pruned active generation exceeds quota but its tip snapshot does not match the active manifest"
            );
        }

        let snapshot_bytes = fs::metadata(SledStorage::snapshot_path(
            storage.data_dir(),
            snapshot.height,
        ))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
        let required_free = config
            .node
            .filesystem_reserve_bytes
            .saturating_add(snapshot_bytes.saturating_mul(2));
        let available_free = filesystem_free_bytes(Path::new(&config.node.data_dir)).unwrap_or(0);
        if available_free < required_free {
            anyhow::bail!(
                "pruned active generation exceeds quota and compaction needs {} free bytes (have {})",
                required_free,
                available_free
            );
        }

        let mut generation_id = active_id.saturating_add(1);
        while SledStorage::generation_path(generations, generation_id).exists()
            || SledStorage::staging_generation_path(generations, generation_id).exists()
        {
            generation_id = generation_id.saturating_add(1);
        }
        let compact_manifest = GenerationManifest {
            generation_id,
            status: GenerationStatus::Staging,
            canonical_height: manifest.canonical_height,
            canonical_hash: manifest.canonical_hash,
            state_root: manifest.state_root,
            profile_fingerprint: manifest.profile_fingerprint.clone(),
            finalized_height: manifest.finalized_height,
            replay_checkpoint: Some(manifest.canonical_height),
        };
        let staging =
            SledStorage::open_staging_from_snapshot(generations, &compact_manifest, &snapshot)?;
        let verified_manifest = GenerationManifest {
            status: GenerationStatus::Verified,
            ..compact_manifest
        };
        let checkpoint = ReplayCheckpoint {
            generation_id,
            height: snapshot.height,
            block_hash: snapshot.block_hash,
            state_root: snapshot.state_root,
        };
        if let Err(error) = SledStorage::write_replay_checkpoint(&staging, &checkpoint)
            .and_then(|_| SledStorage::write_generation_manifest(&staging, &verified_manifest))
        {
            let _ = SledStorage::remove_staging_generation(generations, generation_id);
            return Err(error.into());
        }
        let compacted = match SledStorage::open(&staging) {
            Ok(compacted) => compacted,
            Err(error) => {
                let _ = SledStorage::remove_staging_generation(generations, generation_id);
                return Err(error.into());
            }
        };
        if let Err(error) = compacted.verify_generation_manifest() {
            drop(compacted);
            let _ = SledStorage::remove_staging_generation(generations, generation_id);
            return Err(error.into());
        }
        drop(compacted);
        let published = match SledStorage::publish_staging_generation(
            generations,
            generation_id,
            &verified_manifest,
        ) {
            Ok(path) => path,
            Err(error) => {
                let _ = SledStorage::remove_staging_generation(generations, generation_id);
                return Err(error.into());
            }
        };
        drop(storage);
        eprintln!(
            "compacted over-quota pruned generation {} into verified generation {} at height {}",
            active_id, generation_id, manifest.canonical_height
        );
        SledStorage::open(published).map_err(Into::into)
    }

    /// Run the same verified compaction used at startup before admitting an
    /// isolated candidate replay. Candidate publication otherwise checks the
    /// quota first and can retry a fully available branch forever when sled's
    /// obsolete pages put the active generation over its logical quota.
    fn compact_active_generation_for_live_replay(&mut self, config: &NodeConfig) -> Result<bool> {
        let Self::Full(active) = self else {
            return Ok(false);
        };
        let quota = config.node.max_storage_bytes;
        if quota == 0 || !config.node.pruning_enabled() || active.disk_usage_bytes()? < quota {
            return Ok(false);
        }

        let generations = Path::new(&config.node.data_dir).join("generations");
        let active_id = SledStorage::load_active_generation(&generations)?.ok_or_else(|| {
            anyhow::anyhow!("candidate replay deferred: active generation manifest is unavailable")
        })?;
        // Open a short-lived handle so the existing active handle remains
        // intact until the replacement generation has passed every snapshot
        // and manifest check. The atomic publish switches the manifest first;
        // assigning below then drops the old handle.
        let detached = SledStorage::open(active.data_dir())?;
        let compacted = Self::compact_active_generation_if_over_quota(
            config,
            &generations,
            active_id,
            detached,
        )?;
        *active = compacted;
        Ok(true)
    }

    /// A compaction replacement is occasionally retained as the generic
    /// "previous generation" even though its manifest proves it represents
    /// exactly the same verified tip as the active compact generation. On a
    /// small pruned host that duplicate can consume the staging reserve and
    /// deadlock live candidate publication. Reclaim only those exact
    /// equivalents; a prior generation at a different canonical tip remains
    /// a recovery fallback and is never selected here.
    fn reclaim_snapshot_equivalent_generations(
        &self,
        config: &NodeConfig,
        required_free: u64,
    ) -> Result<bool> {
        if !config.node.pruning_enabled()
            || filesystem_free_bytes(Path::new(&config.node.data_dir))
                .is_some_and(|free| free >= required_free)
        {
            return Ok(false);
        }
        let Self::Full(active) = self else {
            return Ok(false);
        };
        let root = Path::new(&config.node.data_dir).join("generations");
        let Some(active_id) = SledStorage::load_active_generation(&root)? else {
            return Ok(false);
        };
        let active_manifest = active.verify_generation_manifest()?;
        let mut reclaimed = false;
        let entries = fs::read_dir(&root)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("generation-") || name.ends_with(".staging") {
                continue;
            }
            let Some(id) = name
                .strip_prefix("generation-")
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            if id == active_id {
                continue;
            }
            let path = entry.path();
            let Some(manifest) = SledStorage::load_generation_manifest(&path)? else {
                continue;
            };
            let equivalent = matches!(
                manifest.status,
                GenerationStatus::Verified | GenerationStatus::Active
            ) && manifest.canonical_height == active_manifest.canonical_height
                && manifest.canonical_hash == active_manifest.canonical_hash
                && manifest.state_root == active_manifest.state_root
                && manifest.profile_fingerprint == active_manifest.profile_fingerprint
                && manifest.finalized_height == active_manifest.finalized_height;
            if !equivalent {
                continue;
            }
            SledStorage::retire_generation(&path)?;
            fs::remove_dir_all(&path)?;
            reclaimed = true;
            eprintln!(
                "reclaimed snapshot-equivalent generation {} before candidate replay",
                id
            );
            if filesystem_free_bytes(Path::new(&config.node.data_dir))
                .is_some_and(|free| free >= required_free)
            {
                break;
            }
        }
        Ok(reclaimed)
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Full(storage) => storage.is_empty(),
            Self::Partial(storage) => storage.is_empty(),
        }
    }

    fn disk_usage_bytes(&self) -> Result<u64> {
        Ok(match self {
            Self::Full(storage) => storage.disk_usage_bytes()?,
            Self::Partial(storage) => storage.disk_usage_bytes()?,
        })
    }

    fn data_dir(&self) -> std::path::PathBuf {
        match self {
            Self::Full(storage) => storage.data_dir().to_path_buf(),
            Self::Partial(_) => std::path::PathBuf::new(),
        }
    }

    fn generation_status(&self) -> Result<serde_json::Value> {
        let data_dir = self.data_dir();
        let root = if data_dir
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("generation-"))
            && data_dir
                .parent()
                .is_some_and(|parent| parent.file_name().is_some_and(|name| name == "generations"))
        {
            data_dir
                .parent()
                .expect("generation directory has a parent")
                .to_path_buf()
        } else {
            data_dir.join("generations")
        };
        let active = SledStorage::load_active_generation(&root)?;
        let manifest = active
            .map(|id| {
                SledStorage::load_generation_manifest(SledStorage::generation_path(&root, id))
            })
            .transpose()?
            .flatten();
        let replay_checkpoint = active
            .map(|id| SledStorage::load_replay_checkpoint(SledStorage::generation_path(&root, id)))
            .transpose()?
            .flatten();
        let staging_count = std::fs::read_dir(&root)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".staging"))
                    .count()
            })
            .unwrap_or(0);
        let candidate = match self {
            Self::Full(storage) => storage.latest_candidate_tip().ok().flatten(),
            Self::Partial(_) => None,
        };
        Ok(serde_json::json!({
            "activeId": active,
            "status": manifest.as_ref().map(|item| format!("{:?}", item.status).to_lowercase()),
            "activeHeight": manifest.as_ref().map(|item| item.canonical_height),
            "activeHash": manifest.as_ref().map(|item| item.canonical_hash.to_hex()),
            "stateRoot": manifest.as_ref().map(|item| item.state_root.to_hex()),
            "finalizedHeight": manifest.as_ref().map(|item| item.finalized_height),
            "replayProgress": replay_checkpoint.as_ref().map(|checkpoint| serde_json::json!({
                "generationId": checkpoint.generation_id,
                "height": checkpoint.height,
                "blockHash": checkpoint.block_hash.to_hex(),
                "stateRoot": checkpoint.state_root.to_hex(),
            })),
            "candidateTip": candidate.as_ref().map(|(header, _)| serde_json::json!({
                "height": header.number.0,
                "hash": header.hash().to_hex(),
                "stateRoot": header.state_root.to_hex(),
            })),
            "candidateWork": candidate.as_ref().map(|(_, work)| format!("0x{:x}", work)),
            "stagingCount": staging_count,
            "publicationPending": staging_count > 0,
        }))
    }

    fn headers_after(&self, number: u64, limit: usize) -> Result<Vec<BlockHeader>> {
        match self {
            Self::Full(storage) => Ok(storage.headers_after(number, limit)?),
            Self::Partial(storage) => Ok(storage.headers_after(number, limit)),
        }
    }

    fn balance(&self, address: Address) -> Result<Bix> {
        Ok(match self {
            Self::Full(storage) => storage.balance(address)?,
            Self::Partial(_) => Bix(0),
        })
    }

    fn nonce(&self, address: Address) -> Result<u64> {
        Ok(match self {
            Self::Full(storage) => storage.nonce(address)?,
            Self::Partial(_) => 0,
        })
    }

    fn transaction_by_hash(&self, hash: Hash256) -> Result<Transaction, blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.transaction_by_hash(hash),
            Self::Partial(_) => Err(blq_storage::StorageError::NotFound),
        }
    }

    fn transaction_receipt_by_hash(
        &self,
        hash: Hash256,
    ) -> Result<(Receipt, BlockHeader, usize, Transaction), blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.transaction_receipt_by_hash(hash),
            Self::Partial(_) => Err(blq_storage::StorageError::NotFound),
        }
    }

    fn indexed_transaction_receipt_by_hash(
        &self,
        hash: Hash256,
    ) -> Result<(Receipt, BlockHeader, usize, Transaction), blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.indexed_transaction_receipt_by_hash(hash),
            Self::Partial(_) => Err(blq_storage::StorageError::NotFound),
        }
    }

    fn backfill_rewards(&mut self) -> Result<()> {
        let Self::Full(storage) = self else {
            return Ok(());
        };
        let best = match storage.best_header() {
            Ok(header) => header.number.0,
            Err(blq_storage::StorageError::NotFound) => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let indexed_to = storage.reward_indexed_to()?;
        if indexed_to >= best {
            return Ok(());
        }
        if storage.has_persisted_native_accounts()? {
            // A published generation's manifest already binds its tip state
            // root. Older databases can lack only this derived progress
            // marker; replaying the entire archive at boot is both redundant
            // and unsafe on a memory-constrained archive host.
            storage.set_reward_indexed_to(best)?;
            return Ok(());
        }
        for number in indexed_to.saturating_add(1)..=best {
            let block = storage.block_by_number(number)?;
            if block.transactions.iter().any(is_evm_transaction) {
                // EVM blocks persist their merged balance/nonce state and EVM
                // state during insertion; do not replay them through the
                // legacy transfer-only reward backfill path.
                storage.set_reward_indexed_to(number)?;
                continue;
            }
            let accounts = simulate_state_transition_from_accounts(
                storage.account_snapshot()?,
                &block,
                if block.header.number.0 == 0 {
                    0
                } else {
                    storage
                        .header_by_number(blq_primitives::BlockNumber(block.header.number.0 - 1))?
                        .timestamp_seconds
                },
            )?
            .0;
            for (address, (balance, nonce)) in accounts {
                storage.put_account(address, balance, nonce)?;
            }
            storage.set_reward_indexed_to(number)?;
        }
        Ok(())
    }

    fn account_snapshot(&self) -> Result<std::collections::BTreeMap<Address, (Bix, u64)>> {
        Ok(match self {
            Self::Full(storage) => storage.account_snapshot()?,
            Self::Partial(_) => std::collections::BTreeMap::new(),
        })
    }

    fn evm_state(&self) -> Result<RevmState> {
        let Self::Full(storage) = self else {
            anyhow::bail!("EVM state is unavailable on partial storage")
        };
        let mut state = RevmState::default();
        for (address, (balance, nonce, code, slots)) in storage.evm_account_snapshot()? {
            let mut storage_slots = std::collections::BTreeMap::new();
            for (slot, value) in slots {
                storage_slots.insert(
                    alloy_primitives::U256::from_be_bytes(slot.0),
                    alloy_primitives::U256::from_be_bytes(value.0),
                );
            }
            state.put_account(
                alloy_primitives::Address::from(address.0),
                RevmAccount {
                    nonce,
                    balance: alloy_primitives::U256::from(balance.0),
                    code,
                    storage: storage_slots,
                },
            );
        }
        merge_native_accounts_into_revm_state(&mut state, storage.account_snapshot()?);
        Ok(state)
    }

    fn evm_code(&self, address: Address) -> Result<Vec<u8>> {
        match self {
            Self::Full(storage) => Ok(storage.evm_code(address)?),
            Self::Partial(_) => anyhow::bail!("EVM code is unavailable on partial storage"),
        }
    }

    fn evm_storage_at(&self, address: Address, slot: Hash256) -> Result<Hash256> {
        match self {
            Self::Full(storage) => Ok(storage.evm_storage_at(address, slot)?),
            Self::Partial(_) => anyhow::bail!("EVM storage is unavailable on partial storage"),
        }
    }

    fn prune_old_blocks(&self, max_bytes: u64, minimum_body_height: u64) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.prune_old_blocks(max_bytes, minimum_body_height)?),
            Self::Partial(_) => Ok(()),
        }
    }

    fn oldest_body_height(&self) -> Result<Option<u64>> {
        match self {
            Self::Full(storage) => Ok(storage.oldest_body_height()?),
            Self::Partial(storage) => Ok(storage
                .headers_after(0, usize::MAX)
                .first()
                .map(|header| header.number.0)),
        }
    }

    fn snapshot_heights(&self) -> Result<Vec<u64>> {
        let Self::Full(storage) = self else {
            return Ok(Vec::new());
        };
        let root = storage.data_dir().join("generations");
        let Some(active_id) = SledStorage::load_active_generation(&root)? else {
            return Ok(Vec::new());
        };
        let path = SledStorage::generation_path(&root, active_id);
        let Ok(entries) = fs::read_dir(path) else {
            return Ok(Vec::new());
        };
        let mut heights = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.strip_prefix("snapshot-")
                    .and_then(|value| value.strip_suffix(".json"))
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .collect::<Vec<_>>();
        heights.sort_unstable();
        Ok(heights)
    }

    fn store_orphan_block(&self, block: &Block) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.store_orphan_block(block)?),
            Self::Partial(_) => anyhow::bail!("orphan blocks require full storage"),
        }
    }

    fn canonical_blocks(&self) -> Result<Vec<Block>> {
        match self {
            Self::Full(storage) => Ok(storage.canonical_blocks()?),
            Self::Partial(_) => anyhow::bail!("canonical block bodies require full storage"),
        }
    }

    fn block_by_hash(&self, hash: Hash256) -> Result<Block> {
        match self {
            Self::Full(storage) => Ok(storage.block_by_hash(hash)?),
            Self::Partial(_) => anyhow::bail!("block bodies require full storage"),
        }
    }

    fn sync_block_by_hash(&self, hash: Hash256) -> Result<Block> {
        let Self::Full(storage) = self else {
            anyhow::bail!("block bodies require full storage");
        };
        if let Ok(block) = storage.block_by_hash(hash) {
            return Ok(block);
        }
        if let Ok(block) = storage.candidate_block_by_hash(hash) {
            return Ok(block);
        }
        storage
            .orphan_blocks()?
            .into_iter()
            .find(|block| block.header.hash() == hash)
            .ok_or_else(|| anyhow::anyhow!("block {} was not found", hash.to_hex()))
    }

    fn difficulty_header_by_hash(&self, hash: Hash256) -> Result<BlockHeader> {
        if let Ok(header) = self.header_by_hash(hash) {
            return Ok(header);
        }
        self.recovery_spool_block_by_hash(hash)
            .map(|(block, _)| block.header)
    }

    fn latest_candidate_tip(&self) -> Result<Option<(BlockHeader, u128)>> {
        match self {
            Self::Full(storage) => Ok(storage.latest_candidate_tip()?),
            Self::Partial(_) => Ok(None),
        }
    }

    fn indexed_log_block_numbers(
        &self,
        from: u64,
        to: u64,
        addresses: Option<&[Address]>,
        topics: Option<&[Hash256]>,
    ) -> Result<BTreeSet<u64>> {
        match self {
            Self::Full(storage) => {
                Ok(storage.indexed_log_block_numbers(from, to, addresses, topics)?)
            }
            Self::Partial(_) => anyhow::bail!("log indexes require full storage"),
        }
    }

    fn store_candidate_block(&self, block: &Block, cumulative_work: u128) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.store_candidate_block(block, cumulative_work)?),
            Self::Partial(_) => anyhow::bail!("candidate block bodies require full storage"),
        }
    }

    fn remove_candidate_blocks(&self, hashes: &[Hash256]) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.remove_candidate_blocks(hashes)?),
            Self::Partial(_) => Ok(()),
        }
    }

    fn store_recovery_spool_block(
        &self,
        tip_hash: Hash256,
        block: &Block,
        cumulative_work: u128,
    ) -> Result<()> {
        match self {
            Self::Full(storage) => {
                Ok(storage.store_recovery_block_unflushed(tip_hash, block, cumulative_work)?)
            }
            Self::Partial(_) => anyhow::bail!("recovery spool requires full storage"),
        }
    }

    fn recovery_spool_block_by_hash(&self, hash: Hash256) -> Result<(Block, u128)> {
        match self {
            Self::Full(storage) => Ok(storage.recovery_block_by_hash(hash)?),
            Self::Partial(_) => anyhow::bail!("recovery spool requires full storage"),
        }
    }

    fn recovery_spool_blocks_for_tip(&self, tip_hash: Hash256) -> Result<Vec<(Block, u128)>> {
        match self {
            Self::Full(storage) => Ok(storage.recovery_blocks_for_tip(tip_hash)?),
            Self::Partial(_) => anyhow::bail!("recovery spool requires full storage"),
        }
    }

    fn recovery_spool_tips(&self) -> Result<Vec<Hash256>> {
        match self {
            Self::Full(storage) => Ok(storage.recovery_spool_tips()?),
            Self::Partial(_) => Ok(Vec::new()),
        }
    }

    fn clear_recovery_spool_for_tip(&self, tip_hash: Hash256) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.clear_recovery_blocks_for_tip(tip_hash)?),
            Self::Partial(_) => Ok(()),
        }
    }

    fn candidate_work(&self, hash: Hash256) -> Result<u128> {
        match self {
            Self::Full(storage) => Ok(storage.candidate_work(hash)?),
            Self::Partial(_) => anyhow::bail!("candidate block bodies require full storage"),
        }
    }

    fn quarantine_candidate_tip(&self, hash: Hash256, reason: &str) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.quarantine_candidate_tip(hash, reason)?),
            Self::Partial(_) => Ok(()),
        }
    }

    fn clear_canonical_state(&self) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.clear_canonical_state()?),
            Self::Partial(_) => anyhow::bail!("canonical state requires full storage"),
        }
    }

    fn orphan_blocks(&self) -> Result<Vec<Block>> {
        match self {
            Self::Full(storage) => Ok(storage.orphan_blocks()?),
            Self::Partial(_) => Ok(Vec::new()),
        }
    }

    fn remove_orphan_block(&self, hash: Hash256) -> Result<()> {
        match self {
            Self::Full(storage) => Ok(storage.remove_orphan_block(hash)?),
            Self::Partial(_) => Ok(()),
        }
    }
}

fn validate_generation_storage(storage: &SledStorage, pruned: bool) -> Result<()> {
    let best = match storage.best_header() {
        Ok(header) => header,
        Err(blq_storage::StorageError::NotFound) => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let mut previous = storage.header_by_number(blq_primitives::BlockNumber(0))?;
    for number in 1..=best.number.0 {
        let header = storage.header_by_number(blq_primitives::BlockNumber(number))?;
        if header.number.0 != previous.number.0.saturating_add(1) {
            anyhow::bail!("canonical generation has a height gap at height {number}");
        }
        if header.parent_hash != previous.hash() {
            anyhow::bail!("canonical generation has a broken parent link at height {number}");
        }
        if !pruned {
            let block = storage.block_by_number(number)?;
            if block.header != header {
                anyhow::bail!("canonical generation block/header mismatch at height {number}");
            }
        }
        previous = header;
    }
    if previous.hash() != best.hash() {
        anyhow::bail!("canonical generation best-header index is inconsistent");
    }
    if SledStorage::load_generation_manifest(storage.data_dir())?.is_some() {
        storage.verify_generation_manifest()?;
    }
    Ok(())
}

/// Startup must be bounded even for an archive generation that contains far
/// more history than the host can cache. Publication/replay has already run
/// the strict complete-chain validator above; reopening a published generation
/// only needs to prove its durable manifest, genesis anchor, and canonical tip.
fn validate_generation_storage_on_open(storage: &SledStorage, pruned: bool) -> Result<()> {
    if pruned {
        return validate_generation_storage(storage, true);
    }
    let best = storage.best_header()?;
    let tip = storage.header_by_number(best.number)?;
    if tip.hash() != best.hash() {
        anyhow::bail!("archive generation best-header index is inconsistent");
    }
    storage.verify_generation_manifest()?;
    Ok(())
}

/// A generation manifest is derived metadata, not the chain identity itself.
/// Every path that can select, restore, or publish a generation must anchor
/// the stored block zero to the configured network before the generation can
/// become active. This keeps a stale or failed generation from bypassing the
/// startup-only genesis check after a recovery transition.
fn validate_generation_identity(config: &NodeConfig, storage: &SledStorage) -> Result<()> {
    let expected = config
        .node
        .expected_genesis_hash
        .as_deref()
        .map(Hash256::from_hex)
        .transpose()
        .map_err(|err| anyhow::anyhow!("invalid expected_genesis_hash: {err:?}"))?;
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = storage
        .header_by_number(blq_primitives::BlockNumber(0))?
        .hash();
    if actual != expected {
        anyhow::bail!(
            "generation genesis {} does not match configured genesis {}",
            actual.to_hex(),
            expected.to_hex()
        );
    }
    let expected_profile = consensus_profile_for_genesis(expected);
    if let Some(manifest) = SledStorage::load_generation_manifest(storage.data_dir())? {
        if manifest.profile_fingerprint != expected_profile {
            anyhow::bail!("generation consensus profile does not match configured genesis");
        }
    }
    Ok(())
}

fn validate_generation_storage_for_config(
    config: &NodeConfig,
    storage: &SledStorage,
) -> Result<()> {
    validate_generation_identity(config, storage)?;
    validate_generation_storage_on_open(storage, config.node.pruning_enabled())
}

fn ensure_generation_manifest(config: &NodeConfig, storage: &SledStorage) -> Result<()> {
    let path = storage.data_dir();
    if storage.is_empty() {
        return Ok(());
    }
    let best = match storage.best_header() {
        Ok(header) => header,
        Err(blq_storage::StorageError::NotFound) => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    if let Some(manifest) = SledStorage::load_generation_manifest(path)? {
        if manifest.status == GenerationStatus::Active
            && (manifest.canonical_height != best.number.0
                || manifest.canonical_hash != best.hash()
                || manifest.state_root != best.state_root)
        {
            anyhow::bail!(
                "active generation manifest does not match canonical tip: manifest {} {}, storage {} {}",
                manifest.canonical_height,
                manifest.canonical_hash.to_hex(),
                best.number.0,
                best.hash().to_hex()
            );
        }
        storage.verify_generation_manifest()?;
        return Ok(());
    }
    let genesis_hash = match storage.header_by_number(blq_primitives::BlockNumber(0)) {
        Ok(h) => h.hash(),
        Err(blq_storage::StorageError::NotFound) => genesis_header().hash(),
        Err(err) => return Err(err.into()),
    };
    SledStorage::write_generation_manifest(
        path,
        &GenerationManifest {
            generation_id: 0,
            status: GenerationStatus::Active,
            canonical_height: best.number.0,
            canonical_hash: best.hash(),
            state_root: best.state_root,
            profile_fingerprint: consensus_profile_for_genesis(genesis_hash),
            finalized_height: finalized_height(best.number.0),
            replay_checkpoint: None,
        },
    )?;
    eprintln!(
        "initialized generation 0 manifest for {} at height {}",
        config.node.data_dir, best.number.0
    );
    Ok(())
}

impl ChainStorage for NodeStorage {
    fn best_header(&self) -> Result<BlockHeader, blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.best_header(),
            Self::Partial(storage) => storage.best_header(),
        }
    }

    fn header_by_hash(
        &self,
        hash: blq_primitives::Hash256,
    ) -> Result<BlockHeader, blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.header_by_hash(hash),
            Self::Partial(storage) => storage.header_by_hash(hash),
        }
    }

    fn header_by_number(
        &self,
        number: blq_primitives::BlockNumber,
    ) -> Result<BlockHeader, blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.header_by_number(number),
            Self::Partial(storage) => storage.header_by_number(number),
        }
    }

    fn insert_header(&mut self, header: BlockHeader) -> Result<(), blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.insert_header(header),
            Self::Partial(storage) => storage.insert_header(header),
        }
    }

    fn insert_block(
        &mut self,
        block: blq_primitives::Block,
    ) -> Result<(), blq_storage::StorageError> {
        match self {
            Self::Full(storage) => {
                let result = if block.transactions.iter().any(is_evm_transaction) {
                    let parent_timestamp = if block.header.number.0 == 0 {
                        0
                    } else {
                        storage
                            .header_by_number(blq_primitives::BlockNumber(
                                block.header.number.0 - 1,
                            ))?
                            .timestamp_seconds
                    };
                    let simulation = simulate_evm_state_transition_from_state(
                        revm_state_from_sled(storage)?,
                        &block,
                        parent_timestamp,
                    )
                    .map_err(|err| blq_storage::StorageError::Serialization(err.to_string()))?;
                    storage.insert_block(block.clone())?;
                    persist_revm_state(storage, &simulation.state)?;
                    storage.set_reward_indexed_to(block.header.number.0)
                } else {
                    let parent_timestamp = if block.header.number.0 == 0 {
                        0
                    } else {
                        storage
                            .header_by_number(blq_primitives::BlockNumber(
                                block.header.number.0 - 1,
                            ))?
                            .timestamp_seconds
                    };
                    let accounts = simulate_state_transition_from_accounts(
                        storage.account_snapshot()?,
                        &block,
                        parent_timestamp,
                    )
                    .map_err(|err| blq_storage::StorageError::Serialization(err.to_string()))?
                    .0;
                    storage.insert_block(block.clone())?;
                    for (address, (balance, nonce)) in accounts {
                        storage.put_account(address, balance, nonce)?;
                    }
                    storage.set_reward_indexed_to(block.header.number.0)
                };
                result?;
                persist_historical_evm_snapshot(storage, block.header.number.0)?;
                refresh_generation_manifest(storage)
            }
            Self::Partial(storage) => storage.insert_block(block),
        }
    }

    fn block_by_number(
        &self,
        number: u64,
    ) -> Result<blq_primitives::Block, blq_storage::StorageError> {
        match self {
            Self::Full(storage) => storage.block_by_number(number),
            Self::Partial(storage) => storage.block_by_number(number),
        }
    }
}

fn refresh_generation_manifest(storage: &SledStorage) -> Result<(), blq_storage::StorageError> {
    let Some(mut manifest) = SledStorage::load_generation_manifest(storage.data_dir())? else {
        return Ok(());
    };
    let best = storage.best_header()?;
    manifest.status = GenerationStatus::Active;
    manifest.canonical_height = best.number.0;
    manifest.canonical_hash = best.hash();
    manifest.state_root = best.state_root;
    manifest.finalized_height = finalized_height(best.number.0);
    SledStorage::write_generation_manifest(storage.data_dir(), &manifest)?;
    SledStorage::write_generation_publication(storage.data_dir(), &manifest)
}

fn persist_revm_state(
    storage: &SledStorage,
    state: &RevmState,
) -> Result<(), blq_storage::StorageError> {
    for (address, account) in &state.accounts {
        let balance = u128::try_from(account.balance).map_err(|_| {
            blq_storage::StorageError::Serialization(
                "EVM balance exceeds BLQ account range".to_string(),
            )
        })?;
        let mut slots = std::collections::BTreeMap::new();
        for (slot, value) in &account.storage {
            slots.insert(Hash256(slot.to_be_bytes()), Hash256(value.to_be_bytes()));
        }
        storage.put_evm_account(
            Address(address.into_array()),
            Bix(balance),
            account.nonce,
            &account.code,
            &slots,
        )?;
    }
    Ok(())
}

fn persist_historical_evm_snapshot(
    storage: &SledStorage,
    number: u64,
) -> Result<(), blq_storage::StorageError> {
    if number % EVM_STATE_SNAPSHOT_INTERVAL != 0 {
        return Ok(());
    }
    let snapshot = storage.evm_account_snapshot()?;
    storage.put_evm_state_snapshot(number, &snapshot)
}

fn revm_state_from_sled(storage: &SledStorage) -> Result<RevmState, blq_storage::StorageError> {
    let mut state = RevmState::default();
    for (address, (balance, nonce, code, slots)) in storage.evm_account_snapshot()? {
        let mut storage_slots = std::collections::BTreeMap::new();
        for (slot, value) in slots {
            storage_slots.insert(
                alloy_primitives::U256::from_be_bytes(slot.0),
                alloy_primitives::U256::from_be_bytes(value.0),
            );
        }
        state.put_account(
            alloy_primitives::Address::from(address.0),
            RevmAccount {
                nonce,
                balance: alloy_primitives::U256::from(balance.0),
                code,
                storage: storage_slots,
            },
        );
    }
    merge_native_accounts_into_revm_state(&mut state, storage.account_snapshot()?);
    Ok(state)
}

fn merge_native_accounts_into_revm_state(
    state: &mut RevmState,
    accounts: std::collections::BTreeMap<Address, (Bix, u64)>,
) {
    for (address, (balance, nonce)) in accounts {
        let evm_address = alloy_primitives::Address::from(address.0);
        let mut account = state.account(evm_address);
        account.balance = alloy_primitives::U256::from(balance.0);
        account.nonce = nonce;
        state.put_account(evm_address, account);
    }
}

impl NodeConfig {
    fn load(path: Option<&str>) -> Result<Self> {
        let path = path.unwrap_or("config/public-node.toml");
        let config = fs::read_to_string(Path::new(path))?;
        let config: Self = toml::from_str(&config)?;
        if config
            .node
            .block_time_v2_activation_height
            .is_some_and(|height| height == 0)
        {
            anyhow::bail!("block_time_v2_activation_height must be above genesis");
        }
        if let Some(required) = &config.node.required_pow_algorithm {
            if required != blq_pow::POW_ALGORITHM {
                anyhow::bail!(
                    "config requires PoW algorithm {required}, but this binary provides {}",
                    blq_pow::POW_ALGORITHM
                );
            }
        }
        if config.network.max_saved_peers == 0 || config.network.max_saved_peers > MAX_SAVED_PEERS {
            anyhow::bail!("network.max_saved_peers must be between 1 and {MAX_SAVED_PEERS}");
        }
        if config.network.max_inbound_peers == 0
            || config.network.max_inbound_peers > P2P_UNTRUSTED_SESSION_LIMIT
        {
            anyhow::bail!(
                "network.max_inbound_peers must be between 1 and {P2P_UNTRUSTED_SESSION_LIMIT} to preserve outbound recovery capacity"
            );
        }
        Ok(config)
    }
}

fn active_block_time_target_seconds(config: &NodeConfig, height: u64) -> u64 {
    if config
        .node
        .block_time_v2_activation_height
        .is_some_and(|activation| height >= activation)
    {
        blq_primitives::BLOCK_TIME_V2_TARGET_SECONDS
    } else {
        blq_primitives::TARGET_BLOCK_TIME_SECONDS
    }
}

fn start_optional_services(config: &NodeConfig) {
    if config.discovery.enabled {
        let bind = config.discovery.bind.clone();
        thread::spawn(move || {
            if let Err(err) = run_discovery_server(&bind) {
                eprintln!("discovery server failed: {err}");
            }
        });
    }
    if config.relay.enabled {
        let bind = config.relay.bind.clone();
        thread::spawn(move || {
            if let Err(err) = run_relay_node(&bind) {
                eprintln!("relay node failed: {err}");
            }
        });
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum P2pMessage {
    Hello {
        node_mode: NodeMode,
        best_number: u64,
        best_hash: String,
        consensus_profile: String,
        identity_public_key: String,
        identity_signature: String,
        tls_certificate_hash: String,
    },
    GetHeaders {
        from: u64,
        limit: usize,
    },
    Headers {
        headers: Vec<BlockHeader>,
    },
    /// A Bitcoin-style locator is exchanged after the authenticated hello so
    /// a deep competing branch can be recovered forward from its actual
    /// ancestor instead of walking every parent hash back from the tip.
    FindCommonAncestor {
        locator: Vec<String>,
    },
    CommonAncestor {
        height: Option<u64>,
        hash: Option<String>,
    },
    GetBlock {
        number: u64,
    },
    /// Authenticated contiguous body transfer. The provider emits the bounded
    /// response as ordered BlockBody frames so normal frame limits still apply.
    GetBlockRange {
        from: u64,
        limit: usize,
    },
    /// Bounded independent verification for a bulk recovery range. The
    /// witness returns headers only; it never becomes a second full downloader.
    WitnessHeaders {
        tip_hash: String,
        heights: Vec<u64>,
    },
    WitnessHeadersResponse {
        tip_hash: String,
        headers: Vec<BlockHeader>,
    },
    GetBlockByHash {
        hash: String,
    },
    BlockBody {
        block: blq_primitives::Block,
    },
    BlockNotFound {
        hash: String,
    },
    GetTransaction {
        hash: String,
    },
    Transaction {
        data: Option<RpcTransactionData>,
    },
    NewTransaction {
        transaction: Transaction,
    },
    NewTransactionHashes {
        hashes: Vec<Hash256>,
    },
    GetTransactions {
        hashes: Vec<Hash256>,
    },
    Transactions {
        items: Vec<Transaction>,
    },
    /// Peer routes are exchanged only after the signed hello has completed.
    /// They are hints for discovery; each route still requires a fresh
    /// authenticated handshake before it can carry consensus or gossip data.
    PeerExchange {
        peers: Vec<PeerRecord>,
    },
    NewHeader {
        header: BlockHeader,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerRecord {
    address: String,
    /// Operational route metadata; consensus never consumes these fields.
    #[serde(default = "default_route_class")]
    route_class: String,
    #[serde(default)]
    direct: bool,
    #[serde(default)]
    relay: bool,
    #[serde(default)]
    last_success_epoch: u64,
    #[serde(default)]
    last_failure_epoch: Option<u64>,
    #[serde(default)]
    expires_at_epoch: u64,
    #[serde(default)]
    alternate_addresses: Vec<String>,
    #[serde(default)]
    identity_public_key: Option<String>,
    #[serde(default)]
    consensus_profile: String,
    #[serde(default)]
    chain_id: u64,
    #[serde(default)]
    genesis_hash: String,
    #[serde(default)]
    protocol_version: String,
    node_mode: NodeMode,
    best_number: u64,
    best_hash: String,
    #[serde(default)]
    storage_mode: StorageMode,
    #[serde(default)]
    retained_from_height: u64,
    #[serde(default)]
    retained_to_height: u64,
    #[serde(default)]
    snapshot_heights: Vec<u64>,
    /// Advertises derived explorer capabilities only after authentication.
    /// These fields have no consensus or fork-choice effect.
    #[serde(default)]
    explorer_index: bool,
    #[serde(default)]
    explorer_share: bool,
    #[serde(default)]
    explorer_relay: bool,
}

fn default_route_class() -> String {
    "unknown".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum DiscoveryMessage {
    Register {
        peer: PeerRecord,
        identity_public_key: String,
        identity_signature: String,
    },
    GetPeers {
        identity_public_key: String,
        identity_signature: String,
    },
    Peers {
        peers: Vec<PeerRecord>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum RelayMessage {
    Register {
        node_id: String,
        identity_public_key: String,
        identity_signature: String,
    },
    Send {
        target_id: String,
        payload: P2pMessage,
        identity_public_key: String,
        identity_signature: String,
    },
    Broadcast {
        payload: P2pMessage,
        identity_public_key: String,
        identity_signature: String,
    },
    Poll {
        node_id: String,
        identity_public_key: String,
        identity_signature: String,
    },
    Messages {
        messages: Vec<P2pMessage>,
    },
}

fn run_p2p(
    config: NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
) -> Result<()> {
    let (tls_config, tls_certificate_hash) = build_server_tls_config()?;
    start_transaction_gossip_workers();
    start_block_gossip_workers();
    // Restored entries are revalidated during startup and then enter the same
    // bounded gossip queue as new submissions. This lets a non-mining node
    // recover propagation after a restart without rewriting transaction age.
    let restored_transactions = mempool
        .lock()
        .expect("mempool mutex poisoned")
        .pending()
        .to_vec();
    for transaction in restored_transactions {
        enqueue_transaction_gossip(&config, &storage, transaction);
    }
    load_known_peer_identities(&config);
    load_cached_peer_routes(&config);
    register_with_discovery_servers(&config, &storage)?;
    register_with_relay_servers(&config)?;
    start_network_registration_retry(config.clone(), Arc::clone(&storage));
    let score_path = Path::new(&config.node.data_dir).join("peer-scores.json");
    let loaded_scores = PeerScoreBook::load(&score_path).unwrap_or_else(|err| {
        eprintln!("peer score state could not be loaded: {err}");
        PeerScoreBook::default()
    });
    let peer_scores = Arc::new(Mutex::new(loaded_scores));
    {
        let peer_scores = Arc::clone(&peer_scores);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(30));
            let scores = peer_scores.lock().expect("peer score mutex poisoned");
            if let Err(err) = scores.save(&score_path) {
                eprintln!("peer score state could not be saved: {err}");
            }
        });
    }
    start_relay_pollers(
        &config,
        Arc::clone(&storage),
        Arc::clone(&mempool),
        Arc::clone(&peer_scores),
    );
    let mut discovered = discover_peers(&config)?;
    discovered.extend(cached_peer_endpoints());
    discovered.extend(config.network.bootstrap_peers.clone());
    discovered.sort();
    discovered.dedup();
    for peer in discovered {
        active_discovery_routes()
            .lock()
            .expect("active discovery routes poisoned")
            .insert(peer.clone());
        let storage = Arc::clone(&storage);
        let mempool = Arc::clone(&mempool);
        let config = config.clone();
        let peer_scores = Arc::clone(&peer_scores);
        let tls_certificate_hash = tls_certificate_hash.clone();
        thread::spawn(move || loop {
            eprintln!("p2p sync worker active for {peer}");
            if let Err(err) = sync_with_peer(
                &config,
                Arc::clone(&storage),
                Arc::clone(&mempool),
                &peer,
                Arc::clone(&peer_scores),
                &tls_certificate_hash,
            ) {
                record_p2p_handler_error(&err);
                eprintln!("p2p bootstrap peer {peer} failed: {err}; retrying");
                thread::sleep(Duration::from_secs(30));
            }
        });
    }

    // Admit discovered routes through the same bounded sync worker path as
    // seeds. Identity leases inside sync_with_peer prevent duplicate routes
    // from opening concurrent sessions for one authenticated peer.
    {
        let config = config.clone();
        let storage = Arc::clone(&storage);
        let mempool = Arc::clone(&mempool);
        let peer_scores = Arc::clone(&peer_scores);
        let tls_certificate_hash = tls_certificate_hash.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(15));
            let routes = DISCOVERED_PEER_ROUTES
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .expect("discovered peer routes poisoned")
                .values()
                .filter_map(|peer| {
                    validate_peer_record(peer)
                        .ok()
                        .map(|_| peer.address.clone())
                })
                .collect::<Vec<_>>();
            for peer in routes {
                let mut active = active_discovery_routes()
                    .lock()
                    .expect("active discovery routes poisoned");
                if active.len() >= MAX_DISCOVERY_WORKERS || !active.insert(peer.clone()) {
                    continue;
                }
                drop(active);
                let worker_config = config.clone();
                let worker_storage = Arc::clone(&storage);
                let worker_mempool = Arc::clone(&mempool);
                let worker_scores = Arc::clone(&peer_scores);
                let worker_tls = tls_certificate_hash.clone();
                thread::spawn(move || loop {
                    if let Err(err) = sync_with_peer(
                        &worker_config,
                        Arc::clone(&worker_storage),
                        Arc::clone(&worker_mempool),
                        &peer,
                        Arc::clone(&worker_scores),
                        &worker_tls,
                    ) {
                        eprintln!("discovered peer {peer} failed: {err}; retrying");
                        thread::sleep(Duration::from_secs(30));
                    }
                });
            }
        });
    }

    let listener = TcpListener::bind(&config.network.listen)?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    let active_inbound_addresses = Arc::new(Mutex::new(HashSet::new()));
    eprintln!("p2p listening on {}", config.network.listen);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(error) => {
                record_p2p_handler_error(&anyhow::anyhow!(error.to_string()));
                eprintln!("p2p accept failed: {error}; retrying");
                thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        // The read deadline must be shorter than the handler's hard session
        // cap. Otherwise an idle connection can retain a P2P admission slot
        // beyond the cap while blocked in one read.
        stream.set_read_timeout(Some(P2P_INBOUND_READ_TIMEOUT))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        if !try_acquire_connection(&active_connections, config.network.max_inbound_peers) {
            continue;
        }
        let peer_address = stream
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let peer_host = peer_address
            .rsplit_once(':')
            .map(|(host, _)| host.trim_matches(['[', ']']).to_string())
            .unwrap_or_else(|| peer_address.clone());
        let inbound_address_lease =
            match try_acquire_inbound_address(&active_inbound_addresses, peer_host) {
                Some(lease) => lease,
                None => {
                    let _ = stream.shutdown(Shutdown::Both);
                    active_connections.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
            };
        let tls_connection = match ServerConnection::new(Arc::clone(&tls_config)) {
            Ok(connection) => connection,
            Err(err) => {
                active_connections.fetch_sub(1, Ordering::AcqRel);
                let _ = stream.shutdown(Shutdown::Both);
                return Err(err.into());
            }
        };
        let stream = StreamOwned::new(tls_connection, stream);
        let storage = Arc::clone(&storage);
        let mempool = Arc::clone(&mempool);
        let config = config.clone();
        let peer_scores = Arc::clone(&peer_scores);
        let tls_certificate_hash = tls_certificate_hash.clone();
        let active_connections = Arc::clone(&active_connections);
        thread::spawn(move || {
            let _inbound_address_lease = inbound_address_lease;
            let _guard = ActiveConnectionGuard(active_connections);
            let mut stream = stream;
            let handshake_peer = peer_address.clone();
            if let Err(err) = stream.conn.complete_io(&mut stream.sock) {
                let _ = stream.sock.shutdown(Shutdown::Both);
                eprintln!("p2p TLS handshake failed for {handshake_peer}: {err}");
                return;
            }
            eprintln!("p2p TLS handshake complete for {handshake_peer}");
            if let Err(err) = handle_p2p_connection(
                match P2pShutdownGuard::new(stream) {
                    Ok(stream) => stream,
                    Err(err) => {
                        eprintln!("p2p connection rejected from {handshake_peer}: {err}");
                        return;
                    }
                },
                &config,
                storage,
                mempool,
                peer_scores,
                peer_address,
                None,
                &tls_certificate_hash,
            ) {
                record_p2p_handler_error(&err);
                eprintln!("p2p connection failed from {handshake_peer}: {err}");
            }
        });
    }
    Ok(())
}

fn start_transaction_gossip_workers() {
    if TRANSACTION_GOSSIP_QUEUE.get().is_some() {
        return;
    }
    let (sender, receiver) =
        mpsc::sync_channel::<TransactionGossipJob>(MAX_TRANSACTION_GOSSIP_QUEUE);
    if TRANSACTION_GOSSIP_QUEUE.set(sender).is_err() {
        return;
    }
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..TRANSACTION_GOSSIP_WORKERS {
        let receiver = Arc::clone(&receiver);
        thread::spawn(move || transaction_gossip_worker(receiver));
    }
}

fn start_block_gossip_workers() {
    if BLOCK_GOSSIP_QUEUE.get().is_some() {
        return;
    }
    let (sender, receiver) = mpsc::sync_channel::<BlockGossipJob>(MAX_BLOCK_GOSSIP_QUEUE);
    if BLOCK_GOSSIP_QUEUE.set(sender).is_err() {
        return;
    }
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..BLOCK_GOSSIP_WORKERS {
        let receiver = Arc::clone(&receiver);
        thread::spawn(move || block_gossip_worker(receiver));
    }
}

fn block_gossip_worker(receiver: Arc<Mutex<Receiver<BlockGossipJob>>>) {
    loop {
        let job = {
            let receiver = receiver.lock().expect("block gossip queue poisoned");
            receiver.recv()
        };
        let Ok(job) = job else { break };
        let hash = job.block.header.hash();
        if !mark_block_gossip_seen(hash, unix_now()) {
            BLOCK_GOSSIP_DEDUPLICATED.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        match relay_block_to_peers(
            &job.config,
            job.genesis_hash,
            &job.block,
            job.source_peer.as_deref(),
        ) {
            Ok(()) => {
                BLOCK_GOSSIP_RELAYED.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                BLOCK_GOSSIP_FAILURES.fetch_add(1, Ordering::Relaxed);
                *LAST_BLOCK_GOSSIP_ERROR
                    .get_or_init(|| Mutex::new(None))
                    .lock()
                    .expect("block gossip error mutex poisoned") = Some(err.to_string());
                eprintln!("p2p block relay failed: {err}");
            }
        }
    }
}

fn mark_block_gossip_seen(hash: Hash256, now: u64) -> bool {
    let inventory = BLOCK_GOSSIP_INVENTORY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut inventory = inventory.lock().expect("block gossip inventory poisoned");
    inventory.retain(|_, seen| now.saturating_sub(*seen) < BLOCK_GOSSIP_INVENTORY_TTL_SECONDS);
    if inventory.contains_key(&hash) {
        return false;
    }
    inventory.insert(hash, now);
    true
}

fn enqueue_block_gossip(
    config: &NodeConfig,
    genesis_hash: Hash256,
    block: &Block,
    source_peer: Option<&str>,
) {
    if !config.network.enabled {
        return;
    }
    let Some(queue) = BLOCK_GOSSIP_QUEUE.get() else {
        return;
    };
    let job = BlockGossipJob {
        config: config.clone(),
        genesis_hash,
        block: block.clone(),
        source_peer: source_peer.map(str::to_string),
    };
    match queue.try_send(job) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            BLOCK_GOSSIP_FAILURES.fetch_add(1, Ordering::Relaxed);
            *LAST_BLOCK_GOSSIP_ERROR
                .get_or_init(|| Mutex::new(None))
                .lock()
                .expect("block gossip error mutex poisoned") =
                Some("block announcement queue is full".to_string());
            eprintln!("p2p block announcement queue full; sync polling remains available");
        }
        Err(TrySendError::Disconnected(_)) => {
            BLOCK_GOSSIP_FAILURES.fetch_add(1, Ordering::Relaxed);
            *LAST_BLOCK_GOSSIP_ERROR
                .get_or_init(|| Mutex::new(None))
                .lock()
                .expect("block gossip error mutex poisoned") =
                Some("block announcement queue is unavailable".to_string());
        }
    }
}

fn active_discovery_routes() -> &'static Mutex<BTreeSet<String>> {
    ACTIVE_DISCOVERY_ROUTES.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn transaction_gossip_worker(receiver: Arc<Mutex<Receiver<TransactionGossipJob>>>) {
    loop {
        let job = {
            let receiver = receiver.lock().expect("transaction gossip queue poisoned");
            receiver.recv()
        };
        let Ok(job) = job else { break };
        let hash = job.transaction.rpc_hash();
        let now = unix_now();
        let inventory = TRANSACTION_GOSSIP_INVENTORY.get_or_init(|| Mutex::new(BTreeMap::new()));
        {
            let mut inventory = inventory.lock().expect("transaction inventory poisoned");
            inventory.retain(|_, seen| {
                now.saturating_sub(*seen) < TRANSACTION_GOSSIP_INVENTORY_TTL_SECONDS
            });
            if inventory.contains_key(&hash) {
                continue;
            }
            inventory.insert(hash, now);
        }
        match relay_transaction_to_peers(&job.config, &job.storage, job.transaction) {
            Ok(()) => {
                TRANSACTION_GOSSIP_RELAYED.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                TRANSACTION_GOSSIP_FAILURES.fetch_add(1, Ordering::Relaxed);
                eprintln!("p2p transaction relay failed: {err}");
            }
        }
    }
}

fn enqueue_transaction_gossip(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    transaction: Transaction,
) {
    if !config.network.enabled {
        return;
    }
    let Some(queue) = TRANSACTION_GOSSIP_QUEUE.get() else {
        return;
    };
    let job = TransactionGossipJob {
        config: config.clone(),
        storage: Arc::clone(storage),
        transaction,
    };
    match queue.try_send(job) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            eprintln!("p2p transaction relay queue full; retaining transaction locally");
        }
        Err(TrySendError::Disconnected(_)) => {
            eprintln!("p2p transaction relay queue unavailable");
        }
    }
}

fn start_network_registration_retry(config: NodeConfig, storage: Arc<Mutex<NodeStorage>>) {
    if config.network.discovery_servers.is_empty() && config.network.relay_servers.is_empty() {
        return;
    }
    thread::spawn(move || loop {
        if let Err(err) = register_with_discovery_servers(&config, &storage) {
            eprintln!("discovery registration retry failed: {err}");
        }
        if let Err(err) = register_with_relay_servers(&config) {
            eprintln!("relay registration retry failed: {err}");
        }
        thread::sleep(Duration::from_secs(30));
    });
}

fn run_discovery_server(bind: &str) -> Result<()> {
    let peers: Arc<Mutex<Vec<PeerRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind(bind)?;
    eprintln!("discovery server listening on {bind}");
    for stream in listener.incoming() {
        let stream = stream?;
        if active_connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_OPTIONAL_SERVICE_CONNECTIONS).then_some(count + 1)
            })
            .is_err()
        {
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let peers = Arc::clone(&peers);
        let active_connections = Arc::clone(&active_connections);
        thread::spawn(move || {
            let _guard = ActiveConnectionGuard(active_connections);
            if let Err(err) = handle_discovery_connection(stream, peers) {
                eprintln!("discovery connection failed: {err}");
            }
        });
    }
    Ok(())
}

fn handle_discovery_connection(
    mut stream: TcpStream,
    peers: Arc<Mutex<Vec<PeerRecord>>>,
) -> Result<()> {
    let _shutdown = SocketShutdownGuard::new(&stream)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let mut messages_seen = 0usize;
    while read_p2p_line(&mut reader, &mut line)? {
        messages_seen = messages_seen.saturating_add(1);
        if messages_seen > MAX_P2P_MESSAGES_PER_CONNECTION {
            anyhow::bail!("discovery peer exceeded message limit");
        }
        let message: DiscoveryMessage = serde_json::from_str(line.trim())?;
        match message {
            DiscoveryMessage::Register {
                peer,
                identity_public_key,
                identity_signature,
            } => {
                validate_peer_record(&peer)?;
                verify_service_identity(
                    "BLQ-DISCOVERY-REGISTER-v1",
                    &[
                        &peer.address,
                        peer.node_mode.as_str(),
                        &peer.best_number.to_string(),
                        &peer.best_hash,
                        &format!("{:?}", peer.storage_mode),
                        &peer.retained_from_height.to_string(),
                        &peer.retained_to_height.to_string(),
                        &identity_public_key,
                    ],
                    &identity_public_key,
                    &identity_signature,
                )?;
                let mut peers = peers.lock().expect("peer registry mutex poisoned");
                peers.retain(|existing| existing.address != peer.address);
                if peers.len() < MAX_DISCOVERY_PEERS {
                    peers.push(peer);
                }
                send_discovery_message(
                    &mut stream,
                    &DiscoveryMessage::Peers {
                        peers: peers.clone(),
                    },
                )?;
            }
            DiscoveryMessage::GetPeers {
                identity_public_key,
                identity_signature,
            } => {
                verify_service_identity(
                    "BLQ-DISCOVERY-GET-v1",
                    &[&identity_public_key],
                    &identity_public_key,
                    &identity_signature,
                )?;
                let peers = peers.lock().expect("peer registry mutex poisoned").clone();
                send_discovery_message(&mut stream, &DiscoveryMessage::Peers { peers })?;
            }
            DiscoveryMessage::Peers { .. } => {}
        }
        line.clear();
    }
    Ok(())
}

fn run_relay_node(bind: &str) -> Result<()> {
    let inboxes: Arc<Mutex<std::collections::HashMap<String, Vec<P2pMessage>>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind(bind)?;
    eprintln!("relay node listening on {bind}");
    for stream in listener.incoming() {
        let stream = stream?;
        if active_connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_OPTIONAL_SERVICE_CONNECTIONS).then_some(count + 1)
            })
            .is_err()
        {
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let inboxes = Arc::clone(&inboxes);
        let active_connections = Arc::clone(&active_connections);
        thread::spawn(move || {
            let _guard = ActiveConnectionGuard(active_connections);
            if let Err(err) = handle_relay_connection(stream, inboxes) {
                eprintln!("relay connection failed: {err}");
            }
        });
    }
    Ok(())
}

fn handle_relay_connection(
    mut stream: TcpStream,
    inboxes: Arc<Mutex<std::collections::HashMap<String, Vec<P2pMessage>>>>,
) -> Result<()> {
    let _shutdown = SocketShutdownGuard::new(&stream)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let mut messages_seen = 0usize;
    let mut registered_node: Option<(String, String)> = None;
    while read_p2p_line(&mut reader, &mut line)? {
        messages_seen = messages_seen.saturating_add(1);
        if messages_seen > MAX_P2P_MESSAGES_PER_CONNECTION {
            anyhow::bail!("relay peer exceeded message limit");
        }
        let message: RelayMessage = serde_json::from_str(line.trim())?;
        match message {
            RelayMessage::Register {
                node_id,
                identity_public_key,
                identity_signature,
            } => {
                if !valid_relay_node_id(&node_id) {
                    anyhow::bail!("relay node id is missing or too long");
                }
                verify_service_identity(
                    "BLQ-RELAY-REGISTER-v1",
                    &[&node_id, &identity_public_key],
                    &identity_public_key,
                    &identity_signature,
                )?;
                if let Some(existing) = &registered_node {
                    if existing.0 != node_id || existing.1 != identity_public_key {
                        anyhow::bail!("relay connection cannot register a second node id");
                    }
                } else {
                    let mut inboxes = inboxes.lock().expect("relay inbox mutex poisoned");
                    if !inboxes.contains_key(&node_id) && inboxes.len() >= MAX_RELAY_NODES {
                        anyhow::bail!("relay node registry is full");
                    }
                    inboxes.entry(node_id.clone()).or_default();
                    eprintln!("relay registered node {node_id}");
                    registered_node = Some((node_id, identity_public_key));
                }
            }
            RelayMessage::Send {
                target_id,
                payload,
                identity_public_key,
                identity_signature,
            } => {
                if registered_node.is_none() {
                    anyhow::bail!("relay send requires registration");
                }
                let (sender, registered_key) = registered_node.as_ref().expect("checked above");
                if registered_key != &identity_public_key {
                    anyhow::bail!("relay identity key does not match registration");
                }
                verify_service_identity(
                    "BLQ-RELAY-SEND-v1",
                    &[sender, &target_id, &identity_public_key],
                    &identity_public_key,
                    &identity_signature,
                )?;
                if !valid_relay_node_id(&target_id) {
                    anyhow::bail!("relay target id is missing or too long");
                }
                validate_relay_payload(&payload)?;
                let mut inboxes = inboxes.lock().expect("relay inbox mutex poisoned");
                if let Some(inbox) = inboxes.get_mut(&target_id) {
                    if inbox.len() < MAX_RELAY_MESSAGES_PER_NODE {
                        inbox.push(payload);
                    }
                }
            }
            RelayMessage::Broadcast {
                payload,
                identity_public_key,
                identity_signature,
            } => {
                let Some((sender, registered_key)) = registered_node.as_ref() else {
                    anyhow::bail!("relay broadcast requires registration");
                };
                if registered_key != &identity_public_key {
                    anyhow::bail!("relay identity key does not match registration");
                }
                verify_service_identity(
                    "BLQ-RELAY-BROADCAST-v1",
                    &[sender, &identity_public_key],
                    &identity_public_key,
                    &identity_signature,
                )?;
                validate_relay_payload(&payload)?;
                let mut inboxes = inboxes.lock().expect("relay inbox mutex poisoned");
                for (target_id, inbox) in inboxes.iter_mut() {
                    if target_id != sender && inbox.len() < MAX_RELAY_MESSAGES_PER_NODE {
                        inbox.push(payload.clone());
                    }
                }
            }
            RelayMessage::Poll {
                node_id,
                identity_public_key,
                identity_signature,
            } => {
                let Some((registered_id, registered_key)) = registered_node.as_ref() else {
                    anyhow::bail!("relay poll requires registration for the same node id");
                };
                if registered_id != &node_id || registered_key != &identity_public_key {
                    anyhow::bail!("relay poll requires registration for the same node id");
                }
                verify_service_identity(
                    "BLQ-RELAY-POLL-v1",
                    &[&node_id, &identity_public_key],
                    &identity_public_key,
                    &identity_signature,
                )?;
                let messages = inboxes
                    .lock()
                    .expect("relay inbox mutex poisoned")
                    .get_mut(&node_id)
                    .map(std::mem::take)
                    .unwrap_or_default();
                eprintln!(
                    "relay poll served {node_id} with {} message(s)",
                    messages.len()
                );
                send_relay_message(&mut stream, &RelayMessage::Messages { messages })?;
            }
            RelayMessage::Messages { .. } => {}
        }
        line.clear();
    }
    Ok(())
}

fn validate_relay_payload(payload: &P2pMessage) -> Result<()> {
    match payload {
        P2pMessage::NewHeader { .. } | P2pMessage::BlockBody { .. } => Ok(()),
        P2pMessage::Hello { .. }
        | P2pMessage::GetHeaders { .. }
        | P2pMessage::Headers { .. }
        | P2pMessage::FindCommonAncestor { .. }
        | P2pMessage::CommonAncestor { .. }
        | P2pMessage::GetBlock { .. }
        | P2pMessage::GetBlockRange { .. }
        | P2pMessage::WitnessHeaders { .. }
        | P2pMessage::WitnessHeadersResponse { .. }
        | P2pMessage::GetBlockByHash { .. }
        | P2pMessage::BlockNotFound { .. }
        | P2pMessage::GetTransaction { .. }
        | P2pMessage::Transaction { .. }
        | P2pMessage::NewTransaction { .. }
        | P2pMessage::NewTransactionHashes { .. }
        | P2pMessage::GetTransactions { .. }
        | P2pMessage::Transactions { .. } => {
            anyhow::bail!("relay payload must be a new block or header notification")
        }
        P2pMessage::PeerExchange { .. } => {
            anyhow::bail!("peer exchange is not accepted through the relay service")
        }
    }
}

fn valid_relay_node_id(node_id: &str) -> bool {
    !node_id.is_empty() && node_id.len() <= 256 && node_id.is_ascii()
}

fn validate_peer_record(peer: &PeerRecord) -> Result<()> {
    if peer.address.len() > 128 || !peer.address.is_ascii() {
        anyhow::bail!("discovery peer address is missing or too long");
    }
    peer.address
        .parse::<SocketAddr>()
        .map_err(|err| anyhow::anyhow!("discovery peer address is invalid: {err}"))?;
    if !matches!(
        peer.route_class.as_str(),
        "unknown" | "local" | "wan" | "relay"
    ) {
        anyhow::bail!("discovery peer route class is invalid");
    }
    if peer.alternate_addresses.len() > 3 {
        anyhow::bail!("discovery peer contains too many alternate routes");
    }
    for address in &peer.alternate_addresses {
        if address.len() > 128 || !address.is_ascii() {
            anyhow::bail!("discovery peer alternate route is missing or too long");
        }
        address
            .parse::<SocketAddr>()
            .map_err(|err| anyhow::anyhow!("discovery peer alternate route is invalid: {err}"))?;
    }
    Hash256::from_hex(&peer.best_hash)
        .map_err(|err| anyhow::anyhow!("discovery peer hash is invalid: {err:?}"))?;
    if peer.retained_to_height != 0
        && (peer.retained_from_height > peer.retained_to_height
            || peer.retained_to_height < peer.best_number)
    {
        anyhow::bail!("discovery peer retained range is invalid");
    }
    Ok(())
}

fn route_class_for_address(address: &str) -> String {
    let host = address
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(address);
    if host.starts_with("100.")
        || host.starts_with("fd7a:")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
    {
        "local".to_string()
    } else {
        "wan".to_string()
    }
}

fn peer_route_is_fresh(peer: &PeerRecord) -> bool {
    peer.expires_at_epoch == 0 || unix_now() <= peer.expires_at_epoch
}

fn service_auth_payload(domain: &str, fields: &[&str]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in std::iter::once(domain).chain(fields.iter().copied()) {
        let length = u64::try_from(field.len()).expect("service auth field length fits u64");
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(field.as_bytes());
    }
    payload
}

fn verify_service_identity(
    domain: &str,
    fields: &[&str],
    identity_public_key: &str,
    identity_signature: &str,
) -> Result<()> {
    let public_key_bytes = hex::decode(identity_public_key)?;
    let public_key = PublicKey::from_slice(&public_key_bytes)?;
    let signature_bytes = hex::decode(identity_signature)?;
    if signature_bytes.len() != 65 {
        anyhow::bail!("service identity signature has invalid length");
    }
    let recovery_id = RecoveryId::try_from(signature_bytes[64] as i32)?;
    let signature = RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id)?;
    let digest = keccak256(service_auth_payload(domain, fields));
    Secp256k1::new().verify_ecdsa(
        Message::from_digest(digest.0),
        &signature.to_standard(),
        &public_key,
    )?;
    Ok(())
}

fn sync_with_peer(
    config: &NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
    peer: &str,
    peer_scores: Arc<Mutex<PeerScoreBook>>,
    tls_certificate_hash: &str,
) -> Result<()> {
    let mut retry_delay_seconds = 1u64;
    loop {
        if !alternate_route_may_fail_over(peer) {
            // This is an authenticated alias of a peer with a healthy
            // preferred route. Keep it as failover rather than running a
            // second idle sync loop against the same identity.
            thread::sleep(Duration::from_secs(P2P_SYNC_IDLE_RETRY_MAX_SECONDS));
            continue;
        }
        if sync_peer_identity_is_active(peer) {
            thread::sleep(Duration::from_secs(30));
            continue;
        }
        if peer_scores
            .lock()
            .expect("peer score mutex poisoned")
            .is_banned(PeerId::from_advertised_address(peer))
        {
            thread::sleep(Duration::from_secs(60));
            continue;
        }
        eprintln!("p2p sync connecting to {peer}");
        let mut authenticated_session = false;
        let mut made_progress = false;
        let mut confirmed_idle_match = false;
        match connect_p2p_tls(peer) {
            Ok((mut stream, peer_tls_certificate_hash)) => {
                clear_p2p_route_connect_failure(peer);
                eprintln!("p2p sync connected to {peer}");
                SYNC_SESSION_STARTED_AT.store(unix_now(), Ordering::Release);
                storage
                    .lock()
                    .expect("storage mutex poisoned")
                    .begin_sync_batch();
                let address_peer_id = PeerId::from_advertised_address(peer);
                let mut identity_peer_id = None;
                let mut stored_identity_public_key = None;
                let mut sync_identity_lease = None;
                let mut recovery_job_lease = None;
                send_p2p_message(
                    &mut stream,
                    &hello_message(config, &storage, tls_certificate_hash)?,
                )?;
                eprintln!("p2p sync hello sent to {peer}");
                let mut reader = BufReader::new(P2pShutdownGuard::new_configured(stream)?);
                let mut line = String::new();
                let mut bodies_since_headers = 0usize;
                let mut bodies_in_range = 0usize;
                let mut last_import = Instant::now();
                let mut recovery_rate_window = Instant::now();
                let mut retried_cursor_by_number = false;
                loop {
                    if recovery_job_lease.is_some()
                        && last_import.elapsed() >= RECOVERY_NO_PROGRESS_TIMEOUT
                    {
                        eprintln!("p2p sync watchdog reconnecting {peer} after 30s without import");
                        record_recovery_failure(
                            config,
                            peer,
                            "request timed out without an imported body",
                        );
                        break;
                    }
                    let recovery_bodies_remaining = branch_sync_cursors()
                        .lock()
                        .expect("branch sync cursor mutex poisoned")
                        .get(&cursor_key(peer))
                        .map(|cursor| {
                            cursor
                                .tip_height
                                .saturating_sub(cursor.next_height)
                                .saturating_add(1)
                        })
                        .unwrap_or(u64::MAX);
                    if recovery_job_lease.is_some()
                        && recovery_bodies_remaining >= RECOVERY_MIN_BATCH_BODIES as u64
                        && bodies_in_range < RECOVERY_MIN_BATCH_BODIES
                        && recovery_rate_window.elapsed() >= RECOVERY_MIN_BATCH_WINDOW
                    {
                        record_recovery_failure(
                            config,
                            peer,
                            "provider recovery range below minimum throughput",
                        );
                        break;
                    }
                    match read_p2p_line(&mut reader, &mut line) {
                        Ok(false) => break,
                        Ok(_) => {
                            let message = match serde_json::from_str(line.trim()) {
                                Ok(message) => message,
                                Err(err) => {
                                    eprintln!(
                                        "p2p sync from {peer} received invalid message: {err}"
                                    );
                                    break;
                                }
                            };
                            eprintln!(
                                "p2p sync received {} from {peer}",
                                p2p_message_kind(&message)
                            );
                            if let P2pMessage::BlockBody { block } = &message {
                                if let Some(expected_hash) = branch_cursor_next_hash(peer) {
                                    if block.header.hash() != expected_hash {
                                        anyhow::bail!(
                                            "p2p sync peer returned body {} while cursor requires {}",
                                            block.header.hash().to_hex(),
                                            expected_hash.to_hex()
                                        );
                                    }
                                }
                                retried_cursor_by_number = false;
                            }
                            if let P2pMessage::Hello {
                                identity_public_key,
                                best_number,
                                best_hash,
                                consensus_profile,
                                ..
                            } = &message
                            {
                                migrate_branch_sync_cursor(config, peer, identity_public_key);
                                stored_identity_public_key = Some(identity_public_key.clone());
                                identity_peer_id =
                                    Some(PeerId::from_identity_public_key(identity_public_key));
                                authenticated_session = true;
                                let peer_tip_hash =
                                    Hash256::from_hex(best_hash).map_err(|err| {
                                        anyhow::anyhow!("peer advertised invalid tip hash: {err:?}")
                                    })?;
                                confirmed_idle_match = storage
                                    .lock()
                                    .expect("storage mutex poisoned")
                                    .best_header()
                                    .is_ok_and(|local| {
                                        local.number.0 == *best_number
                                            && local.hash() == peer_tip_hash
                                    });
                                // `cursor_key(peer)` may deliberately remain anchored to
                                // an older spool tip while this provider's advertised tip
                                // advances.  Leasing by that durable key prevents a second
                                // sync route from resetting the cursor before the request
                                // path can prove the next parent.
                                let finalized_floor = storage
                                    .lock()
                                    .expect("storage mutex poisoned")
                                    .best_header()
                                    .map(|header| finalized_height(header.number.0))?;
                                let recovery_key = durable_forward_cursor_key(
                                    peer,
                                    consensus_profile,
                                    finalized_floor,
                                )
                                .unwrap_or_else(|| cursor_key(peer));
                                let active_recovery_tip = branch_sync_cursors()
                                    .lock()
                                    .expect("branch sync cursor mutex poisoned")
                                    .get(&recovery_key)
                                    .filter(|cursor| recovery_cursor_requires_provider(cursor))
                                    .map(|cursor| cursor.tip_hash);
                                if let Some(active_recovery_tip) = active_recovery_tip {
                                    if let Some(lease) = RecoveryJobLease::acquire(&recovery_key) {
                                        recovery_job_lease = Some(lease);
                                        let _ = register_recovery_peer_role(
                                            config,
                                            peer,
                                            identity_public_key,
                                            active_recovery_tip,
                                            true,
                                        );
                                    } else if recovery_provider_is_deferred(
                                        active_recovery_tip,
                                        peer_tip_hash,
                                        recovery_job_lease.is_some(),
                                    ) {
                                        if remove_stale_recovery_witness(
                                            config,
                                            active_recovery_tip,
                                            identity_public_key,
                                        ) {
                                            eprintln!(
                                                "p2p sync to {peer} is behind recovery tip {}; not using it as a witness",
                                                active_recovery_tip.to_hex()
                                            );
                                        }
                                        eprintln!(
                                            "p2p sync to {peer} deferred: recovery job already has an active provider"
                                        );
                                        break;
                                    } else if let Some(heights) = register_recovery_peer_role(
                                        config,
                                        peer,
                                        identity_public_key,
                                        active_recovery_tip,
                                        false,
                                    ) {
                                        send_p2p_message(
                                            reader.get_mut(),
                                            &P2pMessage::WitnessHeaders {
                                                tip_hash: active_recovery_tip.to_hex(),
                                                heights,
                                            },
                                        )?;
                                        line.clear();
                                        continue;
                                    } else {
                                        eprintln!("p2p sync to {peer} deferred: recovery job already has an active provider");
                                        break;
                                    }
                                } else {
                                    // A completed spool can survive a restart in
                                    // `waiting-for-witness`. It no longer needs a
                                    // provider lease, but a subsequently connected
                                    // behind peer must still be able to remove itself
                                    // as an invalid witness and unblock publication.
                                    let completed_tip = branch_sync_cursors()
                                        .lock()
                                        .expect("branch sync cursor mutex poisoned")
                                        .get(&recovery_key)
                                        .filter(|cursor| {
                                            cursor.next_height > cursor.tip_height
                                                && cursor.witness_identity.is_some()
                                        })
                                        .map(|cursor| cursor.tip_hash);
                                    if let Some(completed_tip) = completed_tip {
                                        if peer_tip_hash != completed_tip
                                            && remove_stale_recovery_witness(
                                                config,
                                                completed_tip,
                                                identity_public_key,
                                            )
                                        {
                                            eprintln!(
                                                "p2p sync to {peer} is behind completed recovery tip {}; publishing in single-provider mode",
                                                completed_tip.to_hex()
                                            );
                                            start_candidate_recovery(config, Arc::clone(&storage));
                                        }
                                    }
                                }
                                request_peer_branch_cursor(
                                    reader.get_mut(),
                                    config,
                                    &storage,
                                    peer,
                                    *best_number,
                                    best_hash,
                                    consensus_profile,
                                )?;
                            }
                            if let P2pMessage::CommonAncestor { height, hash } = &message {
                                let (Some(height), Some(hash)) = (*height, hash.as_deref()) else {
                                    anyhow::bail!(
                                        "peer could not locate a common canonical ancestor"
                                    );
                                };
                                let hash = Hash256::from_hex(hash).map_err(|err| {
                                    anyhow::anyhow!(
                                        "peer returned invalid common ancestor hash: {err:?}"
                                    )
                                })?;
                                let local_match = storage
                                    .lock()
                                    .expect("storage mutex poisoned")
                                    .block_by_number(height)?;
                                if local_match.header.hash() != hash {
                                    anyhow::bail!(
                                        "peer common ancestor is not local canonical history"
                                    );
                                }
                                let mut key = cursor_key(peer);
                                {
                                    let mut cursors = branch_sync_cursors()
                                        .lock()
                                        .expect("branch sync cursor mutex poisoned");
                                    let cursor = cursors.get_mut(&key).ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "common ancestor arrived without recovery cursor"
                                        )
                                    })?;
                                    cursor.ancestor_height = Some(height);
                                    cursor.ancestor_hash = Some(hash);
                                    cursor.next_height = height.saturating_add(1);
                                    cursor.expected_parent_hash = Some(hash);
                                    cursor.staged_height = height;
                                    cursor.state = "retrieving".to_string();
                                    cursor.updated_at = unix_now();
                                }
                                if let Some(identity) = stored_identity_public_key.as_deref() {
                                    let incoming = branch_sync_cursors()
                                        .lock()
                                        .expect("branch sync cursor mutex poisoned")
                                        .get(&key)
                                        .cloned()
                                        .ok_or_else(|| {
                                            anyhow::anyhow!(
                                                "common ancestor recovery cursor disappeared"
                                            )
                                        })?;
                                    // Do this only after the provider has proved the exact
                                    // canonical ancestor.  A changed tip is then a moving
                                    // target for the existing branch job, not a second fork.
                                    key = coalesce_advancing_recovery_job(
                                        peer,
                                        identity,
                                        incoming.tip_hash,
                                        incoming.tip_height,
                                        &incoming.consensus_profile,
                                        height,
                                        hash,
                                        None,
                                    );
                                }
                                persist_branch_sync_cursors(config)?;
                                if recovery_job_lease.is_none() {
                                    let Some(lease) = RecoveryJobLease::acquire(&key) else {
                                        eprintln!("p2p sync to {peer} deferred: recovery job already has an active provider");
                                        break;
                                    };
                                    recovery_job_lease = Some(lease);
                                }
                                let recovery_tip = branch_sync_cursors()
                                    .lock()
                                    .expect("branch sync cursor mutex poisoned")
                                    .get(&key)
                                    .map(|cursor| cursor.tip_hash);
                                if let (Some(identity), Some(recovery_tip)) =
                                    (stored_identity_public_key.as_deref(), recovery_tip)
                                {
                                    let _ = register_recovery_peer_role(
                                        config,
                                        peer,
                                        identity,
                                        recovery_tip,
                                        true,
                                    );
                                }
                                {
                                    let mut progress = sync_progress()
                                        .lock()
                                        .expect("sync progress mutex poisoned");
                                    progress.active_peer = Some(peer.to_string());
                                    progress.common_ancestor = Some(height);
                                    progress.next_requested_height = branch_sync_cursors()
                                        .lock()
                                        .expect("branch sync cursor mutex poisoned")
                                        .get(&key)
                                        .map(|cursor| cursor.next_height)
                                        .unwrap_or_else(|| height.saturating_add(1));
                                    progress.provider_state = "available";
                                    progress.state = "recovering-branch";
                                }
                                let next_height = branch_sync_cursors()
                                    .lock()
                                    .expect("branch sync cursor mutex poisoned")
                                    .get(&key)
                                    .map(|cursor| cursor.next_height)
                                    .unwrap_or_else(|| height.saturating_add(1));
                                // Persist the exact next height before the
                                // request reaches a fast local provider. The
                                // response may otherwise win this race and be
                                // misclassified as unsolicited.
                                record_recovery_request(config, peer, next_height);
                                send_p2p_message(
                                    reader.get_mut(),
                                    &P2pMessage::GetBlockRange {
                                        from: next_height,
                                        limit: SYNC_RANGE_SIZE,
                                    },
                                )?;
                                line.clear();
                                continue;
                            }
                            if let P2pMessage::WitnessHeadersResponse { tip_hash, headers } =
                                message
                            {
                                let tip_hash = Hash256::from_hex(&tip_hash).map_err(|err| {
                                    anyhow::anyhow!("witness returned invalid tip hash: {err:?}")
                                })?;
                                let identity =
                                    stored_identity_public_key.as_deref().ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "witness response arrived before authenticated hello"
                                        )
                                    })?;
                                let ready =
                                    record_witness_headers(config, tip_hash, identity, headers)?;
                                if ready {
                                    start_candidate_recovery(config, Arc::clone(&storage));
                                }
                                // One witness response covers exactly one
                                // bounded primary range. Reconnect so the
                                // next request samples the next range rather
                                // than leaving an idle witness socket open.
                                break;
                            }
                            if !matches!(message, P2pMessage::Hello { .. })
                                && identity_peer_id.is_some_and(|peer_id| {
                                    peer_scores
                                        .lock()
                                        .expect("peer score mutex poisoned")
                                        .is_banned(peer_id)
                                })
                            {
                                anyhow::bail!("peer identity is banned");
                            }
                            let agreement_message = message.clone();
                            let hello_identity = match &agreement_message {
                                P2pMessage::Hello {
                                    identity_public_key,
                                    ..
                                } => Some(identity_public_key.clone()),
                                _ => None,
                            };
                            let is_hello = hello_identity.is_some();
                            let missing_parent = match &message {
                                P2pMessage::BlockBody { block } => Some(block.header.parent_hash),
                                _ => None,
                            };
                            let is_transaction_gossip =
                                matches!(&message, P2pMessage::NewTransaction { .. });
                            let recovery_range_body = match &agreement_message {
                                P2pMessage::BlockBody { block } => {
                                    is_expected_recovery_body(peer, block)
                                }
                                _ => false,
                            };
                            if let P2pMessage::BlockBody { block } = &agreement_message {
                                // Compute this while holding the cursor lock, then
                                // release it before reset_recovery_cursor_for_fork.
                                // Reset acquires the same mutex; calling it while
                                // the guard is alive deadlocks the sync worker on
                                // the first stale range frame.
                                let has_recovery_cursor = {
                                    let cursors = branch_sync_cursors()
                                        .lock()
                                        .expect("branch sync cursor mutex poisoned");
                                    cursors
                                        .get(&cursor_key(peer))
                                        .or_else(|| {
                                            cursors.values().find(|cursor| {
                                                cursor.provider.as_deref() == Some(peer)
                                            })
                                        })
                                        .is_some_and(|cursor| cursor.ancestor_height.is_some())
                                };
                                if has_recovery_cursor
                                    && !recovery_range_body
                                    && !is_canonical_next_body(&storage, block)
                                    && !is_canonical_body(&storage, block)
                                {
                                    let reason = format!(
                                        "received unrequested recovery body {} at height {}",
                                        block.header.hash().to_hex(),
                                        block.header.number.0,
                                    );
                                    eprintln!("p2p sync closing stale range response: {reason}");
                                    // This body belongs to an earlier request on this
                                    // transport. Keeping the session open consumes the
                                    // remaining stale range and delays the durable cursor.
                                    // Close without a penalty; the next provider session
                                    // reissues the exact persisted height.
                                    // Never reject the durable recovery job
                                    // because one provider route returned a
                                    // different branch. The cursor is keyed
                                    // by the candidate branch and survives
                                    // this route so another provider can
                                    // resume from the same exact height.
                                    let _provider_conflict =
                                        recovery_body_conflicts_with_cursor(peer, block);
                                    // An unrequested body proves this session
                                    // and cursor disagree. Re-discover the
                                    // ancestor unconditionally; retaining the
                                    // spool makes this a metadata repair, not
                                    // a chain-data reset.
                                    let _ = _provider_conflict;
                                    reset_recovery_cursor_for_fork(config, peer);
                                    record_recovery_failure(config, peer, reason);
                                    break;
                                }
                            }
                            let forward_recovery_active = branch_sync_cursors()
                                .lock()
                                .expect("branch sync cursor mutex poisoned")
                                .get(&cursor_key(peer))
                                .is_some_and(|cursor| cursor.ancestor_height.is_some());
                            if forward_recovery_active
                                && is_recovery_sideband_message(&agreement_message)
                            {
                                // `GetBlockRange` has no hash-addressed
                                // response.  Ignore unrelated relay/header
                                // traffic until this bounded range completes
                                // instead of allowing it to abort the durable
                                // recovery cursor.
                                line.clear();
                                continue;
                            }
                            // Only a new canonical height or a body admitted to the
                            // durable recovery range counts as progress.  Duplicate
                            // current-tip bodies are useful confirmation, but are not
                            // a reason to reconnect immediately after this session.
                            let canonical_height_before =
                                if matches!(&agreement_message, P2pMessage::BlockBody { .. }) {
                                    storage
                                        .lock()
                                        .expect("storage mutex poisoned")
                                        .best_header()
                                        .ok()
                                        .map(|header| header.number.0)
                                } else {
                                    None
                                };
                            let import_result = if recovery_range_body {
                                match &agreement_message {
                                    P2pMessage::BlockBody { block } => {
                                        let (tip_hash, next_height, expected_parent) =
                                            forward_recovery_context(peer).ok_or_else(|| {
                                                anyhow::anyhow!(
                                                    "recovery body arrived without a forward cursor"
                                                )
                                            })?;
                                        import_recovery_block(
                                            config,
                                            &storage,
                                            tip_hash,
                                            next_height,
                                            expected_parent,
                                            block,
                                        )
                                    }
                                    _ => unreachable!("checked recovery body"),
                                }
                            } else {
                                handle_p2p_message_from(
                                    reader.get_mut(),
                                    config,
                                    &storage,
                                    &mempool,
                                    message,
                                    Some(&peer_tls_certificate_hash),
                                    Some(peer),
                                )
                            };
                            match import_result {
                                Ok(()) => {
                                    if let Some(identity_public_key) = hello_identity {
                                        remember_verified_peer_identity(
                                            config,
                                            peer,
                                            &identity_public_key,
                                        );
                                        if sync_identity_lease.is_none() {
                                            let Some(lease) =
                                                SyncIdentityLease::acquire(&identity_public_key)
                                            else {
                                                eprintln!(
                                                    "p2p sync to {peer} deferred: peer identity already has an active sync session"
                                                );
                                                break;
                                            };
                                            sync_identity_lease = Some(lease);
                                        }
                                    }
                                    record_verified_peer_tip(&agreement_message);
                                    if matches!(agreement_message, P2pMessage::BlockBody { .. }) {
                                        if let Some(identity) =
                                            stored_identity_public_key.as_deref()
                                        {
                                            mark_peer_body_verified(identity);
                                        }
                                    }
                                    if identity_peer_id.is_some_and(|peer_id| {
                                        peer_scores
                                            .lock()
                                            .expect("peer score mutex poisoned")
                                            .is_banned(peer_id)
                                    }) {
                                        anyhow::bail!("peer identity is banned");
                                    }
                                    peer_scores
                                        .lock()
                                        .expect("peer score mutex poisoned")
                                        .observe_valid(identity_peer_id.unwrap_or(address_peer_id));
                                    if is_hello
                                        && confirmed_idle_match
                                        && recovery_job_lease.is_none()
                                    {
                                        // The signed peer tip exactly matches our canonical
                                        // tip. Do not keep an idle TLS socket until its read
                                        // deadline just to learn that again; regular status
                                        // polling and relay announcements wake this route when
                                        // the peer advances.
                                        break;
                                    }
                                    if matches!(agreement_message, P2pMessage::BlockNotFound { .. })
                                    {
                                        let forward_recovery = branch_sync_cursors()
                                            .lock()
                                            .expect("branch sync cursor mutex poisoned")
                                            .get(&cursor_key(peer))
                                            .is_some_and(|cursor| cursor.ancestor_height.is_some());
                                        if forward_recovery {
                                            // A range job must never fall back into the old
                                            // hash-by-parent walk. Retain its durable height
                                            // cursor and fail over to the next provider.
                                            record_recovery_failure(
                                                config,
                                                peer,
                                                "provider returned BlockNotFound for forward recovery",
                                            );
                                            break;
                                        }
                                        if !retried_cursor_by_number {
                                            if let Some(height) = branch_cursor_next_height(peer) {
                                                retried_cursor_by_number = true;
                                                eprintln!(
                                                    "p2p hash lookup missed cursor body; retrying canonical height {height} from {peer}"
                                                );
                                                send_p2p_message(
                                                    reader.get_mut(),
                                                    &P2pMessage::GetBlock { number: height },
                                                )?;
                                                line.clear();
                                                continue;
                                            }
                                        }
                                        let mut progress = sync_progress()
                                            .lock()
                                            .expect("sync progress mutex poisoned");
                                        progress.active_peer = Some(peer.to_string());
                                        progress.provider_state = "body-unavailable";
                                        progress.state = "waiting-for-provider";
                                        record_recovery_failure(
                                            config,
                                            peer,
                                            "provider returned BlockNotFound",
                                        );
                                        break;
                                    }
                                    if matches!(&agreement_message, P2pMessage::BlockBody { .. }) {
                                        let canonical_height_after = storage
                                            .lock()
                                            .expect("storage mutex poisoned")
                                            .best_header()
                                            .ok()
                                            .map(|header| header.number.0);
                                        record_sync_progress(
                                            peer,
                                            canonical_height_after.unwrap_or(0),
                                            branch_cursor_target_height(peer),
                                        );
                                        last_import = Instant::now();
                                        made_progress |= sync_session_made_progress(
                                            recovery_range_body,
                                            canonical_height_before,
                                            canonical_height_after,
                                        );
                                        bodies_since_headers =
                                            bodies_since_headers.saturating_add(1);
                                        bodies_in_range = bodies_in_range.saturating_add(1);
                                        if bodies_in_range % RECOVERY_MIN_BATCH_BODIES == 0 {
                                            recovery_rate_window = Instant::now();
                                        }
                                        let forward_complete = match &agreement_message {
                                            P2pMessage::BlockBody { block } => {
                                                let complete = record_forward_recovery_progress(
                                                    config, peer, block,
                                                );
                                                if let Some(identity) =
                                                    stored_identity_public_key.as_deref()
                                                {
                                                    let _ = coalesce_recovery_job_after_branch_root(
                                                        peer, identity,
                                                    );
                                                }
                                                // A witness may have returned its headers before
                                                // this final primary sample arrived. Record the
                                                // primary evidence after cursor progress so the
                                                // publication gate sees both completion and the
                                                // newly cross-checked range in one transition.
                                                let witness_ready = record_primary_witness_sample(
                                                    config, peer, block,
                                                )?;
                                                complete || witness_ready
                                            }
                                            _ => false,
                                        };
                                        if forward_complete {
                                            storage
                                                .lock()
                                                .expect("storage mutex poisoned")
                                                .flush_sync_batch()?;
                                            eprintln!(
                                                "p2p recovery fetched complete forward branch from {peer}; evaluating staged publication"
                                            );
                                            start_candidate_recovery(config, Arc::clone(&storage));
                                            break;
                                        }
                                        // Forward recovery is deliberately
                                        // session-bounded.  Check the batch
                                        // boundary before requesting another
                                        // body; the previous order made this
                                        // branch unreachable and let one
                                        // session run indefinitely.
                                        if bodies_since_headers >= SYNC_CHECKPOINT_BATCH_SIZE {
                                            {
                                                let storage_guard =
                                                    storage.lock().expect("storage mutex poisoned");
                                                storage_guard.end_sync_batch()?;
                                                storage_guard.begin_sync_batch();
                                            }
                                            eprintln!(
                                                "p2p recovery checkpointed {} bodies from {peer}",
                                                bodies_since_headers
                                            );
                                            bodies_since_headers = 0;
                                        }
                                        if let P2pMessage::BlockBody { block } = &agreement_message
                                        {
                                            let forward_recovery = branch_sync_cursors()
                                                .lock()
                                                .expect("branch sync cursor mutex poisoned")
                                                .get(&cursor_key(peer))
                                                .is_some_and(|cursor| {
                                                    cursor.ancestor_height.is_some()
                                                });
                                            if forward_recovery {
                                                if bodies_in_range >= SYNC_RANGE_SIZE {
                                                    let next_height =
                                                        block.header.number.0.saturating_add(1);
                                                    // Persist before writing: an in-memory
                                                    // provider can return this next range
                                                    // before the socket loop reaches the
                                                    // following statement.
                                                    record_recovery_request(
                                                        config,
                                                        peer,
                                                        next_height,
                                                    );
                                                    send_p2p_message(
                                                        reader.get_mut(),
                                                        &P2pMessage::GetBlockRange {
                                                            from: next_height,
                                                            limit: SYNC_RANGE_SIZE,
                                                        },
                                                    )?;
                                                    bodies_in_range = 0;
                                                    recovery_rate_window = Instant::now();
                                                }
                                                line.clear();
                                                continue;
                                            }
                                        }
                                        if let Some(parent_hash) = missing_parent {
                                            let forward_recovery = branch_sync_cursors()
                                                .lock()
                                                .expect("branch sync cursor mutex poisoned")
                                                .get(&cursor_key(peer))
                                                .is_some_and(|cursor| {
                                                    cursor.ancestor_height.is_some()
                                                });
                                            let parent_known = storage
                                                .lock()
                                                .expect("storage mutex poisoned")
                                                .block_by_hash(parent_hash)
                                                .is_ok();
                                            if !forward_recovery && !parent_known {
                                                advance_branch_sync_cursor(
                                                    config,
                                                    peer,
                                                    parent_hash,
                                                );
                                                send_p2p_message(
                                                    reader.get_mut(),
                                                    &P2pMessage::GetBlockByHash {
                                                        hash: parent_hash.to_hex(),
                                                    },
                                                )?;
                                            } else {
                                                clear_branch_sync_cursor(config, peer);
                                            }
                                        }
                                        if bodies_since_headers >= SYNC_COMMIT_BATCH_SIZE {
                                            {
                                                let storage_guard =
                                                    storage.lock().expect("storage mutex poisoned");
                                                storage_guard.end_sync_batch()?;
                                            }
                                            eprintln!(
                                                "p2p sync committed a bounded branch batch of {} bodies from {peer}; reconnecting from durable cursor",
                                                bodies_since_headers
                                            );
                                            // A deep parent walk is intentionally split across
                                            // short sessions. This keeps request/message budgets
                                            // bounded and makes the persisted cursor the resume
                                            // point after normal transport churn.
                                            break;
                                        }
                                    }
                                }
                                Err(err) => {
                                    if recovery_range_body
                                        && err.to_string().contains("was not found")
                                    {
                                        mark_recovery_spool_unverified(
                                            config,
                                            peer,
                                            "recovery parent missing from local spool; reconciling checkpoint",
                                        );
                                    }
                                    if is_consensus_profile_mismatch(&err)
                                        || should_defer_transaction_gossip(
                                            is_transaction_gossip,
                                            &err,
                                        )
                                    {
                                        eprintln!("transaction gossip deferred without peer penalty: {err}");
                                        line.clear();
                                        continue;
                                    }
                                    if should_penalize_p2p_error(is_transaction_gossip, &err) {
                                        peer_scores
                                            .lock()
                                            .expect("peer score mutex poisoned")
                                            .penalize(
                                                identity_peer_id.unwrap_or(address_peer_id),
                                                10,
                                            );
                                    } else {
                                        eprintln!(
                                            "p2p sync deferred without peer penalty from {peer}: {err}"
                                        );
                                    }
                                    eprintln!("p2p sync session with {peer} ended: {err}");
                                    break;
                                }
                            }
                            line.clear();
                        }
                        Err(err) if is_read_timeout(&err) => {
                            // A nonblocking TLS read may surface EAGAIN while the
                            // provider is still assembling the next frame. During
                            // recovery keep the lease and durable cursor alive;
                            // the no-progress watchdog remains the hard deadline.
                            if recovery_job_lease.is_some() {
                                thread::sleep(Duration::from_millis(25));
                                continue;
                            }
                            record_recovery_failure(
                                config,
                                peer,
                                format!("transport ended: {err}"),
                            );
                            break;
                        }
                        Err(err) if is_peer_disconnect(&err) => {
                            record_recovery_failure(
                                config,
                                peer,
                                format!("transport ended: {err}"),
                            );
                            break;
                        }
                        Err(err) => {
                            eprintln!("p2p sync read from {peer} ended: {err}");
                            record_recovery_failure(config, peer, format!("read failed: {err}"));
                            break;
                        }
                    }
                }
                storage
                    .lock()
                    .expect("storage mutex poisoned")
                    .end_sync_batch()?;
                drop(sync_identity_lease);
                drop(recovery_job_lease);
                SYNC_SESSION_STARTED_AT.store(0, Ordering::Release);
            }
            Err(err) => {
                record_p2p_route_connect_failure(peer);
                eprintln!("p2p connect to {peer} failed: {err}");
            }
        }
        let delay = sync_retry_delay(
            confirmed_idle_match,
            authenticated_session,
            made_progress,
            &mut retry_delay_seconds,
        );
        thread::sleep(Duration::from_secs(delay));
    }
}

fn register_with_discovery_servers(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
) -> Result<()> {
    let Some(address) = &config.network.advertise_addr else {
        return Ok(());
    };
    if address.is_empty() {
        return Ok(());
    }
    let best = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?;
    let storage_guard = storage.lock().expect("storage mutex poisoned");
    let retained_from = storage_guard.oldest_body_height()?.unwrap_or(0);
    let retained_to = storage_guard.best_header()?.number.0;
    let snapshot_heights = storage_guard.snapshot_heights()?;
    let configured_genesis = configured_genesis_hash(&storage_guard)?;
    drop(storage_guard);
    let mut peer = PeerRecord {
        address: address.clone(),
        route_class: route_class_for_address(address),
        direct: true,
        relay: false,
        last_success_epoch: unix_now(),
        last_failure_epoch: None,
        expires_at_epoch: unix_now().saturating_add(3600),
        alternate_addresses: Vec::new(),
        identity_public_key: None,
        consensus_profile: String::new(),
        chain_id: MAINNET_CHAIN_ID,
        genesis_hash: String::new(),
        protocol_version: "blq-p2p-v1".to_string(),
        node_mode: config.node.mode,
        best_number: best.number.0,
        best_hash: best.hash().to_hex(),
        storage_mode: config.node.storage_mode,
        retained_from_height: retained_from,
        retained_to_height: retained_to,
        snapshot_heights,
        explorer_index: config.explorer.index_enabled(config.node.storage_mode),
        explorer_share: config.explorer.share_enabled(config.node.storage_mode),
        explorer_relay: config.explorer.relay,
    };
    let identity = NodeIdentity::load_or_create(Path::new(&config.node.data_dir))?;
    let identity_public_key = identity.public_key_hex();
    peer.identity_public_key = Some(identity_public_key.clone());
    peer.consensus_profile = network_consensus_profile(config, configured_genesis);
    peer.genesis_hash = configured_genesis.to_hex();
    let identity_signature = identity.sign(&service_auth_payload(
        "BLQ-DISCOVERY-REGISTER-v1",
        &[
            &peer.address,
            peer.node_mode.as_str(),
            &peer.best_number.to_string(),
            &peer.best_hash,
            &format!("{:?}", peer.storage_mode),
            &peer.retained_from_height.to_string(),
            &peer.retained_to_height.to_string(),
            &identity_public_key,
        ],
    ));
    for server in &config.network.discovery_servers {
        match connect_tcp_session(server) {
            Ok(mut stream) => {
                let _shutdown = SocketShutdownGuard::new(&stream)?;
                send_discovery_message(
                    &mut stream,
                    &DiscoveryMessage::Register {
                        peer: peer.clone(),
                        identity_public_key: identity_public_key.clone(),
                        identity_signature: identity_signature.clone(),
                    },
                )?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut response = String::new();
                let _ = BufReader::new(stream).read_line(&mut response);
            }
            Err(err) => eprintln!("discovery register to {server} failed: {err}"),
        }
    }
    Ok(())
}

fn discover_peers(config: &NodeConfig) -> Result<Vec<String>> {
    Ok(discover_peer_records(config)?
        .into_iter()
        .map(|peer| peer.address)
        .collect())
}

fn discover_peer_records(config: &NodeConfig) -> Result<Vec<PeerRecord>> {
    let mut peers = Vec::new();
    let identity = NodeIdentity::load_or_create(Path::new(&config.node.data_dir))?;
    let identity_public_key = identity.public_key_hex();
    let identity_signature = identity.sign(&service_auth_payload(
        "BLQ-DISCOVERY-GET-v1",
        &[&identity_public_key],
    ));
    for server in &config.network.discovery_servers {
        match connect_tcp_session(server) {
            Ok(mut stream) => {
                let _shutdown = SocketShutdownGuard::new(&stream)?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                send_discovery_message(
                    &mut stream,
                    &DiscoveryMessage::GetPeers {
                        identity_public_key: identity_public_key.clone(),
                        identity_signature: identity_signature.clone(),
                    },
                )?;
                let mut reader = BufReader::new(stream.try_clone()?);
                let mut line = String::new();
                if reader.read_line(&mut line)? > 0 {
                    if let DiscoveryMessage::Peers { peers: records } =
                        serde_json::from_str(line.trim())?
                    {
                        peers.extend(records);
                    }
                }
            }
            Err(err) => eprintln!("discovery getPeers from {server} failed: {err}"),
        }
    }
    if let Some(address) = &config.network.advertise_addr {
        peers.retain(|peer| &peer.address != address);
    }
    Ok(peers)
}

fn register_with_relay_servers(config: &NodeConfig) -> Result<()> {
    let Some(node_id) = &config.network.advertise_addr else {
        return Ok(());
    };
    let identity = NodeIdentity::load_or_create(Path::new(&config.node.data_dir))?;
    let identity_public_key = identity.public_key_hex();
    for server in &config.network.relay_servers {
        match connect_tcp_session(server) {
            Ok(mut stream) => {
                let _shutdown = SocketShutdownGuard::new(&stream)?;
                send_relay_message(
                    &mut stream,
                    &RelayMessage::Register {
                        node_id: node_id.clone(),
                        identity_public_key: identity_public_key.clone(),
                        identity_signature: identity.sign(&service_auth_payload(
                            "BLQ-RELAY-REGISTER-v1",
                            &[node_id, &identity_public_key],
                        )),
                    },
                )?;
            }
            Err(err) => eprintln!("relay register to {server} failed: {err}"),
        }
    }
    Ok(())
}

fn start_relay_pollers(
    config: &NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
    peer_scores: Arc<Mutex<PeerScoreBook>>,
) {
    let Some(node_id) = config.network.advertise_addr.clone() else {
        return;
    };
    for server in config.network.relay_servers.clone() {
        let config = config.clone();
        let storage = Arc::clone(&storage);
        let mempool = Arc::clone(&mempool);
        let peer_scores = Arc::clone(&peer_scores);
        let node_id = node_id.clone();
        thread::spawn(move || loop {
            if let Err(err) =
                poll_relay_server(&config, &storage, &mempool, &server, &node_id, &peer_scores)
            {
                eprintln!("relay poll from {server} failed: {err}");
            }
            thread::sleep(Duration::from_secs(10));
        });
    }
}

fn poll_relay_server(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    server: &str,
    node_id: &str,
    peer_scores: &Arc<Mutex<PeerScoreBook>>,
) -> Result<()> {
    if peer_scores
        .lock()
        .expect("peer score mutex poisoned")
        .is_banned(PeerId::from_advertised_address(server))
    {
        anyhow::bail!("relay peer is banned");
    }
    let mut stream = connect_tcp_session(server)?;
    let _shutdown = SocketShutdownGuard::new(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let identity = NodeIdentity::load_or_create(Path::new(&config.node.data_dir))?;
    let identity_public_key = identity.public_key_hex();
    send_relay_message(
        &mut stream,
        &RelayMessage::Register {
            node_id: node_id.to_string(),
            identity_public_key: identity_public_key.clone(),
            identity_signature: identity.sign(&service_auth_payload(
                "BLQ-RELAY-REGISTER-v1",
                &[node_id, &identity_public_key],
            )),
        },
    )?;
    send_relay_message(
        &mut stream,
        &RelayMessage::Poll {
            node_id: node_id.to_string(),
            identity_public_key: identity_public_key.clone(),
            identity_signature: identity.sign(&service_auth_payload(
                "BLQ-RELAY-POLL-v1",
                &[node_id, &identity_public_key],
            )),
        },
    )?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? > 0 {
        if let RelayMessage::Messages { messages } = serde_json::from_str(line.trim())? {
            if !messages.is_empty() {
                eprintln!(
                    "relay poll from {server} received {} block notification(s)",
                    messages.len()
                );
            }
            for message in messages {
                let result = match message {
                    P2pMessage::NewHeader { header } => {
                        handle_relay_header(config, storage, mempool, header)
                    }
                    P2pMessage::BlockBody { block } => {
                        import_network_block(config, storage, mempool, block, None)
                    }
                    _ => anyhow::bail!("relay returned a non-block payload"),
                };
                match result {
                    Ok(()) => {
                        peer_scores
                            .lock()
                            .expect("peer score mutex poisoned")
                            .observe_valid(PeerId::from_advertised_address(server));
                    }
                    Err(err) => {
                        peer_scores
                            .lock()
                            .expect("peer score mutex poisoned")
                            .penalize(PeerId::from_advertised_address(server), 10);
                        return Err(err);
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_relay_header(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    header: BlockHeader,
) -> Result<()> {
    if config.node.mode == NodeMode::Partial {
        return import_network_header(config, storage, header);
    }

    let best = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?;
    if header.number.0 <= best.number.0 {
        return Ok(());
    }

    let expected_hash = header.hash();
    for peer in config
        .network
        .bootstrap_peers
        .iter()
        .take(MAX_RPC_BODY_FETCH_PEERS)
    {
        match fetch_rpc_block_body(config, storage, peer, header.number.0, expected_hash) {
            Ok(block) => return import_network_block(config, storage, mempool, block, None),
            Err(err) => eprintln!("relay header body fetch from {peer} failed: {err}"),
        }
    }
    anyhow::bail!(
        "relay announced block {} but no configured bootstrap peer returned its body",
        header.number.0
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_p2p_connection<S>(
    stream: S,
    config: &NodeConfig,
    storage: Arc<Mutex<NodeStorage>>,
    mempool: Arc<Mutex<Mempool>>,
    peer_scores: Arc<Mutex<PeerScoreBook>>,
    peer_address: String,
    expected_tls_certificate_hash: Option<&str>,
    tls_certificate_hash: &str,
) -> Result<()>
where
    S: Read + Write,
{
    let mut reader = BufReader::new(stream);
    let session_started = Instant::now();
    send_p2p_message(
        reader.get_mut(),
        &hello_message(config, &storage, tls_certificate_hash)?,
    )?;
    eprintln!("p2p inbound hello sent to {peer_address}");
    let mut line = String::new();
    let mut messages_seen = 0usize;
    let mut transactions_seen = 0usize;
    let mut body_requests_seen = 0usize;
    let mut handshake_complete = false;
    let address_peer_id = PeerId::from_advertised_address(&peer_address);
    let mut identity_peer_id = None;
    loop {
        if session_started.elapsed() >= P2P_INBOUND_SESSION_MAX {
            // The peer can reconnect for further work. Releasing the guard
            // here is more important than allowing one idle or chatty inbound
            // socket to deny configured sync/recovery sessions.
            break;
        }
        let has_line = match read_p2p_line(&mut reader, &mut line) {
            Ok(has_line) => has_line,
            Err(err) if is_read_timeout(&err) || is_peer_disconnect(&err) => break,
            Err(err) => return Err(err.into()),
        };
        if !has_line {
            break;
        }
        messages_seen = messages_seen.saturating_add(1);
        if messages_seen > MAX_P2P_MESSAGES_PER_CONNECTION {
            anyhow::bail!("peer exceeded per-connection message limit");
        }
        let message = match serde_json::from_str(line.trim()) {
            Ok(message) => message,
            Err(err) => {
                peer_scores
                    .lock()
                    .expect("peer score mutex poisoned")
                    .penalize(identity_peer_id.unwrap_or(address_peer_id), 20);
                return Err(err.into());
            }
        };
        if matches!(message, P2pMessage::NewTransaction { .. }) {
            transactions_seen = transactions_seen.saturating_add(1);
            if transactions_seen > 256 {
                anyhow::bail!("peer exceeded per-connection transaction gossip limit");
            }
        }
        if matches!(&message, P2pMessage::GetHeaders { .. }) {
            body_requests_seen = 0;
        }
        if matches!(
            message,
            P2pMessage::GetBlock { .. }
                | P2pMessage::GetBlockRange { .. }
                | P2pMessage::GetBlockByHash { .. }
                | P2pMessage::GetTransaction { .. }
        ) {
            body_requests_seen = body_requests_seen.saturating_add(1);
            if body_requests_seen > MAX_P2P_BODY_REQUESTS_PER_CONNECTION {
                anyhow::bail!("peer exceeded per-connection body request limit");
            }
        }
        if let P2pMessage::Hello {
            identity_public_key,
            ..
        } = &message
        {
            identity_peer_id = Some(PeerId::from_identity_public_key(identity_public_key));
        }
        if !matches!(message, P2pMessage::Hello { .. })
            && identity_peer_id.is_some_and(|peer_id| {
                peer_scores
                    .lock()
                    .expect("peer score mutex poisoned")
                    .is_banned(peer_id)
            })
        {
            anyhow::bail!("peer identity is banned");
        }
        handshake_complete = advance_p2p_handshake(&message, handshake_complete)?;
        let agreement_message = message.clone();
        let is_transaction_gossip = matches!(
            &message,
            P2pMessage::NewTransaction { .. }
                | P2pMessage::NewTransactionHashes { .. }
                | P2pMessage::GetTransactions { .. }
                | P2pMessage::Transactions { .. }
        );
        eprintln!(
            "p2p inbound received {} from {peer_address}",
            p2p_message_kind(&message)
        );
        match handle_p2p_message_from(
            reader.get_mut(),
            config,
            &storage,
            &mempool,
            message,
            expected_tls_certificate_hash,
            Some(&peer_address),
        ) {
            Ok(()) => {
                if matches!(agreement_message, P2pMessage::Hello { .. }) {
                    if let Ok(peers) = peer_exchange_records(config) {
                        let _ =
                            send_p2p_message(reader.get_mut(), &P2pMessage::PeerExchange { peers });
                    }
                }
                if let Err(err) = reconcile_peer_tip(reader.get_mut(), &storage, &agreement_message)
                {
                    eprintln!("peer tip reconciliation failed for {peer_address}: {err}");
                }
                record_verified_peer_tip(&agreement_message);
                if identity_peer_id.is_some_and(|peer_id| {
                    peer_scores
                        .lock()
                        .expect("peer score mutex poisoned")
                        .is_banned(peer_id)
                }) {
                    anyhow::bail!("peer identity is banned");
                }
                peer_scores
                    .lock()
                    .expect("peer score mutex poisoned")
                    .observe_valid(identity_peer_id.unwrap_or(address_peer_id));
            }
            Err(err) => {
                if is_consensus_profile_mismatch(&err)
                    || should_defer_transaction_gossip(is_transaction_gossip, &err)
                {
                    eprintln!("transaction gossip deferred without peer penalty: {err}");
                    line.clear();
                    continue;
                }
                if should_penalize_p2p_error(is_transaction_gossip, &err) {
                    peer_scores
                        .lock()
                        .expect("peer score mutex poisoned")
                        .penalize(identity_peer_id.unwrap_or(address_peer_id), 10);
                } else {
                    eprintln!("transaction gossip deferred without peer penalty: {err}");
                }
                return Err(err);
            }
        }
        line.clear();
    }
    Ok(())
}

fn peer_exchange_records(config: &NodeConfig) -> Result<Vec<PeerRecord>> {
    let mut peers = discover_peer_records(config).unwrap_or_default();
    if let Some(routes) = DISCOVERED_PEER_ROUTES.get() {
        peers.extend(
            routes
                .lock()
                .expect("discovered peer routes poisoned")
                .values()
                .cloned(),
        );
    }
    peers.retain(|peer| validate_peer_record(peer).is_ok() && peer_route_is_fresh(peer));
    peers.sort_by(|left, right| left.address.cmp(&right.address));
    peers.dedup_by(|left, right| {
        left.identity_public_key.is_some() && left.identity_public_key == right.identity_public_key
    });
    peers.truncate(32);
    Ok(peers)
}

/// Resume an exact branch walk for an outbound peer session. A long branch
/// may exceed one connection's message budget, so reconnects continue from
/// the oldest missing parent rather than restarting at the remote tip.
fn request_peer_branch_cursor<S: Write>(
    stream: &mut S,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    peer: &str,
    peer_best_number: u64,
    peer_best_hash: &str,
    peer_consensus_profile: &str,
) -> Result<()> {
    let peer_tip = Hash256::from_hex(peer_best_hash)
        .map_err(|err| anyhow::anyhow!("peer advertised invalid tip hash: {err:?}"))?;
    let local = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?;
    let differs = peer_best_number > local.number.0
        || (peer_best_number == local.number.0 && peer_tip != local.hash());
    eprintln!(
        "p2p branch check for {peer}: peer_height={peer_best_number} local_height={} differs={differs}",
        local.number.0
    );
    if !differs {
        clear_canonical_recovery_cursor(config, storage, peer);
        return Ok(());
    }
    reconcile_forward_recovery_spool(config, storage, peer)?;
    // Spool reconciliation may have advanced an obsolete hello target to the
    // last locally validated body.  Do not reopen a range for a job that is
    // already complete: that would overwrite `complete` with `retrieving`
    // and leave publication waiting for another unrelated peer event.
    if peer_best_number <= local.number.0 {
        if let Some(tip_hash) = completed_recovery_tip() {
            eprintln!(
                "p2p recovery has a complete durable spool for {}; evaluating publication",
                tip_hash.to_hex()
            );
            start_candidate_recovery(config, Arc::clone(storage));
            return Ok(());
        }
    }
    let finalized_floor = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()
        .map(|header| finalized_height(header.number.0))?;
    prune_finalized_recovery_cursors(config, finalized_floor);
    let mut existing_key =
        durable_forward_cursor_key(peer, peer_consensus_profile, finalized_floor)
            .unwrap_or_else(|| cursor_key(peer));
    // A signed hello from the same authenticated primary is a moving-tip
    // update for its already-proven branch.  Keep the recovery spool and
    // next-height cursor, but re-key the job to the provider's newer tip so
    // completed staged bodies can actually be selected for publication.
    // Other identities still prove their suffix through the witness path
    // before they can affect this job.
    let primary_retarget = {
        let peer_identity = known_peer_identities()
            .lock()
            .expect("known peer identities mutex poisoned")
            .get(peer)
            .cloned();
        let cursors = branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned");
        cursors.get(&existing_key).and_then(|cursor| {
            (cursor.ancestor_height.is_some()
                && cursor.consensus_profile == peer_consensus_profile
                && cursor.next_height > 0
                && peer_best_number > cursor.tip_height
                && peer_identity.as_deref() == cursor.primary_identity.as_deref())
            .then_some((
                peer_identity,
                cursor.ancestor_height,
                cursor.ancestor_hash,
                cursor.branch_root_hash,
            ))
        })
    };
    if let Some((Some(identity), Some(ancestor_height), Some(ancestor_hash), branch_root_hash)) =
        primary_retarget
    {
        existing_key = coalesce_advancing_recovery_job(
            peer,
            &identity,
            peer_tip,
            peer_best_number,
            peer_consensus_profile,
            ancestor_height,
            ancestor_hash,
            branch_root_hash,
        );
        eprintln!("p2p recovery retargeted durable cursor for {peer} to height {peer_best_number}");
    }
    let (needs_ancestor, next_height, retained_forward_job) = {
        let mut cursors = branch_sync_cursors()
            .lock()
            .expect("branch sync cursor mutex poisoned");
        // A provider's advertised tip changes continuously. Preserve a
        // proven forward cursor and let its expected parent decide whether
        // the next range is still on that branch, rather than making a fresh
        // cursor and rediscovering the ancestor for every new tip.
        if let Some(cursor) = cursors.get_mut(&existing_key) {
            if cursor.ancestor_height.is_some()
                && cursor.consensus_profile == peer_consensus_profile
                && cursor.next_height > 0
            {
                // The canonical tip may have advanced from a completed
                // direct-recovery batch while this durable cursor still
                // names its old first missing body. Resume after the local
                // validated prefix instead of requesting that stale body.
                if cursor.next_height <= local.number.0 {
                    cursor.next_height = local.number.0.saturating_add(1);
                    cursor.expected_parent_hash = Some(local.hash());
                    cursor.last_failure = None;
                }
                // A signed hello proves only a peer's claimed tip. It does
                // not prove that the peer's branch continues the durable
                // cursor we are currently retrieving. Keep the job target
                // stable until its own ordered body stream proves that
                // extension; otherwise a second route can retarget the job
                // and make the first range response look stale.
                cursor.provider = Some(peer.to_string());
                cursor.state = "retrieving".to_string();
                cursor.updated_at = unix_now();
                peer_recovery_keys()
                    .lock()
                    .expect("peer recovery keys mutex poisoned")
                    .insert(peer.to_string(), existing_key.clone());
                (false, cursor.next_height, true)
            } else {
                set_peer_recovery_key(peer, peer_tip);
                let key = recovery_cursor_key(peer_tip);
                let cursor = cursors.entry(key).or_insert_with(|| {
                    new_branch_sync_cursor(
                        peer_tip,
                        peer_best_number,
                        peer_consensus_profile.to_string(),
                    )
                });
                if cursor.tip_height == 0 {
                    cursor.tip_height = peer_best_number;
                    cursor.consensus_profile = peer_consensus_profile.to_string();
                }
                (cursor.ancestor_height.is_none(), cursor.next_height, false)
            }
        } else {
            set_peer_recovery_key(peer, peer_tip);
            let key = recovery_cursor_key(peer_tip);
            let cursor = cursors.entry(key).or_insert_with(|| {
                new_branch_sync_cursor(
                    peer_tip,
                    peer_best_number,
                    peer_consensus_profile.to_string(),
                )
            });
            if cursor.tip_height == 0 {
                cursor.tip_height = peer_best_number;
                cursor.consensus_profile = peer_consensus_profile.to_string();
            }
            (cursor.ancestor_height.is_none(), cursor.next_height, false)
        }
    };
    if let Err(err) = persist_branch_sync_cursors(config) {
        eprintln!("could not persist branch sync cursor: {err}");
    }
    if needs_ancestor {
        record_recovery_request(config, peer, 0);
        send_p2p_message(
            stream,
            &P2pMessage::FindCommonAncestor {
                locator: recovery_locator(storage)?,
            },
        )
    } else {
        // The durable job owns the next contiguous height.  Persist the
        // request before putting it on the wire so a restart resumes this
        // exact block rather than reconnecting without doing useful work.
        record_recovery_request(config, peer, next_height);
        send_p2p_message(
            stream,
            &P2pMessage::GetBlockRange {
                from: next_height,
                limit: SYNC_RANGE_SIZE,
            },
        )?;
        if retained_forward_job {
            eprintln!("p2p recovery continuing durable cursor for {peer} at height {next_height}");
        }
        Ok(())
    }
}

/// Request the exact peer-tip body as soon as a signed hello reveals a tip
/// difference. Parent-hash retrieval then walks the remote branch backward to
/// a known canonical ancestor, which works for same-height and deep forks.
fn reconcile_peer_tip<S: Write>(
    stream: &mut S,
    storage: &Arc<Mutex<NodeStorage>>,
    message: &P2pMessage,
) -> Result<()> {
    // A durable forward recovery owns the connection's ordered body stream.
    // Do not enqueue a competing hash-addressed request from the inbound
    // hello path: its response can interleave with GetBlockRange bodies and
    // make a valid checkpoint look stale.
    if has_durable_recovery_job() {
        return Ok(());
    }
    let P2pMessage::Hello {
        best_number,
        best_hash,
        consensus_profile,
        ..
    } = message
    else {
        return Ok(());
    };
    let local = storage
        .lock()
        .expect("storage mutex poisoned")
        .best_header()?;
    let local_hash = local.hash().to_hex();
    if (*best_number > local.number.0
        || (*best_number == local.number.0 && best_hash != &local_hash))
        && Hash256::from_hex(best_hash).is_ok()
    {
        send_p2p_message(
            stream,
            &P2pMessage::GetBlockByHash {
                hash: best_hash.clone(),
            },
        )?;
    }
    let _ = consensus_profile;
    Ok(())
}

fn should_defer_transaction_gossip(is_transaction_gossip: bool, error: &anyhow::Error) -> bool {
    is_transaction_gossip && !should_penalize_p2p_error(true, error)
}

fn is_consensus_profile_mismatch(error: &anyhow::Error) -> bool {
    error.to_string().contains("consensus profile mismatch")
}

fn should_penalize_p2p_error(is_transaction_gossip: bool, error: &anyhow::Error) -> bool {
    if !is_transaction_gossip {
        let message = error.to_string();
        // Fork choice and synchronization races are expected in a PoW
        // network. They must not permanently ban a bootstrap peer while a
        // candidate branch is being replayed or a body is still arriving.
        return !(message.contains("was not found")
            || message.contains("candidate")
            || message.contains("reorganization")
            || message.contains("stale")
            || message.contains("duplicate")
            || message.contains("Broken pipe")
            || message.contains("connection reset")
            || message.contains("connection refused")
            || message.contains("timed out")
            || message.contains("orphan block pool is full")
            || message.contains("No space left on device")
            || message.contains("per-connection body request limit")
            || message.contains("Resource temporarily unavailable")
            || message.contains("peer identity is banned")
            // A conflicting witness report proves that this recovery attempt
            // is unsafe, but does not identify which authenticated provider
            // is lying. Fail over without penalizing either one automatically.
            || message.contains("witness header mismatch"));
    }
    let message = error.to_string();
    !(message.contains("invalid nonce") || message.contains("insufficient balance"))
}

fn advance_p2p_handshake(message: &P2pMessage, complete: bool) -> Result<bool> {
    match (message, complete) {
        (P2pMessage::Hello { .. }, false) => Ok(true),
        (P2pMessage::Hello { .. }, true) => anyhow::bail!("peer sent duplicate hello"),
        (_, false) => anyhow::bail!(
            "peer must send signed hello before data messages: received {}",
            p2p_message_kind(message)
        ),
        (_, true) => Ok(true),
    }
}

fn p2p_message_kind(message: &P2pMessage) -> &'static str {
    match message {
        P2pMessage::Hello { .. } => "Hello",
        P2pMessage::GetHeaders { .. } => "GetHeaders",
        P2pMessage::Headers { .. } => "Headers",
        P2pMessage::FindCommonAncestor { .. } => "FindCommonAncestor",
        P2pMessage::CommonAncestor { .. } => "CommonAncestor",
        P2pMessage::GetBlock { .. } => "GetBlock",
        P2pMessage::GetBlockRange { .. } => "GetBlockRange",
        P2pMessage::WitnessHeaders { .. } => "WitnessHeaders",
        P2pMessage::WitnessHeadersResponse { .. } => "WitnessHeadersResponse",
        P2pMessage::GetBlockByHash { .. } => "GetBlockByHash",
        P2pMessage::BlockBody { .. } => "BlockBody",
        P2pMessage::BlockNotFound { .. } => "BlockNotFound",
        P2pMessage::GetTransaction { .. } => "GetTransaction",
        P2pMessage::Transaction { .. } => "Transaction",
        P2pMessage::NewTransaction { .. } => "NewTransaction",
        P2pMessage::NewTransactionHashes { .. } => "NewTransactionHashes",
        P2pMessage::GetTransactions { .. } => "GetTransactions",
        P2pMessage::Transactions { .. } => "Transactions",
        P2pMessage::PeerExchange { .. } => "PeerExchange",
        P2pMessage::NewHeader { .. } => "NewHeader",
    }
}

fn handle_p2p_message<S: Write>(
    stream: &mut S,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    message: P2pMessage,
    expected_tls_certificate_hash: Option<&str>,
) -> Result<()> {
    handle_p2p_message_from(
        stream,
        config,
        storage,
        mempool,
        message,
        expected_tls_certificate_hash,
        None,
    )
}

fn handle_p2p_message_from<S: Write>(
    stream: &mut S,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    message: P2pMessage,
    expected_tls_certificate_hash: Option<&str>,
    source_peer: Option<&str>,
) -> Result<()> {
    let expected_profile = {
        let storage = storage.lock().expect("storage mutex poisoned");
        network_consensus_profile(config, configured_genesis_hash(&storage)?)
    };
    match message {
        P2pMessage::Hello {
            node_mode,
            best_number,
            best_hash,
            consensus_profile,
            identity_public_key,
            identity_signature,
            tls_certificate_hash,
        } => verify_p2p_identity_for_profile(
            node_mode,
            best_number,
            &best_hash,
            &consensus_profile,
            &identity_public_key,
            &identity_signature,
            &tls_certificate_hash,
            expected_tls_certificate_hash,
            (!config.network.trusted_peer_keys.is_empty())
                .then_some(config.network.trusted_peer_keys.as_slice()),
            &expected_profile,
        ),
        P2pMessage::GetHeaders { from, limit } => {
            // Snapshot the response while the storage mutex is held, then
            // release it before writing to the peer. A slow client must never
            // make local RPC or other P2P handlers wait on network I/O.
            let headers = {
                let storage = storage.lock().expect("storage mutex poisoned");
                storage.headers_after(from, limit.min(MAX_P2P_HEADERS))?
            };
            send_p2p_message(stream, &P2pMessage::Headers { headers })
        }
        P2pMessage::Headers { headers } => {
            if headers.len() > MAX_P2P_HEADERS {
                anyhow::bail!("peer sent too many headers");
            }
            for header in headers {
                handle_network_header(stream, config, storage, header)?;
                std::thread::yield_now();
            }
            Ok(())
        }
        P2pMessage::FindCommonAncestor { locator } => {
            if locator.len() > MAX_P2P_HEADERS {
                anyhow::bail!("peer sent too many locator hashes");
            }
            let ancestor = {
                let storage = storage.lock().expect("storage mutex poisoned");
                locator.into_iter().find_map(|encoded| {
                    let hash = Hash256::from_hex(&encoded).ok()?;
                    let header = storage.header_by_hash(hash).ok()?;
                    Some((header.number.0, hash))
                })
            };
            send_p2p_message(
                stream,
                &P2pMessage::CommonAncestor {
                    height: ancestor.map(|(height, _)| height),
                    hash: ancestor.map(|(_, hash)| hash.to_hex()),
                },
            )
        }
        P2pMessage::CommonAncestor { .. } => {
            anyhow::bail!("unexpected common ancestor response")
        }
        P2pMessage::GetBlock { number } => {
            let block = storage
                .lock()
                .expect("storage mutex poisoned")
                .block_by_number(number)?;
            send_p2p_message(stream, &P2pMessage::BlockBody { block })
        }
        P2pMessage::GetBlockRange { from, limit } => {
            let limit = limit.min(SYNC_RANGE_SIZE);
            if limit == 0 {
                anyhow::bail!("block range limit must be positive");
            }
            let blocks = {
                let storage = storage.lock().expect("storage mutex poisoned");
                let mut blocks = Vec::with_capacity(limit);
                for number in from..from.saturating_add(limit as u64) {
                    match storage.block_by_number(number) {
                        Ok(block) => blocks.push(block),
                        Err(blq_storage::StorageError::NotFound) => break,
                        Err(err) => return Err(err.into()),
                    }
                }
                blocks
            };
            for block in blocks {
                send_p2p_message(stream, &P2pMessage::BlockBody { block })?;
            }
            Ok(())
        }
        P2pMessage::WitnessHeaders { tip_hash, heights } => {
            if heights.is_empty() || heights.len() > 4 {
                anyhow::bail!("witness header request has an invalid height count");
            }
            let tip_hash = Hash256::from_hex(&tip_hash)
                .map_err(|err| anyhow::anyhow!("invalid witness tip hash: {err:?}"))?;
            let headers = {
                let storage = storage.lock().expect("storage mutex poisoned");
                let best = storage.best_header()?;
                if best.hash() != tip_hash {
                    anyhow::bail!("witness does not share the requested canonical tip");
                }
                let mut headers = Vec::with_capacity(heights.len());
                for height in heights {
                    headers.push(storage.header_by_number(blq_primitives::BlockNumber(height))?);
                }
                headers
            };
            send_p2p_message(
                stream,
                &P2pMessage::WitnessHeadersResponse {
                    tip_hash: tip_hash.to_hex(),
                    headers,
                },
            )
        }
        P2pMessage::WitnessHeadersResponse { .. } => {
            anyhow::bail!("unexpected witness header response")
        }
        P2pMessage::GetBlockByHash { hash } => {
            let hash = Hash256::from_hex(&hash)
                .map_err(|err| anyhow::anyhow!("invalid block hash: {err:?}"))?;
            let block = match storage
                .lock()
                .expect("storage mutex poisoned")
                .sync_block_by_hash(hash)
            {
                Ok(block) => block,
                Err(err) if err.to_string().contains("was not found") => {
                    return send_p2p_message(
                        stream,
                        &P2pMessage::BlockNotFound {
                            hash: hash.to_hex(),
                        },
                    );
                }
                Err(err) => return Err(err),
            };
            send_p2p_message(stream, &P2pMessage::BlockBody { block })
        }
        P2pMessage::GetTransaction { hash } => {
            let hash = Hash256::from_hex(&hash)
                .map_err(|err| anyhow::anyhow!("invalid transaction hash: {err:?}"))?;
            let data = match storage
                .lock()
                .expect("storage mutex poisoned")
                .transaction_receipt_by_hash(hash)
            {
                Ok((receipt, header, transaction_index, transaction)) => Some(RpcTransactionData {
                    receipt,
                    header,
                    transaction_index,
                    transaction,
                }),
                Err(blq_storage::StorageError::NotFound) => None,
                Err(err) => return Err(err.into()),
            };
            send_p2p_message(stream, &P2pMessage::Transaction { data })
        }
        P2pMessage::BlockBody { block } => {
            import_network_block(config, storage, mempool, block, source_peer)
        }
        P2pMessage::BlockNotFound { .. } => Ok(()),
        P2pMessage::Transaction { .. } => anyhow::bail!("unexpected transaction response"),
        P2pMessage::NewTransaction { transaction } => {
            verify_transaction_signature(&transaction)?;
            let base_fee = storage
                .lock()
                .expect("storage mutex poisoned")
                .best_header()?
                .base_fee_per_gas;
            validate_transaction_against_current_state(storage, &transaction, base_fee)?;
            let relay_transaction = transaction.clone();
            mempool
                .lock()
                .expect("mempool mutex poisoned")
                .add(transaction, base_fee)?;
            TRANSACTION_GOSSIP_RECEIVED.fetch_add(1, Ordering::Relaxed);
            enqueue_transaction_gossip(config, storage, relay_transaction);
            Ok(())
        }
        P2pMessage::NewTransactionHashes { hashes } => {
            if hashes.len() > 256 {
                anyhow::bail!("peer sent too many transaction hashes");
            }
            let known = mempool
                .lock()
                .expect("mempool mutex poisoned")
                .pending()
                .iter()
                .map(Transaction::rpc_hash)
                .collect::<BTreeSet<_>>();
            let unknown = hashes
                .into_iter()
                .filter(|hash| !known.contains(hash))
                .take(128)
                .collect();
            send_p2p_message(stream, &P2pMessage::GetTransactions { hashes: unknown })
        }
        P2pMessage::GetTransactions { hashes } => {
            if hashes.len() > 128 {
                anyhow::bail!("peer requested too many transactions");
            }
            let wanted = hashes.into_iter().collect::<BTreeSet<_>>();
            let items = mempool
                .lock()
                .expect("mempool mutex poisoned")
                .pending()
                .iter()
                .filter(|transaction| wanted.contains(&transaction.rpc_hash()))
                .take(128)
                .cloned()
                .collect();
            send_p2p_message(stream, &P2pMessage::Transactions { items })
        }
        P2pMessage::Transactions { items } => {
            if items.len() > 128 {
                anyhow::bail!("peer sent too many transactions");
            }
            let base_fee = storage
                .lock()
                .expect("storage mutex poisoned")
                .best_header()?
                .base_fee_per_gas;
            for transaction in items {
                verify_transaction_signature(&transaction)?;
                validate_transaction_against_current_state(storage, &transaction, base_fee)?;
                if mempool
                    .lock()
                    .expect("mempool mutex poisoned")
                    .add(transaction.clone(), base_fee)
                    .is_ok()
                {
                    TRANSACTION_GOSSIP_RECEIVED.fetch_add(1, Ordering::Relaxed);
                    enqueue_transaction_gossip(config, storage, transaction);
                }
            }
            Ok(())
        }
        P2pMessage::PeerExchange { peers } => {
            if peers.len() > 32 {
                anyhow::bail!("peer exchange contains too many routes");
            }
            let routes = DISCOVERED_PEER_ROUTES.get_or_init(|| Mutex::new(BTreeMap::new()));
            let mut routes = routes.lock().expect("discovered peer routes poisoned");
            for peer in peers {
                validate_peer_record(&peer)?;
                if peer.chain_id != 0 && peer.chain_id != MAINNET_CHAIN_ID {
                    continue;
                }
                if !peer.consensus_profile.is_empty() && peer.consensus_profile != expected_profile
                {
                    continue;
                }
                let route_key = peer
                    .identity_public_key
                    .clone()
                    .filter(|identity| !identity.is_empty())
                    .unwrap_or_else(|| peer.address.clone());
                routes.insert(route_key, peer);
            }
            Ok(())
        }
        P2pMessage::NewHeader { header } => handle_network_header(stream, config, storage, header),
    }
}

fn handle_network_header<S: Write>(
    stream: &mut S,
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    header: BlockHeader,
) -> Result<()> {
    match config.node.mode {
        NodeMode::Partial => import_network_header(config, storage, header),
        NodeMode::Full => {
            let needs_body = {
                let storage = storage.lock().expect("storage mutex poisoned");
                match storage.header_by_number(blq_primitives::BlockNumber(header.number.0)) {
                    Ok(existing) => existing.hash() != header.hash(),
                    Err(blq_storage::StorageError::NotFound) => true,
                    Err(err) => return Err(err.into()),
                }
            };
            if needs_body {
                send_p2p_message(
                    stream,
                    &P2pMessage::GetBlockByHash {
                        hash: header.hash().to_hex(),
                    },
                )?;
            }
            Ok(())
        }
    }
}

fn import_network_block(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    mempool: &Arc<Mutex<Mempool>>,
    block: blq_primitives::Block,
    source_peer: Option<&str>,
) -> Result<()> {
    if config.node.mode != NodeMode::Full {
        return Ok(());
    }
    let import_guard = BLOCK_IMPORT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("block import mutex poisoned");
    validate_live_timestamp_admission(&block.header)?;
    validate_block_transaction_auth(config.node.require_signed_transactions, &block)?;
    let candidate = {
        let mut storage_guard = storage.lock().expect("storage mutex poisoned");
        // Orphans and candidates are intentionally addressable by hash. They
        // must not be treated as canonical duplicates, otherwise a body that
        // arrived before its parent can never be attached when that parent
        // subsequently arrives.
        // Check the indexed hash directly. Materializing the entire archive
        // here made every network import allocate a full Vec<Block>.
        let already_canonical = storage_guard.header_by_hash(block.header.hash()).is_ok();
        if already_canonical {
            drop(import_guard);
            return Ok(());
        }
        let parent = storage_guard.best_header()?;
        // Bodies requested from a header range can arrive out of order. A
        // future block is not fork evidence merely because its canonical
        // parent has not been imported yet; retain it as an orphan and let
        // `drain_orphan_blocks` attach it once the contiguous prefix arrives.
        if block.header.number.0 > parent.number.0.saturating_add(1) {
            storage_guard.store_orphan_block(&block)?;
            drop(import_guard);
            return Ok(());
        }
        if block.header.parent_hash != parent.hash() || block.header.number.0 != parent.number.0 + 1
        {
            queue_competing_block_pending(
                &mut storage_guard,
                &block,
                config.node.require_signed_transactions,
            )?
        } else {
            None
        }
    };
    if let Some(branch) = candidate {
        let included_hashes = branch
            .suffix
            .iter()
            .flat_map(|candidate_block| {
                candidate_block
                    .transactions
                    .iter()
                    .map(|transaction| transaction.hash())
            })
            .collect::<Vec<_>>();
        let published = match stage_and_publish_candidate(config, storage, branch) {
            Ok(()) => {
                if !included_hashes.is_empty() {
                    mempool
                        .lock()
                        .expect("mempool mutex poisoned")
                        .remove_included(&included_hashes);
                }
                true
            }
            Err(err) => {
                eprintln!("candidate import deferred; active chain unchanged: {err}");
                false
            }
        };
        let genesis_hash = {
            let storage_guard = storage.lock().expect("storage mutex poisoned");
            configured_genesis_hash(&storage_guard).unwrap_or_else(|_| genesis_header().hash())
        };
        if published {
            enqueue_block_gossip(config, genesis_hash, &block, source_peer);
        }
        return Ok(());
    }
    let mut storage_guard = storage.lock().expect("storage mutex poisoned");
    let parent = storage_guard.best_header()?;
    if block.header.parent_hash != parent.hash() || block.header.number.0 != parent.number.0 + 1 {
        drain_orphan_blocks(config, &mut storage_guard)?;
        drop(storage_guard);
        start_candidate_recovery(config, Arc::clone(storage));
        return Ok(());
    }
    validate_block_for_storage(config, &storage_guard, &parent, &block)?;
    validate_difficulty_target(
        &storage_guard,
        &parent,
        &block.header,
        config.node.block_time_v2_activation_height,
    )?;
    validate_state_root(&storage_guard, &block)?;
    ensure_storage_cap(config, &storage_guard)?;
    let imported_block = block.clone();
    storage_guard.insert_block(block)?;
    drain_orphan_blocks(config, &mut storage_guard)?;
    drop(storage_guard);
    let included_hashes = imported_block
        .transactions
        .iter()
        .map(|transaction| transaction.hash())
        .collect::<Vec<_>>();
    if !included_hashes.is_empty() {
        mempool
            .lock()
            .expect("mempool mutex poisoned")
            .remove_included(&included_hashes);
    }
    invalidate_local_template_cache();
    schedule_canonical_maintenance(config, storage);
    // Keep lock-free status aligned with the committed canonical prefix. A
    // busy storage mutex must not leave blq_nodeInfo reporting an old height.
    record_sync_progress(
        "canonical-import",
        imported_block.header.number.0,
        imported_block.header.number.0,
    );
    let genesis_hash = {
        let storage = storage.lock().expect("storage mutex poisoned");
        configured_genesis_hash(&storage).unwrap_or_else(|_| genesis_header().hash())
    };
    enqueue_block_gossip(config, genesis_hash, &imported_block, source_peer);
    drop(import_guard);
    Ok(())
}

/// Recovery ranges already have a proven common ancestor and strict
/// parent-first ordering. Keep them out of the ordinary gossip import path:
/// that path attempts fork selection for every body, which turns a long fork
/// into repeated full branch assembly. State and receipt execution remains
/// mandatory, but happens once in the isolated staging publication pass.
fn import_recovery_block(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    tip_hash: Hash256,
    expected_height: u64,
    expected_parent_hash: Hash256,
    block: &Block,
) -> Result<()> {
    let _import_guard = BLOCK_IMPORT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("block import mutex poisoned");
    validate_live_timestamp_admission(&block.header)?;
    validate_block_transaction_auth(config.node.require_signed_transactions, block)?;
    if block.header.number.0 != expected_height {
        anyhow::bail!(
            "recovery body height {} does not match durable cursor {}",
            block.header.number.0,
            expected_height
        );
    }
    if block.header.parent_hash != expected_parent_hash {
        anyhow::bail!("recovery body parent does not match durable cursor");
    }
    let storage_guard = storage.lock().expect("storage mutex poisoned");
    // The first suffix body is anchored by the locator-proven canonical
    // ancestor. Resolve that parent directly by its durable height before
    // falling back to the generic full-history hash scan. This keeps forward
    // recovery independent of a stale/pruned hash index while retaining the
    // exact hash check below.
    let canonical_parent = expected_height
        .checked_sub(1)
        .and_then(|number| storage_guard.block_by_number(number).ok())
        .filter(|parent| parent.header.hash() == block.header.parent_hash);
    let parent_lookup = match canonical_parent {
        Some(parent) => Ok(parent),
        None => storage_guard.block_by_hash(block.header.parent_hash),
    };
    let (parent, parent_work) = match parent_lookup {
        Ok(parent) => {
            let work = storage_guard
                .candidate_work(parent.header.hash())
                .unwrap_or_else(|_| {
                    canonical_work_through_node_storage(&storage_guard, parent.header.number.0)
                        .unwrap_or(0)
                });
            (parent.header, work)
        }
        Err(_) => {
            let (parent, work) = storage_guard
                .recovery_spool_block_by_hash(block.header.parent_hash)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "recovery parent {} was not found in canonical storage or the durable spool",
                        block.header.parent_hash.to_hex()
                    )
                })?;
            (parent.header, work)
        }
    };
    validate_header_for_storage(&storage_guard, &parent, &block.header)?;
    validate_difficulty_target(
        &storage_guard,
        &parent,
        &block.header,
        config.node.block_time_v2_activation_height,
    )?;
    if parent_work == 0 && parent.number.0 != 0 {
        anyhow::bail!("recovery parent has no cumulative-work record");
    }
    let work = parent_work.saturating_add(work_for_target(block.header.difficulty_target));
    storage_guard.store_recovery_spool_block(tip_hash, block, work)?;
    // The recovery spool is the authoritative durable store for this branch.
    // Mirroring every recovered body into the bounded generic candidate pool
    // lets old gossip candidates halt a valid forward recovery at its cap.
    // Candidate reconstruction already resolves spool parents directly.
    Ok(())
}

fn queue_competing_block(
    storage: &mut NodeStorage,
    block: &Block,
    require_signed_transactions: bool,
    block_size_activation_height: Option<u64>,
    block_time_v2_activation_height: Option<u64>,
) -> Result<bool> {
    validate_block_transaction_auth(require_signed_transactions, block)?;
    let branch_parent = match storage.block_by_hash(block.header.parent_hash) {
        Ok(parent) => parent.header,
        Err(_) => {
            storage.store_orphan_block(block)?;
            return Ok(false);
        }
    };
    validate_header_for_storage(storage, &branch_parent, &block.header)?;
    let parent_work = match storage.candidate_work(block.header.parent_hash) {
        Ok(work) => work,
        Err(_) => canonical_work_through_node_storage(storage, branch_parent.number.0)?,
    };
    let candidate_work =
        parent_work.saturating_add(work_for_target(block.header.difficulty_target));
    storage.store_candidate_block(block, candidate_work)?;
    // This synchronous orphan-drain path is retained for compatibility with
    // the legacy in-process promotion helper. Live P2P recovery uses the
    // pending path below, which is storage-backed and does not clone history.
    let canonical = storage.canonical_blocks()?;
    let current_work = canonical_work(&canonical);
    let current_hash = canonical
        .last()
        .map(|block| block.header.hash())
        .ok_or_else(|| anyhow::anyhow!("canonical chain is empty"))?;
    if candidate_work < current_work
        || (candidate_work == current_work
            && canonical
                .last()
                .is_some_and(|item| block.header.number.0 == item.header.number.0)
            && block.header.hash() >= current_hash)
    {
        return Ok(false);
    }
    promote_candidate_chain(
        storage,
        block,
        &canonical,
        block_size_activation_height,
        block_time_v2_activation_height,
    )?;
    Ok(true)
}

fn queue_competing_block_pending(
    storage: &mut NodeStorage,
    block: &Block,
    require_signed_transactions: bool,
) -> Result<Option<CandidateBranch>> {
    validate_block_transaction_auth(require_signed_transactions, block)?;
    let branch_parent = match storage.block_by_hash(block.header.parent_hash) {
        Ok(parent) => parent.header,
        Err(_) => {
            storage.store_orphan_block(block)?;
            return Ok(None);
        }
    };
    validate_header_for_storage(storage, &branch_parent, &block.header)?;
    let parent_work = match storage.candidate_work(block.header.parent_hash) {
        Ok(work) => work,
        Err(_) => canonical_work_through_node_storage(storage, branch_parent.number.0)?,
    };
    let candidate_work =
        parent_work.saturating_add(work_for_target(block.header.difficulty_target));
    storage.store_candidate_block(block, candidate_work)?;
    let current = storage.best_header()?;
    let current_work = canonical_work_through_node_storage(storage, current.number.0)?;
    let current_hash = current.hash();
    if candidate_work < current_work
        || (candidate_work == current_work
            && block.header.number.0 == current.number.0
            && block.header.hash() >= current_hash)
    {
        return Ok(None);
    }
    Ok(Some(candidate_branch_from_storage(storage, block)?))
}

fn drain_orphan_blocks(config: &NodeConfig, storage: &mut NodeStorage) -> Result<()> {
    for _ in 0..MAX_P2P_HEADERS {
        let mut progressed = false;
        for block in storage.orphan_blocks()? {
            let parent = storage.best_header()?;
            if block.header.parent_hash == parent.hash()
                && block.header.number.0 == parent.number.0 + 1
            {
                validate_block_for_storage(config, storage, &parent, &block)?;
                validate_difficulty_target(
                    storage,
                    &parent,
                    &block.header,
                    config.node.block_time_v2_activation_height,
                )?;
                validate_state_root(storage, &block)?;
                storage.insert_block(block.clone())?;
                storage.remove_orphan_block(block.header.hash())?;
                progressed = true;
                continue;
            }
            if storage.header_by_hash(block.header.parent_hash).is_ok() {
                match queue_competing_block(
                    storage,
                    &block,
                    config.node.require_signed_transactions,
                    config.node.block_size_activation_height,
                    config.node.block_time_v2_activation_height,
                ) {
                    Ok(_) => {
                        storage.remove_orphan_block(block.header.hash())?;
                        progressed = true;
                    }
                    Err(err) if err.to_string().contains("was not found") => {
                        // The parent header may arrive before its body. Keep
                        // this orphan for the next body batch instead of
                        // terminating the sync session.
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        if !progressed {
            break;
        }
        if config.node.pruning_enabled() {
            storage
                .prune_old_blocks(config.node.max_storage_bytes, prune_floor(config, storage)?)?;
        }
    }
    Ok(())
}

fn canonical_work(blocks: &[Block]) -> u128 {
    blocks.iter().fold(0u128, |work, block| {
        work.saturating_add(work_for_target(block.header.difficulty_target))
    })
}

fn cumulative_work_through(blocks: &[Block], hash: Hash256) -> Option<u128> {
    let mut work = 0u128;
    for block in blocks {
        work = work.saturating_add(work_for_target(block.header.difficulty_target));
        if block.header.hash() == hash {
            return Some(work);
        }
    }
    None
}

fn canonical_work_through_node_storage(storage: &NodeStorage, height: u64) -> Result<u128> {
    let mut work = 0u128;
    for number in 0..=height {
        let block = storage.block_by_number(number)?;
        work = work.saturating_add(work_for_target(block.header.difficulty_target));
    }
    Ok(work)
}

/// Reconstructs only the candidate suffix. Canonical ancestor discovery reads
/// one canonical height at a time, so an archive node never clones its full
/// history just to decide whether a competing tip is complete.
fn candidate_branch_from_storage(storage: &NodeStorage, tip: &Block) -> Result<CandidateBranch> {
    let mut reversed = Vec::new();
    let mut bytes = 0usize;
    let mut visited = BTreeSet::new();
    let mut current = tip.clone();
    loop {
        if !visited.insert(current.header.hash()) {
            anyhow::bail!("candidate rejected: parent cycle detected");
        }
        if let Ok(canonical) = storage.block_by_number(current.header.number.0) {
            if canonical.header.hash() == current.header.hash() {
                reversed.reverse();
                return Ok(CandidateBranch {
                    common_height: canonical.header.number.0,
                    common_hash: canonical.header.hash(),
                    suffix: reversed,
                });
            }
        }
        bytes = bytes.saturating_add(current.canonical_bytes().len());
        if reversed.len() >= MAX_CANDIDATE_REPLAY_SUFFIX || bytes > MAX_CANDIDATE_REPLAY_BYTES {
            anyhow::bail!("candidate rejected: branch suffix exceeds live replay limit");
        }
        reversed.push(current.clone());
        let parent = storage
            .recovery_spool_block_by_hash(current.header.parent_hash)
            .map(|(block, _)| block)
            .or_else(|_| storage.block_by_hash(current.header.parent_hash))
            .map_err(|_| anyhow::anyhow!("candidate branch incomplete; waiting-for-provider"))?;
        if parent.header.number.0.saturating_add(1) != current.header.number.0
            || parent.header.hash() != current.header.parent_hash
        {
            anyhow::bail!("candidate rejected: non-contiguous parent linkage");
        }
        current = parent;
    }
}

fn candidate_replacement(
    storage: &NodeStorage,
    tip: &Block,
    previous_canonical: &[Block],
) -> Result<CandidateBranch> {
    let canonical_by_hash = previous_canonical
        .iter()
        .map(|block| (block.header.hash(), block))
        .collect::<std::collections::HashMap<_, _>>();
    let mut reversed = Vec::new();
    let mut visited = BTreeSet::new();
    let mut current = tip.clone();
    loop {
        if !visited.insert(current.header.hash()) {
            anyhow::bail!("candidate rejected: parent cycle detected");
        }
        if let Some(canonical) = canonical_by_hash.get(&current.header.hash()) {
            reversed.reverse();
            if reversed.len() > MAX_CANDIDATE_REPLAY_SUFFIX {
                anyhow::bail!("candidate rejected: branch suffix exceeds replay limit");
            }
            return Ok(CandidateBranch {
                common_height: canonical.header.number.0,
                common_hash: canonical.header.hash(),
                suffix: reversed,
            });
        }
        reversed.push(current.clone());
        if reversed.len() > MAX_CANDIDATE_REPLAY_SUFFIX {
            anyhow::bail!("candidate rejected: branch suffix exceeds replay limit");
        }
        let parent = storage
            .recovery_spool_block_by_hash(current.header.parent_hash)
            .map(|(block, _)| block)
            .or_else(|_| storage.block_by_hash(current.header.parent_hash))
            .map_err(|_| anyhow::anyhow!("candidate branch incomplete; waiting-for-provider"))?;
        if parent.header.number.0.saturating_add(1) != current.header.number.0
            || parent.header.hash() != current.header.parent_hash
        {
            anyhow::bail!("candidate rejected: non-contiguous parent linkage");
        }
        current = parent;
    }
}

fn materialize_candidate_replacement(
    branch: &CandidateBranch,
    canonical: &[Block],
) -> Result<Vec<Block>> {
    let ancestor = canonical
        .get(branch.common_height as usize)
        .ok_or_else(|| {
            anyhow::anyhow!("candidate common ancestor is absent from canonical storage")
        })?;
    if ancestor.header.hash() != branch.common_hash {
        anyhow::bail!("candidate common ancestor does not match canonical storage");
    }
    let mut replacement = canonical[..=branch.common_height as usize].to_vec();
    replacement.extend(branch.suffix.iter().cloned());
    Ok(replacement)
}

fn promote_candidate_chain(
    storage: &mut NodeStorage,
    tip: &Block,
    previous_canonical: &[Block],
    block_size_activation_height: Option<u64>,
    block_time_v2_activation_height: Option<u64>,
) -> Result<()> {
    let branch = candidate_replacement(storage, tip, previous_canonical)?;
    let replacement = materialize_candidate_replacement(&branch, previous_canonical)?;
    validate_replacement_in_isolation(
        storage,
        &replacement,
        block_size_activation_height,
        block_time_v2_activation_height,
    )?;
    rebuild_canonical_chain(
        storage,
        &replacement,
        previous_canonical,
        block_size_activation_height,
        block_time_v2_activation_height,
    )
}

fn validate_replacement_in_isolation(
    _storage: &NodeStorage,
    replacement: &[Block],
    block_size_activation_height: Option<u64>,
    block_time_v2_activation_height: Option<u64>,
) -> Result<()> {
    let first = replacement
        .first()
        .ok_or_else(|| anyhow::anyhow!("candidate branch is empty"))?;
    let parent = std::env::temp_dir().join(format!(
        "blq-replay-validation-{}-{}-{}",
        std::process::id(),
        first.header.number.0,
        first.header.hash().to_hex()
    ));
    if parent.exists() {
        std::fs::remove_dir_all(&parent)?;
    }
    std::fs::create_dir_all(&parent)?;
    let result = (|| -> Result<()> {
        let mut isolated = NodeStorage::Full(SledStorage::open(&parent)?);
        replay_canonical_chain(
            &mut isolated,
            replacement,
            block_size_activation_height,
            block_time_v2_activation_height,
        )
    })();
    let cleanup = std::fs::remove_dir_all(&parent).or_else(|err| {
        (err.kind() == io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(err)
    });
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(anyhow::anyhow!("remove replay validation: {err}")),
    }
}

fn finalized_height(best_number: u64) -> u64 {
    best_number.saturating_sub(FINALITY_CONFIRMATION_DEPTH)
}

fn write_periodic_snapshot(config: &NodeConfig, storage: &NodeStorage) -> Result<()> {
    if !config.node.retain_snapshots {
        return Ok(());
    }
    let best = storage.best_header()?;
    if best.number.0 == 0 || best.number.0 % EXECUTION_SNAPSHOT_INTERVAL != 0 {
        return Ok(());
    }
    let NodeStorage::Full(full) = storage else {
        return Ok(());
    };
    let root = Path::new(&config.node.data_dir).join("generations");
    let Some(generation_id) = SledStorage::load_active_generation(&root)? else {
        return Ok(());
    };
    let generation_path = SledStorage::generation_path(&root, generation_id);
    full.create_execution_snapshot(
        &generation_path,
        generation_id,
        best.number.0,
        best.hash(),
        consensus_profile_for_genesis(configured_genesis_hash(storage)?),
        finalized_height(best.number.0),
    )?;
    // A branch cannot reorganize below finality. Keep the previous interval
    // until the new checkpoint itself is finalized, then discard only compact
    // execution snapshots that can no longer be a replay starting point.
    SledStorage::prune_old_execution_snapshots(
        &root,
        finalized_height(best.number.0).saturating_sub(EXECUTION_SNAPSHOT_INTERVAL),
    )?;
    Ok(())
}

fn rebuild_canonical_chain(
    storage: &mut NodeStorage,
    replacement: &[Block],
    previous: &[Block],
    block_size_activation_height: Option<u64>,
    block_time_v2_activation_height: Option<u64>,
) -> Result<()> {
    storage.clear_canonical_state()?;
    let result = replay_canonical_chain(
        storage,
        replacement,
        block_size_activation_height,
        block_time_v2_activation_height,
    );
    if let Err(reorg_error) = result {
        let rollback = storage.clear_canonical_state().and_then(|_| {
            replay_canonical_chain(
                storage,
                previous,
                block_size_activation_height,
                block_time_v2_activation_height,
            )
        });
        if let Err(rollback_error) = rollback {
            anyhow::bail!(
                "candidate reorg failed: {}; rollback failed: {}",
                reorg_error,
                rollback_error
            );
        }
    }
    Ok(())
}

fn replay_canonical_chain(
    storage: &mut NodeStorage,
    chain: &[Block],
    block_size_activation_height: Option<u64>,
    block_time_v2_activation_height: Option<u64>,
) -> Result<()> {
    let genesis = chain
        .first()
        .ok_or_else(|| anyhow::anyhow!("cannot replay an empty chain"))?;
    if genesis.header.number.0 != 0 {
        anyhow::bail!("canonical replay must begin at genesis");
    }
    // A snapshot bootstrap may replay thousands of already-canonical blocks.
    // Keep writes visible to subsequent validation, but flush only at bounded
    // checkpoints rather than adding a synchronous disk barrier per block.
    storage.begin_sync_batch();
    let result = (|| -> Result<()> {
        storage.insert_block(genesis.clone())?;
        for (index, block) in chain.iter().enumerate().skip(1) {
            let parent = storage.best_header()?;
            validate_block_with_genesis_and_activation(
                &parent,
                block,
                configured_genesis_hash(storage)?,
                block_size_activation_height,
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            validate_difficulty_target(
                storage,
                &parent,
                &block.header,
                block_time_v2_activation_height,
            )?;
            validate_state_root(storage, block)?;
            storage.insert_block(block.clone())?;
            if index % REPLAY_CHECKPOINT_INTERVAL == 0 {
                storage.flush_sync_batch()?;
            }
        }
        Ok(())
    })();
    let flush = storage.end_sync_batch();
    result?;
    flush
}

/// Build a historical checkpoint without repeatedly rebuilding and persisting
/// the whole account state. This runs only in an isolated recovery bootstrap;
/// canonical and normal gossip imports retain their ordinary per-block state
/// persistence path.
fn replay_canonical_chain_for_snapshot(
    storage: &mut NodeStorage,
    chain: &[Block],
    block_size_activation_height: Option<u64>,
    block_time_v2_activation_height: Option<u64>,
) -> Result<()> {
    let genesis = chain
        .first()
        .ok_or_else(|| anyhow::anyhow!("cannot replay an empty chain"))?;
    if genesis.header.number.0 != 0 {
        anyhow::bail!("canonical replay must begin at genesis");
    }
    if !matches!(storage, NodeStorage::Full(_)) {
        return replay_canonical_chain(
            storage,
            chain,
            block_size_activation_height,
            block_time_v2_activation_height,
        );
    }
    // Genesis carries the chain's special initial account state. Reuse the
    // ordinary insertion path once, then continue the long replay from that
    // exact state in memory.
    storage.insert_block(genesis.clone())?;
    let NodeStorage::Full(full) = storage else {
        unreachable!("full storage was checked above")
    };

    let genesis_hash = genesis.header.hash();
    let mut native_accounts = full.account_snapshot()?;
    let mut evm_state = revm_state_from_sled(full)?;
    full.begin_batch();
    let result = (|| -> Result<()> {
        for (index, block) in chain.iter().enumerate().skip(1) {
            let parent = full.best_header()?;
            validate_block_with_genesis_and_activation(
                &parent,
                block,
                genesis_hash,
                block_size_activation_height,
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            let expected = expected_difficulty_target_with_lookup(
                &parent,
                &block.header,
                block_time_v2_activation_height,
                |hash| full.header_by_hash(hash).map_err(Into::into),
            )?;
            if block.header.difficulty_target != expected {
                anyhow::bail!(
                    "candidate recovery bootstrap difficulty mismatch at block {}",
                    block.header.number.0
                );
            }
            validate_replay_state_root(
                &mut native_accounts,
                &mut evm_state,
                block,
                parent.timestamp_seconds,
            )?;
            // Use Sled's raw block insertion here. The in-memory state above
            // is authoritative during the bootstrap and is persisted once at
            // completion, avoiding an O(blocks * accounts) state rewrite.
            full.insert_block(block.clone())?;
            if index > 0 && index % REPLAY_CHECKPOINT_INTERVAL == 0 {
                full.flush_batch()?;
                eprintln!(
                    "candidate recovery bootstrap validated canonical height {}",
                    block.header.number.0
                );
            }
        }
        for (address, (balance, nonce)) in &native_accounts {
            full.put_account(*address, *balance, *nonce)?;
        }
        persist_revm_state(full, &evm_state)?;
        if let Some(best) = chain.last() {
            full.set_reward_indexed_to(best.header.number.0)?;
        }
        Ok(())
    })();
    let flush = full.end_batch();
    result?;
    Ok(flush?)
}

fn validate_replay_state_root(
    native_accounts: &mut std::collections::BTreeMap<Address, (Bix, u64)>,
    evm_state: &mut RevmState,
    block: &Block,
    parent_timestamp: u64,
) -> Result<()> {
    if block.transactions.iter().any(is_evm_transaction) {
        let (receipts, gas_used) =
            execute_evm_state_transition_in_place(evm_state, block, parent_timestamp)?;
        let expected = evm_state_root_from_revm_state(evm_state)?;
        if block.header.gas_used != gas_used
            || block.receipts != receipts
            || block.header.transactions_root != transactions_root(&block.transactions)
            || block.header.receipts_root != receipts_root(&block.receipts)
            || block.header.state_root != expected
        {
            anyhow::bail!(
                "candidate recovery bootstrap state validation failed at block {}",
                block.header.number.0
            );
        }
        *native_accounts = accounts_from_revm_state(evm_state)?;
        return Ok(());
    }

    // The staging generation is discarded on any error, so moving the
    // temporary state avoids cloning the full account map once per block.
    let current_accounts = std::mem::take(native_accounts);
    let (accounts, receipts, gas_used) =
        simulate_state_transition_from_accounts(current_accounts, block, parent_timestamp)?;
    let expected = state_root_from_accounts(&accounts)?;
    if block.header.gas_used != gas_used
        || block.receipts != receipts
        || block.header.transactions_root != transactions_root(&block.transactions)
        || block.header.receipts_root != receipts_root(&block.receipts)
        || block.header.state_root != expected
    {
        anyhow::bail!(
            "candidate recovery bootstrap state validation failed at block {}",
            block.header.number.0
        );
    }
    *native_accounts = accounts;
    apply_accounts_to_revm_state(evm_state, native_accounts);
    Ok(())
}

/// Bounded mutable state for a candidate suffix. Archive history deliberately
/// stays out of this structure: the caller supplies only blocks after a
/// verified execution checkpoint.
struct ExecutionReplayOverlay {
    native_accounts: BTreeMap<Address, (Bix, u64)>,
    evm_state: RevmState,
    parent: BlockHeader,
    difficulty_history: Vec<BlockHeader>,
}

impl ExecutionReplayOverlay {
    fn from_snapshot(
        snapshot: ExecutionSnapshot,
        parent: BlockHeader,
        difficulty_history: Vec<BlockHeader>,
    ) -> Result<Self> {
        if snapshot.block_hash != parent.hash()
            || snapshot.height != parent.number.0
            || snapshot.state_root != parent.state_root
        {
            anyhow::bail!("execution snapshot does not match replay parent");
        }
        let mut evm_state = RevmState::default();
        for (address, (balance, nonce, code, slots)) in &snapshot.evm_accounts {
            let mut storage_slots = BTreeMap::new();
            for (slot, value) in slots {
                storage_slots.insert(
                    alloy_primitives::U256::from_be_bytes(slot.0),
                    alloy_primitives::U256::from_be_bytes(value.0),
                );
            }
            evm_state.put_account(
                alloy_primitives::Address::from(address.0),
                RevmAccount {
                    nonce: *nonce,
                    balance: alloy_primitives::U256::from(balance.0),
                    code: code.clone(),
                    storage: storage_slots,
                },
            );
        }
        for (address, (balance, nonce)) in &snapshot.native_accounts {
            let evm_address = alloy_primitives::Address::from(address.0);
            let mut account = evm_state.account(evm_address);
            account.balance = alloy_primitives::U256::from(balance.0);
            account.nonce = *nonce;
            evm_state.put_account(evm_address, account);
        }
        Ok(Self {
            native_accounts: snapshot.native_accounts,
            evm_state,
            parent,
            difficulty_history,
        })
    }

    fn apply(&mut self, config: &NodeConfig, genesis_hash: Hash256, block: &Block) -> Result<()> {
        validate_block_transaction_auth(config.node.require_signed_transactions, block)?;
        validate_block_with_genesis_and_activation(
            &self.parent,
            block,
            genesis_hash,
            config.node.block_size_activation_height,
        )
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let expected_difficulty = expected_difficulty_target_with_lookup(
            &self.parent,
            &block.header,
            config.node.block_time_v2_activation_height,
            |hash| {
                self.difficulty_history
                    .iter()
                    .find(|header| header.hash() == hash)
                    .cloned()
                    .ok_or_else(|| {
                        anyhow::anyhow!("candidate replay difficulty history is incomplete")
                    })
            },
        )?;
        if block.header.difficulty_target != expected_difficulty {
            anyhow::bail!(
                "candidate replay difficulty mismatch at block {}",
                block.header.number.0
            );
        }
        validate_replay_state_root(
            &mut self.native_accounts,
            &mut self.evm_state,
            block,
            self.parent.timestamp_seconds,
        )?;
        self.parent = block.header.clone();
        self.difficulty_history.push(block.header.clone());
        if self.difficulty_history.len() > blq_primitives::BLOCK_TIME_V2_MEDIAN_WINDOW + 1 {
            self.difficulty_history.remove(0);
        }
        Ok(())
    }
}

fn replay_candidate_in_staging(
    config: &NodeConfig,
    replay_blocks: &[Block],
    generation_id: u64,
    snapshot: GenerationSnapshot,
    profile_fingerprint: String,
) -> Result<GenerationManifest> {
    let root = Path::new(&config.node.data_dir).join("generations");
    let staging = SledStorage::staging_generation_path(&root, generation_id);
    let initial = GenerationManifest {
        generation_id,
        status: GenerationStatus::Staging,
        canonical_height: snapshot.height,
        canonical_hash: snapshot.block_hash,
        state_root: snapshot.state_root,
        profile_fingerprint: profile_fingerprint.clone(),
        finalized_height: 0,
        replay_checkpoint: None,
    };
    // Keep the mutable state separate from the legacy archive snapshot. The
    // current staging store still supplies crash-resume checkpoints; fresh
    // replays validate through this bounded execution overlay instead of
    // repeatedly reading state from the staged archive.
    let execution_snapshot = ExecutionSnapshot::from(&snapshot);
    let result = (|| -> Result<GenerationManifest> {
        let checkpoint = if staging.exists() {
            SledStorage::load_replay_checkpoint(&staging)?
        } else {
            None
        };
        let (mut staged, start_index) = if let Some(checkpoint) = checkpoint {
            let index = replay_blocks
                .iter()
                .position(|block| {
                    block.header.number.0 == checkpoint.height
                        && block.header.hash() == checkpoint.block_hash
                })
                .ok_or_else(|| anyhow::anyhow!("staging checkpoint is not on candidate branch"))?;
            let staged = NodeStorage::Full(SledStorage::open(&staging)?);
            let best = staged.best_header()?;
            if best.number.0 != checkpoint.height || best.hash() != checkpoint.block_hash {
                anyhow::bail!("staging checkpoint does not match staged canonical tip");
            }
            eprintln!(
                "resuming candidate replay generation {} from height {}",
                generation_id, checkpoint.height
            );
            (staged, index.saturating_add(1))
        } else {
            let _ = SledStorage::remove_staging_generation(&root, generation_id);
            SledStorage::open_staging_from_snapshot_owned(&root, &initial, snapshot)?;
            let staged = NodeStorage::Full(SledStorage::open(&staging)?);
            (staged, 0)
        };
        eprintln!(
            "candidate replay generation {} validating blocks {} through {}",
            generation_id,
            start_index,
            replay_blocks.len().saturating_sub(1)
        );
        // Loading an account snapshot from Sled for every block turns a long
        // replay into O(blocks * persisted-state).  Keep one authoritative
        // in-memory execution state for this staging generation, validate
        // every supplied root against it, and write it back only after the
        // bounded replay has completed successfully.
        let genesis_hash = configured_genesis_hash(&staged)?;
        staged.begin_sync_batch();
        let replay_result = {
            let NodeStorage::Full(full) = &mut staged else {
                anyhow::bail!("candidate replay requires full staging storage");
            };
            let mut overlay = if start_index == 0 {
                let parent = full.best_header()?;
                let difficulty_history = difficulty_history_headers_with_lookup(&parent, |hash| {
                    full.header_by_hash(hash).map_err(Into::into)
                })?;
                Some(ExecutionReplayOverlay::from_snapshot(
                    execution_snapshot,
                    parent,
                    difficulty_history,
                )?)
            } else {
                None
            };
            let mut native_accounts = if overlay.is_some() {
                BTreeMap::new()
            } else {
                full.account_snapshot()?
            };
            let mut evm_state = if overlay.is_some() {
                RevmState::default()
            } else {
                revm_state_from_sled(full)?
            };
            (|| -> Result<()> {
                for (index, block) in replay_blocks.iter().enumerate().skip(start_index) {
                    if let Some(overlay) = overlay.as_mut() {
                        overlay.apply(config, genesis_hash, block)?;
                    } else {
                        let parent = full.best_header()?;
                        validate_block_with_genesis_and_activation(
                            &parent,
                            block,
                            genesis_hash,
                            config.node.block_size_activation_height,
                        )
                        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                        let expected_difficulty = expected_difficulty_target_with_lookup(
                            &parent,
                            &block.header,
                            config.node.block_time_v2_activation_height,
                            |hash| full.header_by_hash(hash).map_err(Into::into),
                        )?;
                        if block.header.difficulty_target != expected_difficulty {
                            anyhow::bail!(
                                "candidate replay difficulty mismatch at block {}",
                                block.header.number.0
                            );
                        }
                        validate_replay_state_root(
                            &mut native_accounts,
                            &mut evm_state,
                            block,
                            parent.timestamp_seconds,
                        )?;
                    }
                    full.insert_block(block.clone())?;
                    if (index + 1) % REPLAY_CHECKPOINT_INTERVAL == 0
                        || index + 1 == replay_blocks.len()
                    {
                        full.flush_batch()?;
                        let checkpoint = ReplayCheckpoint {
                            generation_id,
                            height: block.header.number.0,
                            block_hash: block.header.hash(),
                            state_root: block.header.state_root,
                        };
                        SledStorage::write_replay_checkpoint(&staging, &checkpoint)?;
                        eprintln!(
                            "candidate replay generation {} checkpointed height {}",
                            generation_id, block.header.number.0
                        );
                    }
                }
                if let Some(overlay) = overlay {
                    native_accounts = overlay.native_accounts;
                    evm_state = overlay.evm_state;
                }
                for (address, (balance, nonce)) in &native_accounts {
                    full.put_account(*address, *balance, *nonce)?;
                }
                persist_revm_state(full, &evm_state)?;
                if let Some(best) = replay_blocks.last() {
                    full.set_reward_indexed_to(best.header.number.0)?;
                }
                Ok(())
            })()
        };
        let flush = staged.end_sync_batch();
        replay_result?;
        flush?;
        let best = staged.best_header()?;
        let manifest = GenerationManifest {
            generation_id,
            status: GenerationStatus::Verified,
            canonical_height: best.number.0,
            canonical_hash: best.hash(),
            state_root: best.state_root,
            profile_fingerprint: profile_fingerprint.clone(),
            finalized_height: finalized_height(best.number.0),
            replay_checkpoint: Some(best.number.0),
        };
        if let NodeStorage::Full(full) = &staged {
            // Replay checkpoints are compact cursor metadata. Persisting a
            // full state snapshot at each checkpoint multiplies staging disk
            // use on a deep recovery. One verified tip snapshot preserves
            // restart/reorg safety without duplicating the database per 16
            // replayed blocks.
            full.create_snapshot(
                &staging,
                generation_id,
                best.number.0,
                best.hash(),
                profile_fingerprint.clone(),
                finalized_height(best.number.0),
            )?;
        }
        SledStorage::write_generation_manifest(&staging, &manifest)?;
        Ok(manifest)
    })();
    if result.is_err() {
        let _ = SledStorage::remove_staging_generation(&root, generation_id);
    }
    result
}

/// Finds a verified checkpoint that can seed a candidate replay. Normally the
/// active generation already has one. Older live databases may predate the
/// snapshot cadence, so we may create a checkpoint from an earlier verified
/// generation only after proving its tip is part of the active canonical chain.
fn candidate_replay_snapshot(
    root: &Path,
    active_id: u64,
    canonical: &[Block],
    common_height: u64,
    profile: &str,
    block_size_activation_height: Option<u64>,
    block_time_v2_activation_height: Option<u64>,
) -> Result<(GenerationSnapshot, bool)> {
    let active_path = SledStorage::generation_path(root, active_id);
    if let Some(snapshot) =
        SledStorage::latest_snapshot_at_or_before(&active_path, common_height, profile)?
    {
        return Ok((snapshot, false));
    }

    let mut previous = Vec::<(u64, PathBuf, GenerationManifest)>::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("generation-") || name.ends_with(".staging") {
            continue;
        }
        let Ok(generation_id) = name.trim_start_matches("generation-").parse::<u64>() else {
            continue;
        };
        if generation_id == active_id {
            continue;
        }
        let path = entry.path();
        let Some(manifest) = SledStorage::load_generation_manifest(&path)? else {
            continue;
        };
        if manifest.status == GenerationStatus::Verified
            && manifest.profile_fingerprint == profile
            && manifest.canonical_height <= common_height
        {
            previous.push((generation_id, path, manifest));
        }
    }
    previous.sort_by_key(|(generation_id, _, _)| std::cmp::Reverse(*generation_id));

    for (generation_id, path, manifest) in previous {
        let Some(canonical_block) = canonical.get(manifest.canonical_height as usize) else {
            continue;
        };
        if canonical_block.header.hash() != manifest.canonical_hash {
            continue;
        }
        let storage = SledStorage::open(&path)?;
        let best = storage.best_header()?;
        if best.number.0 != manifest.canonical_height || best.hash() != manifest.canonical_hash {
            continue;
        }
        let snapshot_path = SledStorage::snapshot_path(&path, manifest.canonical_height);
        if !snapshot_path.exists() {
            storage.create_snapshot(
                &path,
                generation_id,
                manifest.canonical_height,
                manifest.canonical_hash,
                profile.to_owned(),
                manifest.finalized_height,
            )?;
            eprintln!(
                "candidate recovery bootstrapped verified generation {} snapshot at height {}",
                generation_id, manifest.canonical_height
            );
        }
        let snapshot = SledStorage::load_snapshot(snapshot_path)?;
        if snapshot.profile_fingerprint == profile
            && snapshot.height == manifest.canonical_height
            && snapshot.block_hash == manifest.canonical_hash
        {
            return Ok((snapshot, true));
        }
    }

    // Older generations created before periodic snapshots still need a safe
    // route into snapshot-based recovery. Rebuild only the known canonical
    // prefix in an isolated temporary store, validate every block as it is
    // replayed, then persist the resulting snapshot for future restarts. The
    // active generation remains untouched throughout this bootstrap.
    let Some(bootstrap_guard) = SnapshotBootstrapGuard::try_acquire(root)? else {
        anyhow::bail!("candidate recovery bootstrap already in progress");
    };
    let bootstrap = root.join(format!(
        ".snapshot-bootstrap-{}-{}",
        std::process::id(),
        common_height
    ));
    if bootstrap.exists() {
        anyhow::bail!(
            "candidate recovery bootstrap workspace already exists: {}",
            bootstrap.display()
        );
    }
    let result = (|| -> Result<GenerationSnapshot> {
        let mut isolated = NodeStorage::Full(SledStorage::open(&bootstrap)?);
        let prefix_end = common_height as usize;
        let prefix = canonical
            .get(..=prefix_end)
            .ok_or_else(|| anyhow::anyhow!("candidate replay bootstrap height is absent"))?;
        replay_canonical_chain_for_snapshot(
            &mut isolated,
            prefix,
            block_size_activation_height,
            block_time_v2_activation_height,
        )?;
        let block = prefix
            .last()
            .ok_or_else(|| anyhow::anyhow!("candidate replay bootstrap is empty"))?;
        let snapshot_path = match &isolated {
            NodeStorage::Full(storage) => storage.create_snapshot(
                &bootstrap,
                active_id,
                common_height,
                block.header.hash(),
                profile.to_owned(),
                finalized_height(common_height),
            )?,
            NodeStorage::Partial(_) => {
                anyhow::bail!("candidate replay bootstrap requires full storage")
            }
        };
        SledStorage::load_snapshot(snapshot_path).map_err(Into::into)
    })();
    let cleanup = fs::remove_dir_all(&bootstrap).or_else(|err| {
        (err.kind() == io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(err)
    });
    let snapshot = match (result, cleanup) {
        (Ok(snapshot), Ok(())) => snapshot,
        (Err(err), _) => return Err(err),
        (Ok(_), Err(err)) => return Err(anyhow::anyhow!("remove snapshot bootstrap: {err}")),
    };
    // Do not merely assume the bootstrap checkpoint survived the atomic
    // replace. A restart must either load this exact snapshot or fail before
    // allocating a staging generation and replaying the prefix again.
    let persisted_path = SledStorage::write_snapshot(&active_path, &snapshot)?;
    let persisted = SledStorage::load_snapshot(&persisted_path)?;
    if persisted.profile_fingerprint != profile
        || persisted.height != common_height
        || persisted.block_hash != snapshot.block_hash
        || persisted.state_root != snapshot.state_root
    {
        anyhow::bail!(
            "candidate replay bootstrap snapshot verification failed at {}",
            persisted_path.display()
        );
    }
    eprintln!(
        "candidate recovery bootstrapped verified active snapshot at height {}: {}",
        common_height,
        persisted_path.display()
    );
    // See the matching recovery guard above: retain the bootstrap lease for
    // the complete snapshot construction, including the durable write.
    drop(bootstrap_guard);
    Ok((persisted, false))
}

/// A suffix whose ancestor is the current canonical tip is ordinary forward
/// synchronization, not a reorganization. Commit it in place so a pruned
/// node does not need enough spare disk for a duplicate staging generation.
fn commit_direct_candidate_extension(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    branch: &CandidateBranch,
) -> Result<bool> {
    if branch.suffix.is_empty() {
        return Ok(false);
    }
    let published_hashes = branch
        .suffix
        .iter()
        .map(|block| block.header.hash())
        .collect::<Vec<_>>();
    let mut active = storage.lock().expect("storage mutex poisoned");
    let genesis_hash = configured_genesis_hash(&*active)?;
    let NodeStorage::Full(full) = &mut *active else {
        return Ok(false);
    };
    let best = full.best_header()?;
    if best.number.0 != branch.common_height || best.hash() != branch.common_hash {
        return Ok(false);
    }
    let mut parent = best;
    let mut native_accounts = full.account_snapshot()?;
    let mut evm_state = revm_state_from_sled(full)?;
    full.begin_batch();
    let result = (|| -> Result<()> {
        for (index, block) in branch.suffix.iter().enumerate() {
            validate_block_transaction_auth(config.node.require_signed_transactions, block)?;
            validate_block_with_genesis_and_activation(
                &parent,
                block,
                genesis_hash,
                config.node.block_size_activation_height,
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            let expected_difficulty = expected_difficulty_target_with_lookup(
                &parent,
                &block.header,
                config.node.block_time_v2_activation_height,
                |hash| full.header_by_hash(hash).map_err(Into::into),
            )?;
            if block.header.difficulty_target != expected_difficulty {
                anyhow::bail!(
                    "direct recovery difficulty mismatch at block {}",
                    block.header.number.0
                );
            }
            validate_replay_state_root(
                &mut native_accounts,
                &mut evm_state,
                block,
                parent.timestamp_seconds,
            )?;
            full.insert_block(block.clone())?;
            parent = block.header.clone();
            if (index + 1) % REPLAY_CHECKPOINT_INTERVAL == 0 || index + 1 == branch.suffix.len() {
                full.flush_batch()?;
            }
        }
        for (address, (balance, nonce)) in &native_accounts {
            full.put_account(*address, *balance, *nonce)?;
        }
        persist_revm_state(full, &evm_state)?;
        full.set_reward_indexed_to(parent.number.0)?;
        refresh_generation_manifest(full)?;
        Ok(())
    })();
    let flush = full.end_batch();
    result?;
    flush?;
    if config.node.pruning_enabled() {
        active.prune_old_blocks(config.node.max_storage_bytes, prune_floor(config, &active)?)?;
    }
    active.remove_candidate_blocks(&published_hashes)?;
    drop(active);
    record_published_tip_progress(storage);
    eprintln!(
        "direct recovery committed {} canonical extension block(s) through height {}",
        branch.suffix.len(),
        parent.number.0
    );
    Ok(true)
}

fn canonical_work_through_storage(storage: &SledStorage, height: u64) -> Result<u128> {
    let mut work = 0u128;
    for number in 0..=height {
        let header = storage.header_by_number(blq_primitives::BlockNumber(number))?;
        work = work.saturating_add(work_for_target(header.difficulty_target));
    }
    Ok(work)
}

fn suffix_supply_totals(
    storage: &SledStorage,
    ancestor: &BlockHeader,
    previous_best: &BlockHeader,
    replacement: &[Block],
) -> Result<(u64, u128, u128)> {
    let (mut indexed_to, mut total, mut burned) = storage.supply_totals()?;
    // The active chain may have advanced after startup backfill. Repair the
    // derived index at the publication boundary instead of repeatedly
    // replaying a complete candidate that is already ready to publish.
    if indexed_to < previous_best.number.0 {
        backfill_supply_storage(storage)?;
        (indexed_to, total, burned) = storage.supply_totals()?;
        if indexed_to < previous_best.number.0 {
            anyhow::bail!("candidate publication deferred: supply index is incomplete");
        }
    }
    let mut parent_timestamp = ancestor.timestamp_seconds;
    for number in ancestor.number.0.saturating_add(1)..=previous_best.number.0 {
        let block = storage.block_by_number(number)?;
        let (subsidy, burned_fees) = block_supply_delta(&block, parent_timestamp);
        total = total.saturating_sub(subsidy.0);
        burned = burned.saturating_sub(burned_fees.0);
        parent_timestamp = block.header.timestamp_seconds;
    }
    parent_timestamp = ancestor.timestamp_seconds;
    for block in replacement {
        let (subsidy, burned_fees) = block_supply_delta(block, parent_timestamp);
        total = total.saturating_add(subsidy.0);
        burned = burned.saturating_add(burned_fees.0);
        parent_timestamp = block.header.timestamp_seconds;
    }
    Ok((
        ancestor.number.0.saturating_add(replacement.len() as u64),
        total,
        burned,
    ))
}

fn stage_and_publish_candidate(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    branch: CandidateBranch,
) -> Result<()> {
    if commit_direct_candidate_extension(config, storage, &branch)? {
        return Ok(());
    }
    let published_candidate_hashes = branch
        .suffix
        .iter()
        .map(|block| block.header.hash())
        .collect::<Vec<_>>();
    let replay_guard = CANDIDATE_REPLAY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("candidate replay mutex poisoned");

    // Capture only snapshot metadata while the active store is locked.
    // Archive blocks between the snapshot and fork ancestor are streamed
    // later, one body at a time, rather than copied into a replay vector.
    let (
        snapshot,
        replay_parent,
        replay_history,
        publication_ancestor,
        active_tip,
        profile,
        genesis_hash,
    ) = {
        let active = storage.lock().expect("storage mutex poisoned");
        let NodeStorage::Full(full) = &*active else {
            anyhow::bail!("candidate replay requires full storage");
        };
        let ancestor = full.header_by_number(blq_primitives::BlockNumber(branch.common_height))?;
        if ancestor.hash() != branch.common_hash {
            anyhow::bail!("candidate common ancestor does not match canonical storage");
        }
        let mut parent = &ancestor;
        for block in &branch.suffix {
            if block.header.number.0 != parent.number.0.saturating_add(1)
                || block.header.parent_hash != parent.hash()
            {
                anyhow::bail!("candidate rejected: suffix parent linkage is not contiguous");
            }
            parent = &block.header;
        }
        let profile = consensus_profile_for_genesis(configured_genesis_hash(&active)?);
        ensure_candidate_replay_memory_headroom()?;
        let snapshot = SledStorage::latest_execution_snapshot_at_or_before(
            full.data_dir(),
            branch.common_height,
            &profile,
        )?
        .ok_or_else(|| {
            anyhow::anyhow!("candidate replay deferred: no verified execution snapshot")
        })?;
        let snapshot_parent =
            full.header_by_number(blq_primitives::BlockNumber(snapshot.height))?;
        if snapshot_parent.hash() != snapshot.block_hash
            || snapshot_parent.state_root != snapshot.state_root
        {
            anyhow::bail!("candidate replay deferred: execution snapshot is not canonical");
        }
        let replay_history = difficulty_history_headers_with_lookup(&snapshot_parent, |hash| {
            full.header_by_hash(hash).map_err(Into::into)
        })?;
        let replay_len = branch
            .common_height
            .saturating_sub(snapshot.height)
            .saturating_add(branch.suffix.len() as u64);
        if replay_len as usize > MAX_CANDIDATE_REPLAY_SUFFIX {
            anyhow::bail!("candidate rejected: compact snapshot replay exceeds live replay limit");
        }
        let mut suffix_bytes = 0usize;
        for block in &branch.suffix {
            suffix_bytes = suffix_bytes.saturating_add(block.canonical_bytes().len());
            if suffix_bytes > MAX_CANDIDATE_REPLAY_BYTES {
                anyhow::bail!("candidate rejected: suffix exceeds live replay memory budget");
            }
        }
        (
            snapshot,
            snapshot_parent,
            replay_history,
            ancestor,
            full.best_header()?,
            profile,
            configured_genesis_hash(&active)?,
        )
    };

    let mut overlay =
        ExecutionReplayOverlay::from_snapshot(snapshot, replay_parent, replay_history)?;
    for number in overlay.parent.number.0.saturating_add(1)..=branch.common_height {
        let block = {
            let active = storage.lock().expect("storage mutex poisoned");
            let NodeStorage::Full(full) = &*active else {
                anyhow::bail!("candidate replay requires full storage");
            };
            full.block_by_number(number)?
        };
        overlay.apply(config, genesis_hash, &block)?;
        if number % REPLAY_CHECKPOINT_INTERVAL as u64 == 0 {
            ensure_candidate_replay_memory_headroom()?;
        }
    }
    for (index, block) in branch.suffix.iter().enumerate() {
        overlay.apply(config, genesis_hash, block)?;
        if (index + 1) % REPLAY_CHECKPOINT_INTERVAL == 0 {
            ensure_candidate_replay_memory_headroom()?;
        }
    }
    // Consume the overlay before publication.  Cloning the full EVM state at
    // this point briefly retained two archive-sized account/code/storage
    // maps, which is enough to push an otherwise valid reorg into swap on an
    // archive node.  The publication representation owns these values.
    let final_evm_accounts = evm_accounts_from_revm_state_owned(overlay.evm_state)?;
    let final_native_accounts = overlay.native_accounts;
    let final_header = overlay.parent;
    let expected_tip = branch
        .suffix
        .last()
        .ok_or_else(|| anyhow::anyhow!("candidate branch is empty"))?
        .header
        .clone();
    if final_header != expected_tip {
        anyhow::bail!("candidate replay did not reach the supplied tip");
    }

    {
        let mut active = storage.lock().expect("storage mutex poisoned");
        let NodeStorage::Full(full) = &mut *active else {
            anyhow::bail!("candidate replay requires full storage");
        };
        let current = full.best_header()?;
        if current != active_tip {
            anyhow::bail!("candidate publication deferred: active tip changed during replay");
        }
        let ancestor_work = canonical_work_through_storage(full, branch.common_height)?;
        let candidate_work = branch.suffix.iter().fold(ancestor_work, |work, block| {
            work.saturating_add(work_for_target(block.header.difficulty_target))
        });
        let current_work = canonical_work_through_storage(full, current.number.0)?;
        if candidate_work < current_work
            || (candidate_work == current_work && expected_tip.hash() >= current.hash())
        {
            anyhow::bail!("candidate replay superseded by current canonical work");
        }
        let mut target_manifest = SledStorage::load_generation_manifest(full.data_dir())?
            .ok_or_else(|| anyhow::anyhow!("candidate publication requires active manifest"))?;
        target_manifest.status = GenerationStatus::Active;
        target_manifest.canonical_height = expected_tip.number.0;
        target_manifest.canonical_hash = expected_tip.hash();
        target_manifest.state_root = expected_tip.state_root;
        target_manifest.profile_fingerprint = profile;
        target_manifest.finalized_height = finalized_height(expected_tip.number.0);
        target_manifest.replay_checkpoint = Some(expected_tip.number.0);
        let supply_totals =
            suffix_supply_totals(full, &publication_ancestor, &current, &branch.suffix)?;
        full.publish_canonical_suffix(
            &publication_ancestor,
            &branch.suffix,
            &final_native_accounts,
            &final_evm_accounts,
            supply_totals,
            target_manifest,
        )?;
        active.remove_candidate_blocks(&published_candidate_hashes)?;
    }
    record_published_tip_progress(storage);
    drop(replay_guard);
    Ok(())
}

/// The pre-overlay publisher is retained only for historical regression
/// comparison. Live candidate promotion must use the suffix-only publisher
/// below and must never allocate an archive-sized staging generation.
#[allow(dead_code)]
fn stage_and_publish_candidate_legacy(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    branch: CandidateBranch,
) -> Result<()> {
    if commit_direct_candidate_extension(config, storage, &branch)? {
        return Ok(());
    }
    let published_candidate_hashes = branch
        .suffix
        .iter()
        .map(|block| block.header.hash())
        .collect::<Vec<_>>();
    let root = Path::new(&config.node.data_dir).join("generations");
    // Snapshot bootstrap can replay thousands of historical blocks. Capture
    // only the immutable candidate context while the active store is locked,
    // then release it before doing that expensive work. Publication below
    // rechecks the ancestor and work against the current active chain.
    let (active_id, canonical, profile) = {
        let mut active = storage.lock().expect("storage mutex poisoned");
        validate_candidate_branch_shape(&active, &branch)?;
        let required_free = config
            .node
            .filesystem_reserve_bytes
            .saturating_add(MIN_CANDIDATE_REPLAY_FREE_BYTES);
        if active.compact_active_generation_for_live_replay(config)? {
            eprintln!("compacted active pruned generation before candidate replay admission");
            // The compacted generation is snapshot-equivalent to the prior
            // active one, but revalidate the branch against the replacement
            // before allowing replay to allocate its staging generation.
            validate_candidate_branch_shape(&active, &branch)?;
        }
        if active.reclaim_snapshot_equivalent_generations(config, required_free)? {
            eprintln!("reclaimed duplicate pruned generation before candidate replay admission");
        }
        ensure_storage_cap(config, &active)?;
        let available = filesystem_free_bytes(Path::new(&config.node.data_dir)).unwrap_or(0);
        if available < required_free {
            anyhow::bail!("candidate replay deferred: insufficient filesystem budget");
        }
        let canonical = active.canonical_blocks()?;
        let profile = consensus_profile_for_genesis(configured_genesis_hash(&active)?);
        if !matches!(&*active, NodeStorage::Full(_)) {
            anyhow::bail!("candidate replay requires full storage");
        }
        let active_id = SledStorage::load_active_generation(&root)?.ok_or_else(|| {
            anyhow::anyhow!("candidate replay deferred: active generation manifest is unavailable")
        })?;
        if let (Some(common), NodeStorage::Full(full)) =
            (canonical.get(branch.common_height as usize), &*active)
        {
            let best = full.best_header()?;
            let active_path = SledStorage::generation_path(&root, active_id);
            let snapshot_path = SledStorage::snapshot_path(&active_path, branch.common_height);
            if best.number.0 == branch.common_height
                && best.hash() == common.header.hash()
                && !snapshot_path.exists()
            {
                full.create_snapshot(
                    &active_path,
                    active_id,
                    branch.common_height,
                    best.hash(),
                    profile.clone(),
                    finalized_height(branch.common_height),
                )?;
                eprintln!(
                    "candidate recovery captured verified active snapshot at height {}",
                    branch.common_height
                );
            }
        }
        (active_id, canonical, profile)
    };
    let (snapshot, legacy_snapshot) = candidate_replay_snapshot(
        &root,
        active_id,
        &canonical,
        branch.common_height,
        &profile,
        config.node.block_size_activation_height,
        config.node.block_time_v2_activation_height,
    )?;
    let snapshot_height = snapshot.height;
    let snapshot_canonical = canonical.get(snapshot_height as usize).ok_or_else(|| {
        anyhow::anyhow!(
            "candidate replay deferred: snapshot height is absent from canonical storage"
        )
    })?;
    if snapshot_canonical.header.hash() != snapshot.block_hash {
        anyhow::bail!("candidate replay deferred: snapshot does not match canonical ancestor");
    };
    let mut replay_blocks = canonical
        .iter()
        .skip(snapshot_height.saturating_add(1) as usize)
        .take((branch.common_height - snapshot_height) as usize)
        .cloned()
        .collect::<Vec<_>>();
    replay_blocks.extend(branch.suffix.iter().cloned());
    let replay_limit = if legacy_snapshot {
        MAX_LEGACY_SNAPSHOT_RECOVERY_BLOCKS
    } else {
        MAX_CANDIDATE_REPLAY_SUFFIX
    };
    if replay_blocks.len() > replay_limit {
        anyhow::bail!("candidate rejected: snapshot replay exceeds live replay limit");
    }
    let replay_guard = CANDIDATE_REPLAY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("candidate replay mutex poisoned");
    let mut generation_id = SledStorage::load_active_generation(&root)?
        .unwrap_or(0)
        .saturating_add(1);
    while SledStorage::generation_path(&root, generation_id).exists()
        || SledStorage::staging_generation_path(&root, generation_id).exists()
    {
        generation_id = generation_id.saturating_add(1);
    }
    let manifest =
        replay_candidate_in_staging(config, &replay_blocks, generation_id, snapshot, profile)
            .map_err(|err| anyhow::anyhow!("candidate staging replay failed: {err}"))?;
    // Mining may extend the active tip while this isolated replay runs. Do
    // not publish a branch that has become weaker in the meantime.
    let candidate_still_wins = {
        let active = storage.lock().expect("storage mutex poisoned");
        let canonical = active.canonical_blocks().map_err(|err| {
            anyhow::anyhow!("candidate publication could not read active canonical blocks: {err}")
        })?;
        let ancestor_work = cumulative_work_through(&canonical, branch.common_hash)
            .ok_or_else(|| anyhow::anyhow!("candidate common ancestor is no longer canonical"))?;
        let candidate_work = branch.suffix.iter().fold(ancestor_work, |work, block| {
            work.saturating_add(work_for_target(block.header.difficulty_target))
        });
        let current_work = canonical_work(&canonical);
        let current_hash = canonical
            .last()
            .map(|block| block.header.hash())
            .ok_or_else(|| anyhow::anyhow!("canonical chain is empty"))?;
        let candidate_hash = branch
            .suffix
            .last()
            .map(|block| block.header.hash())
            .ok_or_else(|| anyhow::anyhow!("candidate branch is empty"))?;
        candidate_work > current_work
            || (candidate_work == current_work && candidate_hash < current_hash)
    };
    if !candidate_still_wins {
        SledStorage::remove_staging_generation(&root, generation_id)?;
        anyhow::bail!("candidate replay superseded by current canonical work");
    }
    {
        let staged = SledStorage::open(SledStorage::staging_generation_path(&root, generation_id))?;
        validate_generation_storage_for_config(config, &staged).map_err(|err| {
            anyhow::anyhow!("candidate publication staged generation validation failed: {err}")
        })?;
    }
    let active_path = SledStorage::publish_staging_generation(&root, generation_id, &manifest)
        .map_err(|err| {
            anyhow::anyhow!("candidate publication atomic generation swap failed: {err}")
        })?;
    let published_storage = SledStorage::open(&active_path).map_err(|err| {
        anyhow::anyhow!("candidate publication could not open new active generation: {err}")
    })?;
    validate_generation_storage_for_config(config, &published_storage).map_err(|err| {
        anyhow::anyhow!("candidate publication activated an invalid generation: {err}")
    })?;
    let replacement_storage = NodeStorage::Full(published_storage);
    {
        let mut active = storage.lock().expect("storage mutex poisoned");
        *active = replacement_storage;
    }
    if let Err(error) = storage
        .lock()
        .expect("storage mutex poisoned")
        .remove_candidate_blocks(&published_candidate_hashes)
    {
        eprintln!("published recovery could not clear duplicate candidate bodies: {error}");
    }
    record_published_tip_progress(storage);
    remove_abandoned_staging_generations(config)?;
    SledStorage::prune_old_generations(&root)?;
    drop(replay_guard);
    Ok(())
}

fn validate_candidate_branch_shape(active: &NodeStorage, branch: &CandidateBranch) -> Result<()> {
    if branch.suffix.is_empty() {
        anyhow::bail!("candidate branch is empty");
    }
    let canonical = active.canonical_blocks()?;
    let ancestor = canonical
        .get(branch.common_height as usize)
        .ok_or_else(|| {
            anyhow::anyhow!("candidate common ancestor is absent from canonical storage")
        })?;
    if ancestor.header.hash() != branch.common_hash {
        anyhow::bail!("candidate common ancestor does not match canonical storage");
    }
    let mut parent = &ancestor.header;
    for block in &branch.suffix {
        if block.header.number.0 != parent.number.0.saturating_add(1)
            || block.header.parent_hash != parent.hash()
        {
            anyhow::bail!("candidate rejected: suffix parent linkage is not contiguous");
        }
        parent = &block.header;
    }
    Ok(())
}

fn validate_difficulty_target(
    storage: &NodeStorage,
    parent: &BlockHeader,
    child: &BlockHeader,
    block_time_v2_activation_height: Option<u64>,
) -> Result<()> {
    let expected =
        expected_difficulty_target(storage, parent, child, block_time_v2_activation_height)?;
    if child.difficulty_target != expected {
        anyhow::bail!(
            "block difficulty target does not match retarget rule: expected {}, got {}",
            expected.to_hex(),
            child.difficulty_target.to_hex()
        );
    }
    Ok(())
}

fn expected_difficulty_target(
    storage: &NodeStorage,
    parent: &BlockHeader,
    child: &BlockHeader,
    block_time_v2_activation_height: Option<u64>,
) -> Result<Hash256> {
    expected_difficulty_target_with_lookup(parent, child, block_time_v2_activation_height, |hash| {
        storage.difficulty_header_by_hash(hash)
    })
}

fn expected_difficulty_target_with_lookup<F>(
    parent: &BlockHeader,
    child: &BlockHeader,
    block_time_v2_activation_height: Option<u64>,
    previous_header: F,
) -> Result<Hash256>
where
    F: FnMut(Hash256) -> Result<BlockHeader>,
{
    if child.number.0 == 0 {
        return Ok(parent.difficulty_target);
    }
    let actual_seconds = child
        .timestamp_seconds
        .saturating_sub(parent.timestamp_seconds)
        .max(1);
    if block_time_v2_activation_height.is_some_and(|activation| child.number.0 >= activation) {
        let (median_interval, latest_interval) =
            difficulty_history_intervals_with_lookup(parent, previous_header)?;
        return Ok(next_block_difficulty_target_v2(
            parent.difficulty_target,
            median_interval,
            latest_interval,
        ));
    }
    Ok(next_block_difficulty_target(
        parent.difficulty_target,
        actual_seconds,
    ))
}

/// Local admission policy only. Historical replay and fork choice remain
/// deterministic from canonical headers and never call the wall clock.
fn validate_live_timestamp_admission(header: &BlockHeader) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(header.timestamp_seconds);
    if header.timestamp_seconds > now.saturating_add(MAX_LIVE_TIMESTAMP_FUTURE_DRIFT_SECONDS) {
        anyhow::bail!("block timestamp exceeds the live admission future-drift limit");
    }
    Ok(())
}

fn difficulty_history_intervals_with_lookup<F>(
    parent: &BlockHeader,
    previous_header: F,
) -> Result<(u64, u64)>
where
    F: FnMut(Hash256) -> Result<BlockHeader>,
{
    let mut intervals = difficulty_history_headers_with_lookup(parent, previous_header)?
        .windows(2)
        .map(|pair| {
            pair[1]
                .timestamp_seconds
                .saturating_sub(pair[0].timestamp_seconds)
                .max(1)
        })
        .collect::<Vec<_>>();
    let latest = *intervals.last().unwrap_or(&1);
    intervals.sort_unstable();
    Ok((intervals[intervals.len() / 2], latest))
}

fn difficulty_history_headers_with_lookup<F>(
    parent: &BlockHeader,
    mut previous_header: F,
) -> Result<Vec<BlockHeader>>
where
    F: FnMut(Hash256) -> Result<BlockHeader>,
{
    let mut newest_to_oldest = Vec::with_capacity(blq_primitives::BLOCK_TIME_V2_MEDIAN_WINDOW + 1);
    let mut cursor = parent.clone();
    newest_to_oldest.push(cursor.clone());
    for _ in 0..blq_primitives::BLOCK_TIME_V2_MEDIAN_WINDOW {
        if cursor.number.0 == 0 {
            break;
        }
        cursor = previous_header(cursor.parent_hash)?;
        newest_to_oldest.push(cursor.clone());
    }
    newest_to_oldest.reverse();
    Ok(newest_to_oldest)
}

fn validate_state_root(storage: &NodeStorage, block: &Block) -> Result<()> {
    if block.transactions.iter().any(is_evm_transaction) {
        let simulation = simulate_evm_state_transition(storage, block)?;
        let expected = evm_state_root_from_revm_state(&simulation.state)?;
        if block.header.gas_used != simulation.gas_used {
            anyhow::bail!(
                "block gas used does not match EVM execution: expected {}, got {}",
                simulation.gas_used,
                block.header.gas_used
            );
        }
        if block.receipts != simulation.receipts {
            anyhow::bail!("block receipts do not match EVM transaction execution");
        }
        if block.header.transactions_root != transactions_root(&block.transactions) {
            anyhow::bail!("block transactions root does not match transactions");
        }
        if block.header.receipts_root != receipts_root(&block.receipts) {
            anyhow::bail!("block receipts root does not match receipts");
        }
        if block.header.state_root != expected {
            anyhow::bail!(
                "block EVM state root does not match execution: expected {}, got {}",
                expected.to_hex(),
                block.header.state_root.to_hex()
            );
        }
        return Ok(());
    }
    let (accounts, receipts, gas_used) = simulate_state_transition(storage, block)?;
    let expected = state_root_from_accounts(&accounts)?;
    if block.header.gas_used != gas_used {
        anyhow::bail!(
            "block gas used does not match execution: expected {}, got {}",
            gas_used,
            block.header.gas_used
        );
    }
    if block.receipts != receipts {
        anyhow::bail!("block receipts do not match transaction execution");
    }
    if block.header.transactions_root != transactions_root(&block.transactions) {
        anyhow::bail!("block transactions root does not match transactions");
    }
    if block.header.receipts_root != receipts_root(&block.receipts) {
        anyhow::bail!("block receipts root does not match receipts");
    }
    if block.header.state_root != expected {
        anyhow::bail!(
            "block state root does not match execution state: expected {}, got {}",
            expected.to_hex(),
            block.header.state_root.to_hex()
        );
    }
    Ok(())
}

fn build_stateful_block(
    storage: &NodeStorage,
    mut block: Block,
    transactions: Vec<Transaction>,
) -> Result<Block> {
    block.transactions = transactions;
    if block.transactions.iter().any(is_evm_transaction) {
        let simulation = simulate_evm_state_transition(storage, &block)?;
        block.receipts = simulation.receipts;
        block.header.gas_used = simulation.gas_used;
        block.header.transactions_root = transactions_root(&block.transactions);
        block.header.receipts_root = receipts_root(&block.receipts);
        block.header.state_root = evm_state_root_from_revm_state(&simulation.state)?;
        return Ok(block);
    }
    let (accounts, receipts, gas_used) = simulate_state_transition(storage, &block)?;
    block.receipts = receipts;
    block.header.gas_used = gas_used;
    block.header.transactions_root = transactions_root(&block.transactions);
    block.header.receipts_root = receipts_root(&block.receipts);
    block.header.state_root = state_root_from_accounts(&accounts)?;
    Ok(block)
}

fn build_stateful_block_from_accounts(
    accounts: &std::collections::BTreeMap<Address, (Bix, u64)>,
    mut block: Block,
    transactions: Vec<Transaction>,
    parent_timestamp: u64,
) -> Result<Block> {
    block.transactions = transactions;
    let (next_accounts, receipts, gas_used) =
        simulate_state_transition_from_accounts(accounts.clone(), &block, parent_timestamp)?;
    block.receipts = receipts;
    block.header.gas_used = gas_used;
    block.header.transactions_root = transactions_root(&block.transactions);
    block.header.receipts_root = receipts_root(&block.receipts);
    block.header.state_root = state_root_from_accounts(&next_accounts)?;
    Ok(block)
}

struct EvmSimulation {
    state: RevmState,
    receipts: Vec<Receipt>,
    gas_used: u64,
}

fn is_evm_transaction(transaction: &Transaction) -> bool {
    transaction.to.is_none() || !transaction.payload.is_empty()
}

fn validate_block_transaction_auth(require_signed_transactions: bool, block: &Block) -> Result<()> {
    for transaction in &block.transactions {
        if require_signed_transactions
            || transaction.signature.is_some()
            || transaction.external_hash.is_some()
        {
            verify_transaction_signature(transaction)?;
        }
    }
    Ok(())
}

fn simulate_evm_state_transition(storage: &NodeStorage, block: &Block) -> Result<EvmSimulation> {
    let parent_timestamp = if block.header.number.0 == 0 {
        0
    } else {
        storage
            .header_by_number(blq_primitives::BlockNumber(block.header.number.0 - 1))?
            .timestamp_seconds
    };
    simulate_evm_state_transition_from_state(storage.evm_state()?, block, parent_timestamp)
}

fn simulate_evm_state_transition_from_state(
    state: RevmState,
    block: &Block,
    parent_timestamp: u64,
) -> Result<EvmSimulation> {
    let mut state = state;
    let (receipts, gas_used) =
        execute_evm_state_transition_in_place(&mut state, block, parent_timestamp)?;
    Ok(EvmSimulation {
        state,
        receipts,
        gas_used,
    })
}

/// Executes a block by temporarily moving the authoritative replay state into
/// the executor, then returning it to the caller. This avoids cloning a full
/// contract/account map for every block in a staged recovery.
fn execute_evm_state_transition_in_place(
    state: &mut RevmState,
    block: &Block,
    parent_timestamp: u64,
) -> Result<(Vec<Receipt>, u64)> {
    let mut executor = RevmBlockExecutor::new(std::mem::take(state));
    let mut gas_used = 0u64;
    let mut receipts = Vec::with_capacity(block.transactions.len());
    let mut gross_fees = 0u128;
    let mut revm_tips = 0u128;
    for transaction in &block.transactions {
        validate_transaction_fee(transaction, block.header.base_fee_per_gas)?;
        let output = executor
            .execute_transaction(&block.header, transaction)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        gas_used = gas_used
            .checked_add(output.gas_used)
            .ok_or_else(|| anyhow::anyhow!("block gas overflow"))?;
        receipts.push(Receipt {
            transaction_hash: transaction.rpc_hash(),
            success: output.success,
            gas_used: output.gas_used,
            logs_root: logs_root(&output.logs),
            logs: output.logs,
        });
        let effective_gas_price = transaction.max_fee_per_gas.0.min(
            block
                .header
                .base_fee_per_gas
                .0
                .saturating_add(transaction.max_priority_fee_per_gas.0),
        );
        let fee = (output.gas_used as u128).saturating_mul(effective_gas_price);
        gross_fees = gross_fees.saturating_add(fee);
        revm_tips =
            revm_tips.saturating_add((output.gas_used as u128).saturating_mul(
                effective_gas_price.saturating_sub(block.header.base_fee_per_gas.0),
            ));
    }
    if gas_used > block.header.gas_limit {
        anyhow::bail!("block gas used exceeds gas limit");
    }
    let (_, miner_fee) =
        fee_split_for_utilization(utilization_basis_points(gas_used, block.header.gas_limit))
            .split_fee(Bix(gross_fees));
    let beneficiary = alloy_primitives::Address::from(block.header.beneficiary_address().0);
    let mut account = executor.state.account(beneficiary);
    account.balance = account
        .balance
        .saturating_sub(alloy_primitives::U256::from(revm_tips))
        .saturating_add(alloy_primitives::U256::from(
            block_reward_for_interval_bix(parent_timestamp, block.header.timestamp_seconds)
                .0
                .saturating_add(miner_fee.0),
        ));
    executor.state.put_account(beneficiary, account);
    *state = executor.state;
    Ok((receipts, gas_used))
}

fn evm_accounts_from_revm_state(state: &RevmState) -> Result<blq_storage::EvmStateSnapshot> {
    let mut accounts = std::collections::BTreeMap::new();
    for (address, account) in &state.accounts {
        let balance = u128::try_from(account.balance)
            .map_err(|_| anyhow::anyhow!("EVM balance exceeds BLQ account range"))?;
        let mut storage = std::collections::BTreeMap::new();
        for (slot, value) in &account.storage {
            storage.insert(Hash256(slot.to_be_bytes()), Hash256(value.to_be_bytes()));
        }
        accounts.insert(
            Address(address.into_array()),
            (Bix(balance), account.nonce, account.code.clone(), storage),
        );
    }
    Ok(accounts)
}

/// Listener-local capacity stops one class of client from consuming the
/// other's budget. These process-wide counters remain readable even while a
/// storage import owns the node mutex.
struct RpcConnectionGuard(Arc<AtomicUsize>);

impl RpcConnectionGuard {
    fn new(active: Arc<AtomicUsize>) -> Self {
        ACTIVE_RPC_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
        Self(active)
    }
}

impl Drop for RpcConnectionGuard {
    fn drop(&mut self) {
        CLOSING_RPC_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
        self.0.fetch_sub(1, Ordering::AcqRel);
        ACTIVE_RPC_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
        CLOSED_RPC_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
        CLOSING_RPC_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn last_rpc_handler_error() -> &'static Mutex<Option<String>> {
    LAST_RPC_HANDLER_ERROR.get_or_init(|| Mutex::new(None))
}

fn last_p2p_handler_error() -> &'static Mutex<Option<String>> {
    LAST_P2P_HANDLER_ERROR.get_or_init(|| Mutex::new(None))
}

fn record_rpc_handler_error(error: &anyhow::Error) {
    *last_rpc_handler_error()
        .lock()
        .expect("last rpc handler error mutex poisoned") = Some(error.to_string());
}

fn record_p2p_handler_error(error: &anyhow::Error) {
    *last_p2p_handler_error()
        .lock()
        .expect("last p2p handler error mutex poisoned") = Some(error.to_string());
}

/// Converts replay state into the storage publication representation without
/// retaining a second copy of contract bytecode or storage.  This is used only
/// after validation is complete, when the replay overlay is no longer needed.
fn evm_accounts_from_revm_state_owned(state: RevmState) -> Result<blq_storage::EvmStateSnapshot> {
    let mut accounts = std::collections::BTreeMap::new();
    for (address, account) in state.accounts {
        let balance = u128::try_from(account.balance)
            .map_err(|_| anyhow::anyhow!("EVM balance exceeds BLQ account range"))?;
        let storage = account
            .storage
            .into_iter()
            .map(|(slot, value)| (Hash256(slot.to_be_bytes()), Hash256(value.to_be_bytes())))
            .collect();
        accounts.insert(
            Address(address.into_array()),
            (Bix(balance), account.nonce, account.code, storage),
        );
    }
    Ok(accounts)
}

fn evm_state_root_from_revm_state(state: &RevmState) -> Result<Hash256> {
    let accounts = evm_accounts_from_revm_state(state)?;
    Ok(blq_storage::evm_state_root_from_accounts(&accounts)?)
}

type StateTransitionResult = (
    std::collections::BTreeMap<Address, (Bix, u64)>,
    Vec<Receipt>,
    u64,
);

fn simulate_state_transition(
    storage: &NodeStorage,
    block: &Block,
) -> Result<StateTransitionResult> {
    let parent_timestamp = if block.header.number.0 == 0 {
        0
    } else {
        storage
            .header_by_number(blq_primitives::BlockNumber(block.header.number.0 - 1))?
            .timestamp_seconds
    };
    simulate_state_transition_from_accounts(storage.account_snapshot()?, block, parent_timestamp)
}

fn block_supply_delta(block: &Block, parent_timestamp: u64) -> (Bix, Bix) {
    let subsidy = block_reward_for_interval_bix(parent_timestamp, block.header.timestamp_seconds);
    let gas_used = block
        .receipts
        .iter()
        .map(|receipt| receipt.gas_used)
        .sum::<u64>();
    let split =
        fee_split_for_utilization(utilization_basis_points(gas_used, block.header.gas_limit));
    let gross_fees = block
        .transactions
        .iter()
        .zip(block.receipts.iter())
        .map(|(transaction, receipt)| {
            let effective_gas_price = transaction.max_fee_per_gas.0.min(
                block
                    .header
                    .base_fee_per_gas
                    .0
                    .saturating_add(transaction.max_priority_fee_per_gas.0),
            );
            (receipt.gas_used as u128).saturating_mul(effective_gas_price)
        })
        .fold(0u128, u128::saturating_add);
    let (burned, _) = split.split_fee(Bix(gross_fees));
    (subsidy, burned)
}

fn backfill_supply_storage(storage: &SledStorage) -> Result<()> {
    let best = match storage.best_header() {
        Ok(header) => header.number.0,
        Err(blq_storage::StorageError::NotFound) => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let (mut indexed_to, mut total, mut burned) = storage.supply_totals()?;
    if indexed_to > best {
        indexed_to = 0;
        total = 0;
        burned = 0;
        storage.set_supply_totals(indexed_to, total, burned)?;
    }
    if indexed_to >= best {
        return Ok(());
    }
    for number in indexed_to.saturating_add(1)..=best {
        let block = storage.block_by_number(number)?;
        let parent_timestamp = if block.header.number.0 == 0 {
            0
        } else {
            storage
                .header_by_number(blq_primitives::BlockNumber(block.header.number.0 - 1))?
                .timestamp_seconds
        };
        let (subsidy, burned_fees) = block_supply_delta(&block, parent_timestamp);
        total = total.saturating_add(subsidy.0);
        burned = burned.saturating_add(burned_fees.0);
        if number % SUPPLY_BACKFILL_CHECKPOINT_INTERVAL == 0 || number == best {
            storage.set_supply_totals(number, total, burned)?;
        }
    }
    Ok(())
}

fn simulate_state_transition_from_accounts(
    mut accounts: std::collections::BTreeMap<Address, (Bix, u64)>,
    block: &Block,
    parent_timestamp: u64,
) -> Result<StateTransitionResult> {
    let gas_used = block
        .transactions
        .iter()
        .map(|transaction| transaction.gas_limit)
        .try_fold(0u64, |total, gas| {
            total
                .checked_add(gas)
                .ok_or_else(|| anyhow::anyhow!("block gas overflow"))
        })?;
    if gas_used > block.header.gas_limit {
        anyhow::bail!("block gas used exceeds gas limit");
    }
    let split =
        fee_split_for_utilization(utilization_basis_points(gas_used, block.header.gas_limit));
    let mut miner_fees = Bix(0);
    let mut receipts = Vec::new();
    for transaction in &block.transactions {
        validate_transfer_transaction_shape(transaction)?;
        validate_transaction_fee(transaction, block.header.base_fee_per_gas)?;
        let to = transaction
            .to
            .ok_or_else(|| anyhow::anyhow!("contract creation is not implemented yet"))?;
        let sender = accounts.entry(transaction.from).or_insert((Bix(0), 0));
        if sender.1 != transaction.nonce {
            anyhow::bail!(
                "invalid nonce for {}: expected {}, got {}",
                transaction.from.to_hex(),
                sender.1,
                transaction.nonce
            );
        }
        let effective_gas_price = transaction.max_fee_per_gas.0.min(
            block
                .header
                .base_fee_per_gas
                .0
                .saturating_add(transaction.max_priority_fee_per_gas.0),
        );
        let fee = Bix((transaction.gas_limit as u128).saturating_mul(effective_gas_price));
        let total_cost = transaction.value.0.saturating_add(fee.0);
        if sender.0 .0 < total_cost {
            anyhow::bail!(
                "account {} has insufficient balance",
                transaction.from.to_hex()
            );
        }
        sender.0 .0 -= total_cost;
        sender.1 = sender.1.saturating_add(1);
        accounts.entry(to).or_insert((Bix(0), 0)).0 .0 = accounts
            .get(&to)
            .map(|(balance, _)| balance.0)
            .unwrap_or(0)
            .saturating_add(transaction.value.0);
        let (_, miner_fee) = split.split_fee(fee);
        miner_fees.0 = miner_fees.0.saturating_add(miner_fee.0);
        receipts.push(Receipt {
            transaction_hash: transaction.rpc_hash(),
            success: true,
            gas_used: transaction.gas_limit,
            logs_root: Hash256::ZERO,
            logs: Vec::new(),
        });
    }
    let beneficiary = block.header.beneficiary_address();
    let beneficiary_credit =
        block_reward_for_interval_bix(parent_timestamp, block.header.timestamp_seconds)
            .0
            .saturating_add(miner_fees.0);
    if beneficiary_credit > 0 {
        let entry = accounts.entry(beneficiary).or_insert((Bix(0), 0));
        entry.0 .0 = entry.0 .0.saturating_add(beneficiary_credit);
    }
    Ok((accounts, receipts, gas_used))
}

fn validate_transfer_transaction_shape(transaction: &Transaction) -> Result<()> {
    if transaction.to.is_none() {
        return Ok(());
    }
    if !transaction.payload.is_empty() {
        return Ok(());
    }
    if transaction.gas_limit < TRANSFER_GAS {
        anyhow::bail!("plain BLQ transfer gas_limit must be at least {TRANSFER_GAS}");
    }
    Ok(())
}

fn import_network_header(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    header: BlockHeader,
) -> Result<()> {
    if config.node.mode != NodeMode::Partial {
        return Ok(());
    }
    let mut storage = storage.lock().expect("storage mutex poisoned");
    let parent = storage.best_header()?;
    if header.number.0 <= parent.number.0 {
        return Ok(());
    }
    validate_header_for_storage(&storage, &parent, &header)?;
    if header.parent_hash != parent.hash() {
        anyhow::bail!("network header parent hash does not match current best header");
    }
    validate_difficulty_target(
        &storage,
        &parent,
        &header,
        config.node.block_time_v2_activation_height,
    )?;
    ensure_storage_cap(config, &storage)?;
    storage.insert_header(header)?;
    Ok(())
}

fn relay_best_header(config: &NodeConfig, storage: &NodeStorage) -> Result<()> {
    if !config.network.enabled {
        return Ok(());
    }
    let header = storage.best_header()?;
    let block = storage.block_by_number(header.number.0)?;
    enqueue_block_gossip(config, configured_genesis_hash(storage)?, &block, None);
    Ok(())
}

fn relay_block_to_peers(
    config: &NodeConfig,
    genesis_hash: Hash256,
    block: &Block,
    source_peer: Option<&str>,
) -> Result<()> {
    if !config.network.enabled {
        return Ok(());
    }
    let header = block.header.clone();
    let mut peers = config.network.bootstrap_peers.clone();
    peers.extend(cached_peer_endpoints());
    if let Some(routes) = DISCOVERED_PEER_ROUTES.get() {
        peers.extend(
            routes
                .lock()
                .expect("discovered peer routes poisoned")
                .values()
                .map(|peer| peer.address.clone()),
        );
    }
    let source_identity = source_peer.and_then(|peer| {
        known_peer_identities()
            .lock()
            .ok()
            .and_then(|identities| identities.get(peer).cloned())
    });
    peers = peers
        .into_iter()
        .map(|peer| preferred_peer_route(&peer).unwrap_or(peer))
        .filter(|peer| {
            source_peer.is_none_or(|source| source != peer)
                && source_identity.as_ref().is_none_or(|identity| {
                    known_peer_identities()
                        .lock()
                        .ok()
                        .and_then(|identities| identities.get(peer).cloned())
                        .as_ref()
                        != Some(identity)
                })
        })
        .collect();
    peers.sort();
    peers.dedup();
    for peer in &peers {
        let relay_result = (|| -> Result<()> {
            let (mut stream, peer_tls_certificate_hash) = connect_p2p_tls(peer)?;
            send_p2p_message(
                &mut stream,
                &hello_message_from_best_header_with_genesis(
                    config,
                    &header,
                    &peer_tls_certificate_hash,
                    genesis_hash,
                )?,
            )?;
            let mut reader = BufReader::new(P2pShutdownGuard::new_configured(stream)?);
            let mut line = String::new();
            if !read_p2p_line(&mut reader, &mut line)? {
                anyhow::bail!("P2P relay peer closed before hello");
            }
            match serde_json::from_str(line.trim())? {
                P2pMessage::Hello {
                    node_mode,
                    best_number,
                    best_hash,
                    consensus_profile,
                    identity_public_key,
                    identity_signature,
                    tls_certificate_hash,
                } => verify_p2p_identity_with_profile(
                    node_mode,
                    best_number,
                    &best_hash,
                    &consensus_profile,
                    &identity_public_key,
                    &identity_signature,
                    &tls_certificate_hash,
                    Some(&peer_tls_certificate_hash),
                    (!config.network.trusted_peer_keys.is_empty())
                        .then_some(config.network.trusted_peer_keys.as_slice()),
                    &network_consensus_profile(config, genesis_hash),
                )?,
                _ => anyhow::bail!("P2P relay peer did not send hello first"),
            }
            send_p2p_message(
                reader.get_mut(),
                &P2pMessage::BlockBody {
                    block: block.clone(),
                },
            )
        })();
        if let Err(err) = relay_result {
            BLOCK_GOSSIP_FAILURES.fetch_add(1, Ordering::Relaxed);
            *LAST_BLOCK_GOSSIP_ERROR
                .get_or_init(|| Mutex::new(None))
                .lock()
                .expect("block gossip error mutex poisoned") = Some(err.to_string());
            eprintln!("p2p block announcement to {peer} failed: {err}");
        }
    }
    broadcast_relay_block(config, block)?;
    Ok(())
}

fn relay_transaction_async(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    transaction: Transaction,
) {
    if !config.network.enabled {
        return;
    }
    enqueue_transaction_gossip(config, storage, transaction);
}

fn relay_transaction_to_peers(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    transaction: Transaction,
) -> Result<()> {
    if !config.network.enabled {
        return Ok(());
    }
    let (genesis_hash, best_header) = {
        let storage = storage.lock().expect("storage mutex poisoned");
        (
            configured_genesis_hash(&storage).unwrap_or_else(|_| genesis_header().hash()),
            storage.best_header()?,
        )
    };
    for peer in &config.network.bootstrap_peers {
        let Ok((mut stream, certificate_hash)) = connect_p2p_tls(peer) else {
            continue;
        };
        send_p2p_message(
            &mut stream,
            &hello_message_from_best_header_with_genesis(
                config,
                &best_header,
                &certificate_hash,
                genesis_hash,
            )?,
        )?;
        let mut reader = BufReader::new(P2pShutdownGuard::new_configured(stream)?);
        let mut line = String::new();
        if !read_p2p_line(&mut reader, &mut line)? {
            continue;
        }
        let _ = serde_json::from_str::<P2pMessage>(line.trim())?;
        let hash = transaction.rpc_hash();
        send_p2p_message(
            reader.get_mut(),
            &P2pMessage::NewTransactionHashes { hashes: vec![hash] },
        )?;
        loop {
            let mut response = String::new();
            if !read_p2p_line(&mut reader, &mut response)? {
                break;
            }
            match serde_json::from_str(response.trim())? {
                // Peer exchange is a sideband message sent immediately after
                // hello; it must not be mistaken for the inventory response.
                P2pMessage::PeerExchange { peers } => {
                    let _ = handle_p2p_message(
                        reader.get_mut(),
                        config,
                        storage,
                        &Arc::new(Mutex::new(Mempool::default())),
                        P2pMessage::PeerExchange { peers },
                        None,
                    );
                }
                P2pMessage::GetTransactions { hashes } => {
                    if hashes.contains(&hash) {
                        send_p2p_message(
                            reader.get_mut(),
                            &P2pMessage::Transactions {
                                items: vec![transaction.clone()],
                            },
                        )?;
                    }
                    break;
                }
                _ => break,
            }
        }
    }
    Ok(())
}

fn broadcast_relay_block(config: &NodeConfig, block: &Block) -> Result<()> {
    let Some(node_id) = &config.network.advertise_addr else {
        return Ok(());
    };
    let identity = NodeIdentity::load_or_create(Path::new(&config.node.data_dir))?;
    let identity_public_key = identity.public_key_hex();
    for server in &config.network.relay_servers {
        let mut stream = match connect_tcp_session(server) {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("relay broadcast to {server} failed: {err}");
                continue;
            }
        };
        let _shutdown = SocketShutdownGuard::new(&stream)?;
        send_relay_message(
            &mut stream,
            &RelayMessage::Register {
                node_id: node_id.clone(),
                identity_public_key: identity_public_key.clone(),
                identity_signature: identity.sign(&service_auth_payload(
                    "BLQ-RELAY-REGISTER-v1",
                    &[node_id, &identity_public_key],
                )),
            },
        )?;
        send_relay_message(
            &mut stream,
            &RelayMessage::Broadcast {
                payload: P2pMessage::BlockBody {
                    block: block.clone(),
                },
                identity_public_key: identity_public_key.clone(),
                identity_signature: identity.sign(&service_auth_payload(
                    "BLQ-RELAY-BROADCAST-v1",
                    &[node_id, &identity_public_key],
                )),
            },
        )?;
        eprintln!(
            "relay broadcast sent to {server} for block {}",
            block.header.number.0
        );
    }
    Ok(())
}

fn hello_message(
    config: &NodeConfig,
    storage: &Arc<Mutex<NodeStorage>>,
    tls_certificate_hash: &str,
) -> Result<P2pMessage> {
    let storage = storage.lock().expect("storage mutex poisoned");
    let best = match storage.best_header() {
        Ok(h) => h,
        Err(_) => genesis_header(),
    };
    let genesis_hash = configured_genesis_hash(&storage)?;
    hello_message_from_best_header_with_genesis(config, &best, tls_certificate_hash, genesis_hash)
}

fn hello_message_from_best_header(
    config: &NodeConfig,
    best: &BlockHeader,
    tls_certificate_hash: &str,
) -> Result<P2pMessage> {
    hello_message_from_best_header_with_genesis(
        config,
        best,
        tls_certificate_hash,
        genesis_header().hash(),
    )
}

fn hello_message_from_best_header_with_genesis(
    config: &NodeConfig,
    best: &BlockHeader,
    tls_certificate_hash: &str,
    genesis_hash: Hash256,
) -> Result<P2pMessage> {
    let profile = network_consensus_profile(config, genesis_hash);
    let identity = NodeIdentity::load_or_create(Path::new(&config.node.data_dir))?;
    let identity_public_key = identity.public_key_hex();
    let identity_signature = identity.sign(&p2p_hello_payload(
        config.node.mode,
        best.number.0,
        &best.hash().to_hex(),
        &profile,
        &identity_public_key,
        tls_certificate_hash,
    ));
    Ok(P2pMessage::Hello {
        node_mode: config.node.mode,
        best_number: best.number.0,
        best_hash: best.hash().to_hex(),
        consensus_profile: profile,
        identity_public_key,
        identity_signature,
        tls_certificate_hash: tls_certificate_hash.to_string(),
    })
}

fn send_p2p_message<S: Write>(stream: &mut S, message: &P2pMessage) -> Result<()> {
    let line = serde_json::to_string(message)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn read_p2p_line<R: BufRead>(reader: &mut R, line: &mut String) -> io::Result<bool> {
    line.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|position| position + 1)
            .unwrap_or(available.len());
        if line.len().saturating_add(take) > MAX_P2P_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer message exceeds size limit",
            ));
        }
        let has_newline;
        {
            let chunk = &available[..take];
            has_newline = chunk.last() == Some(&b'\n');
            let chunk = std::str::from_utf8(chunk).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer message is not valid UTF-8",
                )
            })?;
            line.push_str(chunk);
        }
        reader.consume(take);
        if has_newline {
            return Ok(true);
        }
    }
}

fn send_discovery_message(stream: &mut TcpStream, message: &DiscoveryMessage) -> Result<()> {
    let line = serde_json::to_string(message)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn send_relay_message(stream: &mut TcpStream, message: &RelayMessage) -> Result<()> {
    let line = serde_json::to_string(message)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn is_read_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn is_expected_rpc_disconnect(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("broken pipe")
        || message.contains("connection reset")
        || message.contains("connection aborted")
        || message.contains("transport endpoint is not connected")
        || message.contains("unexpected eof")
        || message.contains("timed out")
}

fn is_peer_disconnect(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    ) || err
        .to_string()
        .to_ascii_lowercase()
        .contains("unexpected eof")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_gossip_inventory_deduplicates_until_expiry() {
        let _test_guard = SOCKET_COUNTER_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("socket counter test mutex poisoned");
        let hash = genesis_header().hash();
        let now = unix_now();
        BLOCK_GOSSIP_INVENTORY
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .expect("block gossip inventory poisoned")
            .clear();

        assert!(mark_block_gossip_seen(hash, now));
        assert!(!mark_block_gossip_seen(hash, now.saturating_add(1)));
        assert!(mark_block_gossip_seen(
            hash,
            now.saturating_add(BLOCK_GOSSIP_INVENTORY_TTL_SECONDS + 1)
        ));
    }

    #[test]
    fn native_accounts_are_visible_to_evm_state() {
        let address = Address([0x5a; 20]);
        let mut state = RevmState::default();
        merge_native_accounts_into_revm_state(
            &mut state,
            std::collections::BTreeMap::from([(address, (Bix(123_456), 7))]),
        );
        let account = state.account(alloy_primitives::Address::from(address.0));
        assert_eq!(account.balance, alloy_primitives::U256::from(123_456u64));
        assert_eq!(account.nonce, 7);
    }
    use blq_consensus::satisfies_pow;
    use blq_miner::build_empty_template;
    use blq_storage::SledStorage;
    use std::collections::BTreeMap;
    use std::fs;

    fn test_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("blq-node-{name}-{}", std::process::id()));
        fs::remove_dir_all(&path).ok();
        fs::create_dir_all(&path).expect("create test storage");
        path
    }

    #[test]
    fn primary_p2p_connection_admission_is_bounded() {
        let active = AtomicUsize::new(0);
        for _ in 0..P2P_UNTRUSTED_SESSION_LIMIT {
            assert!(try_acquire_connection(&active, P2P_UNTRUSTED_SESSION_LIMIT));
        }
        assert!(!try_acquire_connection(
            &active,
            P2P_UNTRUSTED_SESSION_LIMIT
        ));
        active.fetch_sub(1, Ordering::AcqRel);
        assert!(try_acquire_connection(&active, P2P_UNTRUSTED_SESSION_LIMIT));
    }

    #[test]
    fn inbound_address_lease_rejects_duplicates_and_releases_on_drop() {
        let addresses = Arc::new(Mutex::new(HashSet::new()));
        let first = try_acquire_inbound_address(&addresses, "192.0.2.43".to_string());
        assert!(first.is_some());
        assert!(try_acquire_inbound_address(&addresses, "192.0.2.43".to_string()).is_none());
        assert!(try_acquire_inbound_address(&addresses, "192.0.2.201".to_string()).is_some());
        drop(first);
        assert!(try_acquire_inbound_address(&addresses, "192.0.2.43".to_string()).is_some());
    }

    fn cached_route(identity: &str, route: &str, last_success_epoch: u64) -> CachedPeerRoute {
        CachedPeerRoute {
            identity_public_key: identity.to_string(),
            routes: vec![route.to_string()],
            last_success_epoch,
            last_failure_epoch: None,
            expires_at_epoch: unix_now().saturating_add(P2P_PEER_CACHE_TTL_SECONDS),
        }
    }

    #[test]
    fn peer_route_cache_deduplicates_identities_and_evicts_oldest_success() {
        let first_identity = "02".repeat(33);
        let second_identity = "03".repeat(33);
        let mut routes = BTreeMap::from([
            (
                first_identity.clone(),
                cached_route(&first_identity, "198.51.100.1:30334", 1),
            ),
            (
                second_identity.clone(),
                cached_route(&second_identity, "198.51.100.2:30334", 2),
            ),
        ]);

        trim_cached_peer_routes(&mut routes, 1);

        assert_eq!(routes.len(), 1);
        assert!(routes.contains_key(&second_identity));
    }

    #[test]
    fn peer_route_cache_persists_only_verified_identity_routes() {
        let _test_guard = SOCKET_COUNTER_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("socket counter test mutex poisoned");
        let path = test_path("persisted-peer-routes");
        let config = test_rpc_node_config(&path, Vec::new());
        let identity = "02".repeat(33);
        cached_peer_routes()
            .lock()
            .expect("cached peer routes mutex poisoned")
            .clear();
        known_peer_identities()
            .lock()
            .expect("known peer identities mutex poisoned")
            .clear();

        remember_verified_peer_route(&config, "198.51.100.8:30334", &identity);
        assert!(peer_route_cache_path(&config).exists());

        cached_peer_routes()
            .lock()
            .expect("cached peer routes mutex poisoned")
            .clear();
        load_cached_peer_routes(&config);

        assert_eq!(cached_peer_endpoints(), vec!["198.51.100.8:30334"]);
        assert_eq!(
            known_peer_identities()
                .lock()
                .expect("known peer identities mutex poisoned")
                .get("198.51.100.8:30334"),
            Some(&identity)
        );

        cached_peer_routes()
            .lock()
            .expect("cached peer routes mutex poisoned")
            .clear();
        known_peer_identities()
            .lock()
            .expect("known peer identities mutex poisoned")
            .clear();
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn peer_route_cache_rejects_expired_or_unverified_entries() {
        let identity = "02".repeat(33);
        let mut expired = cached_route(&identity, "198.51.100.9:30334", 1);
        expired.expires_at_epoch = unix_now().saturating_sub(1);
        assert!(!cached_peer_route_is_valid(&expired));

        let invalid = CachedPeerRoute {
            identity_public_key: "not-an-identity".to_string(),
            ..cached_route(&identity, "198.51.100.9:30334", 1)
        };
        assert!(!cached_peer_route_is_valid(&invalid));
    }

    #[test]
    fn rpc_filter_pruning_reclaims_expired_entries() {
        let now = unix_now();
        let mut filters = BTreeMap::from([
            (
                1,
                RpcFilter {
                    kind: RpcFilterKind::Blocks,
                    last_block: 0,
                    last_accessed_at: now.saturating_sub(RPC_FILTER_TTL_SECONDS + 1),
                },
            ),
            (
                2,
                RpcFilter {
                    kind: RpcFilterKind::PendingTransactions,
                    last_block: 0,
                    last_accessed_at: now,
                },
            ),
        ]);

        prune_expired_rpc_filters(&mut filters, now);

        assert!(!filters.contains_key(&1));
        assert!(filters.contains_key(&2));
    }

    struct ShutdownProbe(Arc<AtomicUsize>);

    impl ShutdownTransport for ShutdownProbe {
        fn shutdown_transport(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn rejected_p2p_admission_closes_the_transport() {
        let active = AtomicUsize::new(1);
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let result = admit_p2p_transport(ShutdownProbe(Arc::clone(&shutdowns)), &active, 1);
        assert!(result.is_err());
        assert_eq!(shutdowns.load(Ordering::Acquire), 1);
        assert_eq!(active.load(Ordering::Acquire), 1);
    }

    struct StorageLockProbeWriter {
        storage: Arc<Mutex<NodeStorage>>,
        wrote_with_storage_available: bool,
        bytes: Vec<u8>,
    }

    impl Write for StorageLockProbeWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.wrote_with_storage_available = self.storage.try_lock().is_ok();
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn p2p_response_writes_do_not_hold_the_storage_mutex() {
        let path = test_path("p2p-response-lock-scope");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("initialize genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let config = test_rpc_node_config(&path, Vec::new());
        let mempool = Arc::new(Mutex::new(Mempool::default()));
        let genesis_hash = genesis_header().hash();

        for message in [
            P2pMessage::GetHeaders { from: 0, limit: 1 },
            P2pMessage::FindCommonAncestor {
                locator: vec![genesis_hash.to_hex()],
            },
            P2pMessage::WitnessHeaders {
                tip_hash: genesis_hash.to_hex(),
                heights: vec![0],
            },
        ] {
            let mut writer = StorageLockProbeWriter {
                storage: Arc::clone(&storage),
                wrote_with_storage_available: false,
                bytes: Vec::new(),
            };
            handle_p2p_message(&mut writer, &config, &storage, &mempool, message, None)
                .expect("serve p2p response");
            assert!(
                writer.wrote_with_storage_available,
                "storage mutex must be released before writing a P2P response"
            );
            assert!(!writer.bytes.is_empty());
        }

        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn node_info_returns_while_storage_is_busy() {
        let path = test_path("node-info-storage-busy");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("initialize genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let mut config = test_rpc_node_config(&path, Vec::new());
        let expected_genesis = Hash256([0x42; 32]).to_hex();
        config.node.expected_genesis_hash = Some(expected_genesis.clone());
        let held_storage = storage.lock().expect("hold storage mutex");
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_storage = Arc::clone(&storage);
        let worker = thread::spawn(move || {
            sender
                .send(rpc_node_info(
                    serde_json::json!(1),
                    &config,
                    &worker_storage,
                ))
                .expect("send node info");
        });

        let response = receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("node info must not wait for storage");
        assert!(response.contains("chainId"));
        let response: serde_json::Value =
            serde_json::from_str(&response).expect("node info response");
        assert_eq!(response["result"]["genesisHash"], expected_genesis);
        assert!(response["result"]["consensusProfile"]
            .as_str()
            .expect("profile")
            .contains(&expected_genesis));
        drop(held_storage);
        worker.join().expect("node info worker");
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn recovery_import_accepts_the_exact_durable_cursor_after_restart() {
        let peer = format!("recovery-request-{}", unix_now());
        let block = blq_primitives::genesis_block();
        let tip = Hash256([0x91; 32]);
        let mut cursor = new_branch_sync_cursor(tip, 10, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(0);
        cursor.ancestor_hash = Some(block.header.hash());
        cursor.next_height = 0;
        cursor.expected_parent_hash = Some(block.header.parent_hash);
        cursor.requested_height = Some(0);
        cursor.state = "retrieving".to_string();
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(peer.clone(), cursor);

        assert!(is_expected_recovery_body(&peer, &block));
        {
            let mut cursors = branch_sync_cursors().lock().expect("branch cursors");
            let cursor = cursors.get_mut(&peer).expect("cursor");
            cursor.requested_height = None;
            cursor.state = "waiting-for-provider".to_string();
        }
        // Request bookkeeping may be absent after a provider failure or
        // restart. The durable next-height and parent linkage still identify
        // this response unambiguously.
        assert!(is_expected_recovery_body(&peer, &block));
        let mut wrong_height = block.clone();
        wrong_height.header.number = blq_primitives::BlockNumber(1);
        assert!(!is_expected_recovery_body(&peer, &wrong_height));

        {
            let mut cursors = branch_sync_cursors().lock().expect("branch cursors");
            let cursor = cursors.get_mut(&peer).expect("cursor");
            cursor.next_height = 1;
            cursor.requested_height = Some(1);
            cursor.expected_parent_hash = Some(block.header.hash());
        }
        wrong_height.header.parent_hash = block.header.hash();
        assert!(is_expected_recovery_body(&peer, &wrong_height));

        wrong_height.header.parent_hash = Hash256([0x22; 32]);
        assert!(!is_expected_recovery_body(&peer, &wrong_height));
        assert!(recovery_body_conflicts_with_cursor(&peer, &wrong_height));

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&peer);
    }

    #[test]
    fn sync_block_lookup_serves_candidate_bodies() {
        let path = test_path("candidate-body-lookup");
        let mut storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        let parent = storage.best_header().expect("parent");
        let block = build_test_block(&storage, &parent, Hash256([0x33; 32]));
        let hash = block.header.hash();
        storage
            .store_candidate_block(&block, 10)
            .expect("candidate");
        assert_eq!(
            storage.sync_block_by_hash(hash).expect("candidate body"),
            block
        );
        fs::remove_dir_all(path).ok();
    }

    fn seal_test_block(mut block: Block) -> Block {
        let genesis_hash = genesis_header().hash();
        for nonce in 0..1_000_000u64 {
            block.header.nonce = nonce;
            let result = blq_pow::blq_rx_hash(&block.header, genesis_hash);
            block.header.mix_hash = result.mix_hash;
            if satisfies_pow(result.final_hash, block.header.difficulty_target) {
                return block;
            }
        }
        panic!("test block did not find a proof");
    }

    fn build_test_block(
        storage: &NodeStorage,
        parent: &BlockHeader,
        template_seed: Hash256,
    ) -> Block {
        let template = build_empty_template(
            parent,
            template_seed,
            parent.timestamp_seconds.saturating_add(30),
        );
        let block = build_stateful_block(storage, template.into_unsealed_block(), Vec::new())
            .expect("build test block state");
        seal_test_block(block)
    }

    #[test]
    fn supply_backfill_is_ready_before_suffix_publication() {
        let path = test_path("supply-backfill-startup");
        let mut storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        for seed in [0x41u8, 0x42] {
            let parent = storage.best_header().expect("parent");
            storage
                .insert_block(build_test_block(&storage, &parent, Hash256([seed; 32])))
                .expect("canonical block");
        }

        let NodeStorage::Full(full) = &storage else {
            unreachable!();
        };
        assert_eq!(full.supply_totals().expect("empty supply index").0, 0);
        backfill_supply_storage(full).expect("supply backfill");
        let (indexed_to, total, burned) = full.supply_totals().expect("indexed supply");
        assert_eq!(indexed_to, 2);
        assert!(total > 0);

        // A completed index is cheap and stable to check at every full-node
        // startup, so candidate publication cannot re-enter replay for it.
        backfill_supply_storage(full).expect("idempotent supply backfill");
        assert_eq!(
            full.supply_totals().expect("stable supply index"),
            (indexed_to, total, burned)
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn execution_replay_overlay_requires_an_exact_snapshot_parent() {
        let path = test_path("execution-replay-overlay");
        let mut storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        let parent = storage.best_header().expect("genesis header");
        let snapshot = ExecutionSnapshot {
            generation_id: 1,
            height: parent.number.0,
            block_hash: parent.hash(),
            state_root: parent.state_root,
            profile_fingerprint: "test".into(),
            finalized_height: 0,
            native_accounts: storage.account_snapshot().expect("native accounts"),
            evm_accounts: match &storage {
                NodeStorage::Full(full) => full.evm_account_snapshot().expect("EVM accounts"),
                NodeStorage::Partial(_) => unreachable!("full test storage"),
            },
        };
        let overlay = ExecutionReplayOverlay::from_snapshot(
            snapshot.clone(),
            parent.clone(),
            vec![parent.clone()],
        )
        .expect("matching snapshot opens overlay");
        assert_eq!(overlay.parent.hash(), parent.hash());
        let mut wrong_parent = parent;
        wrong_parent.state_root = Hash256([0x99; 32]);
        assert!(ExecutionReplayOverlay::from_snapshot(snapshot, wrong_parent, Vec::new()).is_err());
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn direct_candidate_extension_commits_without_staging_generation() {
        let main_path = test_path("direct-extension-main");
        let provider_path = test_path("direct-extension-provider");
        let config = test_rpc_node_config(&main_path, Vec::new());
        let mut main = NodeStorage::Full(SledStorage::open(&main_path).expect("open main"));
        let mut provider =
            NodeStorage::Full(SledStorage::open(&provider_path).expect("open provider"));
        initialize_genesis(&mut main, NodeMode::Full).expect("main genesis");
        initialize_genesis(&mut provider, NodeMode::Full).expect("provider genesis");

        let common = main.best_header().expect("common ancestor");
        let first = build_test_block(
            &provider,
            &provider.best_header().expect("provider parent"),
            Hash256([0x61; 32]),
        );
        provider.insert_block(first.clone()).expect("first block");
        let second = build_test_block(
            &provider,
            &provider.best_header().expect("provider parent"),
            Hash256([0x62; 32]),
        );
        provider.insert_block(second.clone()).expect("second block");

        let branch = CandidateBranch {
            common_height: common.number.0,
            common_hash: common.hash(),
            suffix: vec![first.clone(), second.clone()],
        };
        let storage = Arc::new(Mutex::new(main));
        assert!(
            commit_direct_candidate_extension(&config, &storage, &branch)
                .expect("direct extension")
        );
        let guard = storage.lock().expect("main storage");
        assert_eq!(
            guard.best_header().expect("best header").hash(),
            second.header.hash()
        );
        assert_eq!(
            guard
                .block_by_number(first.header.number.0)
                .expect("first canonical block")
                .header
                .hash(),
            first.header.hash()
        );
        drop(guard);
        fs::remove_dir_all(main_path).ok();
        fs::remove_dir_all(provider_path).ok();
    }

    #[test]
    fn cumulative_work_reorg_replays_the_selected_branch() {
        let main_path = test_path("reorg-main");
        let branch_path = test_path("reorg-branch");
        let mut main = NodeStorage::Full(SledStorage::open(&main_path).expect("open main"));
        let mut branch = NodeStorage::Full(SledStorage::open(&branch_path).expect("open branch"));
        initialize_genesis(&mut main, NodeMode::Full).expect("main genesis");
        initialize_genesis(&mut branch, NodeMode::Full).expect("branch genesis");
        let mut main_blocks = Vec::new();
        for _ in 0..5 {
            let parent = main.best_header().expect("main parent");
            let block = build_test_block(&main, &parent, Hash256([0x11; 32]));
            main.insert_block(block.clone()).expect("main block");
            main_blocks.push(block);
        }

        let mut branch_blocks = Vec::new();
        for _ in 0..7 {
            let parent = branch.best_header().expect("branch parent");
            let block = build_test_block(&branch, &parent, Hash256([0x22; 32]));
            branch.insert_block(block.clone()).expect("branch block");
            branch_blocks.push(block);
        }

        for block in branch_blocks.iter().take(5) {
            let _ = queue_competing_block(&mut main, block, false, Some(0), None)
                .expect("queue branch block");
        }
        assert!(
            queue_competing_block(&mut main, &branch_blocks[5], false, Some(0), None)
                .expect("promote branch")
        );
        assert!(
            queue_competing_block(&mut main, &branch_blocks[6], false, Some(0), None)
                .expect("extend branch")
        );
        assert_eq!(
            main.best_header().expect("best header").hash(),
            branch_blocks[6].header.hash()
        );
        for (number, block) in branch_blocks.iter().enumerate() {
            assert_eq!(
                main.block_by_number(number as u64 + 1)
                    .expect("reorg block")
                    .header
                    .hash(),
                block.header.hash()
            );
        }
        assert_ne!(
            main.block_by_number(1)
                .expect("reorg block one")
                .header
                .hash(),
            main_blocks[0].header.hash()
        );

        fs::remove_dir_all(main_path).ok();
        fs::remove_dir_all(branch_path).ok();
    }

    #[test]
    fn periodic_snapshots_are_execution_only_and_do_not_use_legacy_archive_files() {
        let path = test_path("periodic-execution-snapshot");
        let config = test_rpc_node_config(&path, Vec::new());
        let mut storage = SledStorage::open(&path).expect("open storage");
        let mut block = genesis_block();
        block.header.number.0 = EXECUTION_SNAPSHOT_INTERVAL;
        block.header.timestamp_seconds = block
            .header
            .timestamp_seconds
            .saturating_add(EXECUTION_SNAPSHOT_INTERVAL.saturating_mul(30));
        let hash = block.header.hash();
        storage
            .insert_block(block)
            .expect("insert checkpoint block");
        let root = path.join("generations");
        SledStorage::activate_generation(&root, 1).expect("activate generation");
        let node_storage = NodeStorage::Full(storage);

        write_periodic_snapshot(&config, &node_storage).expect("write compact snapshot");

        let generation = SledStorage::generation_path(&root, 1);
        assert!(
            SledStorage::execution_snapshot_path(&generation, EXECUTION_SNAPSHOT_INTERVAL).exists(),
            "periodic replay checkpoint must contain only execution state"
        );
        assert!(
            !SledStorage::snapshot_path(&generation, EXECUTION_SNAPSHOT_INTERVAL).exists(),
            "periodic checkpoint must not serialize the complete archive"
        );
        assert_eq!(
            node_storage.best_header().expect("best header").hash(),
            hash
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn true_fork_publication_reuses_the_active_archive_generation() {
        let main_path = test_path("suffix-reorg-main");
        let branch_path = test_path("suffix-reorg-branch");
        let config = test_rpc_node_config(&main_path, Vec::new());
        let mut main = NodeStorage::Full(SledStorage::open(&main_path).expect("open main"));
        let mut branch = NodeStorage::Full(SledStorage::open(&branch_path).expect("open branch"));
        initialize_genesis(&mut main, NodeMode::Full).expect("main genesis");
        initialize_genesis(&mut branch, NodeMode::Full).expect("branch genesis");
        let (genesis_native_accounts, genesis_evm_accounts) = match &main {
            NodeStorage::Full(full) => (
                full.account_snapshot().expect("genesis native state"),
                full.evm_account_snapshot().expect("genesis EVM state"),
            ),
            NodeStorage::Partial(_) => unreachable!("full test storage"),
        };
        for seed in [0x41, 0x42, 0x43] {
            let parent = main.best_header().expect("main parent");
            let block = build_test_block(&main, &parent, Hash256([seed; 32]));
            main.insert_block(block).expect("main block");
        }
        let mut branch_blocks = Vec::new();
        // Keep this at the 64-block suffix that previously stressed the archive
        // replay path. The live publisher must still reuse the active archive.
        for offset in 0..64u8 {
            let seed = 0x51u8.wrapping_add(offset);
            let parent = branch.best_header().expect("branch parent");
            let block = build_test_block(&branch, &parent, Hash256([seed; 32]));
            branch.insert_block(block.clone()).expect("branch block");
            branch_blocks.push(block);
        }
        let profile = consensus_profile_for_genesis(genesis_header().hash());
        let main_best = {
            let NodeStorage::Full(full) = &main else {
                unreachable!("full test storage")
            };
            let best = full.best_header().expect("main best");
            let manifest = GenerationManifest {
                generation_id: 1,
                status: GenerationStatus::Active,
                canonical_height: best.number.0,
                canonical_hash: best.hash(),
                state_root: best.state_root,
                profile_fingerprint: profile.clone(),
                finalized_height: finalized_height(best.number.0),
                replay_checkpoint: None,
            };
            SledStorage::write_generation_manifest(&main_path, &manifest).expect("main manifest");
            SledStorage::write_generation_publication(&main_path, &manifest)
                .expect("main publication");
            backfill_supply_storage(full).expect("canonical supply index");
            SledStorage::write_execution_snapshot(
                &main_path,
                &ExecutionSnapshot {
                    generation_id: 1,
                    height: 0,
                    block_hash: genesis_header().hash(),
                    state_root: genesis_header().state_root,
                    profile_fingerprint: profile,
                    finalized_height: 0,
                    native_accounts: genesis_native_accounts,
                    evm_accounts: genesis_evm_accounts,
                },
            )
            .expect("genesis execution snapshot");
            best
        };
        let branch_state = match &branch {
            NodeStorage::Full(full) => full.state_root().expect("branch state"),
            NodeStorage::Partial(_) => unreachable!("full test storage"),
        };
        let branch = CandidateBranch {
            common_height: 0,
            common_hash: genesis_header().hash(),
            suffix: branch_blocks.clone(),
        };
        let storage = Arc::new(Mutex::new(main));
        stage_and_publish_candidate(&config, &storage, branch).expect("publish true fork");
        let guard = storage.lock().expect("main storage");
        assert_eq!(
            guard.best_header().expect("published best").hash(),
            branch_blocks.last().expect("branch tip").header.hash()
        );
        assert_eq!(
            guard
                .block_by_number(1)
                .expect("replaced height one")
                .header
                .hash(),
            branch_blocks[0].header.hash()
        );
        assert_ne!(
            guard.best_header().expect("published best").hash(),
            main_best.hash()
        );
        assert_eq!(
            match &*guard {
                NodeStorage::Full(full) => full.state_root().expect("published state"),
                NodeStorage::Partial(_) => unreachable!("full test storage"),
            },
            branch_state
        );
        drop(guard);
        drop(storage);
        let reopened = SledStorage::open(&main_path).expect("reopen published archive");
        let manifest = reopened
            .verify_generation_manifest()
            .expect("published manifest survives restart");
        assert_eq!(
            manifest.canonical_hash,
            branch_blocks.last().expect("branch tip").header.hash()
        );
        assert_eq!(manifest.replay_checkpoint, Some(manifest.canonical_height));
        assert!(
            !main_path.join("generations").exists(),
            "live suffix publication must not allocate the legacy full staging tree"
        );
        fs::remove_dir_all(main_path).ok();
        fs::remove_dir_all(branch_path).ok();
    }

    #[test]
    fn true_fork_publication_uses_the_branch_ancestor_not_the_snapshot_parent() {
        let main_path = test_path("suffix-reorg-snapshot-parent-main");
        let branch_path = test_path("suffix-reorg-snapshot-parent-branch");
        let config = test_rpc_node_config(&main_path, Vec::new());
        let mut main = NodeStorage::Full(SledStorage::open(&main_path).expect("open main"));
        let mut branch = NodeStorage::Full(SledStorage::open(&branch_path).expect("open branch"));
        initialize_genesis(&mut main, NodeMode::Full).expect("main genesis");
        initialize_genesis(&mut branch, NodeMode::Full).expect("branch genesis");
        let (genesis_native_accounts, genesis_evm_accounts) = match &main {
            NodeStorage::Full(full) => (
                full.account_snapshot().expect("genesis native state"),
                full.evm_account_snapshot().expect("genesis EVM state"),
            ),
            NodeStorage::Partial(_) => unreachable!("full test storage"),
        };

        for seed in [0x71, 0x72, 0x73] {
            let parent = main.best_header().expect("shared parent");
            let block = build_test_block(&main, &parent, Hash256([seed; 32]));
            main.insert_block(block.clone()).expect("main shared block");
            branch.insert_block(block).expect("branch shared block");
        }
        let ancestor = main.best_header().expect("fork ancestor");
        for seed in [0x74, 0x75] {
            let parent = main.best_header().expect("main parent");
            main.insert_block(build_test_block(&main, &parent, Hash256([seed; 32])))
                .expect("main divergent block");
        }
        let mut suffix = Vec::new();
        for seed in [0x81, 0x82, 0x83] {
            let parent = branch.best_header().expect("branch parent");
            let block = build_test_block(&branch, &parent, Hash256([seed; 32]));
            branch
                .insert_block(block.clone())
                .expect("branch divergent block");
            suffix.push(block);
        }

        let profile = consensus_profile_for_genesis(genesis_header().hash());
        let NodeStorage::Full(full) = &main else {
            unreachable!("full test storage");
        };
        let best = full.best_header().expect("main best");
        let manifest = GenerationManifest {
            generation_id: 1,
            status: GenerationStatus::Active,
            canonical_height: best.number.0,
            canonical_hash: best.hash(),
            state_root: best.state_root,
            profile_fingerprint: profile.clone(),
            finalized_height: finalized_height(best.number.0),
            replay_checkpoint: None,
        };
        SledStorage::write_generation_manifest(&main_path, &manifest).expect("main manifest");
        SledStorage::write_generation_publication(&main_path, &manifest).expect("main publication");
        backfill_supply_storage(full).expect("canonical supply index");
        SledStorage::write_execution_snapshot(
            &main_path,
            &ExecutionSnapshot {
                generation_id: 1,
                height: 0,
                block_hash: genesis_header().hash(),
                state_root: genesis_header().state_root,
                profile_fingerprint: profile,
                finalized_height: 0,
                native_accounts: genesis_native_accounts,
                evm_accounts: genesis_evm_accounts,
            },
        )
        .expect("genesis execution snapshot");

        let storage = Arc::new(Mutex::new(main));
        stage_and_publish_candidate(
            &config,
            &storage,
            CandidateBranch {
                common_height: ancestor.number.0,
                common_hash: ancestor.hash(),
                suffix: suffix.clone(),
            },
        )
        .expect("publish suffix above non-snapshot ancestor");
        let guard = storage.lock().expect("published storage");
        assert_eq!(
            guard.best_header().expect("published tip").hash(),
            suffix.last().expect("branch tip").header.hash()
        );
        assert_eq!(
            guard
                .block_by_number(ancestor.number.0)
                .expect("retained ancestor")
                .header
                .hash(),
            ancestor.hash()
        );
        drop(guard);
        drop(storage);
        fs::remove_dir_all(main_path).ok();
        fs::remove_dir_all(branch_path).ok();
    }

    #[test]
    fn candidate_branch_uses_only_the_suffix_above_a_known_ancestor() {
        let path = test_path("candidate-suffix");
        let mut storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        for index in 0..7 {
            let parent = storage.best_header().expect("parent");
            let block = build_test_block(&storage, &parent, Hash256([index as u8; 32]));
            storage.insert_block(block).expect("canonical block");
        }
        let canonical = storage.canonical_blocks().expect("canonical chain");
        let parent = canonical[6].header.clone();
        let candidate = build_test_block(&storage, &parent, Hash256([0x99; 32]));
        storage
            .store_candidate_block(&candidate, canonical_work(&canonical).saturating_add(1))
            .expect("candidate");

        let branch = candidate_replacement(&storage, &candidate, &canonical).expect("branch");
        let storage_backed =
            candidate_branch_from_storage(&storage, &candidate).expect("storage-backed branch");
        assert_eq!(branch.common_height, 6);
        assert_eq!(branch.common_hash, canonical[6].header.hash());
        assert_eq!(branch.suffix, vec![candidate]);
        assert_eq!(storage_backed.common_height, branch.common_height);
        assert_eq!(storage_backed.common_hash, branch.common_hash);
        assert_eq!(storage_backed.suffix, branch.suffix);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn candidate_branch_with_missing_parent_waits_for_provider() {
        let path = test_path("candidate-missing-parent");
        let mut storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        let parent = storage.best_header().expect("parent");
        let mut candidate = build_test_block(&storage, &parent, Hash256([0x55; 32]));
        candidate.header.number = blq_primitives::BlockNumber(8);
        candidate.header.parent_hash = Hash256([0x7f; 32]);
        storage
            .store_candidate_block(&candidate, 10)
            .expect("candidate");
        let canonical = storage.canonical_blocks().expect("canonical chain");

        let error =
            candidate_replacement(&storage, &candidate, &canonical).expect_err("missing parent");
        assert!(error.to_string().contains("waiting-for-provider"));
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn candidate_branch_below_confirmation_depth_remains_replayable() {
        let path = test_path("candidate-finality");
        let mut storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        for index in 0..7 {
            let parent = storage.best_header().expect("parent");
            let block = build_test_block(&storage, &parent, Hash256([index as u8; 32]));
            storage.insert_block(block).expect("canonical block");
        }
        let canonical = storage.canonical_blocks().expect("canonical chain");
        let candidate = build_test_block(&storage, &canonical[0].header, Hash256([0xee; 32]));
        storage
            .store_candidate_block(&candidate, 10)
            .expect("candidate");

        let branch = candidate_replacement(&storage, &candidate, &canonical).expect("deep branch");
        assert_eq!(branch.common_height, canonical[0].header.number.0);
        assert_eq!(branch.common_hash, canonical[0].header.hash());
        assert_eq!(branch.suffix, vec![candidate]);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn deep_recovery_cursor_survives_finality_marker_cleanup() {
        let path = test_path("deep-recovery-cursor");
        let config = test_rpc_node_config(&path, Vec::new());
        let tip = Hash256([0xa7; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 100, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(40);
        cursor.ancestor_hash = Some(Hash256([0xa8; 32]));
        cursor.next_height = 41;
        cursor.state = "retrieving".to_string();
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        prune_finalized_recovery_cursors(&config, 94);
        assert!(branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .contains_key(&key));

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn reward_backfill_skips_persisted_evm_contract_creation_blocks() {
        let path = test_path("evm-backfill");
        let mut storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        let caller = Address([0x31; 20]);
        if let NodeStorage::Full(storage) = &storage {
            storage
                .put_evm_account(caller, Bix(10u128.pow(18)), 0, &[], &BTreeMap::new())
                .expect("fund caller");
        }
        let parent = storage.best_header().expect("parent");
        let template = build_empty_template(
            &parent,
            Hash256([0x41; 32]),
            parent.timestamp_seconds.saturating_add(30),
        );
        let transaction = Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: caller,
            to: None,
            value: Bix(0),
            gas_limit: 100_000,
            max_fee_per_gas: Bix(2_000_000_000),
            max_priority_fee_per_gas: Bix(0),
            payload: vec![0x00],
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        };
        let block =
            build_stateful_block(&storage, template.into_unsealed_block(), vec![transaction])
                .expect("build EVM block");
        let block = seal_test_block(block);
        storage.insert_block(block).expect("persist EVM block");
        if let NodeStorage::Full(storage) = &storage {
            storage
                .set_reward_indexed_to(0)
                .expect("reset backfill marker");
        }
        storage.backfill_rewards().expect("backfill EVM block");
        if let NodeStorage::Full(storage) = &storage {
            assert_eq!(storage.reward_indexed_to().expect("read marker"), 1);
        }
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn cumulative_work_reorg_replays_evm_state_without_leaking_abandoned_code() {
        fn creation_block(
            storage: &NodeStorage,
            parent: &BlockHeader,
            seed: Hash256,
            caller: Address,
            value: u8,
        ) -> Block {
            let template =
                build_empty_template(parent, seed, parent.timestamp_seconds.saturating_add(30));
            let runtime = [0x60, value, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
            let mut init_code = vec![
                0x60,
                runtime.len() as u8,
                0x60,
                0x0c,
                0x60,
                0x00,
                0x39,
                0x60,
                runtime.len() as u8,
                0x60,
                0x00,
                0xf3,
            ];
            init_code.extend_from_slice(&runtime);
            let transaction = Transaction {
                chain_id: MAINNET_CHAIN_ID,
                transaction_type: 2,
                nonce: 0,
                from: caller,
                to: None,
                value: Bix(0),
                gas_limit: 100_000,
                max_fee_per_gas: Bix(2_000_000_000),
                max_priority_fee_per_gas: Bix(0),
                payload: init_code,
                access_list: Vec::new(),
                signature: None,
                external_hash: None,
            };
            seal_test_block(
                build_stateful_block(storage, template.into_unsealed_block(), vec![transaction])
                    .expect("build EVM creation block"),
            )
        }

        let main_path = test_path("evm-reorg-main");
        let branch_path = test_path("evm-reorg-branch");
        let mut main = NodeStorage::Full(SledStorage::open(&main_path).expect("open main"));
        let mut branch = NodeStorage::Full(SledStorage::open(&branch_path).expect("open branch"));
        initialize_genesis(&mut main, NodeMode::Full).expect("main genesis");
        initialize_genesis(&mut branch, NodeMode::Full).expect("branch genesis");
        let caller = Address([0x73; 20]);
        let beneficiary = Hash256([0x73; 32]);

        for _ in 0..1 {
            let main_parent = main.best_header().expect("main common parent");
            let main_block = build_test_block(&main, &main_parent, beneficiary);
            main.insert_block(main_block).expect("main common block");
            let branch_parent = branch.best_header().expect("branch common parent");
            let branch_block = build_test_block(&branch, &branch_parent, beneficiary);
            branch
                .insert_block(branch_block)
                .expect("branch common block");
        }

        let main_creation = creation_block(
            &main,
            &main.best_header().expect("main EVM parent"),
            Hash256([0xa1; 32]),
            caller,
            0x2a,
        );
        let main_contract = create_contract_address(caller, 0);
        main.insert_block(main_creation).expect("main EVM block");

        let branch_creation = creation_block(
            &branch,
            &branch.best_header().expect("branch EVM parent"),
            Hash256([0xb1; 32]),
            caller,
            0x2b,
        );
        let branch_contract = create_contract_address(caller, 0);
        branch
            .insert_block(branch_creation)
            .expect("branch EVM block");
        let branch_extension = build_test_block(
            &branch,
            &branch.best_header().expect("branch extension parent"),
            Hash256([0xb2; 32]),
        );
        branch
            .insert_block(branch_extension.clone())
            .expect("branch extension");

        let branch_blocks = branch.canonical_blocks().expect("branch blocks");
        let branch_tip = branch_blocks.last().expect("branch tip").clone();
        assert!(
            queue_competing_block(&mut main, &branch_blocks[2], false, Some(0), None)
                .expect("queue EVM branch")
        );
        assert!(
            queue_competing_block(&mut main, &branch_tip, false, Some(0), None)
                .expect("promote EVM branch")
        );
        assert_eq!(
            main.best_header().expect("promoted tip").hash(),
            branch_tip.header.hash()
        );
        if let NodeStorage::Full(storage) = &main {
            let code = storage
                .evm_code(main_contract)
                .expect("promoted code lookup");
            assert_eq!(branch_contract, main_contract);
            assert_eq!(
                code,
                vec![0x60, 0x2b, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
            );
            assert_ne!(
                code,
                vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
            );
        }
        fs::remove_dir_all(main_path).ok();
        fs::remove_dir_all(branch_path).ok();
    }

    #[test]
    fn persisted_identity_signs_and_rejects_tampered_hello() {
        let path = test_path("identity");
        let identity = NodeIdentity::load_or_create(&path).expect("create identity");
        let public_key = identity.public_key_hex();
        let best_hash = genesis_header().hash().to_hex();
        let profile = consensus_profile();
        let tls_certificate_hash = "test-certificate";
        let signature = identity.sign(&p2p_hello_payload(
            NodeMode::Full,
            0,
            &best_hash,
            &profile,
            &public_key,
            tls_certificate_hash,
        ));
        verify_p2p_identity(
            NodeMode::Full,
            0,
            &best_hash,
            &profile,
            &public_key,
            &signature,
            tls_certificate_hash,
            Some(tls_certificate_hash),
            None,
        )
        .expect("verify identity");
        let mismatched_signature = identity.sign(&p2p_hello_payload(
            NodeMode::Full,
            0,
            &best_hash,
            "different-consensus-profile",
            &public_key,
            tls_certificate_hash,
        ));
        let mismatch = verify_p2p_identity(
            NodeMode::Full,
            0,
            &best_hash,
            "different-consensus-profile",
            &public_key,
            &mismatched_signature,
            tls_certificate_hash,
            Some(tls_certificate_hash),
            None,
        )
        .expect_err("mismatched profile must be rejected");
        assert!(mismatch.to_string().contains("consensus profile mismatch"));
        let trusted = vec![public_key.clone()];
        verify_p2p_identity(
            NodeMode::Full,
            0,
            &best_hash,
            &profile,
            &public_key,
            &signature,
            tls_certificate_hash,
            Some(tls_certificate_hash),
            Some(&trusted),
        )
        .expect("trusted identity");
        let untrusted =
            vec!["02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()];
        assert!(verify_p2p_identity(
            NodeMode::Full,
            0,
            &best_hash,
            &profile,
            &public_key,
            &signature,
            tls_certificate_hash,
            Some(tls_certificate_hash),
            Some(&untrusted),
        )
        .is_err());
        assert!(verify_p2p_identity(
            NodeMode::Full,
            1,
            &best_hash,
            &profile,
            &public_key,
            &signature,
            tls_certificate_hash,
            Some(tls_certificate_hash),
            None,
        )
        .is_err());
        assert!(verify_p2p_identity(
            NodeMode::Full,
            0,
            &best_hash,
            &profile,
            &public_key,
            &signature,
            tls_certificate_hash,
            Some("wrong-certificate"),
            None,
        )
        .is_err());
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn network_profile_binds_block_size_activation_height() {
        let path = test_path("block-size-network-profile");
        let disabled = test_rpc_node_config(&path, Vec::new());
        let mut scheduled = test_rpc_node_config(&path, Vec::new());
        scheduled.node.block_size_activation_height = Some(13_521);

        let genesis = genesis_header().hash();
        let disabled_profile = network_consensus_profile(&disabled, genesis);
        let scheduled_profile = network_consensus_profile(&scheduled, genesis);

        assert!(disabled_profile.contains("block_size_activation_height=disabled"));
        assert!(scheduled_profile.contains("block_size_activation_height=13521"));
        assert_ne!(disabled_profile, scheduled_profile);
        // Snapshot compatibility remains based on the stable storage profile.
        assert!(!consensus_profile_for_genesis(genesis).contains("block_size_activation_height"));
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn network_profile_binds_block_time_v2_activation_height() {
        let path = test_path("block-time-network-profile");
        let disabled = test_rpc_node_config(&path, Vec::new());
        let mut scheduled = test_rpc_node_config(&path, Vec::new());
        scheduled.node.block_time_v2_activation_height = Some(14_000);

        let genesis = genesis_header().hash();
        let disabled_profile = network_consensus_profile(&disabled, genesis);
        let scheduled_profile = network_consensus_profile(&scheduled, genesis);

        assert!(disabled_profile.contains("block_time_v2_activation_height=disabled"));
        assert!(scheduled_profile.contains("block_time_v2_activation_height=14000"));
        assert_ne!(disabled_profile, scheduled_profile);
        assert_eq!(active_block_time_target_seconds(&scheduled, 13_999), 30);
        assert_eq!(active_block_time_target_seconds(&scheduled, 14_000), 15);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn live_timestamp_admission_allows_only_bounded_future_headers() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_secs();
        let mut header = genesis_header();
        header.timestamp_seconds = now.saturating_add(MAX_LIVE_TIMESTAMP_FUTURE_DRIFT_SECONDS - 1);
        validate_live_timestamp_admission(&header).expect("bounded future drift is admitted");

        header.timestamp_seconds = now.saturating_add(MAX_LIVE_TIMESTAMP_FUTURE_DRIFT_SECONDS + 1);
        assert!(validate_live_timestamp_admission(&header).is_err());
    }

    #[test]
    fn p2p_requires_signed_hello_before_data_messages() {
        let data_message = P2pMessage::GetHeaders { from: 0, limit: 1 };
        assert!(advance_p2p_handshake(&data_message, false).is_err());
        assert!(advance_p2p_handshake(&data_message, true).expect("data after hello"));
        let hello = P2pMessage::Hello {
            node_mode: NodeMode::Full,
            best_number: 0,
            best_hash: genesis_header().hash().to_hex(),
            consensus_profile: consensus_profile(),
            identity_public_key: "00".to_string(),
            identity_signature: "00".to_string(),
            tls_certificate_hash: "00".to_string(),
        };
        assert!(advance_p2p_handshake(&hello, false).expect("first hello"));
        assert!(advance_p2p_handshake(&hello, true).is_err());
    }

    #[test]
    fn p2p_reader_rejects_oversized_frames_before_json_parse() {
        let input = vec![b'x'; MAX_P2P_MESSAGE_BYTES + 1];
        let mut reader = BufReader::new(std::io::Cursor::new(input));
        let mut line = String::new();
        let error = read_p2p_line(&mut reader, &mut line).expect_err("oversized frame");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("size limit"));
    }

    #[test]
    fn p2p_reader_bounds_unterminated_frames() {
        let input = vec![b'x'; MAX_P2P_MESSAGE_BYTES + 1];
        let mut reader = BufReader::with_capacity(32, std::io::Cursor::new(input));
        let mut line = String::new();
        let error = read_p2p_line(&mut reader, &mut line).expect_err("unterminated frame");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(line.len() <= MAX_P2P_MESSAGE_BYTES);
    }

    #[test]
    fn p2p_tls_round_trip_uses_encrypted_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS test listener");
        let address = listener.local_addr().expect("TLS test address");
        let (server_config, server_certificate_hash) =
            build_server_tls_config().expect("build TLS server config");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept TLS test connection");
            let connection = ServerConnection::new(server_config).expect("server connection");
            let stream = StreamOwned::new(connection, stream);
            let mut reader = BufReader::new(stream);
            reader
                .get_mut()
                .write_all(b"server!")
                .expect("write TLS greeting");
            reader.get_mut().flush().expect("flush TLS greeting");
            let mut message = [0u8; 8];
            reader.read_exact(&mut message).expect("read TLS message");
            message
        });

        let stream = TcpStream::connect(address).expect("connect TLS test connection");
        let server_name = ServerName::try_from("blq").expect("TLS server name");
        let connection = ClientConnection::new(build_client_tls_config(), server_name)
            .expect("client connection");
        let mut stream = StreamOwned::new(connection, stream);
        stream
            .conn
            .complete_io(&mut stream.sock)
            .expect("TLS handshake");
        let peer_certificate_hash = stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .map(|certificate| certificate_fingerprint(certificate.as_ref()))
            .expect("peer certificate");
        assert_eq!(peer_certificate_hash, server_certificate_hash);
        let mut greeting = [0u8; 7];
        stream.read_exact(&mut greeting).expect("read TLS greeting");
        assert_eq!(greeting, *b"server!");
        stream.write_all(b"blq-tls!").expect("write TLS message");
        stream.flush().expect("flush TLS message");
        assert_eq!(server.join().expect("TLS server thread"), *b"blq-tls!");
    }

    #[test]
    fn historical_rpc_body_fetch_requires_matching_header() {
        let local_path = test_path("rpc-fetch-local");
        let remote_path = test_path("rpc-fetch-remote");
        let mut local = NodeStorage::Full(SledStorage::open(&local_path).expect("local storage"));
        let mut remote =
            NodeStorage::Full(SledStorage::open(&remote_path).expect("remote storage"));
        initialize_genesis(&mut local, NodeMode::Full).expect("local genesis");
        initialize_genesis(&mut remote, NodeMode::Full).expect("remote genesis");
        let parent = remote.best_header().expect("remote parent");
        let block = build_test_block(&remote, &parent, Hash256([0x33; 32]));
        remote.insert_block(block.clone()).expect("remote block");
        local
            .insert_header(block.header.clone())
            .expect("local header");
        let local = Arc::new(Mutex::new(local));
        let remote = Arc::new(Mutex::new(remote));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fetch listener");
        let address = listener.local_addr().expect("fetch address");
        let (server_config, server_certificate_hash) =
            build_server_tls_config().expect("server TLS config");
        let remote_config = test_rpc_node_config(&remote_path, Vec::new());
        let server_remote = Arc::clone(&remote);
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept fetch connection");
            let connection = ServerConnection::new(server_config).expect("server connection");
            let mut stream = StreamOwned::new(connection, socket);
            stream
                .conn
                .complete_io(&mut stream.sock)
                .expect("server TLS handshake");
            send_p2p_message(
                &mut stream,
                &hello_message(&remote_config, &server_remote, &server_certificate_hash)
                    .expect("server hello"),
            )
            .expect("send server hello");
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            assert!(read_p2p_line(&mut reader, &mut line).expect("client hello"));
            assert!(matches!(
                serde_json::from_str::<P2pMessage>(line.trim()).expect("decode client hello"),
                P2pMessage::Hello { .. }
            ));
            line.clear();
            assert!(read_p2p_line(&mut reader, &mut line).expect("get block"));
            let P2pMessage::GetBlockByHash { hash } =
                serde_json::from_str(line.trim()).expect("decode get block")
            else {
                panic!("client did not request a block");
            };
            let hash = Hash256::from_hex(&hash).expect("decode requested hash");
            let block = server_remote
                .lock()
                .expect("remote mutex")
                .block_by_hash(hash)
                .expect("remote block body");
            send_p2p_message(reader.get_mut(), &P2pMessage::BlockBody { block })
                .expect("send block body");
        });
        let local_config = test_rpc_node_config(&local_path, vec![address.to_string()]);
        let fetched = load_rpc_block(&local_config, &local, 1)
            .expect("fetch body")
            .expect("body exists");
        assert_eq!(fetched.header.hash(), block.header.hash());
        server.join().expect("fetch server");
        fs::remove_dir_all(local_path).ok();
        fs::remove_dir_all(remote_path).ok();
    }

    #[test]
    fn historical_rpc_transaction_fetch_requires_matching_hash() {
        let local_path = test_path("rpc-transaction-local");
        let remote_path = test_path("rpc-transaction-remote");
        let mut local = NodeStorage::Full(SledStorage::open(&local_path).expect("local storage"));
        let mut remote =
            NodeStorage::Full(SledStorage::open(&remote_path).expect("remote storage"));
        initialize_genesis(&mut local, NodeMode::Full).expect("local genesis");
        initialize_genesis(&mut remote, NodeMode::Full).expect("remote genesis");
        let parent = remote.best_header().expect("remote parent");
        let mut block = build_test_block(&remote, &parent, Hash256([0x55; 32]));
        let transaction = Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: Address([0x11; 20]),
            to: Some(Address([0x22; 20])),
            value: Bix(0),
            gas_limit: TRANSFER_GAS,
            max_fee_per_gas: block.header.base_fee_per_gas,
            max_priority_fee_per_gas: Bix(0),
            payload: Vec::new(),
            access_list: Vec::new(),
            signature: None,
            external_hash: Some(Hash256([0x66; 32])),
        };
        block.transactions = vec![transaction.clone()];
        block.receipts = vec![Receipt {
            transaction_hash: transaction.rpc_hash(),
            success: true,
            gas_used: TRANSFER_GAS,
            logs_root: Hash256::ZERO,
            logs: Vec::new(),
        }];
        block.header.gas_used = TRANSFER_GAS;
        block.header.transactions_root = transactions_root(&block.transactions);
        block.header.receipts_root = receipts_root(&block.receipts);
        block = seal_test_block(block);
        if let NodeStorage::Full(storage) = &remote {
            storage
                .put_account(transaction.from, Bix(u128::MAX / 2), 0)
                .expect("fund remote sender");
        }
        remote.insert_block(block.clone()).expect("remote block");
        local
            .insert_header(block.header.clone())
            .expect("local header");
        let local = Arc::new(Mutex::new(local));
        let remote = Arc::new(Mutex::new(remote));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind transaction listener");
        let address = listener.local_addr().expect("transaction address");
        let (server_config, server_certificate_hash) =
            build_server_tls_config().expect("server TLS config");
        let remote_config = test_rpc_node_config(&remote_path, Vec::new());
        let server_remote = Arc::clone(&remote);
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept transaction connection");
            let connection = ServerConnection::new(server_config).expect("server connection");
            let mut stream = StreamOwned::new(connection, socket);
            stream
                .conn
                .complete_io(&mut stream.sock)
                .expect("server TLS handshake");
            send_p2p_message(
                &mut stream,
                &hello_message(&remote_config, &server_remote, &server_certificate_hash)
                    .expect("server hello"),
            )
            .expect("send server hello");
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            assert!(read_p2p_line(&mut reader, &mut line).expect("client hello"));
            assert!(matches!(
                serde_json::from_str::<P2pMessage>(line.trim()).expect("decode client hello"),
                P2pMessage::Hello { .. }
            ));
            line.clear();
            assert!(read_p2p_line(&mut reader, &mut line).expect("get transaction"));
            let P2pMessage::GetTransaction { hash } =
                serde_json::from_str(line.trim()).expect("decode get transaction")
            else {
                panic!("client did not request a transaction");
            };
            let hash = Hash256::from_hex(&hash).expect("transaction hash");
            let (receipt, header, transaction_index, transaction) = server_remote
                .lock()
                .expect("remote mutex")
                .transaction_receipt_by_hash(hash)
                .expect("remote transaction");
            let data = RpcTransactionData {
                receipt,
                header,
                transaction_index,
                transaction,
            };
            send_p2p_message(
                reader.get_mut(),
                &P2pMessage::Transaction { data: Some(data) },
            )
            .expect("send transaction");
        });
        let local_config = test_rpc_node_config(&local_path, vec![address.to_string()]);
        let fetched = load_rpc_transaction(&local_config, &local, transaction.rpc_hash())
            .expect("fetch transaction")
            .expect("transaction exists");
        assert_eq!(fetched.transaction.rpc_hash(), transaction.rpc_hash());
        assert_eq!(fetched.header.hash(), block.header.hash());
        server.join().expect("transaction server");
        fs::remove_dir_all(local_path).ok();
        fs::remove_dir_all(remote_path).ok();
    }

    fn test_rpc_node_config(
        data_dir: &std::path::Path,
        bootstrap_peers: Vec<String>,
    ) -> NodeConfig {
        NodeConfig {
            node: NodeSection {
                mode: NodeMode::Full,
                data_dir: data_dir.to_string_lossy().into_owned(),
                mining_enabled: false,
                advertise_rpc: None,
                advertise_websocket: None,
                advertise_p2p: None,
                max_storage_bytes: 0,
                filesystem_reserve_bytes: 0,
                prune_trigger_percent: 75,
                storage_mode: StorageMode::Archive,
                prune_history: false,
                retain_snapshots: true,
                retain_finalized_checkpoints: true,
                historical_peer_fallback: true,
                required_pow_algorithm: None,
                expected_genesis_hash: None,
                genesis_manifest: None,
                require_signed_transactions: false,
                block_size_activation_height: None,
                block_time_v2_activation_height: None,
            },
            rpc: RpcSection {
                enabled: false,
                bind: "127.0.0.1:0".to_string(),
                public_read_only: false,
                max_connections: DEFAULT_RPC_CONNECTIONS,
                mining_token: None,
                mining_upstreams: Vec::new(),
                mining_api_enabled: false,
            },
            network: NetworkSection {
                enabled: true,
                listen: "127.0.0.1:0".to_string(),
                advertise_addr: None,
                bootstrap_peers,
                max_saved_peers: DEFAULT_MAX_SAVED_PEERS,
                max_inbound_peers: P2P_UNTRUSTED_SESSION_LIMIT,
                discovery_servers: Vec::new(),
                relay_servers: Vec::new(),
                trusted_peer_keys: Vec::new(),
            },
            explorer: ExplorerSection::default(),
            discovery: ServiceSection {
                enabled: false,
                bind: "127.0.0.1:0".to_string(),
            },
            relay: ServiceSection {
                enabled: false,
                bind: "127.0.0.1:0".to_string(),
            },
        }
    }

    #[test]
    fn explorer_defaults_follow_storage_mode_and_allow_operator_opt_out() {
        let defaults = ExplorerSection::default();
        assert!(defaults.index_enabled(StorageMode::Archive));
        assert!(defaults.share_enabled(StorageMode::Archive));
        assert!(!defaults.index_enabled(StorageMode::Pruned));
        assert!(!defaults.share_enabled(StorageMode::Pruned));
        assert!(defaults.relay);

        let opt_out = ExplorerSection {
            index: Some(false),
            share: Some(false),
            relay: false,
        };
        assert!(!opt_out.index_enabled(StorageMode::Archive));
        assert!(!opt_out.share_enabled(StorageMode::Archive));
        assert!(!opt_out.relay);
    }

    #[test]
    fn generation_identity_rejects_a_generation_from_another_genesis() {
        let path = test_path("generation-identity-mismatch");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let NodeStorage::Full(storage) = &node_storage else {
            panic!("full storage");
        };
        let mut config = test_rpc_node_config(&path, Vec::new());
        config.node.expected_genesis_hash = Some(Hash256([0x42; 32]).to_hex());

        let error = validate_generation_identity(&config, storage)
            .expect_err("foreign generation must be rejected");
        assert!(error
            .to_string()
            .contains("does not match configured genesis"));

        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn generation_identity_accepts_the_configured_genesis() {
        let path = test_path("generation-identity-match");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let NodeStorage::Full(storage) = &node_storage else {
            panic!("full storage");
        };
        let mut config = test_rpc_node_config(&path, Vec::new());
        config.node.expected_genesis_hash = Some(
            storage
                .header_by_number(blq_primitives::BlockNumber(0))
                .expect("stored genesis")
                .hash()
                .to_hex(),
        );

        validate_generation_identity(&config, storage).expect("matching generation identity");

        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn corrupt_generation_falls_back_to_a_verified_complete_snapshot() {
        let path = test_path("snapshot-generation-fallback");
        let config = test_rpc_node_config(&path, Vec::new());
        let generations = path.join("generations");
        let generation_id = 1;
        let generation = SledStorage::generation_path(&generations, generation_id);
        let mut storage =
            NodeStorage::Full(SledStorage::open(&generation).expect("open generation"));
        initialize_genesis(&mut storage, NodeMode::Full).expect("genesis");
        let best = storage.best_header().expect("best header");
        let profile = consensus_profile_for_genesis(best.hash());
        let NodeStorage::Full(full) = &storage else {
            unreachable!();
        };
        full.create_snapshot(
            &generation,
            generation_id,
            0,
            best.hash(),
            profile.clone(),
            0,
        )
        .expect("snapshot");
        SledStorage::write_generation_manifest(
            &generation,
            &GenerationManifest {
                generation_id,
                status: GenerationStatus::Failed,
                canonical_height: 0,
                canonical_hash: best.hash(),
                state_root: best.state_root,
                profile_fingerprint: profile,
                finalized_height: 0,
                replay_checkpoint: Some(0),
            },
        )
        .expect("failed manifest");
        SledStorage::activate_generation(&generations, generation_id).expect("active generation");
        drop(storage);

        let restored = NodeStorage::open(&config).expect("restore from snapshot");
        assert_eq!(
            restored.best_header().expect("restored best").hash(),
            best.hash()
        );
        assert_eq!(
            SledStorage::load_active_generation(&generations).expect("active generation"),
            Some(2)
        );
        drop(restored);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn inbound_hello_requests_same_height_competing_tip_body() {
        let path = test_path("same-height-tip-reconciliation");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let remote_hash = Hash256([0xabu8; 32]);
        let hello = P2pMessage::Hello {
            node_mode: NodeMode::Full,
            best_number: 0,
            best_hash: remote_hash.to_hex(),
            consensus_profile: consensus_profile_for_genesis(genesis_header().hash()),
            identity_public_key: String::new(),
            identity_signature: String::new(),
            tls_certificate_hash: String::new(),
        };
        let mut output = Vec::new();
        reconcile_peer_tip(&mut output, &storage, &hello).expect("reconcile tip");
        let message: P2pMessage = serde_json::from_slice(
            output
                .split(|byte| *byte == b'\n')
                .next()
                .expect("request line"),
        )
        .expect("decode request");
        assert!(
            matches!(message, P2pMessage::GetBlockByHash { hash } if hash == remote_hash.to_hex())
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn peer_with_higher_tip_requests_exact_tip_body_for_branch_walk() {
        let path = test_path("higher-tip-reconciliation");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let remote_hash = Hash256([0xcdu8; 32]);
        let hello = P2pMessage::Hello {
            node_mode: NodeMode::Full,
            best_number: 2,
            best_hash: remote_hash.to_hex(),
            consensus_profile: consensus_profile_for_genesis(genesis_header().hash()),
            identity_public_key: String::new(),
            identity_signature: String::new(),
            tls_certificate_hash: String::new(),
        };
        let mut output = Vec::new();
        reconcile_peer_tip(&mut output, &storage, &hello).expect("reconcile tip");
        let message: P2pMessage = serde_json::from_slice(
            output
                .split(|byte| *byte == b'\n')
                .next()
                .expect("request line"),
        )
        .expect("decode request");
        assert!(
            matches!(message, P2pMessage::GetBlockByHash { hash } if hash == remote_hash.to_hex())
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn inbound_hello_does_not_compete_with_durable_forward_recovery() {
        let path = test_path("recovery-hello-does-not-request-tip");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let tip = Hash256([0xd1u8; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(
            tip,
            10,
            consensus_profile_for_genesis(genesis_header().hash()),
        );
        cursor.ancestor_height = Some(0);
        cursor.ancestor_hash = Some(genesis_header().hash());
        cursor.next_height = 1;
        cursor.expected_parent_hash = Some(genesis_header().hash());
        cursor.state = "retrieving".to_string();
        branch_sync_cursors()
            .lock()
            .expect("cursor mutex")
            .insert(key.clone(), cursor);
        let hello = P2pMessage::Hello {
            node_mode: NodeMode::Full,
            best_number: 10,
            best_hash: tip.to_hex(),
            consensus_profile: consensus_profile_for_genesis(genesis_header().hash()),
            identity_public_key: String::new(),
            identity_signature: String::new(),
            tls_certificate_hash: String::new(),
        };
        let mut output = Vec::new();
        reconcile_peer_tip(&mut output, &storage, &hello).expect("reconcile tip");
        assert!(output.is_empty());
        branch_sync_cursors()
            .lock()
            .expect("cursor mutex")
            .remove(&key);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn ethereum_block_tags_resolve_to_supported_tips() {
        assert_eq!(parse_block_tag("earliest", 42).expect("earliest"), 0);
        for tag in ["latest", "safe", "finalized", "pending"] {
            assert_eq!(parse_block_tag(tag, 42).expect("tip tag"), 42);
        }
        assert_eq!(parse_block_tag("0x2a", 42).expect("quantity"), 42);
        assert!(parse_block_tag("middle", 42).is_err());
    }

    #[test]
    fn read_only_rpc_policy_blocks_internal_submission_methods() {
        assert!(!rpc_method_allowed_by_policy(
            true,
            false,
            "blq_getBlockTemplate"
        ));
        assert!(!rpc_method_allowed_by_policy(
            true,
            false,
            "blq_submitBlock"
        ));
        assert!(!rpc_method_allowed_by_policy(
            true,
            false,
            "blq_sendTransaction"
        ));
        assert!(rpc_method_allowed_by_policy(
            true,
            false,
            "eth_sendRawTransaction"
        ));
        assert!(rpc_method_allowed_by_policy(
            false,
            false,
            "blq_submitBlock"
        ));
        assert!(rpc_method_allowed_by_policy(
            true,
            true,
            "blq_getBlockTemplate"
        ));
        assert!(rpc_method_allowed_by_policy(true, true, "blq_submitBlock"));
    }

    #[test]
    fn ethereum_filter_lifecycle_supports_log_and_block_polling() {
        let path = test_path("rpc-filters");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open filters"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let mempool = Arc::new(Mutex::new(Mempool::default()));
        let config = test_rpc_node_config(&path, Vec::new());
        let request = |id, method: &str, params: serde_json::Value| {
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": method, "params": params
            })
            .to_string();
            serde_json::from_str::<serde_json::Value>(&handle_json_rpc_request(
                &config, &storage, &mempool, &body,
            ))
            .expect("filter RPC response")
        };
        let log_filter = request(1, "eth_newFilter", serde_json::json!([{"topics": []}]));
        assert!(log_filter["result"].as_str().is_some());
        let log_id = log_filter["result"].as_str().expect("log filter id");
        let changes = request(2, "eth_getFilterChanges", serde_json::json!([log_id]));
        assert_eq!(changes["result"], serde_json::json!([]));
        let logs = request(3, "eth_getFilterLogs", serde_json::json!([log_id]));
        assert_eq!(logs["result"], serde_json::json!([]));
        assert_eq!(
            request(4, "eth_uninstallFilter", serde_json::json!([log_id]))["result"],
            true
        );

        let block_filter = request(5, "eth_newBlockFilter", serde_json::json!([]));
        let block_id = block_filter["result"].as_str().expect("block filter id");
        assert_eq!(
            request(6, "eth_getFilterChanges", serde_json::json!([block_id]))["result"],
            serde_json::json!([])
        );
        assert_eq!(
            request(7, "eth_uninstallFilter", serde_json::json!([block_id]))["result"],
            true
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn websocket_accept_matches_rfc6455_example() {
        let headers = "GET / HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert_eq!(
            websocket_accept(headers).expect("websocket accept"),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn native_http_health_accepts_only_the_root_get_request() {
        assert_eq!(
            http_request_method_and_path("GET / HTTP/1.1\r\nHost: node\r\n\r\n"),
            Some(("GET", "/"))
        );
        assert_eq!(
            http_request_method_and_path("POST / HTTP/1.1\r\nHost: node\r\n\r\n"),
            Some(("POST", "/"))
        );
        assert_eq!(http_request_method_and_path("broken"), None);
    }

    #[test]
    fn json_rpc_batches_dispatch_each_request_and_bound_batch_size() {
        let path = test_path("rpc-batch");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open RPC"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let mempool = Arc::new(Mutex::new(Mempool::default()));
        let config = test_rpc_node_config(&path, Vec::new());
        let body = serde_json::json!([
            {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
            {"jsonrpc": "2.0", "id": 2, "method": "eth_blockNumber", "params": []}
        ])
        .to_string();
        let response: serde_json::Value =
            serde_json::from_str(&handle_json_rpc_request(&config, &storage, &mempool, &body))
                .expect("batch response");
        assert_eq!(response.as_array().expect("response array").len(), 2);
        assert_eq!(response[0]["result"], "0xac9fe");
        assert_eq!(response[1]["result"], "0x0");

        let oversized = serde_json::Value::Array(vec![
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"});
            MAX_RPC_BATCH_REQUESTS + 1
        ]);
        let error: serde_json::Value = serde_json::from_str(&handle_json_rpc_request(
            &config,
            &storage,
            &mempool,
            &oversized.to_string(),
        ))
        .expect("batch limit response");
        assert_eq!(error["error"]["code"], -32600);

        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": []
        })
        .to_string();
        assert!(handle_json_rpc_request(&config, &storage, &mempool, &notification).is_empty());

        let mixed = serde_json::json!([
            {"jsonrpc": "2.0", "method": "eth_chainId", "params": []},
            {"jsonrpc": "2.0", "id": 9, "method": "eth_blockNumber", "params": []}
        ])
        .to_string();
        let mixed_response: serde_json::Value = serde_json::from_str(&handle_json_rpc_request(
            &config, &storage, &mempool, &mixed,
        ))
        .expect("mixed notification batch response");
        assert_eq!(
            mixed_response
                .as_array()
                .expect("mixed response array")
                .len(),
            1
        );
        assert_eq!(mixed_response[0]["id"], 9);
        assert_eq!(mixed_response[0]["result"], "0x0");

        let invalid_version = r#"{"jsonrpc":"1.0","id":3,"method":"eth_chainId"}"#;
        let invalid: serde_json::Value = serde_json::from_str(&handle_json_rpc_request(
            &config,
            &storage,
            &mempool,
            invalid_version,
        ))
        .expect("invalid version response");
        assert_eq!(invalid["id"], serde_json::Value::Null);
        assert_eq!(invalid["error"]["code"], -32600);

        let missing_method = r#"{"jsonrpc":"2.0","id":4}"#;
        let missing: serde_json::Value = serde_json::from_str(&handle_json_rpc_request(
            &config,
            &storage,
            &mempool,
            missing_method,
        ))
        .expect("missing method response");
        assert_eq!(missing["error"]["code"], -32600);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn node_info_exposes_identity_without_private_mining_data() {
        let path = test_path("node-info");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let config = test_rpc_node_config(&path, Vec::new());
        let value: serde_json::Value =
            serde_json::from_str(&rpc_node_info(serde_json::json!(1), &config, &storage))
                .expect("node info response");
        let result = &value["result"];
        assert_eq!(result["chainId"], 707070);
        assert!(result["consensusProfile"]
            .as_str()
            .expect("profile")
            .contains("pow=BLQ-RX/"));
        assert!(result.get("miningToken").is_none());
        assert!(result.get("privateKey").is_none());
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn historical_evm_state_reads_replay_earliest_state() {
        let path = test_path("evm-state-tags");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open state"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let config = test_rpc_node_config(&path, Vec::new());
        let current = serde_json::json!({
            "params": ["0x1111111111111111111111111111111111111111", "0x0"]
        });
        assert_eq!(
            resolve_state_block_tag(&storage, &current, 1).expect("current state"),
            None
        );
        let historical = serde_json::json!({
            "params": ["0x1111111111111111111111111111111111111111", "earliest"]
        });
        assert!(
            rpc_get_balance(serde_json::json!(1), &config, &storage, &historical)
                .contains("\"result\":\"0x0\"")
        );
        assert!(
            rpc_get_transaction_count(serde_json::json!(2), &config, &storage, &historical)
                .contains("\"result\":\"0x0\"")
        );
        assert!(
            rpc_get_code(serde_json::json!(3), &config, &storage, &historical)
                .contains("\"result\":\"0x\"")
        );
        let storage_request = serde_json::json!({
            "params": [
                "0x1111111111111111111111111111111111111111",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "earliest"
            ]
        });
        assert!(
            rpc_get_storage_at(serde_json::json!(4), &config, &storage, &storage_request).contains(
                "\"result\":\"0x0000000000000000000000000000000000000000000000000000000000000000\""
            )
        );
        let call_request = serde_json::json!({
            "params": [
                {
                    "to": "0x1111111111111111111111111111111111111111",
                    "data": "0x"
                },
                "earliest"
            ]
        });
        assert!(
            rpc_eth_call(serde_json::json!(5), &config, &storage, &call_request)
                .contains("\"result\":\"0x\"")
        );
        let estimate_request = serde_json::json!({
            "params": [
                {
                    "to": "0x1111111111111111111111111111111111111111",
                    "data": "0x"
                },
                "earliest"
            ]
        });
        assert!(
            rpc_estimate_gas(serde_json::json!(6), &config, &storage, &estimate_request)
                .contains("\"result\":\"0x5208\"")
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn ethereum_logs_support_block_hash_filters() {
        let path = test_path("logs-block-hash");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open logs"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let genesis_hash = genesis_header().hash().to_hex();
        let storage = Arc::new(Mutex::new(node_storage));
        let config = test_rpc_node_config(&path, Vec::new());
        let request = serde_json::json!({
            "params": [{"blockHash": format!("0x{genesis_hash}")}]
        });
        let response = rpc_get_logs(serde_json::json!(1), &config, &storage, &request);
        assert!(response.contains("\"result\":[]"));

        let invalid_request = serde_json::json!({
            "params": [{
                "blockHash": format!("0x{genesis_hash}"),
                "fromBlock": "0x0"
            }]
        });
        let response = rpc_get_logs(serde_json::json!(2), &config, &storage, &invalid_request);
        assert!(response.contains("cannot be combined"));
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn ethereum_block_position_and_receipt_queries_are_bounded() {
        let path = test_path("block-position-rpc");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open block rpc"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let config = test_rpc_node_config(&path, Vec::new());

        let by_number = serde_json::json!({
            "params": ["earliest", "0x0"]
        });
        assert!(rpc_get_transaction_by_block_number_and_index(
            serde_json::json!(1),
            &config,
            &storage,
            &by_number,
        )
        .contains("\"result\":null"));

        let genesis_hash = genesis_header().hash().to_hex();
        let by_hash = serde_json::json!({
            "params": [format!("0x{genesis_hash}"), "0x0"]
        });
        assert!(rpc_get_transaction_by_block_hash_and_index(
            serde_json::json!(2),
            &config,
            &storage,
            &by_hash,
        )
        .contains("\"result\":null"));

        let receipts = serde_json::json!({
            "params": ["earliest"]
        });
        assert!(
            rpc_get_block_receipts(serde_json::json!(3), &config, &storage, &receipts)
                .contains("\"result\":[]")
        );

        let receipts_by_hash = serde_json::json!({
            "params": [format!("0x{genesis_hash}")]
        });
        assert!(
            rpc_get_block_receipts(serde_json::json!(4), &config, &storage, &receipts_by_hash,)
                .contains("\"result\":[]")
        );
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn relay_requires_registration_before_forwarding() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind relay test");
        let address = listener.local_addr().expect("relay test address");
        let inboxes = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let server_inboxes = Arc::clone(&inboxes);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept relay test");
            handle_relay_connection(stream, server_inboxes)
        });
        let mut client = TcpStream::connect(address).expect("connect relay test");
        send_relay_message(
            &mut client,
            &RelayMessage::Send {
                target_id: "target".to_string(),
                payload: P2pMessage::NewHeader {
                    header: genesis_header(),
                },
                identity_public_key: String::new(),
                identity_signature: String::new(),
            },
        )
        .expect("send unauthenticated relay message");
        drop(client);
        assert!(server.join().expect("relay server").is_err());
        assert!(valid_relay_node_id("192.0.2.43:30334"));
        assert!(!valid_relay_node_id(""));
        assert!(!valid_relay_node_id(&"x".repeat(257)));
    }

    #[test]
    fn authenticated_relay_send_is_returned_to_registered_poller() {
        let sender_path = test_path("relay-round-trip-sender");
        let receiver_path = test_path("relay-round-trip-receiver");
        let sender = NodeIdentity::load_or_create(&sender_path).expect("create sender identity");
        let receiver =
            NodeIdentity::load_or_create(&receiver_path).expect("create receiver identity");
        let sender_id = "127.0.0.1:30334";
        let receiver_id = "127.0.0.1:30335";
        let sender_key = sender.public_key_hex();
        let receiver_key = receiver.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind relay round-trip");
        let address = listener.local_addr().expect("relay round-trip address");
        let inboxes = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let server_inboxes = Arc::clone(&inboxes);
        let server = thread::spawn(move || {
            let (receiver_stream, _) = listener.accept().expect("accept receiver");
            let receiver_inboxes = Arc::clone(&server_inboxes);
            let receiver_server =
                thread::spawn(move || handle_relay_connection(receiver_stream, receiver_inboxes));
            let (sender_stream, _) = listener.accept().expect("accept sender");
            let sender_result = handle_relay_connection(sender_stream, server_inboxes);
            (
                receiver_server.join().expect("receiver relay handler"),
                sender_result,
            )
        });

        let mut receiver_client = TcpStream::connect(address).expect("connect receiver");
        send_relay_message(
            &mut receiver_client,
            &RelayMessage::Register {
                node_id: receiver_id.to_string(),
                identity_public_key: receiver_key.clone(),
                identity_signature: receiver.sign(&service_auth_payload(
                    "BLQ-RELAY-REGISTER-v1",
                    &[receiver_id, &receiver_key],
                )),
            },
        )
        .expect("register receiver");
        for _ in 0..100 {
            if inboxes
                .lock()
                .expect("relay inboxes")
                .contains_key(receiver_id)
            {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(inboxes
            .lock()
            .expect("relay inboxes")
            .contains_key(receiver_id));

        send_relay_message(
            &mut receiver_client,
            &RelayMessage::Poll {
                node_id: receiver_id.to_string(),
                identity_public_key: receiver_key.clone(),
                identity_signature: receiver.sign(&service_auth_payload(
                    "BLQ-RELAY-POLL-v1",
                    &[receiver_id, &receiver_key],
                )),
            },
        )
        .expect("poll empty relay inbox");
        let mut empty_response = String::new();
        BufReader::new(receiver_client.try_clone().expect("clone receiver stream"))
            .read_line(&mut empty_response)
            .expect("read empty relay response");
        let RelayMessage::Messages { messages } =
            serde_json::from_str(empty_response.trim()).expect("decode empty relay response")
        else {
            panic!("empty relay response was not a message batch");
        };
        assert!(messages.is_empty());

        let mut sender_client = TcpStream::connect(address).expect("connect sender");
        send_relay_message(
            &mut sender_client,
            &RelayMessage::Register {
                node_id: sender_id.to_string(),
                identity_public_key: sender_key.clone(),
                identity_signature: sender.sign(&service_auth_payload(
                    "BLQ-RELAY-REGISTER-v1",
                    &[sender_id, &sender_key],
                )),
            },
        )
        .expect("register sender");
        let header = genesis_header();
        send_relay_message(
            &mut sender_client,
            &RelayMessage::Broadcast {
                payload: P2pMessage::NewHeader {
                    header: header.clone(),
                },
                identity_public_key: sender_key.clone(),
                identity_signature: sender.sign(&service_auth_payload(
                    "BLQ-RELAY-BROADCAST-v1",
                    &[sender_id, &sender_key],
                )),
            },
        )
        .expect("broadcast header through relay");
        sender_client
            .shutdown(Shutdown::Both)
            .expect("close sender relay stream");
        drop(sender_client);
        for _ in 0..100 {
            if inboxes
                .lock()
                .expect("relay inboxes")
                .get(receiver_id)
                .is_some_and(|messages| !messages.is_empty())
            {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            inboxes
                .lock()
                .expect("relay inboxes")
                .get(receiver_id)
                .map_or(0, Vec::len),
            1
        );

        send_relay_message(
            &mut receiver_client,
            &RelayMessage::Poll {
                node_id: receiver_id.to_string(),
                identity_public_key: receiver_key.clone(),
                identity_signature: receiver.sign(&service_auth_payload(
                    "BLQ-RELAY-POLL-v1",
                    &[receiver_id, &receiver_key],
                )),
            },
        )
        .expect("poll relay inbox");
        let mut response = String::new();
        BufReader::new(receiver_client.try_clone().expect("clone receiver stream"))
            .read_line(&mut response)
            .expect("read relay response");
        let RelayMessage::Messages { messages } =
            serde_json::from_str(response.trim()).expect("decode relay response")
        else {
            panic!("relay response was not a message batch");
        };
        assert_eq!(messages.len(), 1);
        match &messages[0] {
            P2pMessage::NewHeader { header: received } => assert_eq!(received, &header),
            _ => panic!("relay returned a non-header payload"),
        }
        drop(receiver_client);
        let (receiver_result, sender_result) = server.join().expect("relay round-trip server");
        assert!(receiver_result.is_ok());
        assert!(sender_result.is_ok());
        fs::remove_dir_all(sender_path).ok();
        fs::remove_dir_all(receiver_path).ok();
    }

    #[test]
    fn relay_accepts_new_block_or_header_notifications() {
        assert!(validate_relay_payload(&P2pMessage::NewHeader {
            header: genesis_header(),
        })
        .is_ok());
        assert!(validate_relay_payload(&P2pMessage::GetBlock { number: 1 }).is_err());
        assert!(validate_relay_payload(&P2pMessage::GetTransaction {
            hash: genesis_header().hash().to_hex(),
        })
        .is_err());
        assert!(validate_relay_payload(&P2pMessage::BlockBody {
            block: genesis_block(),
        })
        .is_ok());
        assert!(validate_relay_payload(&P2pMessage::NewTransaction {
            transaction: Transaction {
                chain_id: MAINNET_CHAIN_ID,
                transaction_type: 2,
                nonce: 0,
                from: Address::ZERO,
                to: Some(Address::ZERO),
                value: Bix(0),
                gas_limit: TRANSFER_GAS,
                max_fee_per_gas: Bix(1),
                max_priority_fee_per_gas: Bix(0),
                payload: Vec::new(),
                access_list: Vec::new(),
                signature: None,
                external_hash: None,
            },
        })
        .is_err());
    }

    #[test]
    fn direct_transaction_gossip_revalidates_and_deduplicates() {
        let path = test_path("transaction-gossip");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open gossip"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let secret = SecretKey::from_byte_array([7u8; 32]).expect("secret");
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let public_key_hash = keccak256(&public_key.serialize_uncompressed()[1..]);
        let sender = Address(public_key_hash.0[12..].try_into().expect("address"));
        if let NodeStorage::Full(storage) = &node_storage {
            storage
                .put_account(sender, Bix(1_000_000_000_000_000_000), 0)
                .expect("fund sender");
        }
        let storage = Arc::new(Mutex::new(node_storage));
        let mempool = Arc::new(Mutex::new(Mempool::default()));
        let config = test_rpc_node_config(&path, Vec::new());
        let mut transaction = Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: sender,
            to: Some(Address([0x22; 20])),
            value: Bix(0),
            gas_limit: TRANSFER_GAS,
            max_fee_per_gas: Bix(1_000_000_000),
            max_priority_fee_per_gas: Bix(0),
            payload: Vec::new(),
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        };
        let (r, s, y_parity) = test_signature(
            &secret,
            &transaction_signing_payload(&transaction).expect("signing payload"),
        );
        transaction.signature = Some(TransactionSignature {
            y_parity,
            r: Hash256(r.try_into().expect("r")),
            s: Hash256(s.try_into().expect("s")),
        });
        transaction.external_hash = Some(Hash256(
            keccak256(transaction_signed_bytes(&transaction).expect("wire bytes")).0,
        ));
        let raw = format!(
            "0x{}",
            hex::encode(transaction_signed_bytes(&transaction).expect("wire bytes"))
        );
        let decoded = decode_raw_transaction(&raw).expect("decode primitive EIP-1559 wire bytes");
        assert_eq!(decoded.from, sender);
        assert_eq!(decoded.nonce, 0);
        assert_eq!(decoded.external_hash, transaction.external_hash);
        let mut forged = transaction.clone();
        forged.from = Address([0x44; 20]);
        let mut output = Vec::new();
        assert!(handle_p2p_message(
            &mut output,
            &config,
            &storage,
            &mempool,
            P2pMessage::NewTransaction {
                transaction: forged
            },
            None,
        )
        .is_err());
        handle_p2p_message(
            &mut output,
            &config,
            &storage,
            &mempool,
            P2pMessage::NewTransaction {
                transaction: transaction.clone(),
            },
            None,
        )
        .expect("gossip transaction accepted");
        handle_p2p_message(
            &mut output,
            &config,
            &storage,
            &mempool,
            P2pMessage::NewTransaction { transaction },
            None,
        )
        .expect("duplicate gossip transaction accepted");
        assert_eq!(mempool.lock().expect("mempool").pending().len(), 1);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn block_transaction_auth_rejects_unsigned_evm_payloads() {
        let transaction = Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: Address([0x11; 20]),
            to: None,
            value: Bix(0),
            gas_limit: 100_000,
            max_fee_per_gas: Bix(1_000_000_000),
            max_priority_fee_per_gas: Bix(0),
            payload: vec![0x60, 0x00],
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        };
        let block = Block {
            header: genesis_header(),
            transactions: vec![transaction],
            receipts: Vec::new(),
        };
        assert!(validate_block_transaction_auth(true, &block).is_err());
    }

    #[test]
    fn optional_service_identity_auth_binds_domain_and_fields() {
        let path = test_path("service-auth");
        let identity = NodeIdentity::load_or_create(&path).expect("create service identity");
        let public_key = identity.public_key_hex();
        let signature = identity.sign(&service_auth_payload(
            "BLQ-RELAY-REGISTER-v1",
            &["192.0.2.43:30334", &public_key],
        ));
        verify_service_identity(
            "BLQ-RELAY-REGISTER-v1",
            &["192.0.2.43:30334", &public_key],
            &public_key,
            &signature,
        )
        .expect("valid service signature");
        assert!(verify_service_identity(
            "BLQ-RELAY-SEND-v1",
            &["192.0.2.43:30334", "target", &public_key],
            &public_key,
            &signature,
        )
        .is_err());
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn discovery_rejects_non_socket_peer_records() {
        let peer = PeerRecord {
            address: "not-a-socket".to_string(),
            route_class: "unknown".to_string(),
            direct: false,
            relay: false,
            last_success_epoch: 0,
            last_failure_epoch: None,
            expires_at_epoch: 0,
            alternate_addresses: Vec::new(),
            identity_public_key: None,
            consensus_profile: String::new(),
            chain_id: 0,
            genesis_hash: String::new(),
            protocol_version: String::new(),
            node_mode: NodeMode::Full,
            best_number: 1,
            best_hash: genesis_header().hash().to_hex(),
            storage_mode: StorageMode::Archive,
            retained_from_height: 0,
            retained_to_height: 1,
            snapshot_heights: Vec::new(),
            explorer_index: false,
            explorer_share: false,
            explorer_relay: true,
        };
        assert!(validate_peer_record(&peer).is_err());
        let peer = PeerRecord {
            address: "192.0.2.43:30334".to_string(),
            route_class: "local".to_string(),
            direct: true,
            relay: false,
            last_success_epoch: 0,
            last_failure_epoch: None,
            expires_at_epoch: 0,
            alternate_addresses: Vec::new(),
            identity_public_key: None,
            consensus_profile: String::new(),
            chain_id: 0,
            genesis_hash: String::new(),
            protocol_version: String::new(),
            node_mode: NodeMode::Full,
            best_number: 1,
            best_hash: "bad".to_string(),
            storage_mode: StorageMode::Archive,
            retained_from_height: 0,
            retained_to_height: 1,
            snapshot_heights: Vec::new(),
            explorer_index: false,
            explorer_share: false,
            explorer_relay: true,
        };
        assert!(validate_peer_record(&peer).is_err());
    }

    #[test]
    fn signed_discovery_register_round_trips_through_json() {
        let path = test_path("discovery-auth-round-trip");
        let identity = NodeIdentity::load_or_create(&path).expect("create identity");
        let public_key = identity.public_key_hex();
        let peer = PeerRecord {
            address: "127.0.0.1:30334".to_string(),
            route_class: "local".to_string(),
            direct: true,
            relay: false,
            last_success_epoch: 0,
            last_failure_epoch: None,
            expires_at_epoch: 0,
            alternate_addresses: Vec::new(),
            identity_public_key: None,
            consensus_profile: String::new(),
            chain_id: 0,
            genesis_hash: String::new(),
            protocol_version: String::new(),
            node_mode: NodeMode::Full,
            best_number: 1,
            best_hash: genesis_header().hash().to_hex(),
            storage_mode: StorageMode::Archive,
            retained_from_height: 0,
            retained_to_height: 1,
            snapshot_heights: Vec::new(),
            explorer_index: false,
            explorer_share: false,
            explorer_relay: true,
        };
        let signature = identity.sign(&service_auth_payload(
            "BLQ-DISCOVERY-REGISTER-v1",
            &[
                &peer.address,
                peer.node_mode.as_str(),
                &peer.best_number.to_string(),
                &peer.best_hash,
                &format!("{:?}", peer.storage_mode),
                &peer.retained_from_height.to_string(),
                &peer.retained_to_height.to_string(),
                &public_key,
            ],
        ));
        let encoded = serde_json::to_string(&DiscoveryMessage::Register {
            peer,
            identity_public_key: public_key,
            identity_signature: signature,
        })
        .expect("encode discovery message");
        let decoded: DiscoveryMessage = serde_json::from_str(&encoded).expect("decode message");
        let DiscoveryMessage::Register {
            peer,
            identity_public_key,
            identity_signature,
        } = decoded
        else {
            panic!("unexpected discovery message");
        };
        validate_peer_record(&peer).expect("valid peer record");
        verify_service_identity(
            "BLQ-DISCOVERY-REGISTER-v1",
            &[
                &peer.address,
                peer.node_mode.as_str(),
                &peer.best_number.to_string(),
                &peer.best_hash,
                &format!("{:?}", peer.storage_mode),
                &peer.retained_from_height.to_string(),
                &peer.retained_to_height.to_string(),
                &identity_public_key,
            ],
            &identity_public_key,
            &identity_signature,
        )
        .expect("round-trip signature");
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn discovery_client_registration_is_accepted_by_service_handler() {
        let path = test_path("discovery-client-auth");
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind discovery test");
        let address = listener.local_addr().expect("discovery address");
        let peers = Arc::new(Mutex::new(Vec::new()));
        let server_peers = Arc::clone(&peers);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept discovery test");
            handle_discovery_connection(stream, server_peers)
        });
        let mut config = test_rpc_node_config(&path, Vec::new());
        config.network.advertise_addr = Some("127.0.0.1:30334".to_string());
        config.network.discovery_servers = vec![address.to_string()];
        register_with_discovery_servers(&config, &storage).expect("register discovery peer");
        assert!(server.join().expect("discovery server").is_ok());
        assert_eq!(peers.lock().expect("peer registry").len(), 1);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn raw_transaction_decoder_accepts_legacy_and_access_list_types() {
        let secret = SecretKey::from_byte_array([3; 32]).expect("test secret");
        let signer = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let signer_hash = keccak256(&signer.serialize_uncompressed()[1..]);
        let expected_from = Address(signer_hash.0[12..].try_into().expect("address bytes"));
        let chain_id = 707_070u64;
        let common = vec![
            rlp_encode_u64(0),
            rlp_encode_u64(2),
            rlp_encode_u64(21_000),
            rlp_encode_bytes(&[0x22; 20]),
            rlp_encode_u64(1),
            rlp_encode_bytes(&[]),
        ];
        let mut legacy_signing = common.clone();
        legacy_signing.push(rlp_encode_u64(chain_id));
        legacy_signing.push(rlp_encode_bytes(&[]));
        legacy_signing.push(rlp_encode_bytes(&[]));
        let (r, s, parity) = test_signature(&secret, &encode_rlp_list(&legacy_signing));
        let mut legacy = common;
        legacy.push(rlp_encode_u64(chain_id * 2 + 35 + parity as u64));
        legacy.push(rlp_encode_bytes(&r));
        legacy.push(rlp_encode_bytes(&s));
        let legacy = format!("0x{}", hex::encode(encode_rlp_list(&legacy)));
        let decoded_legacy = decode_raw_transaction(&legacy).expect("decode legacy");
        assert_eq!(decoded_legacy.from, expected_from);
        assert_eq!(decoded_legacy.chain_id, chain_id);
        assert_eq!(decoded_legacy.transaction_type, 0);
        assert_eq!(decoded_legacy.max_priority_fee_per_gas, Bix(0));

        let mut access_signing = vec![
            rlp_encode_u64(chain_id),
            rlp_encode_u64(0),
            rlp_encode_u64(2),
            rlp_encode_u64(21_000),
            rlp_encode_bytes(&[0x22; 20]),
            rlp_encode_u64(1),
            rlp_encode_bytes(&[]),
            rlp_encode_list_payload(&[]),
        ];
        let (r, s, parity) =
            test_signature(&secret, &encode_typed_rlp(0x01, &access_signing.concat()));
        access_signing.push(rlp_encode_u64(parity as u64));
        access_signing.push(rlp_encode_bytes(&r));
        access_signing.push(rlp_encode_bytes(&s));
        let access = format!(
            "0x{}",
            hex::encode(encode_typed_rlp(0x01, &access_signing.concat()))
        );
        let decoded_access = decode_raw_transaction(&access).expect("decode access-list");
        assert_eq!(decoded_access.from, expected_from);
        assert_eq!(decoded_access.chain_id, chain_id);
        assert_eq!(decoded_access.transaction_type, 1);
        assert_eq!(decoded_access.max_fee_per_gas, Bix(2));

        let access_entry = rlp_encode_list_payload(
            &[
                rlp_encode_bytes(&[0x33; 20]),
                rlp_encode_list_payload(&rlp_encode_bytes(&[0x44; 32])),
            ]
            .concat(),
        );
        let access_list = rlp_encode_list_payload(&access_entry);
        let mut dynamic_signing = vec![
            rlp_encode_u64(chain_id),
            rlp_encode_u64(1),
            rlp_encode_u64(1),
            rlp_encode_u64(3),
            rlp_encode_u64(50_000),
            rlp_encode_bytes(&[0x22; 20]),
            rlp_encode_u64(0),
            rlp_encode_bytes(&[0xaa, 0xbb]),
            access_list,
        ];
        let (r, s, parity) =
            test_signature(&secret, &encode_typed_rlp(0x02, &dynamic_signing.concat()));
        dynamic_signing.push(rlp_encode_u64(parity as u64));
        dynamic_signing.push(rlp_encode_bytes(&r));
        dynamic_signing.push(rlp_encode_bytes(&s));
        let dynamic = format!(
            "0x{}",
            hex::encode(encode_typed_rlp(0x02, &dynamic_signing.concat()))
        );
        let decoded_dynamic = decode_raw_transaction(&dynamic).expect("decode EIP-1559");
        assert_eq!(decoded_dynamic.transaction_type, 2);
        assert_eq!(decoded_dynamic.access_list.len(), 1);
        assert_eq!(
            decoded_dynamic.access_list[0].storage_keys,
            vec![Hash256([0x44; 32])]
        );
    }

    #[test]
    fn plain_transfer_accepts_wallet_gas_limit_above_intrinsic() {
        let transaction = Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            value: Bix(0),
            gas_limit: TRANSFER_GAS + 6_300,
            max_fee_per_gas: Bix(1),
            max_priority_fee_per_gas: Bix(0),
            payload: Vec::new(),
            access_list: Vec::new(),
            signature: Some(TransactionSignature {
                y_parity: false,
                r: Hash256::ZERO,
                s: Hash256::ZERO,
            }),
            external_hash: None,
        };
        assert!(validate_transfer_transaction_shape(&transaction).is_ok());
    }

    #[test]
    fn transaction_gossip_state_lag_does_not_penalize_peer() {
        let nonce_error = anyhow::anyhow!("invalid nonce for 0x01: expected 4, got 3");
        let balance_error = anyhow::anyhow!("account 0x01 has insufficient balance");
        let signature_error = anyhow::anyhow!("transaction gossip signature is invalid");
        let backpressure_error = anyhow::anyhow!("peer exceeded per-connection body request limit");
        assert!(!should_penalize_p2p_error(true, &nonce_error));
        assert!(!should_penalize_p2p_error(true, &balance_error));
        assert!(should_penalize_p2p_error(true, &signature_error));
        assert!(should_penalize_p2p_error(false, &nonce_error));
        assert!(!should_penalize_p2p_error(false, &backpressure_error));
    }

    #[test]
    fn trusted_peer_quorum_ignores_lagging_peers_but_blocks_conflicts() {
        let mut local = genesis_header();
        local.number.0 = 1;
        let mut config =
            test_rpc_node_config(std::path::Path::new("target/quorum-test"), Vec::new());
        let profile = network_consensus_profile(&config, local.hash());
        let keys = [
            "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ];
        for (index, key) in keys.iter().enumerate() {
            record_peer_tip(
                key,
                local.number.0,
                &local.hash().to_hex(),
                if index == 2 {
                    "incompatible-profile"
                } else {
                    &profile
                },
            );
        }
        config.network.trusted_peer_keys = keys.iter().map(|key| (*key).to_string()).collect();
        let (safe, available, matching) = trusted_peer_quorum(&config, &local, local.hash());
        assert!(safe);
        assert_eq!((available, matching), (3, 2));

        let lagging = local.number.0.saturating_sub(1);
        record_peer_tip(keys[2], lagging, &local.hash().to_hex(), &profile);
        let (safe, available, matching) = trusted_peer_quorum(&config, &local, local.hash());
        assert!(safe);
        assert_eq!((available, matching), (3, 2));

        record_peer_tip(keys[0], lagging, &local.hash().to_hex(), &profile);
        record_peer_tip(keys[1], lagging, &local.hash().to_hex(), &profile);
        let (safe, available, matching) = trusted_peer_quorum(&config, &local, local.hash());
        assert!(safe);
        assert_eq!((available, matching), (3, 0));

        let conflicting = Hash256([0xabu8; 32]);
        record_peer_tip(keys[2], local.number.0, &conflicting.to_hex(), &profile);
        let (safe, available, matching) = trusted_peer_quorum(&config, &local, local.hash());
        assert!(safe);
        assert_eq!((available, matching), (3, 0));
    }

    #[test]
    fn trusted_peer_quorum_allows_mining_without_peer_reports() {
        let mut local = genesis_header();
        local.number.0 = 7;
        let keys = [
            "02dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ];
        let mut config =
            test_rpc_node_config(std::path::Path::new("target/quorum-empty-test"), Vec::new());
        config.network.trusted_peer_keys = keys.iter().map(|key| (*key).to_string()).collect();

        let (safe, available, matching) = trusted_peer_quorum(&config, &local, local.hash());
        assert!(safe);
        assert_eq!((available, matching), (0, 0));
    }

    #[test]
    fn raw_signature_policy_rejects_high_s_malleability() {
        let r = B256::from([1u8; 32]);
        let low_s = B256::from({
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        });
        let high_s = B256::from([0xffu8; 32]);
        assert!(
            reject_high_s_signature(&EthSignature::from_scalars_and_parity(r, low_s, false))
                .is_ok()
        );
        assert!(
            reject_high_s_signature(&EthSignature::from_scalars_and_parity(r, high_s, false))
                .is_err()
        );
    }

    #[test]
    fn rlp_single_byte_strings_use_canonical_encoding() {
        assert_eq!(super::rlp_encode_bytes(&[0x01]), vec![0x01]);
        assert_eq!(super::rlp_encode_bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(super::rlp_encode_bytes(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn short_lived_socket_guard_releases_the_session_counter() {
        let _test_lock = SOCKET_COUNTER_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("socket counter test mutex poisoned");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind socket test listener");
        let address = listener.local_addr().expect("socket test address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept socket test client");
            let mut byte = [0u8; 1];
            stream.read(&mut byte).expect("read shutdown EOF");
        });
        let stream = connect_tcp_session(&address.to_string()).expect("open short lived session");
        let before = ACTIVE_P2P_SESSIONS.load(Ordering::Acquire);
        {
            let _guard = SocketShutdownGuard::new(&stream).expect("guard stream");
            assert_eq!(ACTIVE_P2P_SESSIONS.load(Ordering::Acquire), before + 1);
        }
        assert_eq!(ACTIVE_P2P_SESSIONS.load(Ordering::Acquire), before);
        drop(stream);
        server.join().expect("socket test server");
    }

    #[test]
    fn rpc_socket_guard_does_not_consume_a_p2p_session() {
        let _test_lock = SOCKET_COUNTER_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("socket counter test mutex poisoned");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc test listener");
        let address = listener.local_addr().expect("rpc test address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept rpc client");
            let mut byte = [0u8; 1];
            stream.read(&mut byte).expect("read rpc shutdown EOF");
        });
        let stream = connect_tcp_session(&address.to_string()).expect("open rpc session");
        let before = ACTIVE_P2P_SESSIONS.load(Ordering::Acquire);
        drop(RpcSocketShutdownGuard::new(&stream).expect("guard rpc stream"));
        assert_eq!(ACTIVE_P2P_SESSIONS.load(Ordering::Acquire), before);
        drop(stream);
        server.join().expect("rpc test server");
    }

    #[test]
    fn rpc_connection_guard_has_a_separate_bounded_counter() {
        let _test_lock = SOCKET_COUNTER_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("socket counter test mutex poisoned");
        let active = Arc::new(AtomicUsize::new(1));
        let before_rpc = ACTIVE_RPC_CONNECTIONS.load(Ordering::Acquire);
        let before_p2p = ACTIVE_P2P_SESSIONS.load(Ordering::Acquire);
        {
            let _guard = RpcConnectionGuard::new(Arc::clone(&active));
            assert_eq!(
                ACTIVE_RPC_CONNECTIONS.load(Ordering::Acquire),
                before_rpc + 1
            );
            assert_eq!(ACTIVE_P2P_SESSIONS.load(Ordering::Acquire), before_p2p);
        }
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(ACTIVE_RPC_CONNECTIONS.load(Ordering::Acquire), before_rpc);
    }

    #[test]
    fn p2p_status_exposes_rpc_handler_pressure() {
        let status = p2p_session_status();
        assert!(status.get("activeRpcConnections").is_some());
        assert!(status.get("closingRpcConnections").is_some());
        assert!(status.get("closedRpcConnections").is_some());
        assert!(status.get("lastP2pHandlerError").is_some());
        assert!(status.get("lastRpcHandlerError").is_some());
    }

    #[test]
    fn default_rpc_connection_limit_preserves_p2p_headroom() {
        assert_eq!(default_rpc_connections(), 64);
        assert!(default_rpc_connections() > P2P_SESSION_LIMIT);
        assert!(default_rpc_connections() < 128);
    }

    #[test]
    fn websocket_idle_deadline_expires_abandoned_subscriptions() {
        assert!(websocket_is_idle(
            Instant::now() - RPC_WEBSOCKET_IDLE_TIMEOUT
        ));
        assert!(!websocket_is_idle(Instant::now()));
    }

    #[test]
    fn sync_identity_lease_prevents_duplicate_peer_sessions() {
        let identity = format!("sync-lease-test-{}", unix_now());
        let first = SyncIdentityLease::acquire(&identity).expect("first lease");
        assert!(SyncIdentityLease::acquire(&identity).is_none());
        drop(first);
        assert!(SyncIdentityLease::acquire(&identity).is_some());
    }

    #[test]
    fn known_duplicate_peer_address_skips_a_second_sync_connection() {
        let identity = format!("known-peer-identity-{}", unix_now());
        let peer = format!("known-peer-address-{}", unix_now());
        known_peer_identities()
            .lock()
            .expect("known peers")
            .insert(peer.clone(), identity.clone());
        let lease = SyncIdentityLease::acquire(&identity).expect("identity lease");
        assert!(sync_peer_identity_is_active(&peer));
        drop(lease);
        assert!(!sync_peer_identity_is_active(&peer));
        known_peer_identities()
            .lock()
            .expect("known peers")
            .remove(&peer);
    }

    #[test]
    fn branch_sync_cursor_resumes_from_the_missing_parent() {
        let path = test_path("branch-sync-cursor");
        fs::create_dir_all(&path).expect("cursor test data directory");
        let config = test_rpc_node_config(&path, Vec::new());
        let peer = format!("cursor-test-{}", unix_now());
        let tip = Hash256([0xa1; 32]);
        let parent = Hash256([0xb2; 32]);
        clear_branch_sync_cursor(&config, &peer);
        branch_sync_cursors().lock().expect("branch cursor").insert(
            peer.clone(),
            new_branch_sync_cursor(tip, 42, "BLQ-RX/2".to_string()),
        );
        advance_branch_sync_cursor(&config, &peer, parent);
        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursor")
            .get(&peer)
            .cloned()
            .expect("cursor");
        assert_eq!(cursor.tip_hash, tip);
        assert_eq!(cursor.next_hash, parent);
        clear_branch_sync_cursor(&config, &peer);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn matching_peer_tips_share_one_recovery_cursor_key() {
        let tip = Hash256([0x55; 32]);
        let first = format!("recovery-peer-a-{}", unix_now());
        let second = format!("recovery-peer-b-{}", unix_now());
        set_peer_recovery_key(&first, tip);
        set_peer_recovery_key(&second, tip);
        assert_eq!(cursor_key(&first), cursor_key(&second));
        assert_eq!(cursor_key(&first), recovery_cursor_key(tip));
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&first);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&second);
    }

    #[test]
    fn recovery_range_ignores_sideband_gossip_messages() {
        assert!(is_recovery_sideband_message(&P2pMessage::BlockNotFound {
            hash: "11".repeat(32),
        }));
        assert!(is_recovery_sideband_message(&P2pMessage::NewHeader {
            header: genesis_header(),
        }));
        assert!(!is_recovery_sideband_message(&P2pMessage::BlockBody {
            block: genesis_block(),
        }));
    }

    #[test]
    fn advancing_provider_tip_retargets_the_existing_recovery_job() {
        let peer = format!("moving-tip-peer-{}", unix_now());
        let identity = format!("moving-tip-identity-{}", unix_now());
        let old_tip = Hash256([0xa4; 32]);
        let new_tip = Hash256([0xa5; 32]);
        let ancestor = Hash256([0xa3; 32]);
        let old_key = recovery_cursor_key(old_tip);
        let incoming_key = recovery_cursor_key(new_tip);
        let mut established = new_branch_sync_cursor(old_tip, 7_000, "BLQ-RX/2".to_string());
        established.ancestor_height = Some(2_600);
        established.ancestor_hash = Some(ancestor);
        established.next_height = 4_201;
        established.staged_height = 4_200;
        established.expected_parent_hash = Some(Hash256([0xa2; 32]));
        established.imported_bodies = 1_600;
        established.primary_identity = Some(identity.clone());
        let mut incoming = new_branch_sync_cursor(new_tip, 7_001, "BLQ-RX/2".to_string());
        incoming.ancestor_height = Some(2_600);
        incoming.ancestor_hash = Some(ancestor);
        incoming.next_height = 2_601;
        incoming.staged_height = 2_600;
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .extend([
                (old_key.clone(), established),
                (incoming_key.clone(), incoming),
            ]);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .insert(peer.clone(), incoming_key);

        let key = coalesce_advancing_recovery_job(
            &peer, &identity, new_tip, 7_001, "BLQ-RX/2", 2_600, ancestor, None,
        );
        assert_eq!(key, recovery_cursor_key(new_tip));
        let cursors = branch_sync_cursors().lock().expect("branch cursors");
        assert!(!cursors.contains_key(&old_key));
        let job = cursors.get(&key).expect("retargeted job");
        assert_eq!(job.tip_hash, new_tip);
        assert_eq!(job.tip_height, 7_001);
        assert_eq!(cursor_spool_tip(job), old_tip);
        assert_eq!(job.next_height, 4_201);
        assert_eq!(job.staged_height, 4_200);
        drop(cursors);
        assert_eq!(
            forward_recovery_context(&peer).map(|context| context.0),
            Some(old_tip),
            "new bodies must stay in the original durable spool after a moving-tip retarget"
        );
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&peer);
    }

    #[test]
    fn matching_branch_root_coalesces_independent_provider_routes() {
        let peer = format!("cross-route-peer-{}", unix_now());
        let first_tip = Hash256([0xb4; 32]);
        let second_tip = Hash256([0xb5; 32]);
        let ancestor = Hash256([0xb3; 32]);
        let branch_root = Hash256([0xb2; 32]);
        let first_key = recovery_cursor_key(first_tip);
        let second_key = recovery_cursor_key(second_tip);
        let mut primary = new_branch_sync_cursor(first_tip, 7_000, "BLQ-RX/2".to_string());
        primary.ancestor_height = Some(2_600);
        primary.ancestor_hash = Some(ancestor);
        primary.branch_root_hash = Some(branch_root);
        primary.next_height = 4_201;
        primary.staged_height = 4_200;
        primary.primary_identity = Some("provider-a".to_string());
        let mut incoming = new_branch_sync_cursor(second_tip, 7_001, "BLQ-RX/2".to_string());
        incoming.ancestor_height = Some(2_600);
        incoming.ancestor_hash = Some(ancestor);
        incoming.branch_root_hash = Some(branch_root);
        incoming.next_height = 2_602;
        incoming.staged_height = 2_601;
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .extend([(first_key.clone(), primary), (second_key.clone(), incoming)]);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .insert(peer.clone(), second_key);

        assert!(coalesce_recovery_job_after_branch_root(&peer, "provider-b"));
        let key = recovery_cursor_key(second_tip);
        let cursors = branch_sync_cursors().lock().expect("branch cursors");
        assert!(!cursors.contains_key(&first_key));
        let job = cursors.get(&key).expect("coalesced job");
        assert_eq!(job.branch_root_hash, Some(branch_root));
        assert_eq!(job.staged_height, 4_200);
        drop(cursors);
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&peer);
    }

    #[test]
    fn forward_recovery_resume_uses_the_persisted_next_height() {
        let peer = format!("forward-resume-peer-{}", unix_now());
        let tip = Hash256([0x73; 32]);
        let parent = Hash256([0x74; 32]);
        let key = recovery_cursor_key(tip);
        set_peer_recovery_key(&peer, tip);
        let mut cursor = new_branch_sync_cursor(tip, 7_581, "BLQ-RX/2".to_string());
        cursor.imported_bodies = 728;
        cursor.ancestor_height = Some(5_393);
        cursor.ancestor_hash = Some(Hash256([0x72; 32]));
        cursor.staged_height = 6_121;
        cursor.next_height = 6_122;
        cursor.expected_parent_hash = Some(parent);
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        assert_eq!(branch_cursor_next_height(&peer), Some(6_122));
        assert_eq!(forward_recovery_context(&peer), Some((tip, 6_122, parent)));

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&peer);
    }

    #[test]
    fn incomplete_recovery_spool_rewinds_to_the_proven_ancestor() {
        let path = test_path("recovery-spool-rewind");
        let config = test_rpc_node_config(&path, Vec::new());
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let peer = format!("recovery-spool-peer-{}", unix_now());
        let tip = Hash256([0x75; 32]);
        let key = recovery_cursor_key(tip);
        set_peer_recovery_key(&peer, tip);
        let mut cursor = new_branch_sync_cursor(tip, 10, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(0);
        cursor.ancestor_hash = Some(genesis_header().hash());
        cursor.imported_bodies = 1;
        cursor.staged_height = 1;
        cursor.next_height = 2;
        cursor.expected_parent_hash = Some(Hash256([0x76; 32]));
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        reconcile_forward_recovery_spool(&config, &storage, &peer).expect("spool repair");
        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .get(&key)
            .cloned()
            .expect("cursor");
        assert_eq!(cursor.next_height, 1);
        assert_eq!(cursor.staged_height, 0);
        assert_eq!(cursor.imported_bodies, 0);
        assert_eq!(cursor.expected_parent_hash, Some(genesis_header().hash()));
        assert!(cursor.spool_verified);

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&peer);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn alternate_moving_tip_waits_for_the_active_recovery_provider() {
        let active_tip = Hash256([0x41; 32]);
        let alternate_tip = Hash256([0x42; 32]);

        assert!(recovery_provider_is_deferred(
            active_tip,
            alternate_tip,
            false
        ));
        assert!(!recovery_provider_is_deferred(
            active_tip, active_tip, false
        ));
        assert!(!recovery_provider_is_deferred(
            active_tip,
            alternate_tip,
            true
        ));
    }

    #[test]
    fn replaying_recovery_tip_remains_admitted_to_only_one_replay() {
        let tip = Hash256([0x7a; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 10, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(0);
        cursor.staged_height = 10;
        cursor.next_height = 11;
        cursor.state = "replaying".to_string();
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        assert_eq!(completed_recovery_tip(), None);
        assert!(recovery_tip_is_replaying(tip));

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
    }

    #[test]
    fn rejected_recovery_tip_does_not_block_forward_sync() {
        let tip = Hash256([0x7b; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 10, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(0);
        cursor.staged_height = 10;
        cursor.next_height = 11;
        cursor.state = "rejected".to_string();
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        assert_eq!(completed_recovery_tip(), None);

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
    }

    #[test]
    fn spool_reconciliation_advances_an_obsolete_target_to_its_validated_tip() {
        let path = test_path("recovery-spool-advance-target");
        let config = test_rpc_node_config(&path, Vec::new());
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let peer = format!("recovery-spool-advance-peer-{}", unix_now());
        let stale_tip = Hash256([0x76; 32]);
        let stale_key = recovery_cursor_key(stale_tip);
        let parent = storage
            .lock()
            .expect("storage")
            .best_header()
            .expect("parent");
        let block = {
            let guard = storage.lock().expect("storage");
            build_test_block(&guard, &parent, Hash256([0x77; 32]))
        };
        let block_hash = block.header.hash();
        storage
            .lock()
            .expect("storage")
            .store_recovery_spool_block(stale_tip, &block, 1)
            .expect("store spool body");

        let mut cursor = new_branch_sync_cursor(stale_tip, 0, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(0);
        cursor.ancestor_hash = Some(parent.hash());
        cursor.next_height = 2;
        cursor.staged_height = 1;
        cursor.expected_parent_hash = Some(block_hash);
        cursor.imported_bodies = 1;
        cursor.spool_verified = true;
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(stale_key.clone(), cursor);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .insert(peer.clone(), stale_key.clone());

        reconcile_forward_recovery_spool(&config, &storage, &peer).expect("spool reconcile");

        let advanced_key = recovery_cursor_key(block_hash);
        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .get(&advanced_key)
            .cloned()
            .expect("advanced cursor");
        assert_eq!(cursor.tip_hash, block_hash);
        assert_eq!(cursor.tip_height, 1);
        assert_eq!(cursor.staged_height, 1);
        assert_eq!(cursor.next_height, 2);
        assert_eq!(cursor.state, "complete");
        assert_eq!(cursor_spool_tip(&cursor), stale_tip);
        assert!(!branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .contains_key(&stale_key));
        assert_eq!(cursor_key(&peer), advanced_key);

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&advanced_key);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&peer);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn startup_restores_a_complete_cursor_from_an_orphaned_recovery_spool() {
        let path = test_path("restore-orphaned-recovery-spool");
        let config = test_rpc_node_config(&path, Vec::new());
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let spool_tip = Hash256([0x78; 32]);
        let parent = storage
            .lock()
            .expect("storage")
            .best_header()
            .expect("parent");
        let block = {
            let guard = storage.lock().expect("storage");
            build_test_block(&guard, &parent, Hash256([0x79; 32]))
        };
        let block_hash = block.header.hash();
        storage
            .lock()
            .expect("storage")
            .store_recovery_spool_block(spool_tip, &block, 1)
            .expect("store spool body");

        restore_orphaned_recovery_spools(&config, &storage).expect("restore spool cursor");

        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .get(&recovery_cursor_key(block_hash))
            .cloned()
            .expect("restored cursor");
        assert_eq!(cursor.tip_hash, block_hash);
        assert_eq!(cursor.spool_tip_hash, Some(spool_tip));
        assert_eq!(cursor.ancestor_height, Some(0));
        assert_eq!(cursor.staged_height, 1);
        assert_eq!(cursor.next_height, 2);
        assert_eq!(cursor.state, "complete");
        assert!(cursor.spool_verified);

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&recovery_cursor_key(block_hash));
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn stale_recovery_ancestor_forces_locator_rediscovery() {
        let path = test_path("recovery-stale-ancestor");
        let config = test_rpc_node_config(&path, Vec::new());
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let peer = format!("recovery-stale-ancestor-peer-{}", unix_now());
        let tip = Hash256([0x7a; 32]);
        let key = recovery_cursor_key(tip);
        set_peer_recovery_key(&peer, tip);
        let mut cursor = new_branch_sync_cursor(tip, 10, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(1);
        cursor.ancestor_hash = Some(Hash256([0x7b; 32]));
        cursor.next_height = 2;
        cursor.staged_height = 1;
        cursor.expected_parent_hash = Some(Hash256([0x7c; 32]));
        cursor.spool_verified = true;
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        reconcile_forward_recovery_spool(&config, &storage, &peer).expect("ancestor repair");
        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .get(&key)
            .cloned()
            .expect("cursor");
        assert_eq!(cursor.ancestor_height, None);
        assert_eq!(cursor.next_height, 0);
        assert_eq!(cursor.state, "pending-retrieval");

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&peer);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn matching_tip_cleans_a_persisted_cursor_without_a_route_binding() {
        let path = test_path("canonical-recovery-cleanup");
        let config = test_rpc_node_config(&path, Vec::new());
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let tip = genesis_header().hash();
        let key = recovery_cursor_key(tip);
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(
                key.clone(),
                new_branch_sync_cursor(tip, 0, "BLQ-RX/2".to_string()),
            );

        // Simulate a restart: the durable cursor survives, but its in-memory
        // peer-to-job association does not.
        clear_canonical_recovery_cursor(&config, &storage, "unbound-peer");

        assert!(!branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .contains_key(&key));
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn lower_unstarted_cursor_does_not_survive_a_canonical_tip_advance() {
        let path = test_path("stale-recovery-cursor-cleanup");
        let config = test_rpc_node_config(&path, Vec::new());
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        for seed in [0x91u8, 0x92] {
            let parent = node_storage.best_header().expect("parent");
            node_storage
                .insert_block(build_test_block(
                    &node_storage,
                    &parent,
                    Hash256([seed; 32]),
                ))
                .expect("canonical block");
        }
        let storage = Arc::new(Mutex::new(node_storage));
        let tip = Hash256([0xa1; 32]);
        let key = recovery_cursor_key(tip);
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(
                key.clone(),
                new_branch_sync_cursor(tip, 1, "BLQ-RX/2".to_string()),
            );

        clear_canonical_recovery_cursor(&config, &storage, "lagging-peer");

        assert!(!branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .contains_key(&key));
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn recovery_job_lease_allows_only_one_bulk_provider() {
        let job = format!("recovery-job-lease-{}", unix_now());
        let first = RecoveryJobLease::acquire(&job).expect("first recovery lease");
        assert!(RecoveryJobLease::acquire(&job).is_none());
        assert!(RecoveryJobLease::acquire("another-moving-tip").is_none());
        drop(first);
        assert!(RecoveryJobLease::acquire(&job).is_some());
    }

    #[test]
    fn witness_samples_are_deterministic_and_bounded() {
        let tip = Hash256([0x5a; 32]);
        let samples = recovery_witness_sample_heights(tip, 100, 227);
        assert!(!samples.is_empty());
        assert!(samples.len() <= 4);
        assert_eq!(samples.first(), Some(&100));
        assert_eq!(samples.last(), Some(&227));
        assert_eq!(samples, recovery_witness_sample_heights(tip, 100, 227));
    }

    #[test]
    fn independent_identity_becomes_a_witness_not_a_second_provider() {
        let path = test_path("recovery-witness-role");
        fs::create_dir_all(&path).expect("witness test directory");
        let config = test_rpc_node_config(&path, Vec::new());
        let tip = Hash256([0x91; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 300, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(100);
        cursor.ancestor_hash = Some(Hash256([0x44; 32]));
        cursor.next_height = 101;
        cursor.staged_height = 100;
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        assert!(
            register_recovery_peer_role(&config, "primary-route", "primary-id", tip, true)
                .is_none()
        );
        let samples =
            register_recovery_peer_role(&config, "witness-route", "witness-id", tip, false)
                .expect("witness samples");
        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .get(&key)
            .cloned()
            .expect("recovery cursor");
        assert_eq!(cursor.primary_identity.as_deref(), Some("primary-id"));
        assert_eq!(cursor.witness_identity.as_deref(), Some("witness-id"));
        assert_eq!(cursor.provider_mode, "waiting-for-witness");
        assert!(samples.len() <= 4);

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn stale_witness_is_removed_without_blocking_completed_recovery() {
        let path = test_path("recovery-stale-witness");
        fs::create_dir_all(&path).expect("witness test directory");
        let config = test_rpc_node_config(&path, Vec::new());
        let tip = Hash256([0x94; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 300, "BLQ-RX/2".to_string());
        cursor.next_height = 301;
        cursor.primary_identity = Some("primary-id".to_string());
        cursor.witness_identity = Some("behind-id".to_string());
        cursor.provider_mode = "waiting-for-witness".to_string();
        cursor.witness_sample_heights = vec![300];
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        assert!(remove_stale_recovery_witness(&config, tip, "behind-id"));
        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .get(&key)
            .cloned()
            .expect("recovery cursor");
        assert_eq!(cursor.witness_identity, None);
        assert_eq!(cursor.provider_mode, "single-provider");
        assert_eq!(cursor.state, "complete");

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn matching_witness_header_marks_a_range_cross_checked() {
        let path = test_path("recovery-witness-evidence");
        fs::create_dir_all(&path).expect("witness evidence directory");
        let config = test_rpc_node_config(&path, Vec::new());
        let header = genesis_header();
        let tip = Hash256([0x92; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 10, "BLQ-RX/2".to_string());
        cursor.witness_identity = Some("witness-id".to_string());
        cursor.provider_mode = "waiting-for-witness".to_string();
        cursor.witness_sample_heights = vec![header.number.0];
        cursor
            .primary_sample_hashes
            .insert(header.number.0, header.hash());
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        assert!(
            !record_witness_headers(&config, tip, "witness-id", vec![header])
                .expect("matching witness response")
        );
        assert_eq!(
            branch_sync_cursors()
                .lock()
                .expect("branch cursors")
                .get(&key)
                .expect("recovery cursor")
                .provider_mode,
            "cross-checked"
        );

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn completed_job_publishes_when_witness_arrives_after_waiting_state() {
        let path = test_path("late-witness-publication");
        fs::create_dir_all(&path).expect("witness test directory");
        let config = test_rpc_node_config(&path, Vec::new());
        let header = genesis_header();
        let tip = Hash256([0x93; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 10, "BLQ-RX/2".to_string());
        cursor.next_height = 11;
        cursor.state = "waiting-for-witness".to_string();
        cursor.witness_identity = Some("witness-id".to_string());
        cursor.provider_mode = "waiting-for-witness".to_string();
        cursor.witness_sample_heights = vec![header.number.0];
        cursor
            .primary_sample_hashes
            .insert(header.number.0, header.hash());
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);

        assert!(
            record_witness_headers(&config, tip, "witness-id", vec![header])
                .expect("matching late witness")
        );
        let cursor = branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .get(&key)
            .cloned()
            .expect("cursor");
        assert_eq!(cursor.state, "complete");
        assert_eq!(cursor.provider_mode, "cross-checked");

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn restart_normalization_keeps_the_most_advanced_shared_recovery_job() {
        let tip = Hash256([0x66; 32]);
        let mut stale = new_branch_sync_cursor(tip, 100, "BLQ-RX/2".to_string());
        stale.imported_bodies = 42;
        stale.updated_at = 10;

        let mut forward = new_branch_sync_cursor(tip, 100, "BLQ-RX/2".to_string());
        forward.ancestor_height = Some(60);
        forward.staged_height = 77;
        forward.next_height = 78;
        forward.updated_at = 11;

        let normalized = normalize_branch_sync_cursors(BTreeMap::from([
            ("old-peer-route".to_string(), stale),
            ("branch:old-name".to_string(), forward),
        ]));
        assert_eq!(normalized.len(), 1);
        let job = normalized
            .get(&recovery_cursor_key(tip))
            .expect("shared job");
        assert_eq!(job.ancestor_height, Some(60));
        assert_eq!(job.staged_height, 77);
        assert_eq!(job.next_height, 78);
    }

    #[test]
    fn forward_recovery_job_is_shared_with_a_second_provider_route() {
        let test_id = format!("{:?}-{}", std::thread::current().id(), unix_now());
        let primary = format!("recovery-primary-{test_id}");
        let witness = format!("recovery-witness-{test_id}");
        let tip = Hash256([0x68; 32]);
        let profile = "BLQ-RX/2".to_string();
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 200, profile.clone());
        cursor.ancestor_height = Some(150);
        cursor.ancestor_hash = Some(Hash256([0x69; 32]));
        cursor.next_height = 181;
        cursor.expected_parent_hash = Some(Hash256([0x6a; 32]));
        cursor.staged_height = 180;
        cursor.provider = Some(primary.clone());
        cursor.state = "retrieving".to_string();

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .remove(&witness);

        assert_eq!(
            durable_forward_cursor_key(&witness, &profile, 100),
            Some(key.clone())
        );

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&key);
    }

    #[test]
    fn restart_normalization_prunes_only_duplicate_spool_metadata() {
        let spool_tip = Hash256([0xc1; 32]);
        let earlier_tip = Hash256([0xc2; 32]);
        let later_tip = Hash256([0xc3; 32]);
        let ancestor = Hash256([0xc4; 32]);
        let root = Hash256([0xc5; 32]);
        let mut advanced = new_branch_sync_cursor(earlier_tip, 7_000, "BLQ-RX/2".to_string());
        advanced.spool_tip_hash = Some(spool_tip);
        advanced.ancestor_hash = Some(ancestor);
        advanced.branch_root_hash = Some(root);
        advanced.ancestor_height = Some(2_600);
        advanced.staged_height = 4_200;
        advanced.next_height = 4_201;
        let mut stale = new_branch_sync_cursor(later_tip, 7_001, "BLQ-RX/2".to_string());
        stale.spool_tip_hash = Some(spool_tip);
        stale.ancestor_hash = Some(ancestor);
        stale.branch_root_hash = Some(root);
        stale.ancestor_height = Some(2_600);
        stale.staged_height = 3_000;
        stale.next_height = 3_001;

        let normalized = normalize_branch_sync_cursors(BTreeMap::from([
            (recovery_cursor_key(earlier_tip), advanced),
            (recovery_cursor_key(later_tip), stale),
        ]));
        assert_eq!(normalized.len(), 1);
        let cursor = normalized.values().next().expect("surviving job");
        assert_eq!(cursor.staged_height, 4_200);
        assert_eq!(cursor_spool_tip(cursor), spool_tip);
    }

    #[test]
    fn completed_forward_job_survives_a_late_transport_failure() {
        let tip = Hash256([0x67; 32]);
        let mut cursor = new_branch_sync_cursor(tip, 100, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(60);
        cursor.staged_height = 100;
        cursor.next_height = 101;
        cursor.state = "waiting-for-provider".to_string();
        cursor.last_failure = Some("peer closed connection".to_string());

        let normalized =
            normalize_branch_sync_cursors(BTreeMap::from([("stale-route".to_string(), cursor)]));
        let job = normalized
            .get(&recovery_cursor_key(tip))
            .expect("completed recovery job");
        assert_eq!(job.state, "complete");
        assert!(job.last_failure.is_none());
        assert_eq!(job.next_height, 101);
    }

    #[test]
    fn empty_completed_recovery_cursor_is_discarded_for_locator_rediscovery() {
        let path = test_path("empty-completed-recovery-cursor");
        fs::create_dir_all(&path).expect("cursor test directory");
        let config = test_rpc_node_config(&path, Vec::new());
        let peer = format!("empty-completed-peer-{}", unix_now());
        let tip = Hash256([0x6b; 32]);
        let key = recovery_cursor_key(tip);
        let mut cursor = new_branch_sync_cursor(tip, 100, "BLQ-RX/2".to_string());
        cursor.ancestor_height = Some(99);
        cursor.ancestor_hash = Some(Hash256([0x6c; 32]));
        cursor.staged_height = 100;
        cursor.next_height = 101;
        cursor.expected_parent_hash = Some(tip);
        cursor.state = "complete".to_string();
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(key.clone(), cursor);
        peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .insert(peer.clone(), key.clone());

        reset_completed_recovery_for_refetch(&config, tip);

        assert!(!branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .contains_key(&key));
        assert!(!peer_recovery_keys()
            .lock()
            .expect("peer recovery keys")
            .contains_key(&peer));
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn durable_branch_cursor_keeps_mining_upstream_after_peer_tip_expires() {
        let path = test_path("sticky-upstream-cursor");
        let mut config = test_rpc_node_config(&path, Vec::new());
        config.rpc.mining_upstreams = vec!["http://127.0.0.1:8545".to_string()];
        let mut node_storage = NodeStorage::Full(SledStorage::open(&path).expect("open storage"));
        initialize_genesis(&mut node_storage, NodeMode::Full).expect("genesis");
        let storage = Arc::new(Mutex::new(node_storage));
        let peer = format!("sticky-upstream-peer-{}", unix_now());
        let remote_tip = Hash256([0xc3; 32]);
        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .insert(
                peer.clone(),
                new_branch_sync_cursor(
                    remote_tip,
                    1,
                    network_consensus_profile(&config, genesis_header().hash()),
                ),
            );

        // No peer-tip report is inserted here. The persisted cursor alone
        // must keep a potentially stale local chain from serving templates.
        assert!(mining_upstream_required(&config, &storage));
        assert_eq!(
            minimum_upstream_template_height(&config, &storage).expect("height"),
            2
        );

        branch_sync_cursors()
            .lock()
            .expect("branch cursors")
            .remove(&peer);
        fs::remove_dir_all(path).ok();
    }

    #[test]
    fn completed_recovery_cursor_does_not_leave_status_waiting_for_provider() {
        let tip = Hash256([0x68; 32]);
        let mut cursor = new_branch_sync_cursor(tip, 100, "BLQ-RX/2".to_string());
        cursor.state = "complete".to_string();
        cursor.next_height = 101;

        assert!(!cursor_waiting_for_provider(Some(&cursor), 100));
        assert!(!cursor_waiting_for_provider(None, 100));

        cursor.state = "waiting-for-provider".to_string();
        assert!(cursor_waiting_for_provider(Some(&cursor), 99));
        assert!(!cursor_waiting_for_provider(Some(&cursor), 100));
    }

    #[test]
    fn cgroup_memory_limit_parser_accepts_numeric_limits_only() {
        assert_eq!(parse_cgroup_memory_limit("1048576\n"), Some(1_048_576));
        assert_eq!(parse_cgroup_memory_limit("max\n"), None);
        assert_eq!(parse_cgroup_memory_limit("not-a-limit"), None);
    }

    #[test]
    fn mempool_pressure_warning_is_edge_triggered_and_rate_limited() {
        let start = Instant::now();
        assert!(should_log_mempool_persistence_pressure(None, start));
        assert!(!should_log_mempool_persistence_pressure(
            Some(start),
            start + MEMPOOL_PERSISTENCE_PRESSURE_LOG_INTERVAL - Duration::from_secs(1),
        ));
        assert!(should_log_mempool_persistence_pressure(
            Some(start),
            start + MEMPOOL_PERSISTENCE_PRESSURE_LOG_INTERVAL,
        ));
    }

    #[test]
    fn duplicate_tip_bodies_do_not_reset_sync_retry_backoff() {
        assert!(!sync_session_made_progress(false, Some(100), Some(100)));
        assert!(!sync_session_made_progress(false, Some(101), Some(100)));
        assert!(sync_session_made_progress(false, Some(100), Some(101)));
        assert!(sync_session_made_progress(true, Some(100), Some(100)));
        assert!(sync_session_made_progress(true, None, None));
    }

    #[test]
    fn matching_signed_tip_uses_the_idle_sync_interval() {
        let mut retry = 1;
        assert_eq!(
            sync_retry_delay(true, true, false, &mut retry),
            P2P_SYNC_IDLE_RETRY_MAX_SECONDS
        );
        assert_eq!(retry, P2P_SYNC_IDLE_RETRY_MAX_SECONDS);
        assert_eq!(sync_retry_delay(false, true, true, &mut retry), 1);
        assert_eq!(retry, 1);
    }

    #[test]
    fn authenticated_peer_routes_prefer_local_and_keep_public_failover() {
        let suffix = unix_now().to_string();
        let mesh = format!("100.99.{}.1:30334", suffix.len());
        let public = format!("198.51.100.{}:30334", suffix.len());
        let identity = format!("route-identity-{suffix}");
        {
            let mut identities = known_peer_identities().lock().expect("identities");
            identities.insert(mesh.clone(), identity.clone());
            identities.insert(public.clone(), identity);
        }

        assert_eq!(
            preferred_peer_route(&public).as_deref(),
            Some(mesh.as_str())
        );
        assert!(!alternate_route_may_fail_over(&public));
        record_p2p_route_connect_failure(&mesh);
        assert!(alternate_route_may_fail_over(&public));

        known_peer_identities()
            .lock()
            .expect("identities")
            .remove(&mesh);
        known_peer_identities()
            .lock()
            .expect("identities")
            .remove(&public);
        clear_p2p_route_connect_failure(&mesh);
    }

    #[test]
    fn candidate_replay_memory_headroom_respects_cgroup_limits() {
        let mib = 1024 * 1024;
        assert!(candidate_replay_memory_headroom_available(None, None, None));
        assert!(candidate_replay_memory_headroom_available(
            Some(299 * mib),
            Some(5 * 1024 * mib),
            Some(6 * 1024 * mib),
        ));
        assert!(!candidate_replay_memory_headroom_available(
            Some(203 * mib),
            Some(512 * mib),
            Some(768 * mib),
        ));
        assert!(!candidate_replay_memory_headroom_available(
            Some(4_500 * mib),
            Some(6 * 1024 * mib),
            Some(5 * 1024 * mib),
        ));
    }

    fn rlp_encode_list_payload(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        super::rlp_encode_list_payload(payload, &mut out);
        out
    }

    fn test_signature(secret: &SecretKey, payload: &[u8]) -> (Vec<u8>, Vec<u8>, bool) {
        let signature = Secp256k1::new()
            .sign_ecdsa_recoverable(Message::from_digest(keccak256(payload).0), secret);
        let (recovery_id, compact) = signature.serialize_compact();
        (
            compact[..32].to_vec(),
            compact[32..].to_vec(),
            i32::from(recovery_id) == 1,
        )
    }
}
