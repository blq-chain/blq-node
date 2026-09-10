use blq_consensus::{validate_transaction_fee, ConsensusError};
use blq_primitives::Transaction;
use blq_primitives::{Bix, Hash256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const MAX_MEMPOOL_TRANSACTIONS: usize = 5_000;
pub const MIN_GAS_PRICE_BIX: u128 = 1_000_000_000; // 1 Gwei

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("consensus rejected transaction: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("transaction replacement fee is not higher")]
    ReplacementFeeTooLow,
    #[error("mempool is full and transaction fee is not competitive")]
    MempoolFull,
    #[error("gas price is below minimum network threshold (1 Gwei)")]
    FeeTooLow,
}

#[derive(Debug, Error)]
pub enum MempoolPersistenceError {
    #[error("mempool persistence I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mempool persistence serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Default)]
pub struct Mempool {
    transactions: Vec<Transaction>,
    first_seen: BTreeMap<Hash256, u64>,
}

#[derive(Serialize, Deserialize)]
struct PersistedEntry {
    transaction: Transaction,
    first_seen: u64,
}

impl Mempool {
    pub fn add(
        &mut self,
        transaction: Transaction,
        base_fee_per_gas: Bix,
    ) -> Result<(), MempoolError> {
        if transaction.max_fee_per_gas.0 < MIN_GAS_PRICE_BIX {
            return Err(MempoolError::FeeTooLow);
        }
        validate_transaction_fee(&transaction, base_fee_per_gas)?;
        if self
            .transactions
            .iter()
            .any(|existing| existing.rpc_hash() == transaction.rpc_hash())
        {
            return Ok(());
        }
        if let Some(existing) = self.transactions.iter_mut().find(|existing| {
            existing.from == transaction.from && existing.nonce == transaction.nonce
        }) {
            if transaction.max_fee_per_gas.0 <= existing.max_fee_per_gas.0 {
                return Err(MempoolError::ReplacementFeeTooLow);
            }
            let hash = transaction.rpc_hash();
            *existing = transaction;
            self.first_seen.insert(hash, now_seconds());
            self.sort_by_fee();
            return Ok(());
        }
        if self.transactions.len() >= MAX_MEMPOOL_TRANSACTIONS {
            let lowest = self
                .transactions
                .last()
                .expect("mempool is non-empty at capacity");
            let new_priority = (
                transaction.max_priority_fee_per_gas,
                transaction.max_fee_per_gas,
            );
            let lowest_priority = (lowest.max_priority_fee_per_gas, lowest.max_fee_per_gas);
            if new_priority <= lowest_priority {
                return Err(MempoolError::MempoolFull);
            }
            let evicted = self
                .transactions
                .pop()
                .expect("mempool is non-empty at capacity");
            self.first_seen.remove(&evicted.rpc_hash());
        }
        let hash = transaction.rpc_hash();
        self.transactions.push(transaction);
        self.first_seen.insert(hash, now_seconds());
        self.sort_by_fee();
        Ok(())
    }

    pub fn pending(&self) -> &[Transaction] {
        &self.transactions
    }

    pub fn pending_with_age(&self, now: u64) -> Vec<(Transaction, u64)> {
        self.transactions
            .iter()
            .map(|transaction| {
                let first_seen = self
                    .first_seen
                    .get(&transaction.rpc_hash())
                    .copied()
                    .unwrap_or(now);
                (transaction.clone(), now.saturating_sub(first_seen))
            })
            .collect()
    }

    pub fn remove_expired(&mut self, now: u64, max_age_seconds: u64) -> usize {
        let removed: Vec<_> = self
            .transactions
            .iter()
            .filter(|transaction| {
                let first_seen = self
                    .first_seen
                    .get(&transaction.rpc_hash())
                    .copied()
                    .unwrap_or(now);
                now.saturating_sub(first_seen) >= max_age_seconds
            })
            .map(Transaction::rpc_hash)
            .collect();
        self.transactions
            .retain(|transaction| !removed.contains(&transaction.rpc_hash()));
        for hash in &removed {
            self.first_seen.remove(hash);
        }
        removed.len()
    }

    pub fn has_nonce_chain(&self, from: blq_primitives::Address, start: u64, target: u64) -> bool {
        (start..target).all(|nonce| {
            self.transactions
                .iter()
                .any(|transaction| transaction.from == from && transaction.nonce == nonce)
        })
    }

    pub fn load(
        path: impl AsRef<Path>,
        base_fee_per_gas: Bix,
    ) -> Result<Self, MempoolPersistenceError> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let mut mempool = Self::default();
        if let Ok(entries) = serde_json::from_value::<Vec<PersistedEntry>>(value.clone()) {
            for entry in entries {
                if mempool
                    .add(entry.transaction.clone(), base_fee_per_gas)
                    .is_ok()
                {
                    mempool
                        .first_seen
                        .insert(entry.transaction.rpc_hash(), entry.first_seen);
                }
            }
        } else {
            let transactions: Vec<Transaction> = serde_json::from_value(value)?;
            for transaction in transactions {
                let _ = mempool.add(transaction, base_fee_per_gas);
            }
        }
        Ok(mempool)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), MempoolPersistenceError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        let entries: Vec<_> = self
            .transactions
            .iter()
            .map(|transaction| PersistedEntry {
                transaction: transaction.clone(),
                first_seen: self
                    .first_seen
                    .get(&transaction.rpc_hash())
                    .copied()
                    .unwrap_or_else(now_seconds),
            })
            .collect();
        fs::write(&temporary, serde_json::to_vec_pretty(&entries)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn drain_for_block(&self, gas_limit: u64) -> Vec<Transaction> {
        let mut candidates = self.transactions.clone();
        candidates.sort_by(|a, b| {
            if a.from == b.from {
                a.nonce.cmp(&b.nonce)
            } else {
                b.max_priority_fee_per_gas
                    .cmp(&a.max_priority_fee_per_gas)
                    .then_with(|| b.max_fee_per_gas.cmp(&a.max_fee_per_gas))
            }
        });
        let mut gas = 0u64;
        let mut out = Vec::new();
        for transaction in &candidates {
            if gas.saturating_add(transaction.gas_limit) > gas_limit {
                continue;
            }
            gas = gas.saturating_add(transaction.gas_limit);
            out.push(transaction.clone());
        }
        out
    }

    pub fn remove_stale_nonces<F>(&mut self, mut expected_nonce: F)
    where
        F: FnMut(blq_primitives::Address) -> u64,
    {
        let removed: Vec<_> = self
            .transactions
            .iter()
            .filter(|transaction| transaction.nonce < expected_nonce(transaction.from))
            .map(Transaction::rpc_hash)
            .collect();
        self.transactions
            .retain(|transaction| transaction.nonce >= expected_nonce(transaction.from));
        for hash in removed {
            self.first_seen.remove(&hash);
        }
    }

    pub fn remove_included(&mut self, hashes: &[Hash256]) {
        let removed: Vec<_> = self
            .transactions
            .iter()
            .filter(|transaction| {
                hashes.contains(&transaction.hash()) || hashes.contains(&transaction.rpc_hash())
            })
            .map(Transaction::rpc_hash)
            .collect();
        self.transactions.retain(|transaction| {
            !hashes.contains(&transaction.hash()) && !hashes.contains(&transaction.rpc_hash())
        });
        for hash in removed {
            self.first_seen.remove(&hash);
        }
    }

    fn sort_by_fee(&mut self) {
        self.transactions.sort_by(|a, b| {
            b.max_priority_fee_per_gas
                .cmp(&a.max_priority_fee_per_gas)
                .then_with(|| b.max_fee_per_gas.cmp(&a.max_fee_per_gas))
        });
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(nonce: u64) -> Transaction {
        Transaction {
            chain_id: 707070,
            transaction_type: 2,
            nonce,
            from: blq_primitives::Address([1; 20]),
            to: Some(blq_primitives::Address([2; 20])),
            value: Bix(1),
            gas_limit: 21_000,
            max_fee_per_gas: Bix(2_000_000_000),
            max_priority_fee_per_gas: Bix(1_000_000_000),
            payload: Vec::new(),
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        }
    }

    #[test]
    fn persistence_round_trip_discards_fee_invalid_entries() {
        let path = std::env::temp_dir().join(format!("blq-mempool-{}.json", std::process::id()));
        let mut mempool = Mempool::default();
        mempool
            .add(transaction(0), Bix(1))
            .expect("add transaction");
        mempool.save(&path).expect("save mempool");
        let loaded = Mempool::load(&path, Bix(1)).expect("load mempool");
        assert_eq!(loaded.pending(), &[transaction(0)]);
        let empty = Mempool::load(&path, Bix(3_000_000_000)).expect("load invalidated mempool");
        assert!(empty.pending().is_empty());
        fs::remove_file(path).ok();
    }

    #[test]
    fn duplicate_transaction_is_idempotent() {
        let mut mempool = Mempool::default();
        let transaction = transaction(0);
        mempool.add(transaction.clone(), Bix(1)).expect("first add");
        mempool.add(transaction, Bix(1)).expect("duplicate add");
        assert_eq!(mempool.pending().len(), 1);
    }

    #[test]
    fn expired_transactions_are_removed_using_first_seen() {
        let mut mempool = Mempool::default();
        mempool
            .add(transaction(0), Bix(1))
            .expect("add transaction");
        let now = now_seconds();
        assert_eq!(mempool.remove_expired(now, 7_200), 0);
        assert_eq!(mempool.remove_expired(now + 7_200, 7_200), 1);
        assert!(mempool.pending().is_empty());
    }

    #[test]
    fn queued_nonce_chain_is_bounded_and_drained_in_order() {
        let mut mempool = Mempool::default();
        mempool
            .add(transaction(0), Bix(1))
            .expect("first transaction");
        mempool
            .add(transaction(1), Bix(1))
            .expect("second transaction");
        let from = transaction(0).from;
        assert!(mempool.has_nonce_chain(from, 0, 2));
        assert!(!mempool.has_nonce_chain(from, 0, 3));
        let drained = mempool.drain_for_block(42_000);
        assert_eq!(
            drained.iter().map(|tx| tx.nonce).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(mempool.pending().len(), 2);
    }

    #[test]
    fn stale_nonces_are_removed_before_template_selection() {
        let mut mempool = Mempool::default();
        mempool
            .add(transaction(0), Bix(1))
            .expect("stale transaction");
        mempool
            .add(transaction(2), Bix(1))
            .expect("future transaction");
        mempool.remove_stale_nonces(|_| 1);
        assert_eq!(
            mempool
                .pending()
                .iter()
                .map(|tx| tx.nonce)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn mempool_rejects_noncompetitive_transactions_at_capacity() {
        let mut mempool = Mempool::default();
        mempool.transactions = (0..MAX_MEMPOOL_TRANSACTIONS as u64)
            .map(|nonce| {
                let mut tx = transaction(nonce);
                tx.from = blq_primitives::Address([(nonce % 251) as u8 + 3; 20]);
                tx
            })
            .collect();
        mempool.sort_by_fee();
        let mut rejected = transaction(10_000);
        rejected.from = blq_primitives::Address([0xfe; 20]);
        assert!(matches!(
            mempool.add(rejected, Bix(1)),
            Err(MempoolError::MempoolFull)
        ));
        assert_eq!(mempool.pending().len(), MAX_MEMPOOL_TRANSACTIONS);
    }
}
