use blq_primitives::{Address, Bix, Hash256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: Bix,
    pub code_hash: Hash256,
    pub storage_root: Hash256,
    pub code: Vec<u8>,
    pub storage: BTreeMap<Hash256, Hash256>,
}

impl Account {
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            balance: Bix(0),
            code_hash: Hash256::ZERO,
            storage_root: Hash256::ZERO,
            code: Vec::new(),
            storage: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("account has insufficient balance")]
    InsufficientBalance,
    #[error("transaction nonce does not match account nonce")]
    InvalidNonce,
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryState {
    pub accounts: BTreeMap<Address, Account>,
}

impl InMemoryState {
    pub fn account(&self, address: Address) -> Account {
        self.accounts
            .get(&address)
            .cloned()
            .unwrap_or_else(Account::empty)
    }

    pub fn put_account(&mut self, address: Address, account: Account) {
        self.accounts.insert(address, account);
    }

    pub fn transfer(
        &mut self,
        from: Address,
        to: Address,
        nonce: u64,
        value: Bix,
        fee: Bix,
    ) -> Result<(), StateError> {
        let mut sender = self.account(from);
        if sender.nonce != nonce {
            return Err(StateError::InvalidNonce);
        }
        let total = value.0.saturating_add(fee.0);
        if sender.balance.0 < total {
            return Err(StateError::InsufficientBalance);
        }
        sender.balance.0 -= total;
        sender.nonce += 1;
        let mut receiver = self.account(to);
        receiver.balance.0 = receiver.balance.0.saturating_add(value.0);
        self.put_account(from, sender);
        self.put_account(to, receiver);
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct StateTransitionSummary {
    pub state_root: Hash256,
    pub receipts_root: Hash256,
    pub gas_used: u64,
    pub burned_fees: Bix,
    pub miner_fees: Bix,
}
