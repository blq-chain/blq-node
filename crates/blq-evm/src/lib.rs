use blq_primitives::{Bix, BlockHeader, Hash256, LogEntry, Transaction};
use blq_state::StateTransitionSummary;
use revm::{
    bytecode::Bytecode,
    context::{BlockEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    context_interface::transaction::{AccessList, AccessListItem},
    database_interface::{DBErrorMarker, Database, DatabaseCommit},
    primitives::{keccak256, Address as RevmAddress, Bytes, TxKind, B256, U256},
    state::{Account, AccountInfo, EvmStorageSlot},
    ExecuteCommitEvm, MainBuilder, MainContext,
};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvmError {
    #[error("transaction execution failed: {0}")]
    Execution(String),
    #[error("invalid EVM address")]
    InvalidAddress,
}

pub trait EvmExecutor {
    fn execute_block(
        &mut self,
        header: &BlockHeader,
        transactions: &[Transaction],
    ) -> Result<StateTransitionSummary, EvmError>;
}

#[derive(Clone, Debug, Default)]
pub struct RevmState {
    pub accounts: BTreeMap<RevmAddress, RevmAccount>,
}

#[derive(Clone, Debug, Default)]
pub struct RevmAccount {
    pub nonce: u64,
    pub balance: U256,
    pub code: Vec<u8>,
    pub storage: BTreeMap<U256, U256>,
}

impl RevmState {
    pub fn account(&self, address: RevmAddress) -> RevmAccount {
        self.accounts.get(&address).cloned().unwrap_or_default()
    }

    pub fn put_account(&mut self, address: RevmAddress, account: RevmAccount) {
        self.accounts.insert(address, account);
    }
}

#[derive(Debug, Error)]
#[error("in-memory REVM database error")]
pub struct RevmDbError;

impl DBErrorMarker for RevmDbError {}

impl Database for RevmState {
    type Error = RevmDbError;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let Some(account) = self.accounts.get(&address).cloned() else {
            return Ok(None);
        };
        let code = if account.code.is_empty() {
            Bytecode::default()
        } else {
            Bytecode::new_legacy(Bytes::from(account.code.clone()))
        };
        Ok(Some(AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: keccak256(&account.code),
            account_id: None,
            code: Some(code),
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        for account in self.accounts.values() {
            if keccak256(&account.code) == code_hash {
                return Ok(Bytecode::new_legacy(Bytes::from(account.code.clone())));
            }
        }
        Ok(Bytecode::default())
    }

    fn storage(&mut self, address: RevmAddress, index: U256) -> Result<U256, Self::Error> {
        Ok(self
            .account(address)
            .storage
            .get(&index)
            .copied()
            .unwrap_or_default())
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl DatabaseCommit for RevmState {
    fn commit(&mut self, changes: revm::primitives::AddressMap<Account>) {
        for (address, account) in changes {
            if account.is_selfdestructed() {
                self.accounts.remove(&address);
                continue;
            }
            let mut next = self.account(address);
            next.nonce = account.info.nonce;
            next.balance = account.info.balance;
            if let Some(code) = account.info.code {
                next.code = code.original_byte_slice().to_vec();
            }
            for (key, slot) in account.storage {
                let EvmStorageSlot { present_value, .. } = slot;
                if present_value == U256::ZERO {
                    next.storage.remove(&key);
                } else {
                    next.storage.insert(key, present_value);
                }
            }
            self.put_account(address, next);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RevmBlockExecutor {
    pub state: RevmState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub success: bool,
    pub gas_used: u64,
    pub output: Vec<u8>,
    pub logs: Vec<LogEntry>,
}

impl RevmBlockExecutor {
    pub fn new(state: RevmState) -> Self {
        Self { state }
    }

    pub fn execute_transaction(
        &mut self,
        header: &BlockHeader,
        transaction: &Transaction,
    ) -> Result<ExecutionOutput, EvmError> {
        let context = revm::Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.chain_id = transaction.chain_id)
            .with_db(&mut self.state)
            .with_block(BlockEnv {
                number: U256::from(header.number.0),
                beneficiary: RevmAddress::from(header.beneficiary_address().0),
                timestamp: U256::from(header.timestamp_seconds),
                gas_limit: header.gas_limit,
                basefee: u64::try_from(header.base_fee_per_gas.0)
                    .map_err(|_| EvmError::Execution("base fee exceeds EVM range".into()))?,
                difficulty: U256::ZERO,
                prevrandao: Some(B256::from(header.mix_hash.0)),
                blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(0, 1)),
                slot_num: header.number.0,
            });
        let kind = match transaction.to {
            Some(to) => TxKind::Call(RevmAddress::from(to.0)),
            None => TxKind::Create,
        };
        let access_list = AccessList(
            transaction
                .access_list
                .iter()
                .map(|item| AccessListItem {
                    address: RevmAddress::from(item.address.0),
                    storage_keys: item
                        .storage_keys
                        .iter()
                        .map(|key| B256::from(key.0))
                        .collect(),
                })
                .collect(),
        );
        let tx = TxEnv::builder()
            .caller(RevmAddress::from(transaction.from.0))
            .gas_limit(transaction.gas_limit)
            .max_fee_per_gas(transaction.max_fee_per_gas.0)
            .gas_priority_fee(Some(transaction.max_priority_fee_per_gas.0))
            .kind(kind)
            .value(U256::from(transaction.value.0))
            .data(Bytes::from(transaction.payload.clone()))
            .access_list(access_list)
            .nonce(transaction.nonce)
            .chain_id(Some(transaction.chain_id))
            .build()
            .map_err(|err| EvmError::Execution(err.to_string()))?;
        let result = context
            .build_mainnet()
            .transact_commit(tx)
            .map_err(|err| EvmError::Execution(err.to_string()))?;
        Ok(ExecutionOutput {
            success: result.is_success(),
            gas_used: result.tx_gas_used(),
            output: result
                .output()
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default(),
            logs: result
                .logs()
                .iter()
                .map(|log| LogEntry {
                    address: blq_primitives::Address(*log.address.0),
                    topics: log
                        .data
                        .topics()
                        .iter()
                        .map(|topic| Hash256(topic.0))
                        .collect(),
                    data: log.data.data.to_vec(),
                })
                .collect(),
        })
    }
}

impl EvmExecutor for RevmBlockExecutor {
    fn execute_block(
        &mut self,
        header: &BlockHeader,
        transactions: &[Transaction],
    ) -> Result<StateTransitionSummary, EvmError> {
        let mut gas_used = 0u64;
        for transaction in transactions {
            let result = self.execute_transaction(header, transaction)?;
            gas_used = gas_used
                .checked_add(result.gas_used)
                .ok_or_else(|| EvmError::Execution("block gas overflow".into()))?;
        }
        Ok(StateTransitionSummary {
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            gas_used,
            burned_fees: Bix(0),
            miner_fees: Bix(0),
        })
    }
}

pub fn hash_to_address(hash: Hash256) -> RevmAddress {
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash.0[12..]);
    RevmAddress::from(out)
}

pub fn hash_to_b256(hash: Hash256) -> B256 {
    B256::from(hash.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blq_primitives::{
        genesis_header, Address, Hash256, TransactionAccessListItem, MAINNET_CHAIN_ID,
    };

    fn header() -> BlockHeader {
        let mut header = genesis_header();
        header.number.0 = 1;
        header.timestamp_seconds = 10;
        header
    }

    fn tx(from: Address, to: Option<Address>, payload: Vec<u8>) -> Transaction {
        Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from,
            to,
            value: Bix(0),
            gas_limit: 100_000,
            max_fee_per_gas: Bix(2_000_000_000),
            max_priority_fee_per_gas: Bix(1_000_000_000),
            payload,
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        }
    }

    #[test]
    fn executes_contract_call_and_returns_data() {
        let caller = Address([0x11; 20]);
        let target = Address([0x22; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code: vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3],
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("contract call executes");
        assert!(output.success);
        assert_eq!(output.output.len(), 32);
        assert_eq!(output.output[31], 0x2a);
    }

    #[test]
    fn independent_callers_commit_distinct_transaction_state() {
        let first = Address([0x61; 20]);
        let second = Address([0x62; 20]);
        let target = Address([0x63; 20]);
        let mut state = RevmState::default();
        for caller in [first, second] {
            state.put_account(
                RevmAddress::from(caller.0),
                RevmAccount {
                    balance: U256::from(10u128.pow(18)),
                    ..Default::default()
                },
            );
        }
        // CALLER, PUSH1 0, SSTORE, STOP: each authenticated caller writes
        // its own identity into the shared contract's storage.
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code: vec![0x33, 0x60, 0x00, 0x55, 0x00],
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        executor
            .execute_transaction(&header(), &tx(first, Some(target), Vec::new()))
            .expect("first caller executes");
        let mut first_value = [0u8; 32];
        first_value[12..].fill(0x61);
        assert_eq!(
            executor.state.account(RevmAddress::from(target.0)).storage[&U256::ZERO],
            U256::from_be_bytes(first_value)
        );
        let mut second_tx = tx(second, Some(target), Vec::new());
        second_tx.nonce = 0;
        executor
            .execute_transaction(&header(), &second_tx)
            .expect("second caller executes");
        let mut second_value = [0u8; 32];
        second_value[12..].fill(0x62);
        assert_eq!(
            executor.state.account(RevmAddress::from(target.0)).storage[&U256::ZERO],
            U256::from_be_bytes(second_value)
        );
    }

    #[test]
    fn reports_reverted_contract_execution_without_failing_the_executor() {
        let caller = Address([0x33; 20]);
        let target = Address([0x44; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code: vec![0x60, 0x00, 0x60, 0x00, 0xfd],
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("revert is an execution result");
        assert!(!output.success);
        assert!(output.gas_used > 0);
        assert!(output.output.is_empty());
    }

    #[test]
    fn block_executor_includes_reverted_transactions_with_status_zero() {
        let caller = Address([0x53; 20]);
        let target = Address([0x54; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code: vec![0x60, 0x00, 0x60, 0x00, 0xfd],
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let summary = executor
            .execute_block(&header(), &[tx(caller, Some(target), Vec::new())])
            .expect("reverted transaction remains valid in a block");
        assert!(summary.gas_used > 0);
    }

    #[test]
    fn commit_removes_selfdestructed_accounts_and_stale_state() {
        let address = RevmAddress::from([0x61; 20]);
        let mut state = RevmState::default();
        state.put_account(
            address,
            RevmAccount {
                code: vec![0x60, 0x00, 0x56],
                storage: [(U256::ZERO, U256::from(7u8))].into_iter().collect(),
                ..Default::default()
            },
        );

        let mut change = Account::default();
        change.mark_selfdestruct();
        let mut changes = revm::primitives::AddressMap::default();
        changes.insert(address, change);
        state.commit(changes);

        assert!(!state.accounts.contains_key(&address));
    }

    #[test]
    fn reverted_storage_write_is_not_committed() {
        let caller = Address([0x35; 20]);
        let target = Address([0x45; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                // SSTORE(0, 2), then revert with an empty payload.
                code: vec![0x60, 0x02, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xfd],
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("revert is an execution result");
        assert!(!output.success);
        assert!(!executor
            .state
            .accounts
            .get(&RevmAddress::from(target.0))
            .expect("target account")
            .storage
            .contains_key(&U256::ZERO));
    }

    #[test]
    fn access_list_warms_storage_and_changes_gas_usage() {
        let caller = Address([0x11; 20]);
        let target = Address([0x22; 20]);
        let code = vec![
            0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code: code.clone(),
                storage: [(U256::ZERO, U256::from(7))].into_iter().collect(),
                ..Default::default()
            },
        );
        let cold = tx(caller, Some(target), Vec::new());
        let mut warm = cold.clone();
        warm.access_list = vec![TransactionAccessListItem {
            address: target,
            storage_keys: vec![Hash256::ZERO],
        }];
        let cold_output = RevmBlockExecutor::new(state.clone())
            .execute_transaction(&header(), &cold)
            .expect("cold storage call");
        let warm_output = RevmBlockExecutor::new(state)
            .execute_transaction(&header(), &warm)
            .expect("access-list storage call");
        assert!(cold_output.success && warm_output.success);
        assert_eq!(cold_output.output, warm_output.output);
        assert_ne!(warm_output.gas_used, cold_output.gas_used);
    }

    #[test]
    fn storage_clear_uses_the_post_london_refund_schedule() {
        let caller = Address([0x55; 20]);
        let target = Address([0x66; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code: vec![0x60, 0x00, 0x60, 0x00, 0x55, 0x00],
                storage: [(U256::ZERO, U256::from(1))].into_iter().collect(),
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("storage clear executes");
        assert!(output.success);
        assert_eq!(output.gas_used, 21_206);
        assert!(!executor
            .state
            .accounts
            .get(&RevmAddress::from(target.0))
            .expect("target account")
            .storage
            .contains_key(&U256::ZERO));
    }

    #[test]
    fn multiple_storage_clears_obey_the_eip3529_refund_cap() {
        let caller = Address([0x67; 20]);
        let target = Address([0x68; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        let mut code = Vec::new();
        for slot in 0u8..5 {
            code.extend_from_slice(&[0x60, 0x00, 0x60, slot, 0x55]);
        }
        code.push(0x00);
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code,
                storage: (0u8..5)
                    .map(|slot| (U256::from(slot), U256::from(1)))
                    .collect(),
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("multiple storage clears execute");
        assert!(output.success);
        // The five refunds are capped by the post-London one-fifth rule.
        assert_eq!(output.gas_used, 36_824);
        let account = executor
            .state
            .accounts
            .get(&RevmAddress::from(target.0))
            .expect("target account");
        assert!(account.storage.is_empty());
    }

    #[test]
    fn absent_accounts_are_distinct_from_existing_empty_accounts() {
        let caller = Address([0x69; 20]);
        let target = Address([0x6a; 20]);
        let absent = [0x6b; 20];
        let mut code = vec![0x73];
        code.extend_from_slice(&absent);
        code.extend_from_slice(&[0x3f, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code,
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state.clone());
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("extcodehash call executes");
        assert!(output.success);
        assert_eq!(output.output, vec![0u8; 32]);

        state.put_account(
            RevmAddress::from(absent),
            RevmAccount {
                nonce: 1,
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("existing empty account call executes");
        assert!(output.success);
        assert_eq!(output.output, keccak256([]).0.to_vec());
    }

    #[test]
    fn sstore_transition_matrix_has_stable_gas_and_state_results() {
        fn run(initial: u128, value: u8) -> (u64, Option<U256>) {
            let caller = Address([0x57; 20]);
            let target = Address([0x58; 20]);
            let mut state = RevmState::default();
            state.put_account(
                RevmAddress::from(caller.0),
                RevmAccount {
                    balance: U256::from(10u128.pow(18)),
                    ..Default::default()
                },
            );
            state.put_account(
                RevmAddress::from(target.0),
                RevmAccount {
                    // PUSH value, PUSH slot 0, SSTORE, STOP.
                    code: vec![0x60, value, 0x60, 0x00, 0x55, 0x00],
                    storage: if initial != 0 {
                        [(U256::ZERO, U256::from(initial))].into_iter().collect()
                    } else {
                        Default::default()
                    },
                    ..Default::default()
                },
            );
            let mut executor = RevmBlockExecutor::new(state);
            let output = executor
                .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
                .expect("SSTORE transition executes");
            (
                output.gas_used,
                executor
                    .state
                    .accounts
                    .get(&RevmAddress::from(target.0))
                    .and_then(|account| account.storage.get(&U256::ZERO).copied()),
            )
        }

        let zero_to_nonzero = run(0, 2);
        let nonzero_to_nonzero = run(1, 2);
        let nonzero_to_zero = run(1, 0);
        let no_op_zero = run(0, 0);
        assert_eq!(zero_to_nonzero.1, Some(U256::from(2)));
        assert_eq!(nonzero_to_nonzero.1, Some(U256::from(2)));
        assert_eq!(nonzero_to_zero.1, None);
        assert_eq!(no_op_zero.1, None);
        assert_eq!(zero_to_nonzero.0, 43_106);
        assert_eq!(nonzero_to_nonzero.0, 26_006);
        assert_eq!(nonzero_to_zero.0, 21_206);
        assert_eq!(no_op_zero.0, 23_206);
    }

    #[test]
    fn out_of_gas_sstore_reports_failure_without_committing_state() {
        let caller = Address([0x59; 20]);
        let target = Address([0x5a; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                code: vec![0x60, 0x02, 0x60, 0x00, 0x55, 0x00],
                ..Default::default()
            },
        );
        let mut transaction = tx(caller, Some(target), Vec::new());
        transaction.gas_limit = 21_000;
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &transaction)
            .expect("out-of-gas is an execution result");
        assert!(!output.success);
        assert!(output.gas_used <= transaction.gas_limit);
        assert!(!executor
            .state
            .accounts
            .get(&RevmAddress::from(target.0))
            .expect("target account")
            .storage
            .contains_key(&U256::ZERO));
    }

    #[test]
    fn emits_addressed_log_with_topic_and_data() {
        let caller = Address([0x71; 20]);
        let target = Address([0x72; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        state.put_account(
            RevmAddress::from(target.0),
            RevmAccount {
                // MSTORE(0, 42), then LOG1(offset=0, size=32, topic=1).
                code: vec![
                    0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x20, 0x60, 0x00, 0xa1, 0x00,
                ],
                ..Default::default()
            },
        );
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, Some(target), Vec::new()))
            .expect("log-producing call executes");
        assert!(output.success);
        assert_eq!(output.logs.len(), 1);
        assert_eq!(output.logs[0].address, target);
        let mut topic = [0u8; 32];
        topic[31] = 1;
        assert_eq!(output.logs[0].topics, vec![Hash256(topic)]);
        assert_eq!(output.logs[0].data.len(), 32);
        assert_eq!(output.logs[0].data[31], 0x2a);
    }

    #[test]
    fn creates_contract_and_persists_runtime_code() {
        let caller = Address([0x55; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(caller.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        let init_code = vec![
            0x60, 0x0a, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x0a, 0x60, 0x00, 0xf3, 0x60, 0x2a,
            0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let mut executor = RevmBlockExecutor::new(state);
        let output = executor
            .execute_transaction(&header(), &tx(caller, None, init_code))
            .expect("contract creation executes");
        assert!(output.success);
        assert!(executor.state.accounts.values().any(|account| account.code
            == vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]));
    }

    // A compact hand-assembled ERC-20 fixture keeps this compatibility test
    // independent of solc while exercising the same ABI selectors and storage
    // layout used by ordinary Solidity tokens.
    fn erc20_fixture() -> Vec<u8> {
        struct Program {
            code: Vec<u8>,
            labels: BTreeMap<&'static str, usize>,
            refs: Vec<(usize, &'static str)>,
        }
        impl Program {
            fn new() -> Self {
                Self {
                    code: Vec::new(),
                    labels: BTreeMap::new(),
                    refs: Vec::new(),
                }
            }
            fn op(&mut self, value: u8) {
                self.code.push(value);
            }
            fn push1(&mut self, value: u8) {
                self.op(0x60);
                self.op(value);
            }
            fn push4(&mut self, value: u32) {
                self.op(0x63);
                self.code.extend_from_slice(&value.to_be_bytes());
            }
            fn push32(&mut self, value: [u8; 32]) {
                self.op(0x7f);
                self.code.extend_from_slice(&value);
            }
            fn label(&mut self, name: &'static str) {
                self.labels.insert(name, self.code.len());
            }
            fn jump_to(&mut self, name: &'static str) {
                self.op(0x61);
                let at = self.code.len();
                self.code.extend_from_slice(&[0, 0]);
                self.refs.push((at, name));
            }
            fn finish(mut self) -> Vec<u8> {
                for (at, name) in self.refs {
                    let value = *self.labels.get(name).expect("fixture label") as u16;
                    self.code[at..at + 2].copy_from_slice(&value.to_be_bytes());
                }
                self.code
            }
        }

        let mut p = Program::new();
        p.push1(0);
        p.op(0x35);
        p.push1(0xe0);
        p.op(0x1c);
        for (selector, label) in [
            (0x1816_0ddd, "total_supply"),
            (0x70a0_8231, "balance_of"),
            (0xa905_9cbb, "transfer"),
        ] {
            p.op(0x80);
            p.push4(selector);
            p.op(0x14);
            p.jump_to(label);
            p.op(0x57);
        }
        p.push1(0);
        p.push1(0);
        p.op(0xfd);

        p.label("total_supply");
        p.op(0x5b);
        p.push1(0);
        p.op(0x54);
        p.push1(0);
        p.op(0x52);
        p.push1(0x20);
        p.push1(0);
        p.op(0xf3);

        p.label("balance_of");
        p.op(0x5b);
        p.push1(4);
        p.op(0x35);
        p.push1(0);
        p.op(0x52);
        p.push1(1);
        p.push1(0x20);
        p.op(0x52);
        p.push1(0x40);
        p.push1(0);
        p.op(0x20);
        p.op(0x54);
        p.push1(0);
        p.op(0x52);
        p.push1(0x20);
        p.push1(0);
        p.op(0xf3);

        p.label("transfer");
        p.op(0x5b);
        p.push1(4);
        p.op(0x35);
        p.push1(0);
        p.op(0x52);
        p.push1(0x24);
        p.op(0x35);
        p.push1(0x20);
        p.op(0x52);
        p.push1(0x20);
        p.op(0x51);
        p.push1(0xe0);
        p.op(0x52);
        p.op(0x33);
        p.push1(0x80);
        p.op(0x52);
        p.push1(1);
        p.push1(0xa0);
        p.op(0x52);
        p.push1(0x40);
        p.push1(0x80);
        p.op(0x20);
        p.op(0x54);
        p.push1(0x60);
        p.op(0x52);
        p.push1(0x60);
        p.op(0x54);
        p.push1(0xe0);
        p.op(0x51);
        p.op(0x10);
        p.jump_to("fail");
        p.op(0x57);
        p.push1(0xe0);
        p.op(0x51);
        p.push1(0x60);
        p.op(0x54);
        p.op(0x03);
        p.push1(0x60);
        p.op(0x52);
        p.push1(0x60);
        p.op(0x51);
        p.push1(0x40);
        p.push1(0x80);
        p.op(0x20);
        p.op(0x55);
        p.push1(1);
        p.push1(0x20);
        p.op(0x52);
        p.push1(0x40);
        p.push1(0);
        p.op(0x20);
        p.push1(0x80);
        p.op(0x54);
        p.push1(0xe0);
        p.op(0x51);
        p.op(0x01);
        p.push1(0x80);
        p.op(0x52);
        p.push1(0x80);
        p.op(0x51);
        p.push1(0x40);
        p.push1(0);
        p.op(0x20);
        p.op(0x55);
        p.push1(0xe0);
        p.op(0x51);
        p.push1(0);
        p.op(0x52);
        p.push1(0x33);
        p.push1(0x20);
        p.op(0x52);
        p.push32([
            0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37,
            0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d,
            0xf5, 0x23, 0xb3, 0xef,
        ]);
        p.push1(0x20);
        p.push1(0);
        p.op(0xa3);
        p.push1(1);
        p.push1(0);
        p.op(0x52);
        p.push1(0x20);
        p.push1(0);
        p.op(0xf3);

        p.label("fail");
        p.op(0x5b);
        p.push1(0);
        p.push1(0);
        p.op(0xfd);
        let runtime = p.finish();
        assert!(runtime.len() < 256);
        let mut init = vec![
            0x60,
            runtime.len() as u8,
            0x60,
            0x0c,
            0x60,
            0,
            0x39,
            0x60,
            runtime.len() as u8,
            0x60,
            0,
            0xf3,
        ];
        init.extend(runtime);
        init
    }

    #[test]
    fn erc20_abi_workflow_reads_balances_transfers_and_emits_event() {
        let owner = Address([0x11; 20]);
        let recipient = Address([0x22; 20]);
        let token = RevmAddress::from([0x33; 20]);
        let mut state = RevmState::default();
        state.put_account(
            RevmAddress::from(owner.0),
            RevmAccount {
                balance: U256::from(10u128.pow(18)),
                ..Default::default()
            },
        );
        let mut init_code = erc20_fixture();
        let runtime = init_code.split_off(12);
        let mut owner_key = [0u8; 64];
        owner_key[12..32].copy_from_slice(&owner.0);
        owner_key[63] = 1;
        let owner_slot = U256::from_be_bytes(keccak256(owner_key).0);
        let mut token_account = RevmAccount {
            code: runtime,
            ..Default::default()
        };
        token_account.storage.insert(U256::ZERO, U256::from(100u64));
        token_account.storage.insert(owner_slot, U256::from(100u64));
        state.put_account(token, token_account);
        let mut executor = RevmBlockExecutor::new(state);
        let mut supply = tx(
            owner,
            Some(Address(token.into_array())),
            vec![0x18, 0x16, 0x0d, 0xdd],
        );
        supply.nonce = 0;
        let output = executor
            .execute_transaction(&header(), &supply)
            .expect("totalSupply");
        assert!(output.success);
        assert_eq!(output.output.last().copied(), Some(100));
        let mut balance = tx(
            owner,
            Some(Address(token.into_array())),
            vec![0x70, 0xa0, 0x82, 0x31],
        );
        balance.payload.extend_from_slice(&[0; 12]);
        balance.payload.extend_from_slice(&owner.0);
        balance.nonce = 1;
        let output = executor
            .execute_transaction(&header(), &balance)
            .expect("balanceOf");
        assert!(output.success);
        assert_eq!(output.output.last().copied(), Some(100));
        let mut transfer = tx(
            owner,
            Some(Address(token.into_array())),
            vec![0xa9, 0x05, 0x9c, 0xbb],
        );
        transfer.payload.extend_from_slice(&[0; 12]);
        transfer.payload.extend_from_slice(&recipient.0);
        transfer.payload.extend_from_slice(&[0; 31]);
        transfer.payload.push(7);
        transfer.nonce = 2;
        let output = executor
            .execute_transaction(&header(), &transfer)
            .expect("transfer");
        assert!(output.success, "transfer reverted: {:?}", output);
        assert_eq!(output.logs.len(), 1);
        assert!(output.logs[0].topics.iter().any(|topic| {
            topic.0
                == [
                    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc,
                    0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5,
                    0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
                ]
        }));
        let mut recipient_balance = tx(
            owner,
            Some(Address(token.into_array())),
            vec![0x70, 0xa0, 0x82, 0x31],
        );
        recipient_balance.payload.extend_from_slice(&[0; 12]);
        recipient_balance.payload.extend_from_slice(&recipient.0);
        recipient_balance.nonce = 3;
        let output = executor
            .execute_transaction(&header(), &recipient_balance)
            .expect("recipient balanceOf");
        assert_eq!(output.output.last().copied(), Some(7));
        assert_eq!(executor.state.account(token).storage.len(), 3);
    }
}
