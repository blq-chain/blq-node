use blq_pow::{blq_rx_hash, validate_pow_fields, PowError};
use blq_primitives::{
    genesis_header, receipts_root, transactions_root, Bix, Block, BlockHeader, Hash256,
    BLOCK_TIME_V2_FAST_MEDIAN_SECONDS, BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR,
    BLOCK_TIME_V2_NORMAL_CAP_NUMERATOR, BLOCK_TIME_V2_SLOW_CAP_DENOMINATOR,
    BLOCK_TIME_V2_SLOW_CAP_NUMERATOR, BLOCK_TIME_V2_SLOW_INTERVAL_SECONDS,
    BLOCK_TIME_V2_TARGET_SECONDS, BLQ_ISSUANCE_PER_INTERVAL_BIX, DIFFICULTY_ADJUSTMENT_INTERVAL,
    EIP1559_BASE_FEE_MAX_CHANGE_DENOMINATOR, EIP1559_ELASTICITY_MULTIPLIER, MAINNET_CHAIN_ID,
    MAX_ACCEPTABLE_BLOCK_TIME_SECONDS, MAX_ACCESS_LIST_ENTRIES, MAX_ACCESS_LIST_STORAGE_KEYS,
    MAX_ACCESS_LIST_STORAGE_KEYS_PER_ENTRY, MAX_BLOCK_BYTES, MAX_BURN_PERCENT,
    MAX_DIFFICULTY_ADJUSTMENT_PERCENT, MAX_TRANSACTION_PAYLOAD_BYTES, MAX_UTILIZATION_BASIS_POINTS,
    MIN_ACCEPTABLE_BLOCK_TIME_SECONDS, MIN_BURN_PERCENT, TARGET_BLOCK_TIME_SECONDS,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("block gas used exceeds gas limit")]
    GasUsedExceedsLimit,
    #[error("proof of work hash is above target")]
    InvalidProofOfWork,
    #[error("proof of work fields are invalid")]
    InvalidProofOfWorkFields,
    #[error("child block number does not follow parent")]
    InvalidBlockNumber,
    #[error("child timestamp is not greater than parent timestamp")]
    InvalidTimestamp,
    #[error("block parent hash does not match parent header hash")]
    InvalidParentHash,
    #[error("block exceeds the maximum canonical size")]
    BlockTooLarge,
    #[error("transactions root does not match block transactions")]
    InvalidTransactionsRoot,
    #[error("receipts root does not match block receipts")]
    InvalidReceiptsRoot,
    #[error("receipts length does not match transactions length")]
    ReceiptTransactionMismatch,
    #[error("transaction chain id is not the Block mainnet chain id")]
    InvalidTransactionChainId,
    #[error("transaction max fee per gas is below block base fee")]
    MaxFeeBelowBaseFee,
    #[error("transaction priority fee exceeds max fee")]
    PriorityFeeExceedsMaxFee,
    #[error("transaction type is unsupported")]
    UnsupportedTransactionType,
    #[error("transaction payload exceeds the maximum size")]
    TransactionPayloadTooLarge,
    #[error("transaction access list exceeds the maximum size")]
    AccessListTooLarge,
    #[error("block base fee does not match parent utilization")]
    InvalidBaseFee,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSplit {
    pub burn_percent: u8,
    pub miner_percent: u8,
}

impl FeeSplit {
    pub fn split_fee(self, fee: Bix) -> (Bix, Bix) {
        let burn = fee.0.saturating_mul(self.burn_percent as u128) / 100;
        (Bix(burn), Bix(fee.0.saturating_sub(burn)))
    }
}

pub fn block_subsidy_bix() -> Bix {
    Bix(BLQ_ISSUANCE_PER_INTERVAL_BIX / DIFFICULTY_ADJUSTMENT_INTERVAL as u128)
}

pub fn issuance_interval_remainder_bix() -> Bix {
    Bix(BLQ_ISSUANCE_PER_INTERVAL_BIX % DIFFICULTY_ADJUSTMENT_INTERVAL as u128)
}

pub fn block_reward_bix(block_number: u64) -> Bix {
    if block_number == 0 {
        return Bix(0);
    }
    let mut reward = block_subsidy_bix().0;
    if block_number % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        reward = reward.saturating_add(issuance_interval_remainder_bix().0);
    }
    Bix(reward)
}

pub fn block_reward_for_interval_bix(parent_timestamp: u64, child_timestamp: u64) -> Bix {
    let elapsed = child_timestamp
        .saturating_sub(parent_timestamp)
        .min(blq_primitives::MAX_REWARD_INTERVAL_SECONDS);
    Bix(BLQ_ISSUANCE_PER_INTERVAL_BIX.saturating_mul(elapsed as u128) / (10 * 60))
}

pub fn fee_split_for_utilization(utilization_basis_points: u64) -> FeeSplit {
    let bounded = utilization_basis_points.min(MAX_UTILIZATION_BASIS_POINTS);
    let burn_range = (MAX_BURN_PERCENT - MIN_BURN_PERCENT) as u64;
    let burn = MIN_BURN_PERCENT as u64 + (burn_range * bounded / MAX_UTILIZATION_BASIS_POINTS);
    FeeSplit {
        burn_percent: burn as u8,
        miner_percent: 100 - burn as u8,
    }
}

pub fn utilization_basis_points(gas_used: u64, gas_limit: u64) -> u64 {
    if gas_limit == 0 {
        return 0;
    }
    gas_used.saturating_mul(MAX_UTILIZATION_BASIS_POINTS) / gas_limit
}

pub fn validate_header(parent: &BlockHeader, child: &BlockHeader) -> Result<(), ConsensusError> {
    validate_header_with_genesis(parent, child, genesis_header().hash())
}

pub fn validate_header_with_genesis(
    parent: &BlockHeader,
    child: &BlockHeader,
    genesis_hash: Hash256,
) -> Result<(), ConsensusError> {
    if child.number.0 != parent.number.0 + 1 {
        return Err(ConsensusError::InvalidBlockNumber);
    }
    if child.timestamp_seconds <= parent.timestamp_seconds {
        return Err(ConsensusError::InvalidTimestamp);
    }
    if child.gas_used > child.gas_limit {
        return Err(ConsensusError::GasUsedExceedsLimit);
    }
    validate_pow_fields(child, genesis_hash).map_err(map_pow_error)?;
    if !satisfies_pow(
        blq_rx_hash(child, genesis_hash).final_hash,
        child.difficulty_target,
    ) {
        return Err(ConsensusError::InvalidProofOfWork);
    }
    Ok(())
}

pub fn validate_block(parent: &BlockHeader, block: &Block) -> Result<(), ConsensusError> {
    validate_block_with_genesis(parent, block, genesis_header().hash())
}

pub fn validate_block_with_genesis(
    parent: &BlockHeader,
    block: &Block,
    genesis_hash: Hash256,
) -> Result<(), ConsensusError> {
    validate_block_with_genesis_and_activation(parent, block, genesis_hash, Some(0))
}

/// Validate with a coordinated activation height for the canonical size rule.
/// `None` disables the rule; `Some(0)` enables it immediately.
pub fn validate_block_with_genesis_and_activation(
    parent: &BlockHeader,
    block: &Block,
    genesis_hash: Hash256,
    activation_height: Option<u64>,
) -> Result<(), ConsensusError> {
    validate_header_with_genesis(parent, &block.header, genesis_hash)?;
    if block.header.parent_hash != parent.hash() {
        return Err(ConsensusError::InvalidParentHash);
    }
    if block_size_rule_active(block.header.number.0, activation_height) {
        validate_block_size(block)?;
    }
    if block.transactions.len() != block.receipts.len() {
        return Err(ConsensusError::ReceiptTransactionMismatch);
    }
    if block.header.transactions_root != transactions_root(&block.transactions) {
        return Err(ConsensusError::InvalidTransactionsRoot);
    }
    if block.header.receipts_root != receipts_root(&block.receipts) {
        return Err(ConsensusError::InvalidReceiptsRoot);
    }
    if block.header.base_fee_per_gas != next_base_fee_per_gas(parent) {
        return Err(ConsensusError::InvalidBaseFee);
    }
    for transaction in &block.transactions {
        validate_transaction_fee(transaction, block.header.base_fee_per_gas)?;
    }
    Ok(())
}

fn block_size_rule_active(height: u64, activation_height: Option<u64>) -> bool {
    activation_height.is_some_and(|activation| height >= activation)
}

fn validate_block_size(block: &Block) -> Result<(), ConsensusError> {
    if block.canonical_bytes().len() > MAX_BLOCK_BYTES {
        return Err(ConsensusError::BlockTooLarge);
    }
    Ok(())
}

pub fn validate_transaction_fee(
    transaction: &blq_primitives::Transaction,
    base_fee_per_gas: Bix,
) -> Result<(), ConsensusError> {
    if transaction.chain_id != MAINNET_CHAIN_ID {
        return Err(ConsensusError::InvalidTransactionChainId);
    }
    if transaction.transaction_type > 2
        || (transaction.transaction_type == 0 && !transaction.access_list.is_empty())
    {
        return Err(ConsensusError::UnsupportedTransactionType);
    }
    if transaction.payload.len() > MAX_TRANSACTION_PAYLOAD_BYTES {
        return Err(ConsensusError::TransactionPayloadTooLarge);
    }
    if transaction.access_list.len() > MAX_ACCESS_LIST_ENTRIES
        || transaction
            .access_list
            .iter()
            .any(|item| item.storage_keys.len() > MAX_ACCESS_LIST_STORAGE_KEYS_PER_ENTRY)
        || transaction
            .access_list
            .iter()
            .map(|item| item.storage_keys.len())
            .sum::<usize>()
            > MAX_ACCESS_LIST_STORAGE_KEYS
    {
        return Err(ConsensusError::AccessListTooLarge);
    }
    if transaction.max_fee_per_gas.0 < base_fee_per_gas.0 {
        return Err(ConsensusError::MaxFeeBelowBaseFee);
    }
    if transaction.max_priority_fee_per_gas.0 > transaction.max_fee_per_gas.0 {
        return Err(ConsensusError::PriorityFeeExceedsMaxFee);
    }
    Ok(())
}

pub fn satisfies_pow(hash: Hash256, target: Hash256) -> bool {
    hash.0 <= target.0
}

fn map_pow_error(error: PowError) -> ConsensusError {
    match error {
        PowError::UnsupportedAlgorithm | PowError::InvalidEpoch | PowError::InvalidMixHash => {
            ConsensusError::InvalidProofOfWorkFields
        }
    }
}

pub fn next_difficulty_target(current_target: Hash256, actual_window_seconds: u64) -> Hash256 {
    let expected = TARGET_BLOCK_TIME_SECONDS * DIFFICULTY_ADJUSTMENT_INTERVAL;
    let bounded_actual = actual_window_seconds.clamp(expected / 4, expected * 4);
    scale_target(current_target, bounded_actual, expected)
}

pub fn next_block_difficulty_target(current_target: Hash256, actual_seconds: u64) -> Hash256 {
    if (MIN_ACCEPTABLE_BLOCK_TIME_SECONDS..=MAX_ACCEPTABLE_BLOCK_TIME_SECONDS)
        .contains(&actual_seconds)
    {
        return current_target;
    }
    let (numerator, denominator) = if actual_seconds > MAX_ACCEPTABLE_BLOCK_TIME_SECONDS {
        (100 + MAX_DIFFICULTY_ADJUSTMENT_PERCENT, 100)
    } else {
        (100 - MAX_DIFFICULTY_ADJUSTMENT_PERCENT, 100)
    };
    scale_target_fraction(current_target, numerator, denominator)
}

/// Deterministic V2 cadence controller. The caller supplies only canonical
/// history: the median of the preceding intervals and the latest confirmed
/// interval. The child timestamp never selects its own PoW target.
pub fn next_block_difficulty_target_v2(
    current_target: Hash256,
    median_interval_seconds: u64,
    latest_interval_seconds: u64,
) -> Hash256 {
    if median_interval_seconds < BLOCK_TIME_V2_FAST_MEDIAN_SECONDS {
        return scale_target_fraction(current_target, 75, 100);
    }
    if latest_interval_seconds >= BLOCK_TIME_V2_SLOW_INTERVAL_SECONDS {
        return scale_target_fraction(
            current_target,
            BLOCK_TIME_V2_SLOW_CAP_NUMERATOR,
            BLOCK_TIME_V2_SLOW_CAP_DENOMINATOR,
        );
    }

    let numerator = median_interval_seconds.saturating_mul(BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR);
    let denominator =
        BLOCK_TIME_V2_TARGET_SECONDS.saturating_mul(BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR);
    if numerator.saturating_mul(BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR)
        < denominator.saturating_mul(BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR - 1)
    {
        return scale_target_fraction(
            current_target,
            BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR - 1,
            BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR,
        );
    }
    if numerator.saturating_mul(BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR)
        > denominator.saturating_mul(BLOCK_TIME_V2_NORMAL_CAP_NUMERATOR)
    {
        return scale_target_fraction(
            current_target,
            BLOCK_TIME_V2_NORMAL_CAP_NUMERATOR,
            BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR,
        );
    }
    scale_target(current_target, numerator, denominator)
}

fn scale_target_fraction(target: Hash256, numerator: u64, denominator: u64) -> Hash256 {
    let (quotient, remainder) = divide_hash_with_remainder(target, denominator);
    let mut out = multiply_hash_u64(quotient, numerator);
    let mut carry = ((remainder as u128 * numerator as u128) / denominator as u128) as u128;
    for byte in out.0.iter_mut().rev() {
        let value = *byte as u128 + (carry & 0xff);
        *byte = (value & 0xff) as u8;
        carry = (carry >> 8) + (value >> 8);
    }
    if carry > 0 {
        Hash256([0xff; 32])
    } else {
        out
    }
}

fn scale_target(target: Hash256, numerator: u64, denominator: u64) -> Hash256 {
    if denominator == 0 {
        return Hash256([0xff; 32]);
    }
    let (quotient, remainder) = divide_hash_with_remainder(target, denominator);
    let mut out = multiply_hash_u64(quotient, numerator);
    let remainder = ((remainder as u128 * numerator as u128) / denominator as u128) as u64;
    let mut carry = remainder as u128;
    for byte in out.0.iter_mut().rev() {
        let value = *byte as u128 + (carry & 0xff);
        *byte = (value & 0xff) as u8;
        carry = (carry >> 8) + (value >> 8);
    }
    if carry > 0 {
        Hash256([0xff; 32])
    } else {
        out
    }
}

fn divide_hash_with_remainder(hash: Hash256, divisor: u64) -> (Hash256, u64) {
    let mut out = [0u8; 32];
    let mut remainder = 0u128;
    for (index, byte) in hash.0.iter().enumerate() {
        let value = (remainder << 8) + *byte as u128;
        out[index] = (value / divisor as u128) as u8;
        remainder = value % divisor as u128;
    }
    (Hash256(out), remainder as u64)
}

fn multiply_hash_u64(hash: Hash256, multiplier: u64) -> Hash256 {
    let mut out = hash.0;
    let mut carry = 0u128;
    for byte in out.iter_mut().rev() {
        let value = *byte as u128 * multiplier as u128 + carry;
        *byte = (value & 0xff) as u8;
        carry = value >> 8;
    }
    if carry > 0 {
        Hash256([0xff; 32])
    } else {
        Hash256(out)
    }
}

pub fn next_base_fee_per_gas(parent: &BlockHeader) -> Bix {
    let target_gas = (parent.gas_limit / EIP1559_ELASTICITY_MULTIPLIER).max(1);
    let parent_base_fee = parent.base_fee_per_gas.0;
    if parent.gas_used == target_gas {
        return parent.base_fee_per_gas;
    }
    if parent.gas_used > target_gas {
        let gas_delta = (parent.gas_used - target_gas) as u128;
        let change = (parent_base_fee * gas_delta
            / target_gas as u128
            / EIP1559_BASE_FEE_MAX_CHANGE_DENOMINATOR as u128)
            .max(1);
        return Bix(parent_base_fee.saturating_add(change));
    }
    let gas_delta = (target_gas - parent.gas_used) as u128;
    let change = parent_base_fee * gas_delta
        / target_gas as u128
        / EIP1559_BASE_FEE_MAX_CHANGE_DENOMINATOR as u128;
    Bix(parent_base_fee.saturating_sub(change))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blq_primitives::{
        Address, Transaction, TransactionAccessListItem, BIX_PER_BLQ, MAX_BURN_PERCENT,
        MAX_TRANSACTION_PAYLOAD_BYTES, MIN_BURN_PERCENT,
    };

    #[test]
    fn subsidy_tracks_interval_issuance_with_known_remainder() {
        let issued = (1..=DIFFICULTY_ADJUSTMENT_INTERVAL)
            .map(block_reward_bix)
            .map(|reward| reward.0)
            .sum::<u128>();
        assert_eq!(issued, BIX_PER_BLQ);
    }

    #[test]
    fn fee_burn_increases_with_utilization() {
        let empty = fee_split_for_utilization(0);
        let full = fee_split_for_utilization(MAX_UTILIZATION_BASIS_POINTS);
        assert_eq!(empty.burn_percent, MIN_BURN_PERCENT);
        assert_eq!(full.burn_percent, MAX_BURN_PERCENT);
        assert_eq!(empty.burn_percent + empty.miner_percent, 100);
        assert_eq!(full.burn_percent + full.miner_percent, 100);
        assert!(full.burn_percent > empty.burn_percent);
    }

    #[test]
    fn utilization_uses_integer_math() {
        assert_eq!(utilization_basis_points(15, 30), 5_000);
        assert_eq!(utilization_basis_points(0, 0), 0);
    }

    #[test]
    fn difficulty_retarget_preserves_target_at_expected_window() {
        let target = Hash256([0x0f; 32]);
        assert_eq!(
            next_difficulty_target(
                target,
                TARGET_BLOCK_TIME_SECONDS * DIFFICULTY_ADJUSTMENT_INTERVAL
            ),
            target
        );
    }

    #[test]
    fn difficulty_retarget_hardens_for_fast_blocks_without_overflow() {
        let target = Hash256([0x0f; 32]);
        let adjusted = next_difficulty_target(
            target,
            TARGET_BLOCK_TIME_SECONDS * DIFFICULTY_ADJUSTMENT_INTERVAL / 4,
        );
        assert!(adjusted.0 < target.0);
        assert_ne!(adjusted, Hash256([0xff; 32]));
    }

    #[test]
    fn per_block_difficulty_has_a_fifteen_to_forty_five_second_deadband() {
        let target = Hash256([0x0f; 32]);
        for seconds in 15..=45 {
            assert_eq!(next_block_difficulty_target(target, seconds), target);
        }
    }

    #[test]
    fn time_based_subsidy_targets_zero_point_one_blq_per_minute() {
        assert_eq!(block_reward_for_interval_bix(0, 30).0, BIX_PER_BLQ / 20);
        assert_eq!(block_reward_for_interval_bix(0, 15).0, BIX_PER_BLQ / 40);
        assert_eq!(block_reward_for_interval_bix(0, 60).0, BIX_PER_BLQ / 10);
        assert_eq!(
            block_reward_for_interval_bix(0, 1_000).0,
            BIX_PER_BLQ * 2 / 10
        );
    }

    #[test]
    fn per_block_difficulty_changes_by_at_most_twenty_five_percent() {
        let target = Hash256([0x0f; 32]);
        let slower = next_block_difficulty_target(target, 600);
        let faster = next_block_difficulty_target(target, 1);
        assert!(slower.0 > target.0);
        assert!(faster.0 < target.0);
        assert_eq!(slower, scale_target_fraction(target, 125, 100));
        assert_eq!(faster, scale_target_fraction(target, 75, 100));
    }

    #[test]
    fn v2_difficulty_targets_a_fifteen_second_median() {
        let target = Hash256([0x0f; 32]);
        assert_eq!(next_block_difficulty_target_v2(target, 15, 15), target);
        assert!(next_block_difficulty_target_v2(target, 10, 10).0 < target.0);
        assert!(next_block_difficulty_target_v2(target, 30, 30).0 > target.0);
    }

    #[test]
    fn v2_uses_emergency_fast_and_slow_bounds() {
        let target = Hash256([0x0f; 32]);
        assert_eq!(
            next_block_difficulty_target_v2(target, 2, 2),
            scale_target_fraction(target, 75, 100)
        );
        assert_eq!(
            next_block_difficulty_target_v2(target, 15, 60),
            scale_target_fraction(target, 9, 8)
        );
    }

    #[test]
    fn block_validation_rejects_bad_parent_hash() {
        let parent = blq_primitives::genesis_header();
        let mut child = parent.clone();
        child.number.0 = 1;
        child.timestamp_seconds = 10;
        child.parent_hash = Hash256([1; 32]);
        child.difficulty_target = Hash256([0xff; 32]);
        child.pow_epoch = blq_pow::epoch_for_height(child.number.0);
        child.mix_hash = blq_pow::blq_rx_hash(&child, parent.hash()).mix_hash;
        let block = Block {
            header: child,
            transactions: Vec::new(),
            receipts: Vec::new(),
        };
        assert_eq!(
            validate_block(&parent, &block),
            Err(ConsensusError::InvalidParentHash)
        );
    }

    #[test]
    fn canonical_block_size_is_limited_to_two_mebibytes() {
        let transaction = Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            value: Bix(0),
            gas_limit: 21_000,
            max_fee_per_gas: Bix(2),
            max_priority_fee_per_gas: Bix(0),
            payload: vec![0; MAX_TRANSACTION_PAYLOAD_BYTES],
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        };
        let block = Block {
            header: blq_primitives::genesis_header(),
            transactions: vec![transaction; 17],
            receipts: Vec::new(),
        };
        assert!(block.canonical_bytes().len() > MAX_BLOCK_BYTES);
        assert_eq!(
            validate_block_size(&block),
            Err(ConsensusError::BlockTooLarge)
        );
    }

    #[test]
    fn block_size_rule_activates_at_the_configured_height() {
        assert!(!block_size_rule_active(1_341, Some(1_342)));
        assert!(block_size_rule_active(1_342, Some(1_342)));
        assert!(block_size_rule_active(1_343, Some(1_342)));
        assert!(!block_size_rule_active(1_343, None));
    }

    #[test]
    fn base_fee_decreases_when_parent_is_empty() {
        let parent = blq_primitives::genesis_header();
        let next = next_base_fee_per_gas(&parent);
        assert!(next.0 < parent.base_fee_per_gas.0);
    }

    #[test]
    fn transaction_fee_validation_rejects_low_max_fee() {
        let tx = blq_primitives::Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: Address::ZERO,
            to: None,
            value: Bix(0),
            gas_limit: 21_000,
            max_fee_per_gas: Bix(1),
            max_priority_fee_per_gas: Bix(0),
            payload: Vec::new(),
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        };
        assert_eq!(
            validate_transaction_fee(&tx, Bix(2)),
            Err(ConsensusError::MaxFeeBelowBaseFee)
        );
    }

    #[test]
    fn transaction_shape_limits_are_consensus_invariants() {
        let mut tx = blq_primitives::Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            value: Bix(0),
            gas_limit: 21_000,
            max_fee_per_gas: Bix(2),
            max_priority_fee_per_gas: Bix(0),
            payload: vec![0; MAX_TRANSACTION_PAYLOAD_BYTES + 1],
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        };
        assert_eq!(
            validate_transaction_fee(&tx, Bix(2)),
            Err(ConsensusError::TransactionPayloadTooLarge)
        );

        tx.payload.clear();
        tx.transaction_type = 3;
        assert_eq!(
            validate_transaction_fee(&tx, Bix(2)),
            Err(ConsensusError::UnsupportedTransactionType)
        );

        tx.transaction_type = 0;
        tx.access_list.push(TransactionAccessListItem {
            address: Address::ZERO,
            storage_keys: Vec::new(),
        });
        assert_eq!(
            validate_transaction_fee(&tx, Bix(2)),
            Err(ConsensusError::UnsupportedTransactionType)
        );
    }
}
