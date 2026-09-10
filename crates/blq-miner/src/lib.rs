use blq_consensus::{next_base_fee_per_gas, satisfies_pow};
use blq_pow::{blq_rx_hash, epoch_for_height};
use blq_primitives::{
    genesis_header, receipts_root, transactions_root, Block, BlockHeader, Hash256, Receipt,
    Transaction,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MinerError {
    #[error("mining is intentionally disabled in the bootstrap node")]
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTemplate {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub target: Hash256,
    pub pow_algorithm: &'static str,
    pub pow_epoch: u64,
    pub epoch_seed: Hash256,
}

impl BlockTemplate {
    pub fn into_unsealed_block(self) -> Block {
        Block {
            header: self.header,
            transactions: self.transactions,
            receipts: Vec::new(),
        }
    }
}

pub fn build_empty_template(
    parent: &BlockHeader,
    beneficiary: Hash256,
    timestamp_seconds: u64,
) -> BlockTemplate {
    build_empty_template_with_genesis(
        parent,
        beneficiary,
        timestamp_seconds,
        genesis_header().hash(),
    )
}

pub fn build_empty_template_with_genesis(
    parent: &BlockHeader,
    beneficiary: Hash256,
    timestamp_seconds: u64,
    genesis_hash: Hash256,
) -> BlockTemplate {
    let header = BlockHeader {
        parent_hash: parent.hash(),
        number: blq_primitives::BlockNumber(parent.number.0 + 1),
        state_root: parent.state_root,
        transactions_root: transactions_root(&[]),
        receipts_root: receipts_root(&[] as &[Receipt]),
        beneficiary,
        difficulty_target: parent.difficulty_target,
        base_fee_per_gas: next_base_fee_per_gas(parent),
        gas_limit: parent.gas_limit,
        gas_used: 0,
        timestamp_seconds,
        pow_algorithm: blq_pow::POW_ALGORITHM.to_string(),
        pow_epoch: epoch_for_height(parent.number.0 + 1),
        extra_nonce: 0,
        mix_hash: Hash256::ZERO,
        nonce: 0,
    };
    let epoch_seed = blq_pow::epoch_seed(header.pow_epoch, genesis_hash);
    BlockTemplate {
        target: header.difficulty_target,
        pow_algorithm: blq_pow::POW_ALGORITHM,
        pow_epoch: header.pow_epoch,
        epoch_seed,
        header,
        transactions: Vec::new(),
    }
}

pub fn seal_empty_template(
    template: BlockTemplate,
    nonce_start: u64,
    nonce_limit: u64,
) -> Option<BlockTemplate> {
    seal_empty_template_with_genesis(template, nonce_start, nonce_limit, genesis_header().hash())
}

pub fn seal_empty_template_with_genesis(
    mut template: BlockTemplate,
    nonce_start: u64,
    nonce_limit: u64,
    genesis_hash: Hash256,
) -> Option<BlockTemplate> {
    let end = nonce_start.saturating_add(nonce_limit);
    for nonce in nonce_start..end {
        template.header.nonce = nonce;
        let result = blq_rx_hash(&template.header, genesis_hash);
        template.header.mix_hash = result.mix_hash;
        if satisfies_pow(result.final_hash, template.target) {
            return Some(template);
        }
    }
    None
}

pub fn start_miner() -> Result<(), MinerError> {
    Err(MinerError::Disabled)
}
