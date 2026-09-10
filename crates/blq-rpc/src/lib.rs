use blq_primitives::{BlockHeader, Hash256, NodeMode, CHAIN_NAME, MAINNET_CHAIN_ID, TICKER};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInfo {
    pub name: &'static str,
    pub ticker: &'static str,
    pub node_mode: &'static str,
    pub best_block: u64,
    pub best_hash: String,
}

#[derive(Clone, Debug)]
pub struct RpcSnapshot {
    pub best_header: BlockHeader,
    pub node_mode: NodeMode,
}

impl RpcSnapshot {
    pub fn handle_json_rpc(&self, body: &str) -> String {
        let parsed: Value = match serde_json::from_str(body) {
            Ok(value) => value,
            Err(_) => return error_response(Value::Null, -32700, "parse error"),
        };
        let id = parsed.get("id").cloned().unwrap_or(Value::Null);
        let method = parsed.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "eth_chainId" => json!(format!("0x{:x}", MAINNET_CHAIN_ID)),
            "net_version" => json!(MAINNET_CHAIN_ID.to_string()),
            "web3_clientVersion" => json!("blq/0.1.0"),
            "eth_blockNumber" => json!(format!("0x{:x}", self.best_header.number.0)),
            "eth_gasPrice" => {
                json!(format!("0x{:x}", self.best_header.base_fee_per_gas.0))
            }
            "eth_maxPriorityFeePerGas" => json!("0x0"),
            "eth_syncing" => json!(false),
            "eth_mining" => json!(false),
            "eth_hashrate" => json!("0x0"),
            "eth_coinbase" => json!("0x0000000000000000000000000000000000000000"),
            "eth_getBlockByNumber" => json!({
                "number": format!("0x{:x}", self.best_header.number.0),
                "hash": self.best_header.hash().to_hex(),
                "parentHash": self.best_header.parent_hash.to_hex(),
                "gasLimit": format!("0x{:x}", self.best_header.gas_limit),
                "gasUsed": format!("0x{:x}", self.best_header.gas_used),
                "baseFeePerGas": format!("0x{:x}", self.best_header.base_fee_per_gas.0),
                "powAlgorithm": self.best_header.pow_algorithm,
                "powEpoch": format!("0x{:x}", self.best_header.pow_epoch),
                "mixHash": self.best_header.mix_hash.to_hex(),
            }),
            "blq_chainInfo" => json!(ChainInfo::from_header(self.node_mode, &self.best_header)),
            "blq_health" => json!({
                "status": "ok",
                "nodeMode": self.node_mode.as_str(),
                "mining": false,
                "bestBlock": self.best_header.number.0,
                "bestHash": self.best_header.hash().to_hex(),
            }),
            "blq_status" => json!({
                "generationId": 0,
                "activeTip": {
                    "height": self.best_header.number.0,
                    "hash": self.best_header.hash().to_hex(),
                    "stateRoot": self.best_header.state_root.to_hex(),
                },
                "candidateTip": Value::Null,
                "candidateWork": Value::Null,
                "replayProgress": Value::Null,
                "replayStatus": "active",
                "publicationPending": false,
                "miningSafety": {
                    "safe": false,
                    "reason": "snapshot fallback",
                },
            }),
            "blq_powSpec" => json!({
                "algorithm": blq_pow::POW_ALGORITHM,
                "epochLength": blq_pow::POW_EPOCH_LENGTH,
                "datasetBytes": blq_pow::POW_DATASET_BYTES,
                "lightCacheBytes": blq_pow::POW_LIGHT_CACHE_BYTES,
                "finalHashDomain": "BLQ-POW-FINAL",
            }),
            "eth_getBalance"
            | "eth_getTransactionCount"
            | "eth_sendRawTransaction"
            | "eth_getTransactionByHash"
            | "eth_getLogs"
            | "eth_call"
            | "eth_estimateGas" => {
                return error_response(id, -32000, "stateful EVM RPC is not implemented yet")
            }
            "blq_getBlockTemplate" => json!(empty_block_template_response(&self.best_header)),
            _ => return error_response(id, -32601, "method not found"),
        };
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })
        .to_string()
    }
}

fn empty_block_template_response(parent: &BlockHeader) -> Value {
    let timestamp = parent.timestamp_seconds.saturating_add(1);
    let template = blq_miner::build_empty_template(parent, Hash256::ZERO, timestamp);
    json!({
        "warning": "empty template only; transaction execution is not enabled yet",
        "chainId": MAINNET_CHAIN_ID,
        "height": template.header.number.0,
        "parentHash": template.header.parent_hash.to_hex(),
        "target": template.target.to_hex(),
        "difficultyTarget": template.header.difficulty_target.to_hex(),
        "baseFeePerGas": format!("0x{:x}", template.header.base_fee_per_gas.0),
        "gasLimit": format!("0x{:x}", template.header.gas_limit),
        "beneficiary": template.header.beneficiary_address().to_hex(),
        "beneficiaryWord": template.header.beneficiary.to_hex(),
        "transactions": [],
        "transactionsRoot": template.header.transactions_root.to_hex(),
        "receiptsRoot": template.header.receipts_root.to_hex(),
        "stateRoot": template.header.state_root.to_hex(),
        "powAlgorithm": template.pow_algorithm,
        "powEpoch": template.pow_epoch,
        "epochSeed": template.epoch_seed.to_hex(),
        "nonceRange": ["0x0", "0xffffffffffffffff"],
    })
}

fn error_response(id: Value, code: i64, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
    .to_string()
}

impl ChainInfo {
    pub fn from_header(node_mode: NodeMode, header: &BlockHeader) -> Self {
        Self {
            name: CHAIN_NAME,
            ticker: TICKER,
            node_mode: node_mode.as_str(),
            best_block: header.number.0,
            best_hash: header.hash().to_hex(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn common_ethereum_probes_are_deterministic() {
        let snapshot = RpcSnapshot {
            best_header: blq_primitives::genesis_header(),
            node_mode: NodeMode::Full,
        };
        for (method, expected) in [
            ("net_version", "707070"),
            ("web3_clientVersion", "blq/0.1.0"),
            ("eth_maxPriorityFeePerGas", "0x0"),
            ("eth_hashrate", "0x0"),
        ] {
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":[]}}"#);
            let response: Value = serde_json::from_str(&snapshot.handle_json_rpc(&body)).unwrap();
            assert_eq!(response["result"], expected);
        }
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_syncing","params":[]}"#;
        let response: Value = serde_json::from_str(&snapshot.handle_json_rpc(body)).unwrap();
        assert_eq!(response["result"], false);
    }
}
