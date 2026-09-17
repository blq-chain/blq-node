use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use alloy_primitives::keccak256;
use anyhow::{anyhow, bail, Context, Result};
use blq_primitives::{
    eip1559_signed_bytes, eip1559_signing_payload, Address, Bix, Hash256, Transaction,
    TransactionSignature, MAINNET_CHAIN_ID,
};
use clap::Parser;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::Serialize;
use serde_json::{json, Value};

const NODE39: &str = "http://192.0.2.39:8545";
const NODE43: &str = "http://192.0.2.43:8546";
const NODE201: &str = "http://192.0.2.201:8546";
const PUBLIC_RPC: &str = "https://rpc.blq-chain.online/rpc";
const EXPLORER: &str = "https://explorer.blq-chain.online";
const GAS_LIMIT: u64 = 21_000;
const MIN_MEMPOOL_FEE_PER_GAS: u128 = 1_000_000_000;

#[derive(Parser, Debug)]
#[command(about = "Bounded live validation of BLQ transaction gossip")]
struct Args {
    /// Required acknowledgement that this will mine and submit live transactions.
    #[arg(long)]
    live: bool,
    #[arg(long)]
    miner: PathBuf,
    #[arg(long)]
    node39: String,
    #[arg(long)]
    node43: String,
    #[arg(long)]
    node201: String,
    #[arg(long)]
    public_rpc: String,
    #[arg(long)]
    explorer: String,
    /// Destination for the redacted, public-only evidence JSON.
    #[arg(long)]
    report: PathBuf,
    #[arg(long, default_value_t = 120)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 4)]
    max_accepted_blocks: u64,
}

#[derive(Serialize)]
struct Evidence {
    account: String,
    started_height: u64,
    finished_height: u64,
    funding: FundingEvidence,
    transactions: Vec<TransactionEvidence>,
    passed: bool,
}

#[derive(Serialize)]
struct FundingEvidence {
    funded: bool,
    height: Option<u64>,
    elapsed_ms: u128,
}

#[derive(Serialize)]
struct TransactionEvidence {
    submitted_to: String,
    hash: String,
    accepted: bool,
    duplicate_harmless: bool,
    node39_pending_seen: bool,
    canonical_block: Option<u64>,
    receipt_visible: ReceiptEvidence,
    pending_removed: PendingEvidence,
    elapsed_ms: u128,
}

#[derive(Serialize)]
struct ReceiptEvidence {
    node39: bool,
    node43: bool,
    node201: bool,
    public_rpc: bool,
}

#[derive(Serialize)]
struct PendingEvidence {
    node39: bool,
    node43: bool,
    node201: bool,
    public_rpc: bool,
    explorer_proxy: bool,
}

struct MinerGuard {
    child: Option<Child>,
}

impl MinerGuard {
    fn start(miner: &PathBuf, beneficiary: &str) -> Result<Self> {
        let child = Command::new(miner)
            .args([
                "solo",
                "--node",
                "https://rpc.blq-chain.online/rpc",
                "--beneficiary",
                beneficiary,
                "--threads",
                "1",
                "--report-every",
                "60",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("could not start the bounded release miner")?;
        Ok(Self { child: Some(child) })
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for MinerGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.live {
        bail!("refusing live mining and transaction submission without --live");
    }
    validate_args(&args)?;
    let evidence = run(&args);
    match evidence {
        Ok(evidence) => {
            write_evidence(&args.report, &evidence)?;
            println!(
                "release gossip validation passed for {}; evidence: {}",
                evidence.account,
                args.report.display()
            );
            Ok(())
        }
        Err(error) => {
            let failure = json!({"passed": false, "error": redact_error(&error.to_string())});
            write_json(&args.report, &failure)?;
            Err(error)
        }
    }
}

fn validate_args(args: &Args) -> Result<()> {
    if !args.miner.is_file() {
        bail!("the supplied miner path is not a file");
    }
    for (given, expected, name) in [
        (&args.node39, NODE39, "node39"),
        (&args.node43, NODE43, "node43"),
        (&args.node201, NODE201, "node201"),
        (&args.public_rpc, PUBLIC_RPC, "public RPC"),
        (&args.explorer, EXPLORER, "explorer"),
    ] {
        if given.trim_end_matches('/') != expected.trim_end_matches('/') {
            bail!("{name} must use the approved release endpoint");
        }
    }
    if args.timeout_seconds < 30 || args.timeout_seconds > 300 {
        bail!("timeout-seconds must be between 30 and 300");
    }
    if !(3..=6).contains(&args.max_accepted_blocks) {
        bail!("max-accepted-blocks must be between 3 and 6");
    }
    Ok(())
}

fn run(args: &Args) -> Result<Evidence> {
    let deadline = Instant::now() + Duration::from_secs(args.timeout_seconds);
    let secret = disposable_secret()?;
    let account = address_for_secret(&secret);
    let account_text = account.to_hex();
    println!("using disposable release account {account_text}");

    let started_height = block_number(&args.node39)?;
    let gas_price = gas_price(&args.node39)?;
    let max_fee = gas_price.saturating_mul(2).max(MIN_MEMPOOL_FEE_PER_GAS);
    let required_balance = u128::from(GAS_LIMIT)
        .saturating_mul(max_fee)
        .saturating_mul(2);

    let funding_started = Instant::now();
    let funding_height = mine_until(args, &account_text, deadline, |height| {
        if height.saturating_sub(started_height) > args.max_accepted_blocks {
            return Err(anyhow!("accepted-block bound exceeded during funding"));
        }
        Ok(balance(&args.node39, &account_text)? >= required_balance)
    })?;
    let funding = FundingEvidence {
        funded: true,
        height: Some(funding_height),
        elapsed_ms: funding_started.elapsed().as_millis(),
    };
    if !wait_for_funding_convergence(args, &account_text, required_balance, deadline)? {
        bail!("funding block was not visible on every node before transaction validation");
    }

    let first = validate_transaction_path(
        args,
        &secret,
        account,
        0,
        "node43",
        &args.node43,
        max_fee,
        deadline,
        started_height,
    )?;
    let second = validate_transaction_path(
        args,
        &secret,
        account,
        1,
        "node201",
        &args.node201,
        max_fee,
        deadline,
        started_height,
    )?;
    let finished_height = block_number(&args.node39)?;
    if finished_height.saturating_sub(started_height) > args.max_accepted_blocks {
        bail!("accepted-block bound exceeded");
    }
    Ok(Evidence {
        account: account_text,
        started_height,
        finished_height,
        funding,
        transactions: vec![first, second],
        passed: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_transaction_path(
    args: &Args,
    secret: &SecretKey,
    account: Address,
    nonce: u64,
    label: &str,
    submit_endpoint: &str,
    max_fee: u128,
    deadline: Instant,
    started_height: u64,
) -> Result<TransactionEvidence> {
    let started = Instant::now();
    let (mut raw, hash) = signed_self_transfer(secret, account, nonce, max_fee)?;
    let hash_text = format!("0x{}", hash.to_hex());
    let accepted = submit_raw_transaction(submit_endpoint, &raw, &hash_text)?;
    let node39_pending_seen = wait_until(deadline, || pending_contains(&args.node39, &hash_text))?;
    if !node39_pending_seen {
        bail!("{label} transaction was not observed in node39's mempool before the deadline");
    }
    let duplicate_harmless = submit_raw_transaction(submit_endpoint, &raw, &hash_text)?;
    raw.fill(0);

    mine_until(args, &account.to_hex(), deadline, |height| {
        if height.saturating_sub(started_height) > args.max_accepted_blocks {
            return Err(anyhow!(
                "accepted-block bound exceeded while mining {label} transaction"
            ));
        }
        Ok(receipt_block(&args.node39, &hash_text)?.is_some())
    })?;
    let canonical_block = receipt_block(&args.node39, &hash_text)?;
    let receipts = wait_for_receipts(args, &hash_text, deadline)?;
    let pending_removed = wait_for_pending_removal(args, &hash_text, deadline)?;
    if !receipts.node39 || !receipts.node43 || !receipts.node201 || !receipts.public_rpc {
        bail!("{label} receipt was not visible from every required endpoint");
    }
    if !pending_removed.node39
        || !pending_removed.node43
        || !pending_removed.node201
        || !pending_removed.public_rpc
        || !pending_removed.explorer_proxy
    {
        bail!("{label} transaction remained active pending after canonical inclusion");
    }
    Ok(TransactionEvidence {
        submitted_to: label.to_string(),
        hash: hash_text,
        accepted,
        duplicate_harmless,
        node39_pending_seen,
        canonical_block,
        receipt_visible: receipts,
        pending_removed,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn mine_until<F>(args: &Args, beneficiary: &str, deadline: Instant, mut complete: F) -> Result<u64>
where
    F: FnMut(u64) -> Result<bool>,
{
    let mut miner = MinerGuard::start(&args.miner, beneficiary)?;
    let result = loop {
        if Instant::now() >= deadline {
            break Err(anyhow!("release validation deadline expired while mining"));
        }
        let height = block_number(&args.node39)?;
        if complete(height)? {
            break Ok(height);
        }
        thread::sleep(Duration::from_secs(1));
    };
    miner.stop();
    result
}

fn wait_for_receipts(args: &Args, hash: &str, deadline: Instant) -> Result<ReceiptEvidence> {
    wait_until(deadline, || {
        let evidence = ReceiptEvidence {
            node39: receipt_block(&args.node39, hash)?.is_some(),
            node43: receipt_block(&args.node43, hash)?.is_some(),
            node201: receipt_block(&args.node201, hash)?.is_some(),
            public_rpc: receipt_block_https(&args.public_rpc, hash)?.is_some(),
        };
        Ok(evidence.node39 && evidence.node43 && evidence.node201 && evidence.public_rpc)
    })?;
    Ok(ReceiptEvidence {
        node39: receipt_block(&args.node39, hash)?.is_some(),
        node43: receipt_block(&args.node43, hash)?.is_some(),
        node201: receipt_block(&args.node201, hash)?.is_some(),
        public_rpc: receipt_block_https(&args.public_rpc, hash)?.is_some(),
    })
}

fn wait_for_funding_convergence(
    args: &Args,
    address: &str,
    required_balance: u128,
    deadline: Instant,
) -> Result<bool> {
    wait_until(deadline, || {
        Ok(balance(&args.node39, address)? >= required_balance
            && balance(&args.node43, address)? >= required_balance
            && balance(&args.node201, address)? >= required_balance
            && balance_https(&args.public_rpc, address)? >= required_balance)
    })
}

fn wait_for_pending_removal(args: &Args, hash: &str, deadline: Instant) -> Result<PendingEvidence> {
    wait_until(deadline, || {
        let evidence = pending_evidence(args, hash)?;
        Ok(evidence.node39
            && evidence.node43
            && evidence.node201
            && evidence.public_rpc
            && evidence.explorer_proxy)
    })?;
    pending_evidence(args, hash)
}

fn pending_evidence(args: &Args, hash: &str) -> Result<PendingEvidence> {
    Ok(PendingEvidence {
        node39: !pending_contains(&args.node39, hash)?,
        node43: !pending_contains(&args.node43, hash)?,
        node201: !pending_contains(&args.node201, hash)?,
        public_rpc: !pending_contains_https(&args.public_rpc, hash)?,
        explorer_proxy: !pending_contains_https(&format!("{}/api/rpc", args.explorer), hash)?,
    })
}

fn wait_until<F>(deadline: Instant, mut check: F) -> Result<bool>
where
    F: FnMut() -> Result<bool>,
{
    loop {
        if check()? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn disposable_secret() -> Result<SecretKey> {
    let mut bytes = [0u8; 32];
    loop {
        getrandom::fill(&mut bytes).map_err(|_| anyhow!("OS randomness unavailable"))?;
        if let Ok(secret) = SecretKey::from_byte_array(bytes) {
            bytes.fill(0);
            return Ok(secret);
        }
    }
}

fn address_for_secret(secret: &SecretKey) -> Address {
    let public = PublicKey::from_secret_key(&Secp256k1::new(), secret).serialize_uncompressed();
    let digest = keccak256(&public[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest.0[12..]);
    Address(address)
}

fn signed_self_transfer(
    secret: &SecretKey,
    account: Address,
    nonce: u64,
    max_fee: u128,
) -> Result<(Vec<u8>, Hash256)> {
    let mut transaction = Transaction {
        chain_id: MAINNET_CHAIN_ID,
        transaction_type: 2,
        nonce,
        from: account,
        to: Some(account),
        value: Bix(0),
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: Bix(max_fee),
        max_priority_fee_per_gas: Bix(0),
        payload: Vec::new(),
        access_list: Vec::new(),
        signature: None,
        external_hash: None,
    };
    let payload = eip1559_signing_payload(&transaction).map_err(|error| anyhow!(error))?;
    let signature = Secp256k1::new()
        .sign_ecdsa_recoverable(Message::from_digest(keccak256(&payload).0), secret);
    let (recovery_id, compact) = signature.serialize_compact();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&compact[..32]);
    s.copy_from_slice(&compact[32..]);
    transaction.signature = Some(TransactionSignature {
        y_parity: i32::from(recovery_id) == 1,
        r: Hash256(r),
        s: Hash256(s),
    });
    let raw = eip1559_signed_bytes(&transaction).map_err(|error| anyhow!(error))?;
    Ok((raw.clone(), Hash256(keccak256(raw).0)))
}

fn submit_raw_transaction(endpoint: &str, raw: &[u8], expected_hash: &str) -> Result<bool> {
    let raw_hex = format!("0x{}", hex::encode(raw));
    let response = rpc_http(endpoint, "eth_sendRawTransaction", json!([raw_hex]))?;
    if response.get("result").and_then(Value::as_str) == Some(expected_hash) {
        return Ok(true);
    }
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if message.contains("known") || message.contains("duplicate") || message.contains("already") {
        return Ok(true);
    }
    let category = if message.contains("signature") {
        "signature"
    } else if message.contains("fee") || message.contains("gas") {
        "fee or gas"
    } else if message.contains("nonce") {
        "nonce"
    } else if message.contains("balance") {
        "balance"
    } else {
        "validation"
    };
    bail!("transaction submission was rejected by {category} validation")
}

fn block_number(endpoint: &str) -> Result<u64> {
    parse_quantity(rpc_http(endpoint, "eth_blockNumber", json!([]))?["result"].as_str())
}

fn gas_price(endpoint: &str) -> Result<u128> {
    parse_quantity_u128(rpc_http(endpoint, "eth_gasPrice", json!([]))?["result"].as_str())
}

fn balance(endpoint: &str, address: &str) -> Result<u128> {
    parse_quantity_u128(
        rpc_http(endpoint, "eth_getBalance", json!([address, "latest"]))?["result"].as_str(),
    )
}

fn balance_https(endpoint: &str, address: &str) -> Result<u128> {
    parse_quantity_u128(
        rpc_https(endpoint, "eth_getBalance", json!([address, "latest"]))?["result"].as_str(),
    )
}

fn receipt_block(endpoint: &str, hash: &str) -> Result<Option<u64>> {
    receipt_block_from(rpc_http(
        endpoint,
        "eth_getTransactionReceipt",
        json!([hash]),
    )?)
}

fn receipt_block_https(endpoint: &str, hash: &str) -> Result<Option<u64>> {
    receipt_block_from(rpc_https(
        endpoint,
        "eth_getTransactionReceipt",
        json!([hash]),
    )?)
}

fn receipt_block_from(response: Value) -> Result<Option<u64>> {
    let Some(receipt) = response.get("result").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    parse_quantity(receipt["blockNumber"].as_str()).map(Some)
}

fn pending_contains(endpoint: &str, hash: &str) -> Result<bool> {
    pending_contains_response(
        rpc_http(endpoint, "blq_pendingTransactions", json!([]))?,
        hash,
    )
}

fn pending_contains_https(endpoint: &str, hash: &str) -> Result<bool> {
    pending_contains_response(
        rpc_https(endpoint, "blq_pendingTransactions", json!([]))?,
        hash,
    )
}

fn pending_contains_response(response: Value, hash: &str) -> Result<bool> {
    let transactions = response["result"]
        .as_array()
        .ok_or_else(|| anyhow!("pending RPC response was malformed"))?;
    Ok(transactions.iter().any(|transaction| {
        transaction["hash"]
            .as_str()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(hash))
    }))
}

fn parse_quantity(value: Option<&str>) -> Result<u64> {
    u64::from_str_radix(
        value
            .and_then(|value| value.strip_prefix("0x"))
            .ok_or_else(|| anyhow!("RPC quantity was malformed"))?,
        16,
    )
    .context("RPC quantity was not a u64")
}

fn parse_quantity_u128(value: Option<&str>) -> Result<u128> {
    u128::from_str_radix(
        value
            .and_then(|value| value.strip_prefix("0x"))
            .ok_or_else(|| anyhow!("RPC quantity was malformed"))?,
        16,
    )
    .context("RPC quantity was not a u128")
}

fn rpc_http(endpoint: &str, method: &str, params: Value) -> Result<Value> {
    let address = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("direct RPC endpoint must use http"))?;
    if address.contains('/') {
        bail!("direct RPC endpoint must not contain a path");
    }
    let body =
        json!({"jsonrpc":"2.0", "id":"release-gossip-check", "method":method, "params":params})
            .to_string();
    let mut stream = TcpStream::connect_timeout(
        &address
            .parse()
            .context("direct RPC endpoint was malformed")?,
        Duration::from_secs(10),
    )
    .context("direct RPC transport failed")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(stream, "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        .context("direct RPC write failed")?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("direct RPC read failed")?;
    let (_, response_body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("direct RPC response was malformed"))?;
    serde_json::from_str(response_body).context("direct RPC JSON was malformed")
}

fn rpc_https(endpoint: &str, method: &str, params: Value) -> Result<Value> {
    let body =
        json!({"jsonrpc":"2.0", "id":"release-gossip-check", "method":method, "params":params})
            .to_string();
    let command = if cfg!(windows) { "curl.exe" } else { "curl" };
    let output = Command::new(command)
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "10",
            "--request",
            "POST",
            "--header",
            "content-type: application/json",
            "--data-binary",
            &body,
            endpoint,
        ])
        .output()
        .context("could not start HTTPS RPC client")?;
    if !output.status.success() {
        bail!("HTTPS RPC request failed");
    }
    serde_json::from_slice(&output.stdout).context("HTTPS RPC JSON was malformed")
}

fn write_evidence(path: &PathBuf, evidence: &Evidence) -> Result<()> {
    write_json(path, &serde_json::to_value(evidence)?)
}

fn write_json(path: &PathBuf, value: &Value) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("report path needs a parent directory"))?;
    fs::create_dir_all(parent).context("could not create report directory")?;
    fs::write(path, serde_json::to_vec_pretty(value)?).context("could not write redacted evidence")
}

fn redact_error(error: &str) -> &'static str {
    if error.contains("deadline") {
        "validation deadline expired"
    } else if error.contains("receipt") {
        "receipt visibility validation failed"
    } else if error.contains("pending") {
        "pending removal validation failed"
    } else if error.contains("submission") {
        "transaction submission validation failed"
    } else {
        "release gossip validation failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_redacted_by_shape() {
        let report = Evidence {
            account: "0x1111111111111111111111111111111111111111".to_string(),
            started_height: 1,
            finished_height: 4,
            funding: FundingEvidence {
                funded: true,
                height: Some(2),
                elapsed_ms: 1,
            },
            transactions: Vec::new(),
            passed: true,
        };
        let text = serde_json::to_string(&report).unwrap().to_ascii_lowercase();
        assert!(!text.contains("secret"));
        assert!(!text.contains("private"));
        assert!(!text.contains("raw"));
    }

    #[test]
    fn miner_guard_stops_a_child() {
        let mut command = if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/C", "ping -n 30 127.0.0.1 >NUL"]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 30"]);
            command
        };
        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut guard = MinerGuard { child: Some(child) };
        guard.stop();
        assert!(guard.child.is_none());
    }
}
