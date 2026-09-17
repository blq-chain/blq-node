use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const CHAIN_NAME: &str = "Block";
pub const TICKER: &str = "BLQ";
pub const NATIVE_DECIMALS: u8 = 18;
pub const BIX_PER_BLQ: u128 = 1_000_000_000_000_000_000;
pub const TARGET_BLOCK_TIME_SECONDS: u64 = 30;
pub const MIN_ACCEPTABLE_BLOCK_TIME_SECONDS: u64 = 15;
pub const MAX_ACCEPTABLE_BLOCK_TIME_SECONDS: u64 = 45;
pub const MAX_DIFFICULTY_ADJUSTMENT_PERCENT: u64 = 25;
/// Number of canonical inter-block intervals used by the V2 cadence controller.
pub const BLOCK_TIME_V2_MEDIAN_WINDOW: usize = 16;
pub const BLOCK_TIME_V2_TARGET_SECONDS: u64 = 15;
pub const BLOCK_TIME_V2_FAST_MEDIAN_SECONDS: u64 = 3;
pub const BLOCK_TIME_V2_SLOW_INTERVAL_SECONDS: u64 = 60;
pub const BLOCK_TIME_V2_NORMAL_CAP_NUMERATOR: u64 = 17;
pub const BLOCK_TIME_V2_NORMAL_CAP_DENOMINATOR: u64 = 16;
pub const BLOCK_TIME_V2_SLOW_CAP_NUMERATOR: u64 = 9;
pub const BLOCK_TIME_V2_SLOW_CAP_DENOMINATOR: u64 = 8;
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 60;
pub const BLQ_ISSUANCE_PER_INTERVAL_BIX: u128 = BIX_PER_BLQ;
pub const MAX_REWARD_INTERVAL_SECONDS: u64 = 120;
pub const MIN_BURN_PERCENT: u8 = 5;
pub const MAX_BURN_PERCENT: u8 = 40;
pub const MAX_UTILIZATION_BASIS_POINTS: u64 = 10_000;
pub const MAINNET_CHAIN_ID: u64 = 707_070;
pub const MAINNET_GENESIS_HASH: &str =
    "79a7f512edc606d2ef444382099b870edc0c4e78b82b8a3d81d758254e49d352";
pub const EMPTY_TRANSACTIONS_ROOT: Hash256 = Hash256([0; 32]);
pub const EMPTY_RECEIPTS_ROOT: Hash256 = Hash256([0; 32]);
pub const GENESIS_GAS_LIMIT: u64 = 30_000_000;
pub const GENESIS_TIMESTAMP_SECONDS: u64 = 0;
pub const GENESIS_DIFFICULTY_TARGET: Hash256 = Hash256([0x0f; 32]);
pub const INITIAL_BASE_FEE_PER_GAS_BIX: u128 = 1_000_000_000;
pub const EIP1559_ELASTICITY_MULTIPLIER: u64 = 2;
pub const EIP1559_BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;
pub const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 128 * 1024;
/// Maximum canonical serialized size of a block accepted by consensus.
pub const MAX_BLOCK_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ACCESS_LIST_ENTRIES: usize = 256;
pub const MAX_ACCESS_LIST_STORAGE_KEYS_PER_ENTRY: usize = 1_024;
pub const MAX_ACCESS_LIST_STORAGE_KEYS: usize = 4_096;
#[cfg(feature = "native-randomx")]
pub const DEFAULT_POW_ALGORITHM: &str = "BLQ-RX/2";
#[cfg(not(feature = "native-randomx"))]
pub const DEFAULT_POW_ALGORITHM: &str = "BLQ-RX/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeMode {
    Full,
    Partial,
}

impl NodeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0; 32]);

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(value: &str) -> Result<Self, HexHashError> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(trimmed).map_err(|_| HexHashError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(HexHashError::InvalidLength(bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HexHashError {
    InvalidHex,
    InvalidLength(usize),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub const ZERO: Self = Self([0; 20]);

    pub fn to_hex(self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn from_hex(value: &str) -> Result<Self, HexHashError> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(trimmed).map_err(|_| HexHashError::InvalidHex)?;
        if bytes.len() != 20 {
            return Err(HexHashError::InvalidLength(bytes.len()));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn from_word(value: Hash256) -> Self {
        let mut out = [0u8; 20];
        out.copy_from_slice(&value.0[12..]);
        Self(out)
    }

    pub fn to_word(self) -> Hash256 {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&self.0);
        Hash256(out)
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AddressVisitor;

        impl<'de> serde::de::Visitor<'de> for AddressVisitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a 20-byte Ethereum address as hex, or legacy byte array")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Address::from_hex(value).map_err(|err| E::custom(format!("{err:?}")))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                match bytes.len() {
                    20 => {
                        let mut out = [0u8; 20];
                        out.copy_from_slice(&bytes);
                        Ok(Address(out))
                    }
                    32 => {
                        let mut word = [0u8; 32];
                        word.copy_from_slice(&bytes);
                        Ok(Address::from_word(Hash256(word)))
                    }
                    len => Err(serde::de::Error::custom(format!(
                        "invalid address length {len}"
                    ))),
                }
            }
        }

        deserializer.deserialize_any(AddressVisitor)
    }
}

pub fn parse_beneficiary(value: &str) -> Result<Hash256, HexHashError> {
    match Address::from_hex(value) {
        Ok(address) => Ok(address.to_word()),
        Err(HexHashError::InvalidLength(20)) => unreachable!(),
        Err(_) => Hash256::from_hex(value),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bix(pub u128);

impl Serialize for Bix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Bix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BixVisitor;

        impl serde::de::Visitor<'_> for BixVisitor {
            type Value = Bix;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a decimal string or integer bix amount")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Bix(value as u128))
            }

            fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Bix(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value
                    .parse::<u128>()
                    .map(Bix)
                    .map_err(|_| E::custom("invalid bix amount"))
            }
        }

        deserializer.deserialize_any(BixVisitor)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockNumber(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    #[serde(default = "default_transaction_type")]
    pub transaction_type: u8,
    pub nonce: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub value: Bix,
    pub gas_limit: u64,
    pub max_fee_per_gas: Bix,
    #[serde(default)]
    pub max_priority_fee_per_gas: Bix,
    pub payload: Vec<u8>,
    #[serde(default)]
    pub access_list: Vec<TransactionAccessListItem>,
    #[serde(default)]
    pub signature: Option<TransactionSignature>,
    #[serde(default)]
    pub external_hash: Option<Hash256>,
}

fn default_transaction_type() -> u8 {
    2
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionAccessListItem {
    pub address: Address,
    pub storage_keys: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionSignature {
    pub y_parity: bool,
    pub r: Hash256,
    pub s: Hash256,
}

impl Transaction {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u64(&mut out, self.chain_id);
        put_u64(&mut out, self.nonce);
        put_address(&mut out, self.from);
        match self.to {
            Some(to) => {
                out.push(1);
                put_address(&mut out, to);
            }
            None => out.push(0),
        }
        put_u128(&mut out, self.value.0);
        put_u64(&mut out, self.gas_limit);
        put_u128(&mut out, self.max_fee_per_gas.0);
        put_u128(&mut out, self.max_priority_fee_per_gas.0);
        put_bytes(&mut out, &self.payload);
        // Preserve legacy and type-2 empty-list encoding so current block roots remain stable.
        // Typed transactions with access-list semantics carry their type in the root payload.
        if !self.access_list.is_empty() || self.transaction_type == 1 {
            out.push(0xa5);
            out.push(self.transaction_type);
            put_u64(&mut out, self.access_list.len() as u64);
            for item in &self.access_list {
                put_address(&mut out, item.address);
                put_u64(&mut out, item.storage_keys.len() as u64);
                for key in &item.storage_keys {
                    put_hash(&mut out, *key);
                }
            }
        }
        match &self.signature {
            Some(signature) => {
                out.push(1);
                out.push(u8::from(signature.y_parity));
                put_hash(&mut out, signature.r);
                put_hash(&mut out, signature.s);
            }
            None => out.push(0),
        }
        out
    }

    pub fn hash(&self) -> Hash256 {
        hash_bytes(&self.canonical_bytes())
    }

    pub fn rpc_hash(&self) -> Hash256 {
        self.external_hash.unwrap_or_else(|| self.hash())
    }
}

/// Encodes the EIP-1559 payload signed by an externally owned account.
///
/// This lives with the transaction model so operational tooling and the node
/// always produce exactly the same wire payload.
pub fn eip1559_signing_payload(transaction: &Transaction) -> Result<Vec<u8>, String> {
    if transaction.transaction_type != 2 {
        return Err(format!(
            "expected EIP-1559 transaction type 2, got {}",
            transaction.transaction_type
        ));
    }
    let recipient = transaction
        .to
        .map(|address| address.0.to_vec())
        .unwrap_or_default();
    Ok(eip1559_typed_rlp(
        &[
            eip1559_rlp_u64(transaction.chain_id),
            eip1559_rlp_u64(transaction.nonce),
            eip1559_rlp_u128(transaction.max_priority_fee_per_gas.0),
            eip1559_rlp_u128(transaction.max_fee_per_gas.0),
            eip1559_rlp_u64(transaction.gas_limit),
            eip1559_rlp_bytes(&recipient),
            eip1559_rlp_u128(transaction.value.0),
            eip1559_rlp_bytes(&transaction.payload),
            eip1559_encode_access_list(&transaction.access_list),
        ]
        .concat(),
    ))
}

/// Encodes a signed EIP-1559 transaction for `eth_sendRawTransaction`.
pub fn eip1559_signed_bytes(transaction: &Transaction) -> Result<Vec<u8>, String> {
    if transaction.transaction_type != 2 {
        return Err(format!(
            "expected EIP-1559 transaction type 2, got {}",
            transaction.transaction_type
        ));
    }
    let signature = transaction
        .signature
        .as_ref()
        .ok_or_else(|| "EIP-1559 transaction requires a signature".to_string())?;
    let recipient = transaction
        .to
        .map(|address| address.0.to_vec())
        .unwrap_or_default();
    Ok(eip1559_typed_rlp(
        &[
            eip1559_rlp_u64(transaction.chain_id),
            eip1559_rlp_u64(transaction.nonce),
            eip1559_rlp_u128(transaction.max_priority_fee_per_gas.0),
            eip1559_rlp_u128(transaction.max_fee_per_gas.0),
            eip1559_rlp_u64(transaction.gas_limit),
            eip1559_rlp_bytes(&recipient),
            eip1559_rlp_u128(transaction.value.0),
            eip1559_rlp_bytes(&transaction.payload),
            eip1559_encode_access_list(&transaction.access_list),
            eip1559_rlp_u64(u64::from(signature.y_parity)),
            eip1559_rlp_word(signature.r.0),
            eip1559_rlp_word(signature.s.0),
        ]
        .concat(),
    ))
}

fn eip1559_encode_access_list(access_list: &[TransactionAccessListItem]) -> Vec<u8> {
    let entries = access_list
        .iter()
        .map(|item| {
            let keys = eip1559_rlp_list(
                &item
                    .storage_keys
                    .iter()
                    .map(|key| eip1559_rlp_bytes(&key.0))
                    .collect::<Vec<_>>(),
            );
            eip1559_rlp_list(&[eip1559_rlp_bytes(&item.address.0), keys])
        })
        .collect::<Vec<_>>();
    eip1559_rlp_list(&entries)
}

fn eip1559_typed_rlp(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02];
    eip1559_rlp_list_payload(payload, &mut out);
    out
}

fn eip1559_rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let payload = fields.concat();
    let mut out = Vec::new();
    eip1559_rlp_list_payload(&payload, &mut out);
    out
}

fn eip1559_rlp_list_payload(payload: &[u8], out: &mut Vec<u8>) {
    eip1559_rlp_header(0xc0, payload.len(), out);
    out.extend_from_slice(payload);
}

fn eip1559_rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = Vec::new();
    eip1559_rlp_header(0x80, bytes.len(), &mut out);
    out.extend_from_slice(bytes);
    out
}

fn eip1559_rlp_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return eip1559_rlp_bytes(&[]);
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    eip1559_rlp_bytes(&bytes[first..])
}

fn eip1559_rlp_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return eip1559_rlp_bytes(&[]);
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(15);
    eip1559_rlp_bytes(&bytes[first..])
}

fn eip1559_rlp_word(value: [u8; 32]) -> Vec<u8> {
    if value.iter().all(|byte| *byte == 0) {
        return eip1559_rlp_bytes(&[]);
    }
    let first = value.iter().position(|byte| *byte != 0).unwrap_or(31);
    eip1559_rlp_bytes(&value[first..])
}

fn eip1559_rlp_header(offset: u8, len: usize, out: &mut Vec<u8>) {
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

impl BlockHeader {
    pub fn beneficiary_address(&self) -> Address {
        Address::from_word(self.beneficiary)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub transaction_hash: Hash256,
    pub success: bool,
    pub gas_used: u64,
    pub logs_root: Hash256,
    #[serde(default)]
    pub logs: Vec<LogEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub address: Address,
    pub topics: Vec<Hash256>,
    pub data: Vec<u8>,
}

impl LogEntry {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.address.0);
        put_u64(&mut out, self.topics.len() as u64);
        for topic in &self.topics {
            put_hash(&mut out, *topic);
        }
        put_bytes(&mut out, &self.data);
        out
    }
}

impl Receipt {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_hash(&mut out, self.transaction_hash);
        out.push(u8::from(self.success));
        put_u64(&mut out, self.gas_used);
        put_hash(&mut out, self.logs_root);
        if !self.logs.is_empty() {
            put_u64(&mut out, self.logs.len() as u64);
            for log in &self.logs {
                put_bytes(&mut out, &log.canonical_bytes());
            }
        }
        out
    }
}

pub fn logs_root(logs: &[LogEntry]) -> Hash256 {
    if logs.is_empty() {
        Hash256::ZERO
    } else {
        merkle_like_root(logs.iter().map(LogEntry::canonical_bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: Hash256,
    pub number: BlockNumber,
    pub state_root: Hash256,
    pub transactions_root: Hash256,
    pub receipts_root: Hash256,
    pub beneficiary: Hash256,
    pub difficulty_target: Hash256,
    #[serde(default = "default_base_fee")]
    pub base_fee_per_gas: Bix,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp_seconds: u64,
    #[serde(default = "default_pow_algorithm")]
    pub pow_algorithm: String,
    #[serde(default)]
    pub pow_epoch: u64,
    #[serde(default)]
    pub extra_nonce: u64,
    #[serde(default)]
    pub mix_hash: Hash256,
    pub nonce: u64,
}

impl BlockHeader {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_hash(&mut out, self.parent_hash);
        put_u64(&mut out, self.number.0);
        put_hash(&mut out, self.state_root);
        put_hash(&mut out, self.transactions_root);
        put_hash(&mut out, self.receipts_root);
        put_hash(&mut out, self.beneficiary);
        put_hash(&mut out, self.difficulty_target);
        put_u128(&mut out, self.base_fee_per_gas.0);
        put_u64(&mut out, self.gas_limit);
        put_u64(&mut out, self.gas_used);
        put_u64(&mut out, self.timestamp_seconds);
        put_bytes(&mut out, self.pow_algorithm.as_bytes());
        put_u64(&mut out, self.pow_epoch);
        put_u64(&mut out, self.extra_nonce);
        put_hash(&mut out, self.mix_hash);
        put_u64(&mut out, self.nonce);
        out
    }

    pub fn pow_preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_hash(&mut out, self.parent_hash);
        put_u64(&mut out, self.number.0);
        put_hash(&mut out, self.state_root);
        put_hash(&mut out, self.transactions_root);
        put_hash(&mut out, self.receipts_root);
        put_hash(&mut out, self.beneficiary);
        put_hash(&mut out, self.difficulty_target);
        put_u128(&mut out, self.base_fee_per_gas.0);
        put_u64(&mut out, self.gas_limit);
        put_u64(&mut out, self.gas_used);
        put_u64(&mut out, self.timestamp_seconds);
        put_bytes(&mut out, self.pow_algorithm.as_bytes());
        put_u64(&mut out, self.pow_epoch);
        put_u64(&mut out, self.extra_nonce);
        put_u64(&mut out, self.nonce);
        out
    }

    pub fn hash(&self) -> Hash256 {
        hash_bytes(&self.canonical_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub receipts: Vec<Receipt>,
}

impl Block {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.header.canonical_bytes();
        put_u64(&mut out, self.transactions.len() as u64);
        for transaction in &self.transactions {
            put_bytes(&mut out, &transaction.canonical_bytes());
        }
        put_u64(&mut out, self.receipts.len() as u64);
        for receipt in &self.receipts {
            put_bytes(&mut out, &receipt.canonical_bytes());
        }
        out
    }
}

pub fn genesis_header() -> BlockHeader {
    BlockHeader {
        parent_hash: Hash256::ZERO,
        number: BlockNumber(0),
        state_root: Hash256::ZERO,
        transactions_root: EMPTY_TRANSACTIONS_ROOT,
        receipts_root: EMPTY_RECEIPTS_ROOT,
        beneficiary: Hash256::ZERO,
        difficulty_target: GENESIS_DIFFICULTY_TARGET,
        base_fee_per_gas: Bix(INITIAL_BASE_FEE_PER_GAS_BIX),
        gas_limit: GENESIS_GAS_LIMIT,
        gas_used: 0,
        timestamp_seconds: GENESIS_TIMESTAMP_SECONDS,
        pow_algorithm: DEFAULT_POW_ALGORITHM.to_string(),
        pow_epoch: 0,
        extra_nonce: 0,
        mix_hash: Hash256::ZERO,
        nonce: 0,
    }
}

pub fn genesis_block() -> Block {
    Block {
        header: genesis_header(),
        transactions: Vec::new(),
        receipts: Vec::new(),
    }
}

pub fn transactions_root(transactions: &[Transaction]) -> Hash256 {
    merkle_like_root(transactions.iter().map(Transaction::canonical_bytes))
}

pub fn receipts_root(receipts: &[Receipt]) -> Hash256 {
    merkle_like_root(receipts.iter().map(Receipt::canonical_bytes))
}

pub fn hash_bytes(bytes: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Hash256(hasher.finalize().into())
}

fn merkle_like_root<I>(items: I) -> Hash256
where
    I: IntoIterator<Item = Vec<u8>>,
{
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    for item in items {
        count += 1;
        hasher.update((item.len() as u64).to_be_bytes());
        hasher.update(item);
    }
    if count == 0 {
        return Hash256::ZERO;
    }
    hasher.update(count.to_be_bytes());
    Hash256(hasher.finalize().into())
}

fn put_hash(out: &mut Vec<u8>, value: Hash256) {
    out.extend_from_slice(&value.0);
}

fn put_address(out: &mut Vec<u8>, value: Address) {
    out.extend_from_slice(&value.0);
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn default_chain_id() -> u64 {
    MAINNET_CHAIN_ID
}

fn default_base_fee() -> Bix {
    Bix(INITIAL_BASE_FEE_PER_GAS_BIX)
}

fn default_pow_algorithm() -> String {
    DEFAULT_POW_ALGORITHM.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_uses_compiled_pow_profile() {
        assert_eq!(genesis_header().pow_algorithm, DEFAULT_POW_ALGORITHM);
    }

    #[test]
    fn beneficiary_accepts_ethereum_address() {
        let word = parse_beneficiary("0x1111111111111111111111111111111111111111").unwrap();
        assert_eq!(
            word.to_hex(),
            "0000000000000000000000001111111111111111111111111111111111111111"
        );
        assert_eq!(
            Address::from_word(word).to_hex(),
            "0x1111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn beneficiary_still_accepts_legacy_word() {
        let word =
            parse_beneficiary("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        assert_eq!(
            word.to_hex(),
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn eip1559_encoding_requires_the_expected_type_and_signature() {
        let transaction = Transaction {
            chain_id: MAINNET_CHAIN_ID,
            transaction_type: 2,
            nonce: 0,
            from: Address::ZERO,
            to: Some(Address([0x11; 20])),
            value: Bix(0),
            gas_limit: 21_000,
            max_fee_per_gas: Bix(7),
            max_priority_fee_per_gas: Bix(0),
            payload: Vec::new(),
            access_list: Vec::new(),
            signature: None,
            external_hash: None,
        };
        let signing = eip1559_signing_payload(&transaction).unwrap();
        assert_eq!(signing[0], 0x02);
        assert!(eip1559_signed_bytes(&transaction).is_err());

        let mut wrong_type = transaction.clone();
        wrong_type.transaction_type = 1;
        assert!(eip1559_signing_payload(&wrong_type).is_err());
    }
}
