use bitcoin::{absolute::LockTime, block::Version, Txid};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MempoolTransaction {
    pub(crate) txid: Txid,
    version: Version,
    locktime: LockTime,
    size: u32,
    weight: u32,
    fee: u64,
    vin: Vec<Input>,
    pub(crate) vout: Vec<Output>,
    status: Status,
}

#[derive(Debug, Serialize, Deserialize)]
struct Input {
    is_coinbase: bool,
    prevout: Option<Prevout>,
    scriptsig: String,
    scriptsig_asm: String,
    sequence: u64,
    txid: Txid,
    vout: u32,
    witness: Vec<String>,
    inner_redeemscript_asm: String,
    inner_witnessscript_asm: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Prevout {
    value: i64,
    scriptpubkey: String,
    scriptpubkey_address: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub(crate) value: u64,
    pub(crate) scriptpubkey: String,
    pub(crate) scriptpubkey_address: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Status {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
    block_time: Option<u64>,
}
