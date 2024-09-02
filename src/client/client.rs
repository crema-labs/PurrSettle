use std::vec;

use bitcoin::{Address, Amount, Network, ScriptBuf, TxOut, Txid};
use reqwest::{header, Client};
use serde::Deserialize;

use super::{error::MempoolClientError, types::MempoolTransaction};

#[derive(Deserialize, Debug)]
pub struct UtxoSpent {
    spent: bool,
}

pub struct MempoolClient {
    pub url: String,
    network: Network,
}

#[derive(Debug)]
pub struct UTXO {
    pub txid: Txid,
    pub vout: u32,
    pub amount: u64,
    pub spk: String,
}

impl Into<TxOut> for &UTXO {
    fn into(self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: ScriptBuf::from_hex(&self.spk).unwrap(),
        }
    }
}

impl MempoolClient {
    pub fn new(url: String, network: Network) -> MempoolClient {
        MempoolClient {
            url,
            network: network.into(),
        }
    }

    pub async fn get_utxos(&self, address: &Address) -> Result<Vec<UTXO>, MempoolClientError> {
        let tx_url = format!("{}/address/{}/txs", self.url, address);
        let spent_utxo_url = format!("{}/outspends", self.url);

        let client = Client::new();
        let mut response = client.get(tx_url).send().await?.text().await?;

        let txs: Vec<MempoolTransaction> = serde_json::from_str(&response)?;

        let mut required_outspends = vec![];

        for tx in txs.iter() {
            required_outspends.push(("txId[]", tx.txid.to_string()));
        }

        response = client
            .get(&spent_utxo_url)
            .query(&required_outspends)
            .send()
            .await?
            .text()
            .await?;

        let nested_outspends: Vec<Vec<UtxoSpent>> = serde_json::from_str(&response)?;
        let flat_outspends = nested_outspends
            .into_iter()
            .flatten()
            .collect::<Vec<UtxoSpent>>();

        let my_spk = address.script_pubkey().to_hex_string();

        let outputs = txs
            .into_iter()
            .flat_map(|tx| {
                tx.vout.into_iter().enumerate().map(move |(i, o)| UTXO {
                    amount: o.value,
                    spk: o.scriptpubkey,
                    txid: tx.txid,
                    vout: i as u32, //need this index early on
                })
            })
            .enumerate()
            .filter(|(i, _o)| flat_outspends[*i].spent == false)
            .filter(|(_i, o)| o.spk == my_spk)
            .map(|(_i, o)| o)
            .collect::<Vec<UTXO>>();

        Ok(outputs)
    }

    pub async fn broadcast(&self, tx_hex: String) -> Result<String, MempoolClientError> {
        let broadcast_url = format!("{}/tx", self.url);

        let client = Client::new();
        let response = client
            .post(broadcast_url)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(tx_hex)
            .send()
            .await?
            .text()
            .await?;

        return Ok(response);
    }
}
