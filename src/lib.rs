mod client;
mod schnorr;

use std::str::FromStr;

use bitcoin::{
    consensus::Encodable,
    ecdsa,
    opcodes::all::{OP_CAT, OP_CHECKSIG, OP_SWAP},
    script::Script,
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafNode, LeafVersion, TaprootBuilder},
    Address, Amount, EcdsaSighashType, KnownHrp, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

use bitcoin::hashes::Hash;
use client::client::UTXO;
use k256::elliptic_curve::point::AffineCoordinates;
use secp256k1::{All, PublicKey, SecretKey};

pub fn fr_p2tr_script(r: [u8; 32], pubkey: &XOnlyPublicKey) -> ScriptBuf {
    let builder = Script::builder();
    builder
        .push_slice(&r)
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CAT)
        .push_slice(pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn fr_p2tr_spk(
    secp: &secp256k1::Secp256k1<All>,
    my_pubkey: &XOnlyPublicKey,
    r: [u8; 32],
) -> Result<(ScriptBuf, Option<ControlBlock>), SpendFRP2TRError> {
    //This will never panic
    let pubkey =
        PublicKey::from_str("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
            .unwrap();

    let fr_script = fr_p2tr_script(r, &my_pubkey);
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, fr_script.clone())
        .map_err(|_| SpendFRP2TRError::ScriptError("Could not create taproot spend info".to_string()))?
        .finalize(secp, pubkey.x_only_public_key().0)
        .map_err(|_| {
            SpendFRP2TRError::ScriptError("Could not finalize taproot spend info".to_string())
        })?;

    let tweaked_pubkey = taproot_spend_info.output_key();

    let spk = Address::p2tr_tweaked(tweaked_pubkey, KnownHrp::Testnets).script_pubkey();

    Ok((
        spk,
        taproot_spend_info.control_block(&(fr_script, LeafVersion::TapScript)),
    ))
}

pub fn fr_p2tr_leaf_hash(pubkey: &XOnlyPublicKey, r: [u8; 32]) -> Option<TapLeafHash> {
    let fr_script = fr_p2tr_script(r, pubkey);
    LeafNode::new_script(fr_script.clone(), bitcoin::taproot::LeafVersion::TapScript).leaf_hash()
}

#[derive(Debug)]
pub enum TxError {
    SignatureFailed,
    Encoding,
}

pub fn spend_p2wpkh(
    secp: &secp256k1::Secp256k1<All>,
    sk: SecretKey,
    utxo: &UTXO,
    recipient: ScriptBuf,
) -> Result<String, TxError> {
    let input = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    };

    let output = TxOut {
        script_pubkey: recipient,
        value: Amount::from_sat(utxo.amount - 1000),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        input: vec![input],
        output: vec![output],
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
    };

    let mut sighash_cache = SighashCache::new(&tx);
    let hash = sighash_cache
        .p2wpkh_signature_hash(
            0,
            &ScriptBuf::from_hex(&utxo.spk).unwrap(),
            Amount::from_sat(utxo.amount),
            bitcoin::EcdsaSighashType::All,
        )
        .map_err(|_| TxError::SignatureFailed)?;

    let msg =
        secp256k1::Message::from_digest_slice(&hash[..]).map_err(|_| TxError::SignatureFailed)?;
    let signature = secp.sign_ecdsa(&msg, &sk);

    let ecdsa_signature = ecdsa::Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    };

    let witness = Witness::p2wpkh(&ecdsa_signature, &sk.public_key(&secp));

    tx.input[0].witness = witness;
    let mut tx_serialized = vec![];
    let _ = tx
        .consensus_encode(&mut tx_serialized)
        .map_err(|_| TxError::Encoding)?;

    let tx_hex = hex::encode(tx_serialized);

    return Ok(tx_hex);
}

#[derive(Debug)]
pub enum SpendFRP2TRError {
    TxError(TxError),
    ScriptError(String),
}

pub fn spend_fr_p2tr(
    secp: &secp256k1::Secp256k1<All>,
    sk: SecretKey,
    utxo: &UTXO,
    k_raw: [u8; 32],
    recipient: &Address,
) -> Result<String, SpendFRP2TRError> {
    let input = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    };

    let (_, R) = schnorr::utils::negate_if_odd_raw(k_raw)
        .map_err(|_| SpendFRP2TRError::ScriptError("Invalid nonce".to_string()))?;

    let my_x_only_pubkey = sk.x_only_public_key(secp).0;
    let r_x: [u8; 32] = R.x().try_into().map_err(|_| {
        SpendFRP2TRError::ScriptError("Could not convert nonce to bytes".to_string())
    })?;

    let (_, cb) = match fr_p2tr_spk(secp, &my_x_only_pubkey, r_x) {
        Ok((spk, Some(cb))) => (spk, cb),
        Ok((_, None)) => {
            return Err(SpendFRP2TRError::ScriptError(
                "Could not create script".to_string(),
            ))
        }
        Err(_) => {
            return Err(SpendFRP2TRError::ScriptError(
                "Could not create script".to_string(),
            ))
        }
    };

    let leaf_hash = fr_p2tr_leaf_hash(&my_x_only_pubkey, r_x).ok_or(
        SpendFRP2TRError::ScriptError("Could not create leaf hash".to_string()),
    )?;

    let output = TxOut {
        script_pubkey: recipient.script_pubkey(),
        value: Amount::from_sat(utxo.amount - 1000),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        input: vec![input],
        output: vec![output],
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
    };

    let tx_out: TxOut = utxo.into();
    let mut sighash_cache = SighashCache::new(&tx);
    let hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[tx_out]),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|_| SpendFRP2TRError::TxError(TxError::SignatureFailed))?;

    let msg = hash.to_byte_array();
    let signature = schnorr::sign(msg, sk, k_raw)
        .map_err(|_| SpendFRP2TRError::TxError(TxError::SignatureFailed))?;

    let mut writer = vec![];
    let script = fr_p2tr_script(
        signature[..32].try_into().unwrap(),
        &sk.x_only_public_key(&secp).0,
    );

    tx.input[0].witness.push(&signature[32..64]);
    tx.input[0].witness.push(script);
    cb.encode(&mut writer)
        .map_err(|_| SpendFRP2TRError::TxError(TxError::Encoding))?;
    tx.input[0].witness.push(writer.as_slice());

    let mut tx_serialized = vec![];
    let _ = tx
        .consensus_encode(&mut tx_serialized)
        .map_err(|_| SpendFRP2TRError::TxError(TxError::Encoding))?;
    let tx_hex = hex::encode(tx_serialized);
    return Ok(tx_hex);
}

#[derive(Debug)]
pub enum FrP2trEots<'a> {
    InvalidPubkey(&'a [u8]),
    Eots(schnorr::EOTSError),
}

fn get_signature_from_fr_p2tr(tx: &Transaction) -> Vec<u8> {
    let s = &tx.input[0].witness[0];
    let r = &tx.input[0].witness[1][1..(1 + 32)];

    return [r, s].concat();
}

fn get_hash_from_fr_p2tr<'a>(
    tx: &'a Transaction,
    tx_out: &TxOut,
) -> Result<[u8; 32], FrP2trEots<'a>> {
    let r: [u8; 32] = tx.input[0].witness[1][1..(1 + 32)].try_into().unwrap();
    let x_only_pubkey_slice = &tx.input[0].witness[1][(1 + 32 + 3)..(1 + 32 + 3 + 32)];
    let x_only_pubkey = XOnlyPublicKey::from_slice(x_only_pubkey_slice)
        .map_err(|_| FrP2trEots::InvalidPubkey(x_only_pubkey_slice))?;

    let leaf_hash = fr_p2tr_leaf_hash(&x_only_pubkey, r).unwrap();

    //since the transactions are broadcasted, we can assume that hash generation will not panic
    let mut sighash_cache = SighashCache::new(tx);
    let hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[tx_out]),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();
    let msg = hash.to_byte_array();

    Ok(msg)
}

pub fn extract_pk_from_fr_p2tr_txs<'a>(
    tx1: &'a Transaction,
    tx2: &'a Transaction,
    tx_out: &TxOut,
) -> Result<[u8; 32], FrP2trEots<'a>> {
    let sig1 = get_signature_from_fr_p2tr(tx1);
    let sig2 = get_signature_from_fr_p2tr(tx2);

    let x_only_pubkey =
        XOnlyPublicKey::from_slice(&tx1.input[0].witness[1][(1 + 32 + 3)..(1 + 32 + 3 + 32)])
            .map_err(|_| {
                FrP2trEots::InvalidPubkey(&tx1.input[0].witness[1][(1 + 32 + 3)..(1 + 32 + 3 + 32)])
            })?;

    // both transaction will have the same txout anyways
    let msg1 = get_hash_from_fr_p2tr(tx1, tx_out)?;
    let msg2 = get_hash_from_fr_p2tr(tx2, tx_out)?;

    let pk = schnorr::extract_pk_from_sigs([sig1, sig2], [msg1, msg2], x_only_pubkey)
        .map_err(|o| FrP2trEots::Eots(o))?;

    return Ok(pk);
}

#[cfg(test)]
mod tests {
    use crate::{
        client::client::{MempoolClient, UTXO},
        extract_pk_from_fr_p2tr_txs, fr_p2tr_spk,
        schnorr::utils::negate_if_odd_raw,
        spend_fr_p2tr, spend_p2wpkh,
    };
    use bitcoin::{
        address, consensus::Decodable, params::Params, Address, Amount, CompressedPublicKey,
        KnownHrp, NetworkKind, PrivateKey, Transaction, TxOut,
    };
    use k256::elliptic_curve::point::AffineCoordinates;
    use secp256k1::{Secp256k1, SecretKey};

    fn derive_pk() -> (SecretKey, CompressedPublicKey) {
        let pk_string = "f14871b9d7d8fb0bd791f97848eca7e37e04e1be034278139b39aaca611a4666";
        let hex = hex::decode(pk_string).expect("could not decode private key into hex");

        let secp = Secp256k1::new();
        let secret_key =
            secp256k1::SecretKey::from_slice(&hex.as_slice()).expect("invalid private key");
        let private_key = PrivateKey::new(secret_key, NetworkKind::Test);
        let compressed_pubkey = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("could not create compresed pubkey");

        (secret_key, compressed_pubkey)
    }

    fn get_mempool_client() -> MempoolClient {
        return MempoolClient::new(
            "https://catnet-mempool.btcwild.life/api/v1".to_string(),
            bitcoin::Network::Signet,
        );
    }

    fn get_bob_address() -> Address {
        let pk_string = "f14871b9d7d8fb0bd791f97848eca7e37e04e1be034278139b39aaca611a4665";
        let hex = hex::decode(pk_string).expect("could not decode private key into hex");

        let secp = Secp256k1::new();
        let secret_key =
            secp256k1::SecretKey::from_slice(&hex.as_slice()).expect("invalid private key");
        let private_key = PrivateKey::new(secret_key, NetworkKind::Test);
        let compressed_pubkey = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("could not create compresed pubkey");
        let address = Address::p2wpkh(&compressed_pubkey, KnownHrp::Testnets);

        return address;
    }

    #[tokio::test]
    async fn converts_p2wpkh_to_fr_p2tr() {
        let mempool_client = get_mempool_client();
        let (sk, compressed_pubkey) = derive_pk();
        let address = address::Address::p2wpkh(&compressed_pubkey, KnownHrp::Testnets);

        dbg!(&address);

        let secp = secp256k1::Secp256k1::new();
        let utxos = mempool_client.get_utxos(&address).await.unwrap();

        let mut k_prime = [0; 32];
        k_prime[31] = 1;
        let (_, R) = negate_if_odd_raw(k_prime).unwrap();

        let (spk, _) = fr_p2tr_spk(
            &secp,
            &sk.x_only_public_key(&secp).0,
            R.x().try_into().unwrap(),
        )
        .unwrap();

        let fr_pt2r_funding = spend_p2wpkh(&secp, sk, &utxos[0], spk).unwrap();

        let txid = mempool_client.broadcast(fr_pt2r_funding).await.unwrap();
        assert_eq!(txid.len(), 64);
        dbg!(txid);
    }

    #[tokio::test]
    async fn should_spend_fr_p2tr() {
        let mempool_client = get_mempool_client();
        let (sk, _) = derive_pk();

        let secp = secp256k1::Secp256k1::new();
        let mut k_prime = [0; 32];
        k_prime[31] = 1;
        let (_, R) = negate_if_odd_raw(k_prime).unwrap();

        let (spk, _) = fr_p2tr_spk(
            &secp,
            &sk.x_only_public_key(&secp).0,
            R.x().as_slice().try_into().unwrap(),
        )
        .unwrap();
        let address =
            Address::from_script(spk.as_script(), Params::new(bitcoin::Network::Signet)).unwrap();

        let utxos = mempool_client.get_utxos(&address).await.unwrap();
        let bob_address = get_bob_address();

        let spend_tx_hex = spend_fr_p2tr(&secp, sk, &utxos[0], k_prime, &bob_address).unwrap();

        let txid = mempool_client.broadcast(spend_tx_hex).await.unwrap();

        assert_eq!(txid.len(), 64);
        dbg!(txid);
    }

    #[tokio::test]
    async fn alice_double_spend_penalty() {
        let mempool_client = get_mempool_client();
        let (sk, compressed_pubkey) = derive_pk();
        let secp = secp256k1::Secp256k1::new();
        let mut k_prime = [0; 32];
        k_prime[31] = 1;
        let (_, R) = negate_if_odd_raw(k_prime).unwrap();
        let (spk, _) = fr_p2tr_spk(
            &secp,
            &sk.x_only_public_key(&secp).0,
            R.x().as_slice().try_into().unwrap(),
        )
        .unwrap();

        let alice_address = Address::p2wpkh(&compressed_pubkey, KnownHrp::Testnets);
        let bob_address = get_bob_address();

        let tx1_hex_vec = hex::decode("02000000000101159d850ed31028eca68045a35127f2015115c51352a7b75aa4505089e2f829a100000000000000000001b08e980000000000160014022dc0c50d6200d65d62a6e47328cc228ab9c52e03203531c5dbcff9d20d2f0abd30cfc92585feaabe06076c9603129902ed91f3f623452079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817987c7e20e1271d51c8ffc41374b937b9bdf019016985544e4d28580f4ded238335f44c58ac21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac000000000").unwrap();
        let mut tx1_hex = tx1_hex_vec.as_slice();
        let tx1 = Transaction::consensus_decode(&mut tx1_hex).unwrap();

        let tx2_hex_vec = hex::decode(
            spend_fr_p2tr(
                &secp,
                sk,
                &UTXO {
                    amount: 9999000,
                    spk: spk.to_hex_string(),
                    vout: tx1.input[0].previous_output.vout,
                    txid: tx1.input[0].previous_output.txid,
                },
                k_prime,
                &alice_address,
            )
            .unwrap()
            .as_bytes(),
        )
        .unwrap();
        let mut tx2_hex = tx2_hex_vec.as_slice();
        let tx2 = Transaction::consensus_decode(&mut tx2_hex).unwrap();

        assert_eq!(
            tx1.input[0].previous_output.txid,
            tx2.input[0].previous_output.txid
        );
        assert_eq!(
            tx1.input[0].previous_output.vout,
            tx2.input[0].previous_output.vout
        );

        assert_eq!(tx1.input[0].sequence, tx2.input[0].sequence);
        assert_eq!(tx1.input[0].script_sig, tx2.input[0].script_sig);

        assert_eq!(tx1.input[0].witness[1], tx2.input[0].witness[1]);
        assert_eq!(tx1.input[0].witness[2], tx2.input[0].witness[2]);

        let derived_pk = extract_pk_from_fr_p2tr_txs(
            &tx1,
            &tx2,
            &TxOut {
                script_pubkey: spk,
                value: Amount::from_sat(9999000),
            },
        )
        .unwrap();

        assert_eq!(derived_pk, sk.secret_bytes());

        let utxos = mempool_client.get_utxos(&alice_address).await.unwrap();

        dbg!(&utxos);

        let tx_hex = spend_p2wpkh(
            &secp,
            SecretKey::from_slice(&derived_pk).unwrap(),
            &utxos[0],
            bob_address.script_pubkey(),
        )
        .unwrap();

        let txid = mempool_client.broadcast(tx_hex).await.unwrap();
        dbg!(txid);
    }
}
