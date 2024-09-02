# PurrSettle

PurrSettle is a Rust-based tool designed to enhance Bitcoin script security by utilizing the OP_CAT operation to commit nonces in Bitcoin scripts. It is a proof-of-concept that ensures that UTXOs (Unspent Transaction Outputs) are never double-spent, and enforces that if a double-spend occurs, the perpetrator ends up revealing their private key. 

## Features
- Nonce Commitment: Uses OP_CAT to securely commit a nonce to Bitcoin scripts.
- Double-Spend Prevention: Ensures that even if a double-spend occurs, the perpetrator reveals the private key in the process. 

## Usage
The PurrSettle script generation can be found [here](./src/lib.rs) in the `fr_p2tr_script` function. The `fr` stands for Fixed R (which is the nonce). We have taken this terminology from this [paper](https://eprint.iacr.org/2017/394.pdf). Although this paper makes use of p2wpkh scripts, PurrSettle has been derived to work with p2tr scripts. This is because Schnorr Signatures are simple 64 byte signatures, where as p2wpkh makes use of ECDSA signatures. It is much harder to work with ECDSA signatures, because of variable length DER encoding (the lenght of `s` will not be known during script generation). Although still possible, this makes ECDSA signatures much more difficult to work with.

## Transactions
PurrSettle makes use of OP_CAT. While OP_CAT is currently disabled in the bitcoin mainnet, it is enabled in StarkWare's signet which you can find [here](https://catnet-mempool.btcwild.life/). 

You can find the spending transaction from the PurrSettle script [here](https://catnet-mempool.btcwild.life/tx/4bf1ef90ca0575c8aa951282a157fbe646b890829e1b54e7df16e3aafe86a0f5).

To see that you can use derive someone's private key, you can fund this address: `tb1qgjsm5082hykhttmx20s4rvwrf49v73qezdkmwh` [with this faucet](https://catnet-faucet.btcwild.life/) and once that's confirmed, you can run the `alice_double_spend_penalty` test case using `cargo test double_spend -- --nocapture`.
This test case will: 
- Derive the private key of the address (alice's address).
- Spend the funds to another address (bob's address) and logs the txid of the final settlement.

## License

PurrSettle is licensed under the [MIT license](./LICENSE).
