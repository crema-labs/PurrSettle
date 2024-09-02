pub mod utils;

use bitcoin::XOnlyPublicKey;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::group::GroupEncoding;
use k256::{
    elliptic_curve::{point::AffineCoordinates, PrimeField},
    AffinePoint, Scalar,
};
use secp256k1::SecretKey;
use std::ops::Add;
use std::ops::Mul;
use utils::{negate_if_odd, tagged_hash};

#[derive(Debug)]
pub enum SchnorrError {
    InvalidPrivateKey,
    InvalidNonce,
    InvalidChallenge,
    InvalidSignature,
}

#[derive(Debug)]
pub enum EOTSError {
    SameNonce,
    InvalidSignature(u8),
    InvalidChallenge(u8),
    InvalidSignatureCombination,
}

/// Signs a message hash using the given secret key and nonce over the secp256k1 curve.
/// Follows the BIP-0340 standard for the signing process.
///
/// # Arguments
///
/// * `hash` - A 32-byte array representing the hash of the message to be signed.
/// * `sk` - The secret key used to sign the message. This key should be securely generated and stored.
/// * `k_raw` - A 32-byte array representing the nonce used during signing. This value should be
///            unique for each message.
///
/// # Returns
///
/// Returns a `Result` which, on success, contains a `Vec<u8>` representing the signature.
/// On failure, returns a `SchnorrError` indicating the reason for the failure.
pub fn sign(hash: [u8; 32], sk: SecretKey, k_raw: [u8; 32]) -> Result<Vec<u8>, SchnorrError> {
    let d_prime = Scalar::from_repr(sk.secret_bytes().into())
        .into_option()
        .ok_or(SchnorrError::InvalidPrivateKey)?;
    let (d, P) = negate_if_odd(d_prime);

    let (k, R) = negate_if_odd(
        Scalar::from_repr(k_raw.into())
            .into_option()
            .ok_or(SchnorrError::InvalidNonce)?,
    );

    let msg = [R.x(), P.x(), hash.into()].concat();

    let e_raw = tagged_hash("BIP0340/challenge", msg.as_slice());
    let e = Scalar::from_repr(e_raw.into())
        .into_option()
        .ok_or(SchnorrError::InvalidChallenge)?;

    let ed = e.mul(d);
    let k_plus_ed = k.add(&ed);

    let sig = [R.x(), k_plus_ed.to_bytes()].concat();

    return Ok(sig);
}

/// Verifies a Schnorr signature against a given public key and message hash.
///
/// This function checks if the provided Schnorr signature is valid for the given message hash
/// and public key. The verification is based on the BIP-0340 standard.
///
/// # Arguments
///
/// * `pubkey` - The public key against which the signature is verified. This should be in the
///              `XOnlyPublicKey` format, representing the public key in compressed form.
/// * `hash` - A 32-byte array representing the hash of the message that was supposedly signed.
/// * `sig` - A vector containing the signature to be verified. The signature is expected to be
///           64 bytes long, where the first 32 bytes represent the `r` value and the next
///           32 bytes represent the `s` value.
///
/// # Returns
///
/// Returns a `Result` which, on success, contains a boolean:
/// * `true` if the signature is valid.
/// * `false` if the signature is invalid, but the function executed without errors.
///
/// On failure, returns a `SchnorrError` indicating the reason for the failure.
pub fn verify(pubkey: XOnlyPublicKey, hash: [u8; 32], sig: &Vec<u8>) -> Result<bool, SchnorrError> {
    let P = pubkey.public_key(secp256k1::Parity::Even);
    let r_raw: &[u8; 32] = &sig[..32].try_into().unwrap();
    let s_raw: &[u8; 32] = &sig[32..64].try_into().unwrap();

    let msg = [r_raw, &pubkey.serialize()[..], &hash].concat();
    let e_raw = tagged_hash("BIP0340/challenge", msg.as_slice());
    let e = Scalar::from_repr(e_raw.into())
        .into_option()
        .ok_or(SchnorrError::InvalidChallenge)?;

    let s = Scalar::from_repr((*s_raw).into())
        .into_option()
        .ok_or(SchnorrError::InvalidSignature)?;
    let S = AffinePoint::generator().mul(s).to_affine();

    let eP = AffinePoint::from_bytes((&P.serialize()).into())
        .unwrap()
        .mul(e)
        .to_affine();

    let R = (S.to_curve() - eP).to_affine();

    if R.y_is_odd().into() {
        return Ok(false);
    }

    if R.x().as_slice() != r_raw {
        return Ok(false);
    }

    Ok(true)
}

/// Extracts a private key from two related Schnorr signatures and their corresponding message hashes.
///
/// This function is designed to recover the private key used to sign two different messages
/// with the same nonce. It assumes that the signatures were generated using the BIP-0340
/// Schnorr signature scheme. If the signatures are valid and the same nonce was used,
/// the private key can be extracted by computing the difference between the signatures
/// and their corresponding challenge scalars.
///
/// # Arguments
///
/// * `sigs` - An array containing two Schnorr signatures, each in the form of a 64-byte vector.
///            Each signature is expected to be 64 bytes long, where the first 32 bytes represent
///            the `r` value and the next 32 bytes represent the `s` value.
/// * `hashes` - A 2D array containing the two 32-byte message hashes corresponding to the signatures.
/// * `pubkey` - The public key associated with the private key being extracted, in the form of an
///              `XOnlyPublicKey`.
///
/// # Returns
///
/// Returns a `Result` which, on success, contains the 32-byte private key extracted from the signatures.
/// On failure, returns an `EOTSError` indicating the reason for the failure.
pub fn extract_pk_from_sigs(
    sigs: [Vec<u8>; 2],
    hashes: [[u8; 32]; 2],
    pubkey: XOnlyPublicKey,
) -> Result<[u8; 32], EOTSError> {
    let r1_raw: [u8; 32] = sigs[0][..32].try_into().unwrap();
    let s1_raw: [u8; 32] = sigs[0][32..64].try_into().unwrap();

    let r2_raw: [u8; 32] = sigs[1][..32].try_into().unwrap();
    let s2_raw: [u8; 32] = sigs[1][32..64].try_into().unwrap();

    if r1_raw != r2_raw {
        return Err(EOTSError::SameNonce);
    }

    let s1 = Scalar::from_repr(s1_raw.into())
        .into_option()
        .ok_or(EOTSError::InvalidSignature(0))?;
    let s2 = Scalar::from_repr(s2_raw.into())
        .into_option()
        .ok_or(EOTSError::InvalidSignature(1))?;

    let mut msg = [&r1_raw, &pubkey.serialize()[..], &hashes[0]].concat();
    let e1_raw = tagged_hash("BIP0340/challenge", msg.as_slice());

    msg = [&r2_raw, &pubkey.serialize()[..], &hashes[1]].concat();
    let e2_raw = tagged_hash("BIP0340/challenge", msg.as_slice());

    let hm1 = Scalar::from_repr(e1_raw.into())
        .into_option()
        .ok_or(EOTSError::InvalidChallenge(0))?;
    let hm2 = Scalar::from_repr(e2_raw.into())
        .into_option()
        .ok_or(EOTSError::InvalidChallenge(1))?;

    let numerator = s1.sub(&s2);
    let denominator = hm1.sub(&hm2);
    let inverse_denominator = denominator
        .invert()
        .into_option()
        .ok_or(EOTSError::InvalidSignatureCombination)?;

    let numerator = numerator.mul(inverse_denominator);

    return Ok(numerator.to_bytes().into());
}

#[cfg(test)]
mod tests {
    use k256::sha2::Digest;
    use k256::sha2::Sha256;
    use secp256k1::SecretKey;

    use crate::schnorr::tagged_hash;

    use super::extract_pk_from_sigs;
    use super::sign;
    use super::verify;

    fn sha256(msg: &[u8]) -> [u8; 32] {
        let mut sha256 = Sha256::new();
        sha256.update(msg);

        return sha256.finalize().into();
    }

    #[test]
    fn tagged_hash_works() {
        let tag = "BIP0340/challenge";
        let msg = "hello".as_bytes();
        let hash = tagged_hash(tag, msg);

        assert_eq!(
            hash,
            [
                169, 127, 244, 220, 89, 226, 225, 88, 192, 10, 125, 156, 241, 231, 214, 15, 176,
                144, 236, 245, 247, 40, 182, 209, 123, 231, 203, 187, 15, 197, 114, 221
            ]
        );
    }

    fn get_pk() -> SecretKey {
        let pk_string = "f14871b9d7d8fb0bd791f97848eca7e37e04e1be034278139b39aaca611a4666";
        let hex = hex::decode(pk_string).expect("could not decode private key into hex");

        secp256k1::SecretKey::from_slice(&hex.as_slice()).expect("invalid private key")
    }

    #[test]
    fn signing_should_work() {
        let hash: [u8; 32] = sha256("hello".as_bytes());
        let sk = get_pk();
        let mut nonce: [u8; 32] = [0u8; 32];
        nonce[31] = 1;

        let sig = sign(hash, sk, nonce).unwrap();
        let secp = secp256k1::Secp256k1::new();
        let ok = verify(sk.public_key(&secp).x_only_public_key().0, hash, &sig).unwrap();
        assert!(ok)
    }

    #[test]
    fn should_extract_pk() {
        let msg1 = sha256("hello1".as_bytes());
        let msg2 = sha256("hello2".as_bytes());

        let mut nonce: [u8; 32] = [0u8; 32];
        nonce[31] = 1;

        let pk = get_pk();
        let secp = secp256k1::Secp256k1::new();
        let sig1 = sign(msg1, pk, nonce).unwrap();
        let sig2 = sign(msg2, pk, nonce).unwrap();

        let extracted_pk = extract_pk_from_sigs(
            [sig1, sig2],
            [msg1, msg2],
            pk.public_key(&secp).x_only_public_key().0,
        );

        assert!(extracted_pk.unwrap() == pk.secret_bytes())
    }
}
