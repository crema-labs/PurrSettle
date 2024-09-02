use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::PrimeField;
use k256::sha2::{Digest, Sha256};
use k256::{AffinePoint, Scalar};
use std::ops::Mul;

pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);

    hasher.finalize().into()
}

pub fn sha256(msg: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    hasher.finalize().into()
}

pub fn negate_if_odd(d_prime: Scalar) -> (Scalar, AffinePoint) {
    let D = AffinePoint::generator().mul(d_prime).to_affine();
    if D.y_is_odd().into() {
        return (d_prime.negate(), D);
    }

    (d_prime, D)
}

pub(crate) fn negate_if_odd_raw(d_prime: [u8; 32]) -> Result<(Scalar, AffinePoint), String> {
    let d_prime = Scalar::from_repr(d_prime.into())
        .into_option()
        .ok_or("Invalid nonce".to_string())?;
    return Ok(negate_if_odd(d_prime));
}
