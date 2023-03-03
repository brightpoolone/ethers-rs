//! These utils are NOT meant for general usage. They are ONLY meant for use
//! within this module. They DO NOT perform basic safety checks and may panic
//! if used incorrectly.

use std::convert::TryFrom;

use ethers_core::{
    k256::{
        ecdsa::{Signature as KSig, VerifyingKey},
        elliptic_curve::sec1::ToEncodedPoint,
    },
    types::Address,
    utils::keccak256,
};
use rusoto_kms::{GetPublicKeyResponse, SignResponse};

use crate::aws::AwsSignerError;

/// Convert a verifying key to an ethereum address
pub(super) fn verifying_key_to_address(key: &VerifyingKey) -> Address {
    // false for uncompressed
    let uncompressed_pub_key = key.to_encoded_point(false);
    let public_key = uncompressed_pub_key.to_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    Address::from_slice(&hash[12..])
}

/// Decode an AWS KMS Pubkey response
pub(super) fn decode_pubkey(resp: GetPublicKeyResponse) -> Result<VerifyingKey, AwsSignerError> {
    let raw = resp
        .public_key
        .ok_or_else(|| AwsSignerError::from("Pubkey not found in response".to_owned()))?;

    let spk = spki::SubjectPublicKeyInfo::try_from(raw.as_ref())?;
    let key = VerifyingKey::from_sec1_bytes(spk.subject_public_key)?;

    Ok(key)
}

/// Decode an AWS KMS Signature response
pub(super) fn decode_signature(resp: SignResponse) -> Result<KSig, AwsSignerError> {
    let raw = resp
        .signature
        .ok_or_else(|| AwsSignerError::from("Signature not found in response".to_owned()))?;

    let sig = KSig::from_der(&raw)?;
    Ok(sig.normalize_s().unwrap_or(sig))
}
