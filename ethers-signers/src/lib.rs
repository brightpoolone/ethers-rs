//! Provides a unified interface for locally signing transactions.
#![deny(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

mod wallet;
pub use wallet::{MnemonicBuilder, Wallet, WalletError};

/// Re-export the BIP-32 crate so that wordlists can be accessed conveniently.
pub use coins_bip39;

/// A wallet instantiated with a locally stored private key
pub type LocalWallet = Wallet<ethers_core::k256::ecdsa::SigningKey>;

#[cfg(feature = "yubi")]
/// A wallet instantiated with a YubiHSM
pub type YubiWallet = Wallet<yubihsm::ecdsa::Signer<ethers_core::k256::Secp256k1>>;

#[cfg(feature = "ledger")]
mod ledger;
#[cfg(feature = "ledger")]
pub use ledger::{
    app::LedgerEthereum as Ledger,
    types::{DerivationType as HDPath, LedgerError},
};

#[cfg(feature = "trezor")]
mod trezor;
#[cfg(feature = "trezor")]
pub use trezor::{
    app::TrezorEthereum as Trezor,
    types::{DerivationType as TrezorHDPath, TrezorError},
};

#[cfg(feature = "yubi")]
pub use yubihsm;

#[cfg(feature = "aws")]
mod aws;

#[cfg(feature = "aws")]
pub use aws::{AwsSigner, AwsSignerError};

#[cfg(feature = "pkcs11")]
mod pkcs11;

#[cfg(feature = "pkcs11")]
pub use pkcs11::Pkcs11Signer;

use async_trait::async_trait;
use ethers_core::{
    k256::{
        ecdsa::{
            recoverable::{Id, Signature as RSig},
            Signature as KSig, VerifyingKey,
        },
        FieldBytes,
    },
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Address, Signature, U256,
    },
};
use std::error::Error;

/// Applies [EIP155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md)
pub fn to_eip155_v<T: Into<u8>>(recovery_id: T, chain_id: u64) -> u64 {
    (recovery_id.into() as u64) + 35 + chain_id * 2
}

/// Modify the v value of a signature to conform to eip155
fn apply_eip155(sig: &mut Signature, chain_id: u64) {
    sig.v = chain_id * 2 + 35 + ((sig.v - 1) % 2);
}

/// Makes a trial recovery to check whether an RSig corresponds to a known
/// `VerifyingKey`
fn check_candidate(sig: &RSig, digest: [u8; 32], vk: &VerifyingKey) -> bool {
    if let Ok(key) = sig.recover_verifying_key_from_digest_bytes(digest.as_ref().into()) {
        key == *vk
    } else {
        false
    }
}

/// Recover an rsig from a signature under a known key by trial/error
fn rsig_from_digest_bytes_trial_recovery(sig: &KSig, digest: [u8; 32], vk: &VerifyingKey) -> RSig {
    let sig_0 = RSig::new(sig, Id::new(0).unwrap()).unwrap();
    let sig_1 = RSig::new(sig, Id::new(1).unwrap()).unwrap();

    if check_candidate(&sig_0, digest, vk) {
        sig_0
    } else if check_candidate(&sig_1, digest, vk) {
        sig_1
    } else {
        panic!("bad sig");
    }
}

/// Converts a recoverable signature to an ethers signature
fn rsig_to_ethsig(sig: &RSig) -> Signature {
    let v: u8 = sig.recovery_id().into();
    let v = (v + 27) as u64;
    let r_bytes: FieldBytes = sig.r().into();
    let s_bytes: FieldBytes = sig.s().into();
    let r = U256::from_big_endian(r_bytes.as_slice());
    let s = U256::from_big_endian(s_bytes.as_slice());
    Signature { r, s, v }
}

/// Trait for signing transactions and messages
///
/// Implement this trait to support different signing modes, e.g. Ledger, hosted etc.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Signer: std::fmt::Debug + Send + Sync {
    type Error: Error + Send + Sync;
    /// Signs the hash of the provided message after prefixing it
    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error>;

    /// Signs the transaction
    async fn sign_transaction(&self, message: &TypedTransaction) -> Result<Signature, Self::Error>;

    /// Encodes and signs the typed data according EIP-712.
    /// Payload must implement Eip712 trait.
    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error>;

    /// Returns the signer's Ethereum Address
    fn address(&self) -> Address;

    /// Returns the signer's chain id
    fn chain_id(&self) -> u64;

    /// Sets the signer's chain id
    #[must_use]
    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self;
}
