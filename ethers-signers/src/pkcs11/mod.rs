use super::{apply_eip155, rsig_from_digest_bytes_trial_recovery, rsig_to_ethsig};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
};
use ethers_core::{
    k256::ecdsa::{Error as KError, Signature as KSig, VerifyingKey},
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Address, Signature, H256,
    },
    utils::{hash_message, keccak256},
};
use std::{fmt, path::Path};

#[derive(Clone)]
pub struct Pkcs11Signer {
    pkcs11: Pkcs11,
    slot: Slot,
    pin: String,
    chain_id: u64,
    priv_key_handle: ObjectHandle,
    address: Address,
    pubkey: VerifyingKey,
}

impl fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("slot", &self.slot.id())
            .field("chain_id", &self.chain_id)
            .field("address", &self.address)
            .field("pubkey", &hex::encode(self.pubkey.to_bytes()))
            .finish()
    }
}

impl fmt::Display for Pkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pkcs11Signer {{ address: {}, chain_id: {}, slot: {} }}",
            self.address,
            self.chain_id,
            self.slot.id()
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Pkcs11SignerError {
    #[error("{0}")]
    Cryptoki(#[from] cryptoki::error::Error),
    #[error("error encoding eip712 struct: {0:?}")]
    Eip712Error(String),
    #[error("{0}")]
    K256Error(#[from] KError),
    #[error("slot not found")]
    SlotNotFound,
    #[error("key not found")]
    KeyNotFound,
    #[error("key params not found")]
    KeyParamsNotFound,
    #[error("wrong key")]
    WrongKey,
    #[error("wrong key params")]
    WrongKeyParams,
}

/// Secp256k1 curve OID: 06052b8104000a
const EC_SECP256K1: [u8; 7] = [6, 5, 43, 129, 4, 0, 10];

/// Find card slot with a given serial number.
fn get_slot_with_serial_number(
    pkcs11: &Pkcs11,
    serial_number: &str,
) -> Result<Slot, Pkcs11SignerError> {
    let slots = pkcs11.get_slots_with_initialized_token()?;
    for slot in slots {
        if let Ok(info) = pkcs11.get_token_info(slot) {
            if serial_number == info.serial_number() {
                return Ok(slot);
            }
        }
    }
    Err(Pkcs11SignerError::SlotNotFound)
}

impl Pkcs11Signer {
    /// Instantiate a new signer.
    pub fn new(
        module_path: &Path,
        serial_number: &str,
        pin: String,
        key_id: Vec<u8>,
        chain_id: u64,
    ) -> Result<Self, Pkcs11SignerError> {
        let mut pkcs11 = Pkcs11::new(module_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        let slot = get_slot_with_serial_number(&pkcs11, serial_number)?;
        let session = pkcs11.open_ro_session(slot)?;
        session.login(UserType::User, Some(&pin))?;

        // Retrieve private key
        let mut objects = session.find_objects(&[
            Attribute::SignRecover(true),
            Attribute::KeyType(KeyType::EC),
            Attribute::EcParams(EC_SECP256K1.into()),
            Attribute::Id(key_id.clone()),
        ])?;
        let priv_key_handle = match objects.pop() {
            Some(handle) => handle,
            None => return Err(Pkcs11SignerError::KeyNotFound),
        };

        // Retrieve public key
        let mut objects = session.find_objects(&[
            Attribute::Verify(true),
            Attribute::KeyType(KeyType::EC),
            Attribute::EcParams(EC_SECP256K1.into()),
            Attribute::Id(key_id),
        ])?;
        let pub_key_handle = match objects.pop() {
            Some(handle) => handle,
            None => return Err(Pkcs11SignerError::KeyNotFound),
        };

        // Retrieve public key parameters
        let mut attrs = session.get_attributes(pub_key_handle, &[AttributeType::Value])?;
        let ec_point = match attrs.pop() {
            Some(Attribute::Value(value)) => {
                let length = value.len();
                // Uncompressed format: 0x04 | len (=65) | 0x04 | X (32 bytes) | Y (32 bytes)
                if length > 2 && value[0] == 4 && value[1] as usize == length - 2 {
                    value
                } else {
                    return Err(Pkcs11SignerError::WrongKeyParams);
                }
            }
            _ => return Err(Pkcs11SignerError::KeyParamsNotFound),
        };

        // Convert public key params to `Address`
        let hash = keccak256(&ec_point[3..]);
        let address = Address::from_slice(&hash[12..]);

        // Convert public key params to `VerifyingKey`
        let pubkey = VerifyingKey::from_sec1_bytes(&ec_point[2..])
            .map_err(|_| Pkcs11SignerError::WrongKey)?;

        Ok(Self { pkcs11, slot, pin, chain_id, priv_key_handle, address, pubkey })
    }

    /// Open PKCS#11 session and login user with PIN.
    fn open_session(&self) -> Result<Session, Pkcs11SignerError> {
        let session = self.pkcs11.open_ro_session(self.slot)?;
        session.login(UserType::User, Some(&self.pin))?;
        Ok(session)
    }

    /// Sign a digest with this signer's key and add the eip155 `v` value
    /// corresponding to the input chain_id
    async fn sign_digest_with_eip155(
        &self,
        digest: H256,
        chain_id: u64,
    ) -> Result<Signature, Pkcs11SignerError> {
        let session = self.open_session()?;
        let sig = session.sign(&Mechanism::Ecdsa, self.priv_key_handle, digest.as_bytes())?;
        let sig = KSig::try_from(sig.as_ref())?;

        let sig = rsig_from_digest_bytes_trial_recovery(&sig, digest.into(), &self.pubkey);

        let mut sig = rsig_to_ethsig(&sig);
        apply_eip155(&mut sig, chain_id);
        Ok(sig)
    }
}

#[async_trait::async_trait]
impl super::Signer for Pkcs11Signer {
    type Error = Pkcs11SignerError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        let digest = hash_message(message.as_ref());
        self.sign_digest_with_eip155(digest, self.chain_id).await
    }

    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature, Self::Error> {
        let mut tx_with_chain = tx.clone();
        let chain_id = tx_with_chain.chain_id().map(|id| id.as_u64()).unwrap_or(self.chain_id);
        tx_with_chain.set_chain_id(chain_id);

        let digest = tx_with_chain.sighash();
        self.sign_digest_with_eip155(digest, chain_id).await
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        let digest =
            payload.encode_eip712().map_err(|e| Self::Error::Eip712Error(e.to_string()))?;

        let session = self.open_session()?;
        let sig = session.sign(&Mechanism::Ecdsa, self.priv_key_handle, &digest)?;
        let sig = KSig::try_from(sig.as_ref())?;
        let sig = rsig_from_digest_bytes_trial_recovery(&sig, digest, &self.pubkey);

        let sig = rsig_to_ethsig(&sig);
        Ok(sig)
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn with_chain_id<T: Into<u64>>(mut self, chain_id: T) -> Self {
        self.chain_id = chain_id.into();
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Signer;
    use std::env::var;

    #[tokio::test]
    async fn test_hsm() {
        let chain_id = 1;
        let module_path = match var("PKCS11_MODULE_PATH") {
            Ok(path) => path,
            _ => return,
        };
        let serial_number = match var("PKCS11_SERIAL_NUMBER") {
            Ok(sn) => sn,
            _ => return,
        };
        let pin = match var("PKCS11_PIN") {
            Ok(pin) => pin,
            _ => return,
        };
        let key_id = match var("PKCS11_KEY_ID") {
            Ok(id) => id,
            _ => return,
        };
        let signer = Pkcs11Signer::new(
            Path::new(&module_path),
            &serial_number,
            pin,
            hex::decode(key_id).unwrap(),
            chain_id,
        )
        .unwrap();

        let message = vec![0, 1, 2, 3];

        let sig = signer.sign_message(message.clone()).await.unwrap();
        assert_eq!(sig.to_vec().len(), 65);
        sig.verify(message.clone(), signer.address).expect("valid signature");
        assert_eq!(sig.recover(message).unwrap(), signer.address());
    }
}
