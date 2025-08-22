use crate::types::{CryptoError, EncryptedData};

pub trait CryptoProtocol {
    fn encrypt_key(
        &self,
        recipient_identifier: &[u8],
        msg_hash: Option<&[u8]>,
        key: &[u8],
    ) -> Result<EncryptedData, CryptoError>;
    fn decrypt_key(
        &self,
        encrypted_data: &EncryptedData,
        privkey: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn sign_message(&self, privkey: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify_signature(
        &self,
        pubkey: &[u8],
        message_hash: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;
}