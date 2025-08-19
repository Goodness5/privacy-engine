use thiserror::Error;
use serde::{Serialize, Deserialize};





#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedKey {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("ECDSA sign failed")]
    SignError,
    #[error("Public key recovery failed")]
    RecoverError,
    #[error("Invalid point on curve")]
    PointError,
    #[error("Symmetric encryption/decryption failed")]
    SymmetricError,
    #[error("Scalar conversion failed")]
    ScalarError,
    #[error("Field element conversion failed")]
    FieldError,
    #[error("Decode error")]
    DecodeError,
    #[error("dectypting key failed")]
    DecryptionError(String),
    #[error("Encryption error")]
    EncryptionError(String),
    #[error("Signature error")]
    SignatureError(String),
    #[error("Key generation error")]
    KeyGenerationError(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Invalid key type")]
    InvalidKeyType,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,

}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RecipientEncryptedKey {
    pub pubkey: Vec<u8>,
    pub encrypted_key: EncryptedData,
    pub protocol: Protocol,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum Protocol {
    Starknet,
    X25519,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecipientInfo {
    pub pubkey: Vec<u8>,
    pub protocol: Protocol,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub recipient_keys: Vec<RecipientEncryptedKey>,
}