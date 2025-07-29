use serde::{Serialize, Deserialize};

/// Information about a recipient for encrypted messages.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecipientInfo {
    /// Public key of the recipient (e.g., X25519 pubkey).
    pub pubkey: Vec<u8>,

    /// The encrypted symmetric key (keybox) for this recipient.
    pub keybox: Vec<u8>,
}

/// Result of encrypting a message for multiple recipients.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptResult {
    /// The ephemeral public key used in this encryption session.
    pub ephemeral_pubkey: Vec<u8>,

    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,

    /// Metadata for each recipient including pubkey and encrypted keybox.
    pub recipients: Vec<RecipientInfo>,
}


#[derive(Debug)]
pub struct RecipientEncryptedKey {
    pub pubkey: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub nonce: Vec<u8>,
}