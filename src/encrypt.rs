use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use crate::types::{EncryptResult, RecipientEncryptedKey, RecipientInfo};
use x25519_dalek::{EphemeralSecret, PublicKey};


fn generate_aes_key() -> Key<Aes256Gcm> {
    Aes256Gcm::generate_key(&mut OsRng)
}


/// Encrypt a message for multiple recipients.
///
/// # Arguments
/// * `cipher_text` - The plaintext message to encrypt.
/// * `pub_keys` - Optional vector of public keys, each as a Vec<u8> (any length, e.g., 32 bytes for Curve25519, or longer for other schemes).
pub fn encrypt_message(cipher_text: String, pub_keys: Option<Vec<Vec<u8>>>) {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    match cipher.encrypt(&nonce, cipher_text.as_bytes()) {
        Ok(encrypted_message) => {
            // Success! Do whatever with encrypted_message
            println!("Encrypted message length: {}", encrypted_message.len());
            // ... continue processing ...
        },
        Err(e) => {
            eprintln!("Encryption failed: {:?}. Retrying with formatted string...", e);
            // Try to format the string: trim, normalize newlines, etc.
            let formatted = cipher_text.trim().replace("\r\n", "\n").replace("\r", "\n");
            match cipher.encrypt(&nonce, formatted.as_bytes()) {
                Ok(encrypted_message) => {
                    println!("Encrypted message length (after formatting): {}", encrypted_message.len());
                    // ... continue processing ...
                },
                Err(e2) => {
                    eprintln!("Encryption failed again: {:?}", e2);
                }
            }
        }
    }
}



pub fn encrypt_shared_secret(
    secret: Key<Aes256Gcm>,
    sender_ephemeral_secret: &EphemeralSecret,
    pub_keys: Option<Vec<Vec<u8>>>,
) -> Result<Vec<RecipientEncryptedKey>, Box<dyn std::error::Error>> {

    
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_generate_aes_key() {
        let key = generate_aes_key();
        // Convert the key to a hex string for easy viewing
        let hex_key = hex::encode(key);
        println!("Generated AES key: {}", hex_key);
        // Optionally, assert the length is 32 bytes
        assert_eq!(key.len(), 32);
    }
}
