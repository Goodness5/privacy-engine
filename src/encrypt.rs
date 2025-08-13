use aes_gcm::{
    aead::{rand_core, Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Key, Nonce
};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use crate::types::{EncryptResult, RecipientEncryptedKey, RecipientInfo};
use x25519_dalek::{EphemeralSecret, PublicKey};
// use rand_core::RngCore;


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



pub fn encrypt_shared_secret_for_recipients(
    secret: &[u8],
    recipients_pubkeys: Vec<Vec<u8>>,
) -> Result<Vec<RecipientEncryptedKey>, Box<dyn std::error::Error>> {
    let mut encrypted_keys = Vec::with_capacity(recipients_pubkeys.len());

    for pubkey_bytes in recipients_pubkeys {
        // Parse recipient public key (more efficient clone handling)
        let recipient_pubkey = PublicKey::from(<[u8; 32]>::try_from(&pubkey_bytes[..])?);

        // Generate ephemeral key pair
        let ephemeral_secret = EphemeralSecret::new(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);
        let ephemeral_pub_bytes = ephemeral_pub.as_bytes().to_vec();

        // Perform X25519 key agreement
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);

        // Derive AES key - consider using HKDF in production for better key derivation
        let aes_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
        let cipher = Aes256Gcm::new(aes_key);

        // Generate random nonce (12 bytes for AES-GCM)
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        // Encrypt the secret
        let encrypted = cipher.encrypt(nonce, secret).unwrap();

        // Store all necessary components for decryption
        encrypted_keys.push(RecipientEncryptedKey {
            pubkey: pubkey_bytes,
            ephemeral_pubkey: ephemeral_pub_bytes,
            encrypted_key: encrypted,
            nonce: nonce.to_vec(),
        });
    }

    Ok(encrypted_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    // #[test]
    // fn test_generate_aes_key() {
    //     let key = generate_aes_key();
    //     // Convert the key to a hex string for easy viewing
    //     let hex_key = hex::encode(key);
    //     println!("Generated AES key: {}", hex_key);
    //     // Optionally, assert the length is 32 bytes
    //     assert_eq!(key.len(), 32);
    // }
}
