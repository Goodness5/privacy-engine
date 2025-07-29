use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};
use thiserror::Error;

use crate::types::RecipientEncryptedKey;

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Invalid key length (expected 32)")] InvalidKeyLength,
    #[error("Invalid ephemeral public key length (expected 32)")] InvalidPublicKey,
    #[error("Decryption failed")] DecryptionFailed,
}


pub fn decrypt_shared_secret(
    recipient_private_key: &[u8],
    encrypted: &RecipientEncryptedKey,
) -> Result<Vec<u8>, DecryptionError> {
    let priv_array: [u8; 32] = recipient_private_key.try_into()
        .map_err(|_| DecryptionError::InvalidKeyLength)?;
    let recipient_secret = StaticSecret::from(priv_array);

    let ephem_array: [u8; 32] = encrypted.ephemeral_pubkey.as_slice()
        .try_into().map_err(|_| DecryptionError::InvalidPublicKey)?;
    let sender_pub = PublicKey::from(ephem_array);

    let shared: SharedSecret = recipient_secret.diffie_hellman(&sender_pub);

    let key = Key::<Aes256Gcm>::from_slice(shared.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce_arr: [u8; 12] = encrypted.nonce.as_slice()
        .try_into().expect("Nonce must be 12 bytes");
    cipher.decrypt(Nonce::from_slice(&nonce_arr), encrypted.encrypted_key.as_ref())
        .map_err(|_| DecryptionError::DecryptionFailed)
}








#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{StaticSecret, PublicKey};
    use base64::{decode};
    
    // #[test]
    // #[test]
    // fn test_decrypt_shared_secret_print() {
    //     use super::*;
    
    
    //     let recipient_private_key: [u8; 32] = hex_literal::hex!("");
    //     let recipient_public: [u8; 32] = hex_literal::hex!("");
    //     let ephemeral_pubkey: [u8; 32] = hex_literal::hex!("");
    //     let nonce: [u8; 12] = hex_literal::hex!("");
    //     let encrypted_key: Vec<u8> = hex_literal::hex!("").to_vec();
    
    //     let encrypted = RecipientEncryptedKey {
    //         ephemeral_pubkey: ephemeral_pubkey.to_vec(),
    //         nonce: nonce.to_vec(),
    //         encrypted_key,
    //         pubkey: recipient_public.to_vec(),
    //     };
    
    //     let result = decrypt_shared_secret(&recipient_private_key, &encrypted);
    
    //     match result {
    //         Ok(decrypted) => {
    //             println!("Decrypted key: {:?}", hex::encode(&decrypted));
    //             // assert length or pattern if you expect anything specific
    //             assert!(!decrypted.is_empty());
    //         },
    //         Err(e) => {
    //             println!("Decryption failed: {:?}", e);
    //             panic!("decryption failed when it should not");
    //         }
    //     }
    // }
    
    
}
