use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Key, Nonce,
};
use crate::types::{EncryptResult, RecipientEncryptedKey, RecipientInfo, Protocol, CryptoError, EncryptedData};
use crate::traits::crypto::CryptoProtocol;
use crate::chains::x25519::X25519Protocol;
use crate::chains::starknet::StarknetProtocol;

fn generate_aes_key() -> Key<Aes256Gcm> {
    Aes256Gcm::generate_key(&mut OsRng)
}

fn get_protocol_impl(protocol: Protocol) -> Box<dyn CryptoProtocol> {
    match protocol {
        Protocol::X25519 => Box::new(X25519Protocol::new()),
        Protocol::Starknet => Box::new(StarknetProtocol),
    }
}

pub fn encrypt_message(message: &[u8], recipients: Vec<RecipientInfo>) -> Result<EncryptResult, CryptoError> {
    let key = generate_aes_key();
    let cipher = Aes256Gcm::new(&key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, message)
        .map_err(|_| CryptoError::SymmetricError)?;

    let mut recipient_keys: Vec<RecipientEncryptedKey> = Vec::with_capacity(recipients.len());
    for recipient in recipients.into_iter() {
        let protocol_impl = get_protocol_impl(recipient.protocol);
        let wrapped: EncryptedData = protocol_impl.encrypt_key(&recipient.pubkey, None, key.as_slice())?;
        recipient_keys.push(RecipientEncryptedKey {
            pubkey: recipient.pubkey,
            encrypted_key: wrapped,
            protocol: recipient.protocol,
        });
    }

    Ok(EncryptResult {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        recipient_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::dotenv;
    use std::env;
    use starknet_types_core::felt::Felt;
    use crate::decrypt::decrypt_shared_secret;

    #[test]
    fn test_generate_aes_key_len() {
        let key = generate_aes_key();
        assert_eq!(key.len(), 32);
    }

    fn load_env_keys() -> (Vec<u8>, Vec<u8>) {
        dotenv().ok();
        let privkey_felt = env
            ::var("TEST_PRIVKEY")
            .expect("TEST_PRIVKEY must be set")
            .parse::<Felt>()
            .expect("Invalid private key format");
        let pubkey_felt = env
            ::var("TEST_PUBKEY")
            .expect("TEST_PUBKEY must be set")
            .parse::<Felt>()
            .expect("Invalid public key format");
        (privkey_felt.to_bytes_be().to_vec(), pubkey_felt.to_bytes_be().to_vec())
    }

    #[test]
    fn test_encrypt_message_and_decrypt_key_starknet() {
        let (privkey_bytes, pubkey_bytes) = load_env_keys();
        let message = b"hello starknet recipients".to_vec();

        let recipients = vec![RecipientInfo { pubkey: pubkey_bytes.clone(), protocol: Protocol::Starknet }];
        let result = encrypt_message(&message, recipients).expect("encrypt ok");

        assert_eq!(result.recipient_keys.len(), 1);
        let enc_key = &result.recipient_keys[0];

        let decrypted_key = decrypt_shared_secret(&privkey_bytes, enc_key).expect("unwrap ok");
        assert_eq!(decrypted_key.len(), 32);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&decrypted_key));
        let nonce = Nonce::from_slice(&result.nonce);
        let plaintext = cipher.decrypt(nonce, result.ciphertext.as_ref()).expect("decrypt msg ok");
        assert_eq!(plaintext, message);
    }
}
