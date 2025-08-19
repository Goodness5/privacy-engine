use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Key, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{traits::crypto::CryptoProtocol, types::WrappedKey};
use crate::types::{CryptoError, EncryptedData};

pub struct X25519Protocol;

impl X25519Protocol {
    pub fn new() -> Self {
        X25519Protocol
    }

    pub fn generate_ephemeral_keypair(&self) -> Result<(EphemeralSecret, Vec<u8>), CryptoError> {
        let secret = EphemeralSecret::new(OsRng);
        let pubkey = PublicKey::from(&secret).as_bytes().to_vec();
        Ok((secret, pubkey))
    }

    pub fn derive_shared_secret(&self, secret: &EphemeralSecret, pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let recipient_pubkey = PublicKey::from(
            <[u8; 32]>::try_from(pubkey).map_err(|_| CryptoError::PointError)?,
        );
        let shared_secret = secret.diffie_hellman(&recipient_pubkey);
        Ok(shared_secret.as_bytes().to_vec())
    }
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let secret = StaticSecret::new(OsRng);
        let pubkey = PublicKey::from(&secret).as_bytes().to_vec();
        Ok((secret.to_bytes().to_vec(), pubkey))
    }
}

impl CryptoProtocol for X25519Protocol {
    fn encrypt_key(&self, key: &[u8], _msg_hash: Option<&[u8]>, pubkey: &str) -> Result<WrappedKey, CryptoError> {
        let (eph_secret, ephemeral_pubkey) = self.generate_ephemeral_keypair()?;
        let aes_key_bytes = self.derive_shared_secret(&eph_secret, pubkey)?;
        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
        let cipher = Aes256Gcm::new(aes_key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            ephemeral_pubkey,
        })
    }

    fn decrypt_key(&self, encrypted_data: &EncryptedData, privkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let privkey_scalar = <[u8; 32]>::try_from(privkey).map_err(|_| CryptoError::PointError)?;
        let ephemeral_pubkey = PublicKey::from(
            <[u8; 32]>::try_from(&encrypted_data.ephemeral_pubkey[..])
                .map_err(|_| CryptoError::PointError)?,
        );
        let shared_secret = StaticSecret::from(privkey_scalar).diffie_hellman(&ephemeral_pubkey);
        let aes_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&encrypted_data.nonce);
        cipher
            .decrypt(nonce, encrypted_data.ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
    }



    fn sign_message(&self, _privkey: &[u8], _message_hash: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::SignatureError("X25519 does not support signing".to_string()))
    }

    fn verify_signature(&self, _pubkey: &[u8], _message_hash: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Err(CryptoError::SignatureError("X25519 does not support verification".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CryptoError;

    #[test]
    fn test_generate_keypair() {
        let protocol = X25519Protocol::new();
        let (privkey, pubkey) = protocol.generate_keypair().unwrap();
        assert_eq!(privkey.len(), 32);
        assert_eq!(pubkey.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let protocol = X25519Protocol::new();
        let (privkey, pubkey) = protocol.generate_keypair().unwrap();
        let key = b"test_key_123456789012345678901234".to_vec();
        let encrypted = protocol.encrypt_key(&key, &pubkey).unwrap();
        let decrypted = protocol.decrypt_key(&encrypted, &privkey).unwrap();
        // assert_eq!(decrypted, key);
    }
}