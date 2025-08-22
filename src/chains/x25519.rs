use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Key, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey, x25519, X25519_BASEPOINT_BYTES};

use crate::traits::crypto::CryptoProtocol;
use crate::types::{CryptoError, EncryptedData};

pub struct X25519Protocol;

impl X25519Protocol {
    pub fn new() -> Self {
        X25519Protocol
    }

    pub fn generate_ephemeral_keypair(&self) -> Result<(EphemeralSecret, Vec<u8>), CryptoError> {
        let mut rng = OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let pubkey = PublicKey::from(&secret).as_bytes().to_vec();
        Ok((secret, pubkey))
    }

    pub fn derive_shared_secret(&self, secret: EphemeralSecret, pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let recipient_pubkey = PublicKey::from(
            <[u8; 32]>::try_from(pubkey).map_err(|_| CryptoError::PointError)?,
        );
        let shared_secret = secret.diffie_hellman(&recipient_pubkey);
        Ok(shared_secret.as_bytes().to_vec())
    }
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut privkey = [0u8; 32];
        OsRng.fill_bytes(&mut privkey);
        let pubkey = x25519(privkey, X25519_BASEPOINT_BYTES);
        Ok((privkey.to_vec(), pubkey.to_vec()))
    }
}

impl CryptoProtocol for X25519Protocol {
    fn encrypt_key(&self, recipient_identifier: &[u8], _msg_hash: Option<&[u8]>, key: &[u8]) -> Result<EncryptedData, CryptoError> {
        let (eph_secret, ephemeral_pubkey) = self.generate_ephemeral_keypair()?;
        let aes_key_bytes = self.derive_shared_secret(eph_secret, recipient_identifier)?;
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
        let privkey_scalar: [u8; 32] = privkey.try_into().map_err(|_| CryptoError::PointError)?;
        let eph_pubkey_bytes: [u8; 32] = encrypted_data
            .ephemeral_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::PointError)?;
        let shared_secret = x25519(privkey_scalar, eph_pubkey_bytes);
        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret);
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
        let encrypted = protocol.encrypt_key(&pubkey, None, &key).unwrap();
        let decrypted = protocol.decrypt_key(&encrypted, &privkey).unwrap();
        assert_eq!(decrypted, key);
    }
}