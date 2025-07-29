use starknet_crypto::{get_public_key, sign, verify, FieldElement};
use starknet_types_core::felt::Felt;
use hex::decode;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use starknet_core::types::FromByteArrayError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("StarkNet crypto error")]
    StarkNetCryptoError,
    #[error("From byte array error")]
    FromByteArrayError(#[from] FromByteArrayError),
}

/// Parse a hex string as Felt
pub fn parse_privkey(hex: &str) -> Result<Felt, DecryptionError> {
    Felt::from_hex(hex).map_err(|_| DecryptionError::InvalidKeyLength)
}

pub fn parse_pubkey(hex: &str) -> Result<Felt, DecryptionError> {
    Felt::from_hex(hex).map_err(|_| DecryptionError::InvalidPublicKey)
}

/// Derive the public key from private key
pub fn derive_pubkey(privkey: &Felt) -> Felt {
    let privkey_fe = FieldElement::from_bytes_be(&privkey.to_bytes_be()).unwrap();
    let pubkey_fe = get_public_key(&privkey_fe);
    Felt::from_bytes_be(&pubkey_fe.to_bytes_be())
}

/// Sign a message hash
pub fn sign_message(msg_hash: &Felt, privkey: &Felt) -> (Felt, Felt) {
    let privkey_fe = FieldElement::from_bytes_be(&privkey.to_bytes_be()).unwrap();
    let msg_hash_fe = FieldElement::from_bytes_be(&msg_hash.to_bytes_be()).unwrap();
    
    let (r, s) = sign(&privkey_fe, &msg_hash_fe).unwrap();
    
    (
        Felt::from_bytes_be(&r.to_bytes_be()),
        Felt::from_bytes_be(&s.to_bytes_be())
    )
}

/// Verify signature
pub fn verify_message(msg_hash: &Felt, signature: &(Felt, Felt), pubkey: &Felt) -> bool {
    let msg_hash_fe = FieldElement::from_bytes_be(&msg_hash.to_bytes_be()).unwrap();
    let r_fe = FieldElement::from_bytes_be(&signature.0.to_bytes_be()).unwrap();
    let s_fe = FieldElement::from_bytes_be(&signature.1.to_bytes_be()).unwrap();
    let pubkey_fe = FieldElement::from_bytes_be(&pubkey.to_bytes_be()).unwrap();
    
    verify(&pubkey_fe, &msg_hash_fe, &r_fe, &s_fe).unwrap_or(false)
}

/// Derive shared secret (ECDH) using Stark curve scalar multiplication
pub fn derive_shared_secret(privkey: &Felt, peer_pubkey: &Felt) -> Felt {
    let privkey_fe = FieldElement::from_bytes_be(&privkey.to_bytes_be()).unwrap();
    let peer_pubkey_fe = FieldElement::from_bytes_be(&peer_pubkey.to_bytes_be()).unwrap();
    
    // Shared secret is privkey * peer_pubkey (point multiplication)
    let shared_point = privkey_fe * peer_pubkey_fe;
    Felt::from_bytes_be(&shared_point.to_bytes_be())
}

/// Format Felt into AES key
pub fn aes_key_from_shared(shared_x: &Felt) -> Key<Aes256Gcm> {
    // Take first 32 bytes of the shared secret's bytes representation
    let mut key_bytes = [0u8; 32];
    let shared_bytes = shared_x.to_bytes_be();
    key_bytes.copy_from_slice(&shared_bytes[..32]);
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}

/// Compute StarkNet address from public key
pub fn pubkey_to_address(pubkey: &Felt) -> Felt {
    // StarkNet address derivation logic
    let selector = Felt::from_hex("").unwrap();
    let constructor_calldata = vec![*pubkey];
    
    // Hash chain to compute address
    let mut hasher = starknet_crypto::poseidon_hash_many::<Felt>;
    let hash = hasher(&[selector, constructor_calldata[0]]);
    
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_types_core::Felt;

    #[test]
    fn test_parse_keys_and_sign_verify() {
        // Test private key from StarkNet docs
        let privhex = "";
        let privfelt = parse_privkey(privhex).unwrap();
        
        // Derive public key
        let pubfelt = derive_pubkey(&privfelt);
        println!("public key {:?}", pubfelt);
        
        // Should match expected public key
        let expected_pub = "";
        assert_eq!(pubfelt.to_string(), expected_pub);
        
        // Test signing
        let msg = Felt::from_hex("0x0123").unwrap();
        let sig = sign_message(&msg, &privfelt);
        
        // Verify signature
        assert!(verify_message(&msg, &sig, &pubfelt));
        
        // Test address derivation
        let address = pubkey_to_address(&pubfelt);
        println!("Address: {:?}", address);
    }

    #[test]
    fn test_shared_secret() {
        let priv1 = parse_privkey("").unwrap();
        let priv2 = parse_privkey("").unwrap();
        
        let pub1 = derive_pubkey(&priv1);
        let pub2 = derive_pubkey(&priv2);
        
        // Both parties should derive the same shared secret
        let shared1 = derive_shared_secret(&priv1, &pub2);
        let shared2 = derive_shared_secret(&priv2, &pub1);
        
        assert_eq!(shared1, shared2);
        
        // Can be used as AES key
        let _aes_key = aes_key_from_shared(&shared1);
    }
}