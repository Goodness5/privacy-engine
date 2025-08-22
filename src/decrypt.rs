use crate::types::{RecipientEncryptedKey, Protocol, CryptoError};
use crate::traits::crypto::CryptoProtocol;
use crate::chains::x25519::X25519Protocol;
use crate::chains::starknet::StarknetProtocol;

fn get_protocol_impl(protocol: Protocol) -> Box<dyn CryptoProtocol> {
    match protocol {
        Protocol::X25519 => Box::new(X25519Protocol::new()),
        Protocol::Starknet => Box::new(StarknetProtocol),
    }
}

pub fn decrypt_shared_secret(
    recipient_private_key: &[u8],
    encrypted: &RecipientEncryptedKey,
) -> Result<Vec<u8>, CryptoError> {
    let protocol = get_protocol_impl(encrypted.protocol);
    protocol.decrypt_key(&encrypted.encrypted_key, recipient_private_key)
}








#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::dotenv;
    use std::env;
    use starknet_types_core::felt::Felt;
    use crate::types::{RecipientEncryptedKey, Protocol};
    use crate::chains::starknet::StarknetProtocol;

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
    fn test_starknet_encrypt_decrypt_key_with_pubkey() {
        let (privkey_bytes, pubkey_bytes) = load_env_keys();
        let protocol = StarknetProtocol;

        let key_to_wrap = b"sample_symmetric_key_32_bytes_len!!"; // 32 bytes

        let wrapped = protocol
            .encrypt_key(&pubkey_bytes, None, key_to_wrap)
            .expect("wrap ok");

        let enc = RecipientEncryptedKey {
            pubkey: pubkey_bytes.clone(),
            encrypted_key: wrapped,
            protocol: Protocol::Starknet,
        };

        let unwrapped = decrypt_shared_secret(&privkey_bytes, &enc).expect("unwrap ok");
        assert_eq!(unwrapped, key_to_wrap);
    }
}
