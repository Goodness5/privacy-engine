use dotenv::dotenv;
use std::env;

use privacy_engine::encrypt::encrypt_message;
use privacy_engine::decrypt::decrypt_shared_secret;
use privacy_engine::types::{RecipientInfo, Protocol};
use starknet_types_core::felt::Felt;
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}, Key, Nonce};

fn read_felt_bytes(var: &str) -> Vec<u8> {
    env::var(var)
        .expect(var)
        .parse::<Felt>()
        .expect("invalid felt hex string")
        .to_bytes_be()
        .to_vec()
}

fn read_user2_bytes(key: &str, fallback: &str) -> Vec<u8> {
    if let Ok(v) = env::var(key) {
        v.parse::<Felt>().expect("invalid felt hex").to_bytes_be().to_vec()
    } else if let Ok(v) = env::var(fallback) {
        v.parse::<Felt>().expect("invalid felt hex").to_bytes_be().to_vec()
    } else {
        panic!("{} or {} must be set", key, fallback)
    }
}

#[test]
fn encrypt_agreement_for_two_and_decrypt_each() {
    dotenv().ok();

    // User1 (primary env)
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           Stage: Load User1 Environment                     ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let user1_priv = read_felt_bytes("TEST_PRIVKEY");
    let user1_pub = read_felt_bytes("TEST_PUBKEY");
    // Do not print private keys
    println!("  📋 user1_pub_hex      : {}", hex::encode(&user1_pub));

    // User2 (support both uppercase and lowercase variable names as described)
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           Stage: Load User2 Environment                     ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let user2_priv = read_user2_bytes("USER2_PRIVATEKEY", "user2_privatekey");
    let user2_pub = read_user2_bytes("USER2_PUBLICKEY", "user2_publickey");
    // Do not print private keys
    println!("  📋 user2_pub_hex      : {}", hex::encode(&user2_pub));

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                        Stage: Prepare Plaintext Agreement                   ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let agreement = b"This is the agreement text to be shared among two users.".to_vec();
    println!("  📄 agreement_utf8     : {}", String::from_utf8_lossy(&agreement));

    let recipients = vec![
        RecipientInfo { pubkey: user1_pub.clone(), protocol: Protocol::Starknet },
        RecipientInfo { pubkey: user2_pub.clone(), protocol: Protocol::Starknet },
    ];

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║              Stage: Encrypt Message & Wrap Symmetric Key Per Recipient      ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let result = encrypt_message(&agreement, recipients).expect("encrypt ok");

    println!("  🔐 message_ciphertext_hex : {}", hex::encode(&result.ciphertext));
    println!("  🔑 message_nonce_hex      : {}", hex::encode(&result.nonce));

    for (i, rk) in result.recipient_keys.iter().enumerate() {
        println!("\n  ┌───────────────── Wrapped Key for Recipient {} ─────────────────┐", i + 1);
        println!("  │ protocol                    : {:?}", rk.protocol);
        println!("  │ recipient_pubkey_hex        : {}", hex::encode(&rk.pubkey));
        println!("  │ wrapped_ephemeral_pubkey_hex: {}", hex::encode(&rk.encrypted_key.ephemeral_pubkey));
        println!("  │ wrapped_key_ciphertext_hex  : {}", hex::encode(&rk.encrypted_key.ciphertext));
        println!("  │ wrapped_key_nonce_hex       : {}", hex::encode(&rk.encrypted_key.nonce));
        println!("  └─────────────────────────────────────────────────────────────────────┘");
    }

    // Decrypt using user1's private key
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                        Stage: User1 Unwrap Symmetric Key                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let user1_wrapped = &result.recipient_keys[0];
    let user1_sym_key = decrypt_shared_secret(&user1_priv, user1_wrapped).expect("user1 unwrap ok");
    println!("  🔓 user1_symmetric_key_hex: {}", hex::encode(&user1_sym_key));
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                   Stage: User1 Decrypt Ciphertext with Symmetric Key        ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let cipher1 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&user1_sym_key));
    let nonce = Nonce::from_slice(&result.nonce);
    let plaintext1 = cipher1.decrypt(nonce, result.ciphertext.as_ref()).expect("user1 decrypt ok");
    println!("  📖 user1_decrypted_plaintext_utf8: {}", String::from_utf8_lossy(&plaintext1));

    // Decrypt using user2's private key
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                        Stage: User2 Unwrap Symmetric Key                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let user2_wrapped = &result.recipient_keys[1];
    let user2_sym_key = decrypt_shared_secret(&user2_priv, user2_wrapped).expect("user2 unwrap ok");
    println!("  🔓 user2_symmetric_key_hex: {}", hex::encode(&user2_sym_key));
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                   Stage: User2 Decrypt Ciphertext with Symmetric Key        ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    let cipher2 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&user2_sym_key));
    let plaintext2 = cipher2.decrypt(nonce, result.ciphertext.as_ref()).expect("user2 decrypt ok");
    println!("  📖 user2_decrypted_plaintext_utf8: {}", String::from_utf8_lossy(&plaintext2));

    assert_eq!(plaintext1, agreement);
    assert_eq!(plaintext2, agreement);
}


