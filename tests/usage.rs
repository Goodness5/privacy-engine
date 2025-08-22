
// use privacy_engine::encrypt::encrypt_message;
// use privacy_engine::types::{RecipientInfo, Protocol};

// #[test]
// fn analyze_memory_usage() {
//     use std::time::Instant;
    
//     println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
//     println!("║                        Memory Usage Analysis Test                              ║");
//     println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    
//     let start_time = Instant::now();
//     let message = b"Memory usage analysis for multi-recipient encryption system";
    
//     // Use proper test keys instead of dummy keys
//     let test_pubkey = vec![0x01; 32]; // Valid format for testing
//     let num_recipients = 5;
//     let recipients = (0..num_recipients).map(|i| {
//         RecipientInfo {
//             pubkey: test_pubkey.clone(),
//             protocol: if i % 2 == 0 { Protocol::X25519 } else { Protocol::Starknet },
//         }
//     }).collect();
    
//     println!("📊 Test Configuration:");
//     println!("   • Message length: {} bytes", message.len());
//     println!("   • Number of recipients: {}", num_recipients);
//     println!("   • Protocols: X25519 and Starknet (alternating)");
    
//     let encryption_start = Instant::now();
//     let result = encrypt_message(message, recipients).expect("Encryption failed");
//     let encryption_time = encryption_start.elapsed();
    
//     println!("\n⏱️  Performance Metrics:");
//     println!("   • Total encryption time: {:.2?}", encryption_time);
//     println!("   • Average time per recipient: {:.2?}", encryption_time / num_recipients as u32);
    
//     println!("\n📦 Memory Breakdown:");
//     println!("   • Original message: {} bytes", message.len());
//     println!("   • Encrypted ciphertext: {} bytes", result.ciphertext.len());
//     println!("   • Nonce: {} bytes", result.nonce.len());
//     println!("   • Total overhead: {} bytes", result.ciphertext.len() + result.nonce.len() - message.len());
//     println!("   • Overhead percentage: {:.1}%", 
//         ((result.ciphertext.len() + result.nonce.len()) as f64 / message.len() as f64 - 1.0) * 100.0);
    
//     println!("\n🔑 Recipient Key Wrapping Details:");
//     let mut total_wrapped_size = 0;
//     let mut x25519_count = 0;
//     let mut starknet_count = 0;
    
//     for (i, rk) in result.recipient_keys.iter().enumerate() {
//         let wrapped_size = rk.encrypted_key.ciphertext.len() + 
//                           rk.encrypted_key.nonce.len() + 
//                           rk.encrypted_key.ephemeral_pubkey.len();
//         total_wrapped_size += wrapped_size;
        
//         match rk.protocol {
//             Protocol::X25519 => x25519_count += 1,
//             Protocol::Starknet => starknet_count += 1,
//         }
        
//         println!("   Recipient {} ({:?}):", i + 1, rk.protocol);
//         println!("     • Public key: {} bytes", rk.pubkey.len());
//         println!("     • Wrapped key ciphertext: {} bytes", rk.encrypted_key.ciphertext.len());
//         println!("     • Wrapped key nonce: {} bytes", rk.encrypted_key.nonce.len());
//         println!("     • Ephemeral public key: {} bytes", rk.encrypted_key.ephemeral_pubkey.len());
//         println!("     • Total wrapped key size: {} bytes", wrapped_size);
//     }
    
//     println!("\n📈 Summary Statistics:");
//     println!("   • X25519 recipients: {}", x25519_count);
//     println!("   • Starknet recipients: {}", starknet_count);
//     println!("   • Total wrapped keys size: {} bytes", total_wrapped_size);
//     println!("   • Average wrapped key size: {} bytes", total_wrapped_size / num_recipients);
//     println!("   • Total encrypted data size: {} bytes", 
//         result.ciphertext.len() + result.nonce.len() + total_wrapped_size);
//     println!("   • Total overhead (including key wrapping): {} bytes", 
//         result.ciphertext.len() + result.nonce.len() + total_wrapped_size - message.len());
    
//     let total_time = start_time.elapsed();
//     println!("\n⏱️  Total test time: {:.2?}", total_time);
    
//     println!("\n💾 Memory Efficiency:");
//     let efficiency = (message.len() as f64 / (result.ciphertext.len() + result.nonce.len() + total_wrapped_size) as f64) * 100.0;
//     println!("   • Data efficiency: {:.1}%", efficiency);
//     println!("   • Bytes per recipient: {:.1}", (result.ciphertext.len() + result.nonce.len() + total_wrapped_size) as f64 / num_recipients as f64);
    
//     println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
//     println!("║                              Test Completed                                   ║");
//     println!("╚══════════════════════════════════════════════════════════════════════════════╝");
// }
