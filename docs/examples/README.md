# Examples

This section provides practical examples and use cases for the Privacy Engine, demonstrating how to use the library in real-world scenarios.

## Example Categories

### [Multi-Recipient Encryption](./multi-recipient.md)
Learn how to encrypt messages for multiple recipients using different cryptographic protocols.

**Key Features:**
- Encrypt for multiple users simultaneously
- Mix different protocols (Starknet + X25519)
- Efficient key wrapping per recipient
- Cross-protocol compatibility

### [Cross-Protocol Communication](./cross-protocol.md)
See how users with different cryptographic schemes can communicate securely.

**Key Features:**
- Starknet users communicating with X25519 users
- Protocol-agnostic message encryption
- Unified decryption interface
- Real-world interoperability scenarios

### [Integration with ZK Systems](./zk-integration.md)
Explore how to integrate the Privacy Engine with zero-knowledge proof systems.

**Key Features:**
- ZK-compatible key management
- Privacy-preserving encryption
- Integration with Starknet ZK proofs
- Advanced cryptographic primitives

## Quick Examples

### Basic Multi-Recipient Encryption

```rust
use privacy_engine::encrypt::encrypt_message;
use privacy_engine::types::{RecipientInfo, Protocol};

// Prepare message and recipients
let message = b"Hello, secure world!";
let recipients = vec![
    RecipientInfo {
        pubkey: user1_pubkey,
        protocol: Protocol::Starknet,
    },
    RecipientInfo {
        pubkey: user2_pubkey,
        protocol: Protocol::X25519,
    },
];

// Encrypt for all recipients
let result = encrypt_message(message, recipients)?;
```

### Protocol-Specific Key Management

```rust
use privacy_engine::chains::starknet::StarknetProtocol;
use privacy_engine::chains::x25519::X25519Protocol;

// Starknet key generation and signing
let starknet = StarknetProtocol;
let signature = starknet.sign_message(&private_key, &message_hash)?;

// X25519 key exchange
let x25519 = X25519Protocol::new();
let (private_key, public_key) = x25519.generate_keypair()?;
```

### Decryption and Key Recovery

```rust
use privacy_engine::decrypt::decrypt_shared_secret;
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}, Key, Nonce};

// Unwrap symmetric key using recipient's private key
let symmetric_key = decrypt_shared_secret(&recipient_private_key, &wrapped_key)?;

// Decrypt message using symmetric key
let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&symmetric_key));
let nonce = Nonce::from_slice(&result.nonce);
let plaintext = cipher.decrypt(nonce, result.ciphertext.as_ref())?;
```

## Example Applications

### Secure Messaging System

```rust
// Example: Building a secure messaging system
struct SecureMessage {
    content: Vec<u8>,
    recipients: Vec<RecipientInfo>,
    encrypted_result: Option<EncryptResult>,
}

impl SecureMessage {
    fn encrypt(&mut self) -> Result<(), CryptoError> {
        self.encrypted_result = Some(encrypt_message(&self.content, self.recipients.clone())?);
        Ok(())
    }
    
    fn decrypt_for_recipient(&self, private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let result = self.encrypted_result.as_ref().ok_or(CryptoError::EncryptionError("Not encrypted".to_string()))?;
        
        // Find recipient's wrapped key
        let wrapped_key = result.recipient_keys.iter()
            .find(|rk| /* match recipient */)
            .ok_or(CryptoError::EncryptionError("Recipient not found".to_string()))?;
        
        // Decrypt
        let symmetric_key = decrypt_shared_secret(private_key, wrapped_key)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&symmetric_key));
        let nonce = Nonce::from_slice(&result.nonce);
        cipher.decrypt(nonce, result.ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionError("Decryption failed".to_string()))
    }
}
```

### Blockchain Integration

```rust
// Example: Integrating with blockchain systems
struct BlockchainMessage {
    transaction_hash: Vec<u8>,
    signature: Vec<u8>,
    encrypted_payload: EncryptResult,
}

impl BlockchainMessage {
    fn verify_and_decrypt(&self, expected_signer: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Verify signature using Starknet protocol
        let starknet = StarknetProtocol;
        let is_valid = starknet.verify_signature(expected_signer, &self.transaction_hash, &self.signature)?;
        
        if !is_valid {
            return Err(CryptoError::SignatureError("Invalid signature".to_string()));
        }
        
        // Decrypt payload
        let symmetric_key = decrypt_shared_secret(private_key, &self.encrypted_payload.recipient_keys[0])?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&symmetric_key));
        let nonce = Nonce::from_slice(&self.encrypted_payload.nonce);
        cipher.decrypt(nonce, self.encrypted_payload.ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionError("Decryption failed".to_string()))
    }
}
```

### IoT Device Communication

```rust
// Example: Secure communication between IoT devices
struct IoTMessage {
    device_id: String,
    sensor_data: Vec<u8>,
    timestamp: u64,
}

struct IoTSecurity {
    protocol: X25519Protocol,
    device_keypair: (Vec<u8>, Vec<u8>),
}

impl IoTSecurity {
    fn new() -> Self {
        let protocol = X25519Protocol::new();
        let keypair = protocol.generate_keypair().expect("Failed to generate keypair");
        
        Self {
            protocol,
            device_keypair: keypair,
        }
    }
    
    fn encrypt_for_gateway(&self, message: &IoTMessage, gateway_pubkey: &[u8]) -> Result<EncryptedData, CryptoError> {
        let message_bytes = serde_json::to_vec(message).map_err(|_| CryptoError::EncryptionError("Serialization failed".to_string()))?;
        self.protocol.encrypt_key(gateway_pubkey, None, &message_bytes)
    }
    
    fn decrypt_from_device(&self, encrypted: &EncryptedData) -> Result<IoTMessage, CryptoError> {
        let message_bytes = self.protocol.decrypt_key(encrypted, &self.device_keypair.0)?;
        serde_json::from_slice(&message_bytes).map_err(|_| CryptoError::DecryptionError("Deserialization failed".to_string()))
    }
}
```

## Testing Examples

### Running Integration Tests

```bash
# Test multi-recipient encryption with pretty output
cargo test --test starknet_multi -- --nocapture

# Test cross-protocol functionality
cargo test --test cross_protocol -- --nocapture

# Test ZK integration
cargo test --test zk_integration -- --nocapture
```

### Environment Setup for Examples

Create a `.env` file for testing:

```env
# Primary user (Starknet)
TEST_PRIVKEY=0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
TEST_PUBKEY=0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
TEST_MSG_HASH=0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

# Secondary user (for multi-recipient tests)
USER2_PRIVATEKEY=0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
USER2_PUBLICKEY=0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210

# Optional: Secret key for testing
TEST_SECRET_KEY=my_secret_key_for_testing
```

## Performance Examples

### Benchmarking Different Protocols

```rust
use std::time::Instant;

fn benchmark_protocols() {
    let message = b"Benchmark message for performance testing";
    let recipients = vec![
        RecipientInfo { pubkey: starknet_pubkey, protocol: Protocol::Starknet },
        RecipientInfo { pubkey: x25519_pubkey, protocol: Protocol::X25519 },
    ];
    
    // Benchmark encryption
    let start = Instant::now();
    let result = encrypt_message(message, recipients).expect("Encryption failed");
    let encryption_time = start.elapsed();
    
    println!("Encryption time: {:?}", encryption_time);
    println!("Ciphertext size: {} bytes", result.ciphertext.len());
    println!("Total wrapped keys: {}", result.recipient_keys.len());
}
```

### Memory Usage Analysis

```rust
fn analyze_memory_usage() {
    let message = b"Memory usage analysis";
    let recipients = (0..10).map(|i| {
        RecipientInfo {
            pubkey: vec![i; 32], // Dummy key
            protocol: if i % 2 == 0 { Protocol::Starknet } else { Protocol::X25519 },
        }
    }).collect();
    
    let result = encrypt_message(message, recipients).expect("Encryption failed");
    
    println!("Message size: {} bytes", message.len());
    println!("Ciphertext size: {} bytes", result.ciphertext.len());
    println!("Nonce size: {} bytes", result.nonce.len());
    println!("Total wrapped keys size: {} bytes", 
        result.recipient_keys.iter().map(|rk| {
            rk.encrypted_key.ciphertext.len() + 
            rk.encrypted_key.nonce.len() + 
            rk.encrypted_key.ephemeral_pubkey.len()
        }).sum::<usize>());
}
```

## Error Handling Examples

### Comprehensive Error Handling

```rust
fn robust_encryption_example() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Robust error handling example";
    let recipients = vec![
        RecipientInfo { pubkey: user1_pubkey, protocol: Protocol::Starknet },
        RecipientInfo { pubkey: user2_pubkey, protocol: Protocol::X25519 },
    ];
    
    match encrypt_message(message, recipients) {
        Ok(result) => {
            println!("Encryption successful");
            println!("Ciphertext: {} bytes", result.ciphertext.len());
            println!("Recipients: {}", result.recipient_keys.len());
            Ok(())
        }
        Err(CryptoError::EncryptionError(msg)) => {
            eprintln!("Encryption failed: {}", msg);
            Err(msg.into())
        }
        Err(CryptoError::InvalidKeyFormat) => {
            eprintln!("Invalid key format provided");
            Err("Invalid key format".into())
        }
        Err(e) => {
            eprintln!("Unexpected error: {:?}", e);
            Err(e.into())
        }
    }
}
```

## Getting Help

- **Documentation**: Check the [API Reference](../api-reference.md) for detailed function documentation
- **Protocol Details**: See [Protocols](../protocols/README.md) for protocol-specific information
- **Security**: Review [Security](../security.md) considerations
- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Discussions**: Join community discussions for help and ideas

## Contributing Examples

We welcome contributions of new examples! To contribute:

1. **Create a new example file** in the appropriate category
2. **Include comprehensive documentation** explaining the use case
3. **Add tests** to verify the example works correctly
4. **Update this index** to include your new example
5. **Submit a pull request** with your contribution

### Example Template

```markdown
# Example Name

Brief description of what this example demonstrates.

## Use Case

Detailed explanation of when and why you would use this approach.

## Code Example

```rust
// Your example code here
```

## Explanation

Step-by-step explanation of how the code works.

## Testing

How to test this example.

## Related Examples

Links to related examples or documentation.
```
