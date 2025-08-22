# Starknet Protocol

The Starknet protocol implementation provides cryptographic primitives specifically designed for the Starknet ecosystem and zero-knowledge proof systems.

## Overview

The Starknet protocol uses the Stark curve (y² = x³ + x + b) and provides:
- **ECDSA signatures** with public key recovery
- **ECDH key agreement** on the Stark curve
- **Key derivation** using SHA-256
- **Signature-based key recovery** for enhanced privacy

## Cryptographic Primitives

### Curve Parameters

- **Curve**: Stark curve (y² = x³ + x + b)
- **Field**: Prime field with characteristic p
- **Base point**: Generator point G
- **Order**: Prime order n

### Key Sizes

- **Private Key**: 32 bytes (field element)
- **Public Key**: 32 bytes (x-coordinate)
- **Ephemeral Public Key**: 64 bytes (x || y coordinates)
- **Signature**: 96 bytes (r || s || v)

## Key Features

### 1. Public Key Recovery

The Starknet protocol supports recovering public keys from signatures and message hashes:

```rust
use privacy_engine::chains::starknet::StarknetProtocol;
use starknet_types_core::felt::Felt;

let protocol = StarknetProtocol;
let signature = protocol.sign_message(&private_key, &message_hash)?;
let recovered_pubkey = StarknetProtocol::recover_pubkey(&message_hash_felt, &signature)?;
```

### 2. Signature-Based Encryption

You can encrypt keys using either:
- **Direct public key**: Standard ECDH key agreement
- **Signature + message hash**: Recover public key first, then perform ECDH

```rust
// Method 1: Direct public key
let encrypted = protocol.encrypt_key(&public_key, None, &symmetric_key)?;

// Method 2: Signature-based (for privacy)
let encrypted = protocol.encrypt_key(&signature, Some(&message_hash), &symmetric_key)?;
```

### 3. ECDSA Signing and Verification

```rust
// Sign a message
let signature = protocol.sign_message(&private_key, &message_hash)?;

// Verify a signature
let is_valid = protocol.verify_signature(&public_key, &message_hash, &signature)?;
```

## Implementation Details

### Key Generation

```rust
// Generate private key (32 bytes)
let private_key: [u8; 32] = /* your private key */;

// Derive public key
let private_felt = Felt::from_bytes_be(&private_key);
let public_felt = /* curve multiplication */;
let public_key = public_felt.to_bytes_be();
```

### Key Agreement

```rust
// Generate ephemeral key pair
let ephemeral_secret = Scalar::from_be_bytes_mod_order(&random_bytes);
let ephemeral_public = AffinePoint::GENERATOR * ephemeral_secret;

// Perform ECDH
let shared_secret = recipient_public * ephemeral_secret;
let shared_x = shared_secret.x_coordinate();

// Derive AES key
let mut hasher = Sha256::new();
hasher.update(shared_x);
let aes_key = hasher.finalize();
```

### Key Recovery

```rust
pub fn recover_pubkey(msg_hash: &Felt, sig: &ExtendedSignature) -> Result<Felt, CryptoError> {
    let msg_fe = CryptoFieldElement::from_bytes_be(&msg_hash.to_bytes_be())?;
    let r_fe = CryptoFieldElement::from_bytes_be(&sig.r.to_bytes_be())?;
    let s_fe = CryptoFieldElement::from_bytes_be(&sig.s.to_bytes_be())?;
    let v_fe = CryptoFieldElement::from_bytes_be(&sig.v.to_bytes_be())?;

    let pubkey_fe = recover(&msg_fe, &r_fe, &s_fe, &v_fe)?;
    Ok(Felt::from_bytes_be(&pubkey_fe.to_bytes_be()))
}
```

## Usage Examples

### Basic Key Encryption

```rust
use privacy_engine::chains::starknet::StarknetProtocol;
use privacy_engine::types::{EncryptedData, CryptoError};

let protocol = StarknetProtocol;
let recipient_pubkey: Vec<u8> = /* recipient's public key */;
let symmetric_key: Vec<u8> = /* 32-byte symmetric key */;

let encrypted: EncryptedData = protocol.encrypt_key(
    &recipient_pubkey,
    None, // No message hash for direct public key
    &symmetric_key
)?;
```

### Signature-Based Encryption

```rust
let signature: Vec<u8> = /* 96-byte signature (r||s||v) */;
let message_hash: Vec<u8> = /* 32-byte message hash */;

let encrypted: EncryptedData = protocol.encrypt_key(
    &signature,
    Some(&message_hash), // Provide message hash for recovery
    &symmetric_key
)?;
```

### Key Decryption

```rust
let recipient_private_key: Vec<u8> = /* recipient's private key */;
let decrypted_key: Vec<u8> = protocol.decrypt_key(&encrypted, &recipient_private_key)?;
```

### Message Signing

```rust
let private_key: Vec<u8> = /* signer's private key */;
let message_hash: Vec<u8> = /* hash of message to sign */;

let signature: Vec<u8> = protocol.sign_message(&private_key, &message_hash)?;
// signature is 96 bytes: r(32) || s(32) || v(32)
```

### Signature Verification

```rust
let public_key: Vec<u8> = /* signer's public key */;
let message_hash: Vec<u8> = /* hash of signed message */;
let signature: Vec<u8> = /* signature to verify */;

let is_valid: bool = protocol.verify_signature(&public_key, &message_hash, &signature)?;
```

## Data Formats

### Public Key Format

```rust
// 32-byte x-coordinate as big-endian bytes
let public_key: Vec<u8> = vec![0x12, 0x34, /* ... 30 more bytes */];
```

### Private Key Format

```rust
// 32-byte field element as big-endian bytes
let private_key: Vec<u8> = vec![0xab, 0xcd, /* ... 30 more bytes */];
```

### Signature Format

```rust
// 96-byte signature: r(32) || s(32) || v(32)
let signature: Vec<u8> = vec![
    // r component (32 bytes)
    0x12, 0x34, /* ... 30 more bytes */,
    // s component (32 bytes)
    0x56, 0x78, /* ... 30 more bytes */,
    // v component (32 bytes)
    0x9a, 0xbc, /* ... 30 more bytes */
];
```

### Ephemeral Public Key Format

```rust
// 64-byte ephemeral key: x(32) || y(32)
let ephemeral_pubkey: Vec<u8> = vec![
    // x-coordinate (32 bytes)
    0x12, 0x34, /* ... 30 more bytes */,
    // y-coordinate (32 bytes)
    0x56, 0x78, /* ... 30 more bytes */,
];
```

## Security Considerations

### Key Management

- **Private Keys**: Never share or log private keys
- **Key Generation**: Use cryptographically secure random number generation
- **Key Storage**: Store keys securely using appropriate key management systems

### Signature Security

- **Nonce Reuse**: Never reuse nonces for different messages
- **Message Hashing**: Always hash messages before signing
- **Verification**: Always verify signatures before processing

### Curve Security

- **Stark Curve**: Well-established curve with proven security
- **ECDSA**: Standard signature scheme with recovery
- **Key Derivation**: SHA-256 provides strong key derivation

## Performance Characteristics

### Timing Benchmarks

| Operation | Average Time | Notes |
|-----------|--------------|-------|
| Key Generation | ~2ms | Includes curve multiplication |
| Key Agreement | ~3ms | ECDH computation |
| Signing | ~5ms | ECDSA with recovery |
| Verification | ~4ms | ECDSA verification |
| Key Recovery | ~6ms | From signature and hash |

### Memory Usage

- **Key Storage**: 32 bytes per key
- **Signature Storage**: 96 bytes per signature
- **Ephemeral Keys**: 64 bytes per encryption
- **Shared Secrets**: 32 bytes (x-coordinate only)

## Integration with Starknet

### Smart Contract Integration

```rust
// Example: Verifying signatures in smart contracts
let signature = /* from transaction */;
let message_hash = /* transaction hash */;
let expected_pubkey = /* expected signer */;

let recovered_pubkey = StarknetProtocol::recover_pubkey(&message_hash, &signature)?;
assert_eq!(recovered_pubkey, expected_pubkey);
```

### Zero-Knowledge Proofs

The Starknet protocol is designed to work with zero-knowledge proof systems:

```rust
// Example: Proving knowledge of private key without revealing it
let private_key = /* secret */;
let public_key = /* derived public key */;

// In ZK proof: prove knowledge of private_key such that
// public_key = private_key * G
// without revealing private_key
```

## Testing

### Unit Tests

```bash
# Run Starknet-specific tests
cargo test --test starknet_protocol

# Run with verbose output
cargo test --test starknet_protocol -- --nocapture
```

### Integration Tests

```bash
# Test multi-recipient encryption with Starknet
cargo test --test starknet_multi -- --nocapture
```

### Test Environment

Create a `.env` file for testing:

```env
TEST_PRIVKEY=0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
TEST_PUBKEY=0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
TEST_MSG_HASH=0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

## Error Handling

### Common Errors

```rust
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("ECDSA sign failed")]
    SignError,
    #[error("Public key recovery failed")]
    RecoverError,
    #[error("Invalid point on curve")]
    PointError,
    #[error("Symmetric encryption/decryption failed")]
    SymmetricError,
    // ... other errors
}
```

### Error Recovery

```rust
match protocol.encrypt_key(&pubkey, None, &key) {
    Ok(encrypted) => {
        // Success
    }
    Err(CryptoError::PointError) => {
        // Invalid public key
    }
    Err(CryptoError::SymmetricError) => {
        // Encryption failed
    }
    Err(e) => {
        // Other errors
    }
}
```

## Best Practices

1. **Always verify signatures** before processing
2. **Use fresh ephemeral keys** for each encryption
3. **Hash messages** before signing
4. **Validate public keys** before use
5. **Handle errors gracefully** in production code
6. **Use secure random number generation** for keys
7. **Store keys securely** using appropriate key management
