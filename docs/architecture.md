# Architecture

This document describes the architectural design and cryptographic foundations of the Privacy Engine.

## Design Principles

### 1. Multi-Protocol Support
The Privacy Engine is designed to support multiple cryptographic protocols simultaneously, allowing users with different cryptographic schemes to participate in secure communication.

### 2. Hybrid Encryption
We use a hybrid encryption approach that combines:
- **Symmetric encryption** (AES-256-GCM) for message content
- **Asymmetric encryption** for key wrapping and distribution

### 3. Protocol Agnostic Interface
The core encryption/decryption logic is protocol-agnostic, with protocol-specific implementations plugged in through a trait-based system.

### 4. Zero-Knowledge Ready
The design is compatible with zero-knowledge proof systems, making it suitable for privacy-preserving applications.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Privacy Engine                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   encrypt.rs    │    │   decrypt.rs    │                │
│  │                 │    │                 │                │
│  │ • Message       │    │ • Key unwrapping│                │
│  │   encryption    │    │ • Message       │                │
│  │ • Key wrapping  │    │   decryption    │                │
│  └─────────────────┘    └─────────────────┘                │
├─────────────────────────────────────────────────────────────┤
│                    Protocol Layer                           │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   Starknet      │    │     X25519      │                │
│  │   Protocol      │    │    Protocol     │                │
│  │                 │    │                 │                │
│  │ • ECDSA         │    │ • Diffie-Hellman│                │
│  │ • Key recovery  │    │ • Key agreement │                │
│  │ • Curve25519    │    │ • X25519 curve  │                │
│  └─────────────────┘    └─────────────────┘                │
├─────────────────────────────────────────────────────────────┤
│                    Core Types                               │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   types.rs      │    │ traits/crypto.rs│                │
│  │                 │    │                 │                │
│  │ • EncryptResult │    │ • CryptoProtocol│                │
│  │ • RecipientInfo │    │   trait         │                │
│  │ • Protocol enum │    │ • Unified API   │                │
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Flow

### Encryption Process

1. **Message Preparation**
   ```
   Plaintext → UTF-8 bytes
   ```

2. **Symmetric Key Generation**
   ```
   Random 32-byte key → AES-256-GCM key
   ```

3. **Message Encryption**
   ```
   Plaintext + AES key + Random nonce → Ciphertext
   ```

4. **Per-Recipient Key Wrapping**
   ```
   For each recipient:
   AES key + Recipient pubkey + Protocol → Wrapped key
   ```

5. **Result Assembly**
   ```
   Ciphertext + Nonce + Wrapped keys → EncryptResult
   ```

### Decryption Process

1. **Key Unwrapping**
   ```
   Wrapped key + Recipient privkey + Protocol → AES key
   ```

2. **Message Decryption**
   ```
   Ciphertext + AES key + Nonce → Plaintext
   ```

## Protocol Implementations

### Starknet Protocol

**Cryptographic Primitives:**
- **Curve**: Stark curve (y² = x³ + x + b)
- **Key Agreement**: ECDH on Stark curve
- **Signature**: ECDSA with key recovery
- **Key Derivation**: SHA-256 of shared secret

**Key Features:**
- Public key recovery from signatures
- Support for both direct public keys and signature-based recovery
- 64-byte ephemeral public keys (x || y coordinates)

### X25519 Protocol

**Cryptographic Primitives:**
- **Curve**: Curve25519
- **Key Agreement**: X25519 Diffie-Hellman
- **Key Derivation**: Direct use of shared secret

**Key Features:**
- Standard X25519 key exchange
- 32-byte ephemeral public keys
- No signature support (key exchange only)

## Data Structures

### Core Types

```rust
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,           // AES-256-GCM encrypted message
    pub nonce: Vec<u8>,               // 12-byte nonce for AES-GCM
    pub recipient_keys: Vec<RecipientEncryptedKey>, // Per-recipient wrapped keys
}

pub struct RecipientEncryptedKey {
    pub pubkey: Vec<u8>,              // Recipient's public key
    pub encrypted_key: EncryptedData, // Wrapped symmetric key
    pub protocol: Protocol,           // Cryptographic protocol used
}

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,          // Encrypted symmetric key
    pub nonce: Vec<u8>,              // Nonce for key encryption
    pub ephemeral_pubkey: Vec<u8>,   // Ephemeral public key
}
```

### Protocol Trait

```rust
pub trait CryptoProtocol {
    fn encrypt_key(
        &self,
        recipient_identifier: &[u8],
        msg_hash: Option<&[u8]>,
        key: &[u8],
    ) -> Result<EncryptedData, CryptoError>;
    
    fn decrypt_key(
        &self,
        encrypted_data: &EncryptedData,
        privkey: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    
    fn sign_message(&self, privkey: &[u8], message_hash: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify_signature(&self, pubkey: &[u8], message_hash: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}
```

## Security Considerations

### Cryptographic Strength

- **AES-256-GCM**: Provides authenticated encryption with 256-bit security
- **Random Nonces**: Each encryption uses a fresh random nonce
- **Key Derivation**: Proper key derivation from shared secrets
- **Protocol Isolation**: Each protocol implementation is isolated

### Key Management

- **Ephemeral Keys**: Fresh ephemeral keys for each encryption
- **No Key Reuse**: Symmetric keys are never reused
- **Secure Randomness**: Uses cryptographically secure random number generation

### Protocol Security

- **Starknet**: Based on well-established ECDSA and ECDH
- **X25519**: Standard Curve25519 implementation
- **Hybrid Approach**: Combines best of symmetric and asymmetric crypto

## Performance Characteristics

### Encryption
- **Time Complexity**: O(n) where n is number of recipients
- **Space Complexity**: O(n) for wrapped keys + O(1) for message

### Decryption
- **Time Complexity**: O(1) for single recipient
- **Space Complexity**: O(1) for message size

### Key Sizes
- **AES Key**: 32 bytes
- **Nonce**: 12 bytes
- **Starknet Ephemeral**: 64 bytes (x || y)
- **X25519 Ephemeral**: 32 bytes

## Extensibility

The architecture supports easy addition of new protocols:

1. Implement the `CryptoProtocol` trait
2. Add protocol to the `Protocol` enum
3. Register in the protocol registry
4. Update documentation

This modular design allows for future protocol additions while maintaining backward compatibility.
