# Supported Protocols

The Privacy Engine supports multiple cryptographic protocols, allowing secure communication between parties using different cryptographic schemes.

## Protocol Overview

| Protocol | Curve | Key Size | Signature | Key Recovery | Use Case |
|----------|-------|----------|-----------|--------------|----------|
| **Starknet** | Stark Curve | 32 bytes | ✅ ECDSA | ✅ Yes | Blockchain, ZK systems |
| **X25519** | Curve25519 | 32 bytes | ❌ No | ❌ No | Standard key exchange |

## Protocol Selection

### When to Use Starknet Protocol

- **Blockchain Integration**: When working with Starknet or compatible blockchains
- **Zero-Knowledge Systems**: For applications requiring ZK proof compatibility
- **Signature Recovery**: When you need to recover public keys from signatures
- **Advanced Features**: When you need ECDSA signing and verification

### When to Use X25519 Protocol

- **Standard Key Exchange**: For traditional Diffie-Hellman key exchange
- **Performance**: When you need maximum performance for key agreement
- **Compatibility**: When working with systems that expect standard X25519
- **Simplicity**: When you only need key exchange without signatures

## Protocol Comparison

### Cryptographic Properties

| Property | Starknet | X25519 |
|----------|----------|--------|
| **Curve** | Stark curve (y² = x³ + x + b) | Curve25519 |
| **Key Agreement** | ECDH on Stark curve | X25519 Diffie-Hellman |
| **Signature** | ECDSA with recovery | Not supported |
| **Key Derivation** | SHA-256 of shared secret | Direct use |
| **Ephemeral Key Size** | 64 bytes (x \|\| y) | 32 bytes |
| **Security Level** | 128-bit | 128-bit |

### Performance Characteristics

| Metric | Starknet | X25519 |
|--------|----------|--------|
| **Key Generation** | ~2ms | ~1ms |
| **Key Agreement** | ~3ms | ~2ms |
| **Signature** | ~5ms | N/A |
| **Verification** | ~4ms | N/A |
| **Memory Usage** | Higher | Lower |

## Protocol Implementation Details

### [Starknet Protocol](./starknet.md)
Detailed documentation for the Starknet protocol implementation, including:
- Cryptographic primitives
- Key recovery mechanisms
- Signature schemes
- Integration with Starknet ecosystem

### [X25519 Protocol](./x25519.md)
Comprehensive guide for the X25519 protocol, covering:
- Curve25519 mathematics
- Diffie-Hellman key exchange
- Performance optimizations
- Standard compliance

## Cross-Protocol Communication

The Privacy Engine enables secure communication between users using different protocols:

```rust
// User A uses Starknet, User B uses X25519
let recipients = vec![
    RecipientInfo {
        pubkey: starknet_user_pubkey,
        protocol: Protocol::Starknet,
    },
    RecipientInfo {
        pubkey: x25519_user_pubkey,
        protocol: Protocol::X25519,
    },
];

// Both users can decrypt the same message using their respective protocols
let result = encrypt_message(message, recipients)?;
```

## Adding New Protocols

To add support for a new cryptographic protocol:

1. **Implement the Protocol Trait**
   ```rust
   impl CryptoProtocol for NewProtocol {
       fn encrypt_key(&self, recipient_identifier: &[u8], msg_hash: Option<&[u8]>, key: &[u8]) -> Result<EncryptedData, CryptoError> {
           // Implementation
       }
       
       fn decrypt_key(&self, encrypted_data: &EncryptedData, privkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
           // Implementation
       }
       
       // ... other methods
   }
   ```

2. **Add to Protocol Enum**
   ```rust
   pub enum Protocol {
       Starknet,
       X25519,
       NewProtocol, // Add here
   }
   ```

3. **Register in Protocol Registry**
   ```rust
   fn get_protocol_impl(protocol: Protocol) -> Box<dyn CryptoProtocol> {
       match protocol {
           Protocol::Starknet => Box::new(StarknetProtocol),
           Protocol::X25519 => Box::new(X25519Protocol::new()),
           Protocol::NewProtocol => Box::new(NewProtocol::new()), // Add here
       }
   }
   ```

4. **Update Documentation**
   - Add protocol-specific documentation
   - Update this overview page
   - Include examples and use cases

## Security Considerations

### Protocol-Specific Security

- **Starknet**: Based on well-established ECDSA and ECDH on the Stark curve
- **X25519**: Standard Curve25519 implementation with proven security

### Cross-Protocol Security

- Each protocol maintains its own security properties
- No security degradation when mixing protocols
- All protocols provide equivalent security levels

### Key Management

- Each protocol has its own key format and validation
- Keys are never converted between protocols
- Protocol-specific key derivation ensures isolation

## Future Protocol Support

Planned protocol additions:

- **Secp256k1**: For Bitcoin/Ethereum compatibility
- **Ed25519**: For high-performance signature schemes
- **P-256**: For FIPS compliance
- **Custom Curves**: For specialized use cases

## Protocol Testing

Each protocol includes comprehensive tests:

```bash
# Test specific protocol
cargo test --test starknet_protocol
cargo test --test x25519_protocol

# Test cross-protocol functionality
cargo test --test cross_protocol
```

## Getting Help

- Check protocol-specific documentation for detailed information
- Review the [API Reference](../api-reference.md) for function documentation
- See [Examples](../examples/README.md) for practical use cases
- Open an issue for protocol-specific questions or bugs
