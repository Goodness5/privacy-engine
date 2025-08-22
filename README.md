# Privacy Engine 🔐

A multi-protocol cryptographic library for secure message encryption and key management across different blockchain protocols.

[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-GitBook-blue.svg)](docs/README.md)

## 🚀 Features

- **Multi-Protocol Support**: Encrypt messages for recipients using different cryptographic protocols (Starknet, X25519)
- **Hybrid Encryption**: Combines symmetric encryption for messages with asymmetric key wrapping
- **Cross-Protocol Compatibility**: Share encrypted data between users with different cryptographic schemes
- **Zero-Knowledge Ready**: Designed to work with zero-knowledge proof systems
- **Production Ready**: Built with industry-standard cryptographic primitives (AES-256-GCM, ECDSA, X25519)

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
privacy-engine = "0.1.0"
```

## 🎯 Quick Start

### Basic Multi-Recipient Encryption

```rust
use privacy_engine::encrypt::encrypt_message;
use privacy_engine::types::{RecipientInfo, Protocol};

// Encrypt a message for multiple recipients
let message = b"Hello, secure world!";
let recipients = vec![
    RecipientInfo {
        pubkey: user1_pubkey,  // Vec<u8>
        protocol: Protocol::Starknet,
    },
    RecipientInfo {
        pubkey: user2_pubkey,  // Vec<u8>
        protocol: Protocol::X25519,
    },
];

let result = encrypt_message(message, recipients)?;
```

### Decrypting Messages

```rust
use privacy_engine::decrypt::decrypt_shared_secret;
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}, Key, Nonce};

// Unwrap symmetric key using recipient's private key
let symmetric_key = decrypt_shared_secret(&recipient_private_key, &wrapped_key)?;

// Decrypt message using symmetric key
let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&symmetric_key));
let nonce = Nonce::from_slice(&result.nonce);
let plaintext = cipher.decrypt(nonce, result.ciphertext.as_ref())?;

println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));
```

## 🔧 Supported Protocols

| Protocol | Curve | Key Size | Signature | Key Recovery | Use Case |
|----------|-------|----------|-----------|--------------|----------|
| **Starknet** | Stark Curve | 32 bytes | ✅ ECDSA | ✅ Yes | Blockchain, ZK systems |
| **X25519** | Curve25519 | 32 bytes | ❌ No | ❌ No | Standard key exchange |

## 🏗️ Architecture

The Privacy Engine uses a hybrid encryption approach:

1. **Message Encryption**: AES-256-GCM for message content
2. **Key Wrapping**: Protocol-specific asymmetric encryption for symmetric keys
3. **Multi-Recipient**: Each recipient gets their own wrapped key
4. **Cross-Protocol**: Different protocols can be mixed in the same encryption

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
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## 🧪 Testing

### Run Integration Tests

```bash
# Test multi-recipient encryption with pretty output
cargo test --test starknet_multi -- --nocapture
```

### Environment Setup

Create a `.env` file for testing:

```env
# Primary user (Starknet)
TEST_PRIVKEY=0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
TEST_PUBKEY=0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
TEST_MSG_HASH=0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

# Secondary user (for multi-recipient tests)
USER2_PRIVATEKEY=0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
USER2_PUBLICKEY=0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

## 📚 Documentation

- **[Getting Started](docs/getting-started.md)** - Setup and basic usage
- **[Architecture](docs/architecture.md)** - Design principles and cryptographic foundations
- **[Protocols](docs/protocols/README.md)** - Detailed protocol documentation
  - [Starknet Protocol](docs/protocols/starknet.md)
  - [X25519 Protocol](docs/protocols/x25519.md)
- **[Examples](docs/examples/README.md)** - Practical use cases and examples
- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Security](docs/security.md)** - Security considerations and best practices

## 🔒 Security Features

- **AES-256-GCM**: Authenticated encryption with 256-bit security
- **Random Nonces**: Fresh random nonces for each encryption
- **Ephemeral Keys**: Fresh ephemeral keys for each operation
- **Protocol Isolation**: Each protocol maintains its security properties
- **Zero-Knowledge Compatible**: Designed for ZK proof systems

## 🚀 Use Cases

- **Secure Messaging**: Multi-recipient encrypted messaging
- **Blockchain Integration**: Secure communication in blockchain applications
- **IoT Security**: Device-to-device encrypted communication
- **Zero-Knowledge Systems**: Privacy-preserving cryptographic applications
- **Cross-Platform**: Interoperability between different cryptographic schemes

## 🛠️ Development

### Project Structure

```
privacy-engine/
├── src/
│   ├── encrypt.rs          # Main encryption functionality
│   ├── decrypt.rs          # Decryption utilities
│   ├── types.rs            # Core data structures
│   ├── traits/
│   │   └── crypto.rs       # Cryptographic protocol trait
│   └── chains/
│       ├── starknet.rs     # Starknet protocol implementation
│       └── x25519.rs       # X25519 protocol implementation
├── tests/
│   └── starknet_multi.rs   # Integration tests
└── docs/                   # Documentation
```

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/contributing.md) for details.

### Development Setup

1. Clone the repository
2. Install Rust 1.70+
3. Run `cargo build` to build the project
4. Run `cargo test` to run tests
5. Create a `.env` file for integration tests

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **[Documentation](docs/README.md)** - Complete documentation
- **[Examples](docs/examples/README.md)** - Usage examples
- **[Security](docs/security.md)** - Security considerations
- **[Issues](https://github.com/your-repo/privacy-engine/issues)** - Bug reports and feature requests

## ⚡ Performance

| Operation | Starknet | X25519 |
|-----------|----------|--------|
| Key Generation | ~2ms | ~1ms |
| Key Agreement | ~3ms | ~2ms |
| Message Encryption | ~1ms | ~1ms |
| Memory Overhead | Medium | Low |

## 🎯 Roadmap

- [ ] **Secp256k1 Protocol**: Bitcoin/Ethereum compatibility
- [ ] **Ed25519 Protocol**: High-performance signatures
- [ ] **P-256 Protocol**: FIPS compliance
- [ ] **Custom Curves**: Specialized use cases
- [ ] **WebAssembly Support**: Browser compatibility
- [ ] **Python Bindings**: Python integration
- [ ] **JavaScript Bindings**: Node.js integration

---

**Privacy Engine** - Secure, multi-protocol cryptographic communication for the modern web. 🔐✨
