# Getting Started

<div align="center">

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; border-radius: 15px; margin: 2rem 0; box-shadow: 0 10px 30px rgba(0,0,0,0.2);">

<h2 style="color: white; margin: 0; font-size: 2rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
🚀 Quick Start Guide
</h2>

<p style="color: rgba(255,255,255,0.9); font-size: 1.1rem; margin: 1rem 0 0 0;">
Get up and running with Privacy Engine in minutes
</p>

</div>

</div>

---

## 📦 Installation

<div style="background: #f8f9fa; border-left: 4px solid #667eea; padding: 1.5rem; margin: 2rem 0; border-radius: 0 8px 8px 0;">

### Prerequisites

- **Rust 1.70+** - Latest stable Rust compiler
- **Cargo** - Rust package manager
- **Git** - Version control system

</div>

### Add to Your Project

<div style="background: #2d3748; color: #e2e8f0; padding: 2rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```toml
[dependencies]
privacy-engine = "0.1.0"
```

</div>

### Build the Project

<div style="background: #2d3748; color: #e2e8f0; padding: 1.5rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```bash
cargo build
```

</div>

## 🎯 Basic Usage

### 1. Import the Library

<div style="background: #2d3748; color: #e2e8f0; padding: 2rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```rust
use privacy_engine::encrypt::encrypt_message;
use privacy_engine::decrypt::decrypt_shared_secret;
use privacy_engine::types::{RecipientInfo, Protocol, EncryptResult};
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}, Key, Nonce};
```

</div>

### 2. Encrypt a Message

<div style="background: #2d3748; color: #e2e8f0; padding: 2rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```rust
// Prepare your message
let message = b"Hello, secure world!";

// Define recipients
let recipients = vec![
    RecipientInfo {
        pubkey: user1_pubkey,  // Vec<u8> - recipient's public key
        protocol: Protocol::Starknet,
    },
    RecipientInfo {
        pubkey: user2_pubkey,  // Vec<u8> - recipient's public key
        protocol: Protocol::X25519,
    },
];

// Encrypt the message
let result: EncryptResult = encrypt_message(message, recipients)?;
```

</div>

### 3. Decrypt a Message

<div style="background: #2d3748; color: #e2e8f0; padding: 2rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```rust
// For each recipient, decrypt using their private key
let recipient_key = &result.recipient_keys[0]; // Get the first recipient's wrapped key

// Unwrap the symmetric key using recipient's private key
let symmetric_key = decrypt_shared_secret(&recipient_private_key, recipient_key)?;

// Decrypt the message using the symmetric key
let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&symmetric_key));
let nonce = Nonce::from_slice(&result.nonce);
let plaintext = cipher.decrypt(nonce, result.ciphertext.as_ref())?;

println!("Decrypted message: {}", String::from_utf8_lossy(&plaintext));
```

</div>

## 🔧 Environment Setup

### For Testing with Starknet

<div style="background: #f8f9fa; border: 2px solid #e2e8f0; padding: 1.5rem; border-radius: 12px; margin: 1rem 0;">

Create a `.env` file in your project root:

<div style="background: #2d3748; color: #e2e8f0; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; font-family: 'Fira Code', monospace; font-size: 0.9rem;">

```env
# User 1 (Primary)
TEST_PRIVKEY=0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
TEST_PUBKEY=0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
TEST_MSG_HASH=0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

# User 2 (Optional)
USER2_PRIVATEKEY=0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
USER2_PUBLICKEY=0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

</div>

</div>

### Key Formats

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin: 2rem 0;">

<div style="background: white; border: 2px solid #667eea; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

<h4 style="margin: 0 0 1rem 0; color: #667eea;">🔗 Starknet</h4>
<p style="margin: 0; color: #4a5568;">Use Felt (Field Element) format as hex strings</p>

</div>

<div style="background: white; border: 2px solid #f5576c; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

<h4 style="margin: 0 0 1rem 0; color: #f5576c;">🔐 X25519</h4>
<p style="margin: 0; color: #4a5568;">Use raw 32-byte keys (can be hex-encoded)</p>

</div>

</div>

## 🧪 Running Tests

### Basic Tests

<div style="background: #2d3748; color: #e2e8f0; padding: 1.5rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```bash
cargo test
```

</div>

### Integration Test with Pretty Output

<div style="background: #2d3748; color: #e2e8f0; padding: 1.5rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```bash
cargo test --test starknet_multi -- --nocapture
```

</div>

<div style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 1.5rem; border-radius: 12px; margin: 1rem 0;">

This will run the multi-recipient encryption test with detailed, formatted output showing each stage of the encryption/decryption process.

</div>

## 📁 Project Structure

<div style="background: #f8f9fa; padding: 2rem; border-radius: 12px; margin: 2rem 0; border: 2px solid #e2e8f0;">

<pre style="background: #2d3748; color: #e2e8f0; padding: 1.5rem; border-radius: 8px; overflow-x: auto; font-family: 'Fira Code', monospace; font-size: 0.9rem; margin: 0;">

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

</pre>

</div>

## 🚀 Quick Examples

### Multi-Recipient Encryption

<div style="background: #2d3748; color: #e2e8f0; padding: 2rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```rust
use privacy_engine::encrypt::encrypt_message;
use privacy_engine::types::{RecipientInfo, Protocol};

// Encrypt for multiple recipients with different protocols
let message = b"Hello, secure world!";
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

let result = encrypt_message(message, recipients)?;
println!("Encrypted for {} recipients", result.recipient_keys.len());
```

</div>

### Protocol-Specific Operations

<div style="background: #2d3748; color: #e2e8f0; padding: 2rem; border-radius: 12px; margin: 1rem 0; font-family: 'Fira Code', monospace;">

```rust
use privacy_engine::chains::starknet::StarknetProtocol;
use privacy_engine::chains::x25519::X25519Protocol;

// Starknet signing and verification
let starknet = StarknetProtocol;
let signature = starknet.sign_message(&private_key, &message_hash)?;
let is_valid = starknet.verify_signature(&public_key, &message_hash, &signature)?;

// X25519 key generation
let x25519 = X25519Protocol::new();
let (private_key, public_key) = x25519.generate_keypair()?;
```

</div>

## 🔍 Troubleshooting

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin: 2rem 0;">

<div style="background: white; border: 2px solid #f5576c; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

<h4 style="margin: 0 0 1rem 0; color: #f5576c;">❌ Compilation Errors</h4>
<p style="margin: 0; color: #4a5568;">Ensure you're using Rust 1.70+ and all dependencies are properly installed.</p>

</div>

<div style="background: white; border: 2px solid #4facfe; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

<h4 style="margin: 0 0 1rem 0; color: #4facfe;">🔑 Missing Dependencies</h4>
<p style="margin: 0; color: #4a5568;">Run `cargo build` to download and compile all required dependencies.</p>

</div>

<div style="background: white; border: 2px solid #43e97b; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

<h4 style="margin: 0 0 1rem 0; color: #43e97b;">🌍 Environment Variables</h4>
<p style="margin: 0; color: #4a5568;">Check that your `.env` file is properly formatted and located in the project root.</p>

</div>

<div style="background: white; border: 2px solid #fa709a; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

<h4 style="margin: 0 0 1rem 0; color: #fa709a;">🔐 Key Format</h4>
<p style="margin: 0; color: #4a5568;">Ensure keys are in the correct format for your chosen protocol.</p>

</div>

</div>

## 📚 Next Steps

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; border-radius: 15px; margin: 2rem 0;">

<h3 style="margin: 0 0 1.5rem 0; text-align: center;">Ready to Learn More?</h3>

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<a href="./architecture.md" style="color: white; text-decoration: none;">
<h4 style="margin: 0 0 0.5rem 0;">🏗️ Architecture</h4>
<p style="margin: 0; font-size: 0.9rem;">Understand the design principles</p>
</a>
</div>

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<a href="./protocols/README.md" style="color: white; text-decoration: none;">
<h4 style="margin: 0 0 0.5rem 0;">🔧 Protocols</h4>
<p style="margin: 0; font-size: 0.9rem;">Learn about supported protocols</p>
</a>
</div>

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<a href="./examples/README.md" style="color: white; text-decoration: none;">
<h4 style="margin: 0 0 0.5rem 0;">💡 Examples</h4>
<p style="margin: 0; font-size: 0.9rem;">See practical use cases</p>
</a>
</div>

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<a href="./security.md" style="color: white; text-decoration: none;">
<h4 style="margin: 0 0 0.5rem 0;">🔒 Security</h4>
<p style="margin: 0; font-size: 0.9rem;">Security best practices</p>
</a>
</div>

</div>

</div>

## 🆘 Getting Help

<div style="background: #f8f9fa; border-left: 4px solid #667eea; padding: 1.5rem; margin: 2rem 0; border-radius: 0 8px 8px 0;">

- **📖 Documentation**: Check the [API Reference](./api-reference.md) for detailed function documentation
- **💡 Examples**: Review the [Examples](./examples/README.md) for working code samples
- **🐛 Issues**: Open an issue on GitHub for bugs or feature requests
- **💬 Discussions**: Join community discussions for help and ideas

</div>

---

<div style="text-align: center; margin: 3rem 0; color: #718096;">

**Ready to build secure, multi-protocol applications?** 🚀

<br><br>

<a href="./architecture.md" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 0.75rem 1.5rem; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 0 0.5rem;">Continue to Architecture →</a>

<a href="./protocols/README.md" style="display: inline-block; background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%); color: white; padding: 0.75rem 1.5rem; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 0 0.5rem;">Explore Protocols →</a>

</div>
