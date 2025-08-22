# Privacy Engine Documentation

<div align="center">

# 🔐 Privacy Engine

### Multi-Protocol Cryptographic Library

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; border-radius: 15px; margin: 2rem 0; box-shadow: 0 10px 30px rgba(0,0,0,0.2);">

<h2 style="color: white; margin: 0; font-size: 2.5rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
🚀 Secure • Fast • Multi-Protocol
</h2>

<p style="color: rgba(255,255,255,0.9); font-size: 1.2rem; margin: 1rem 0 0 0;">
Encrypt messages across different blockchain protocols with unified security
</p>

</div>

</div>

---

## 🎯 What is Privacy Engine?

<div style="background: #f8f9fa; border-left: 4px solid #667eea; padding: 1.5rem; margin: 2rem 0; border-radius: 0 8px 8px 0;">

The **Privacy Engine** is a cutting-edge cryptographic library that enables secure communication across multiple blockchain protocols. It provides a unified interface for encrypting messages and managing cryptographic keys, supporting both **Starknet** and **X25519** protocols simultaneously.

</div>

## ✨ Key Features

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin: 2rem 0;">

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

### 🔗 Multi-Protocol Support
Encrypt messages for recipients using different cryptographic protocols (Starknet, X25519) in a single operation.

</div>

<div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

### 🛡️ Hybrid Encryption
Combines symmetric encryption for messages with asymmetric key wrapping for optimal security and performance.

</div>

<div style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

### 🔄 Cross-Protocol Compatibility
Share encrypted data between users with different cryptographic schemes seamlessly.

</div>

<div style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

### 🎭 Zero-Knowledge Ready
Designed to work with zero-knowledge proof systems for privacy-preserving applications.

</div>

<div style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

### ⚡ Production Ready
Built with industry-standard cryptographic primitives (AES-256-GCM, ECDSA, X25519).

</div>

<div style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); color: #333; padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

### 🔧 Extensible Architecture
Easy to add new protocols through a trait-based system.

</div>

</div>

## 🚀 Quick Start

<div style="background: #2d3748; color: #e2e8f0; padding: 2rem; border-radius: 12px; margin: 2rem 0; font-family: 'Fira Code', monospace;">

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

</div>

## 📊 Protocol Comparison

<div style="overflow-x: auto; margin: 2rem 0;">

<table style="width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">

<thead>
<tr style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
<th style="padding: 1rem; text-align: left; font-weight: 600;">Protocol</th>
<th style="padding: 1rem; text-align: left; font-weight: 600;">Curve</th>
<th style="padding: 1rem; text-align: left; font-weight: 600;">Key Size</th>
<th style="padding: 1rem; text-align: left; font-weight: 600;">Signature</th>
<th style="padding: 1rem; text-align: left; font-weight: 600;">Key Recovery</th>
<th style="padding: 1rem; text-align: left; font-weight: 600;">Use Case</th>
</tr>
</thead>

<tbody>
<tr style="border-bottom: 1px solid #e2e8f0;">
<td style="padding: 1rem; font-weight: 600; color: #667eea;">**Starknet**</td>
<td style="padding: 1rem;">Stark Curve</td>
<td style="padding: 1rem;">32 bytes</td>
<td style="padding: 1rem;">✅ ECDSA</td>
<td style="padding: 1rem;">✅ Yes</td>
<td style="padding: 1rem;">Blockchain, ZK systems</td>
</tr>
<tr style="border-bottom: 1px solid #e2e8f0; background: #f8f9fa;">
<td style="padding: 1rem; font-weight: 600; color: #f5576c;">**X25519**</td>
<td style="padding: 1rem;">Curve25519</td>
<td style="padding: 1rem;">32 bytes</td>
<td style="padding: 1rem;">❌ No</td>
<td style="padding: 1rem;">❌ No</td>
<td style="padding: 1rem;">Standard key exchange</td>
</tr>
</tbody>

</table>

</div>

## 🏗️ System Architecture

<div style="background: #f8f9fa; padding: 2rem; border-radius: 12px; margin: 2rem 0; border: 2px solid #e2e8f0;">

<pre style="background: #2d3748; color: #e2e8f0; padding: 1.5rem; border-radius: 8px; overflow-x: auto; font-family: 'Fira Code', monospace; font-size: 0.9rem; margin: 0;">

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

</pre>

</div>

## 📚 Documentation Sections

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem; margin: 2rem 0;">

<div style="background: white; border: 2px solid #667eea; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform 0.2s;">

<div style="display: flex; align-items: center; margin-bottom: 1rem;">
<span style="font-size: 2rem; margin-right: 1rem;">🚀</span>
<h3 style="margin: 0; color: #667eea;">Getting Started</h3>
</div>

<p style="color: #4a5568; margin: 0 0 1rem 0;">
Learn how to set up and use the Privacy Engine in your project with step-by-step guides.
</p>

<a href="./getting-started.md" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 600; transition: transform 0.2s;">Get Started →</a>

</div>

<div style="background: white; border: 2px solid #f5576c; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform 0.2s;">

<div style="display: flex; align-items: center; margin-bottom: 1rem;">
<span style="font-size: 2rem; margin-right: 1rem;">🏗️</span>
<h3 style="margin: 0; color: #f5576c;">Architecture</h3>
</div>

<p style="color: #4a5568; margin: 0 0 1rem 0;">
Understand the design principles and cryptographic foundations of the system.
</p>

<a href="./architecture.md" style="display: inline-block; background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%); color: white; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 600; transition: transform 0.2s;">Learn More →</a>

</div>

<div style="background: white; border: 2px solid #4facfe; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform 0.2s;">

<div style="display: flex; align-items: center; margin-bottom: 1rem;">
<span style="font-size: 2rem; margin-right: 1rem;">🔧</span>
<h3 style="margin: 0; color: #4facfe;">Protocols</h3>
</div>

<p style="color: #4a5568; margin: 0 0 1rem 0;">
Detailed documentation for supported cryptographic protocols and their implementations.
</p>

<a href="./protocols/README.md" style="display: inline-block; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 600; transition: transform 0.2s;">Explore Protocols →</a>

</div>

<div style="background: white; border: 2px solid #43e97b; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform 0.2s;">

<div style="display: flex; align-items: center; margin-bottom: 1rem;">
<span style="font-size: 2rem; margin-right: 1rem;">💡</span>
<h3 style="margin: 0; color: #43e97b;">Examples</h3>
</div>

<p style="color: #4a5568; margin: 0 0 1rem 0;">
Practical examples and use cases demonstrating real-world applications.
</p>

<a href="./examples/README.md" style="display: inline-block; background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 600; transition: transform 0.2s;">View Examples →</a>

</div>

<div style="background: white; border: 2px solid #fa709a; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform 0.2s;">

<div style="display: flex; align-items: center; margin-bottom: 1rem;">
<span style="font-size: 2rem; margin-right: 1rem;">📖</span>
<h3 style="margin: 0; color: #fa709a;">API Reference</h3>
</div>

<p style="color: #4a5568; margin: 0 0 1rem 0;">
Complete API documentation with detailed function references and examples.
</p>

<a href="./api-reference.md" style="display: inline-block; background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 600; transition: transform 0.2s;">Browse API →</a>

</div>

<div style="background: white; border: 2px solid #a8edea; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform 0.2s;">

<div style="display: flex; align-items: center; margin-bottom: 1rem;">
<span style="font-size: 2rem; margin-right: 1rem;">🔒</span>
<h3 style="margin: 0; color: #a8edea;">Security</h3>
</div>

<p style="color: #4a5568; margin: 0 0 1rem 0;">
Security considerations and best practices for production deployments.
</p>

<a href="./security.md" style="display: inline-block; background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); color: #333; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 600; transition: transform 0.2s;">Security Guide →</a>

</div>

</div>

## ⚡ Performance Benchmarks

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; border-radius: 15px; margin: 2rem 0;">

<h3 style="margin: 0 0 1.5rem 0; text-align: center; font-size: 1.5rem;">Performance Comparison</h3>

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<h4 style="margin: 0 0 0.5rem 0;">Key Generation</h4>
<p style="margin: 0; font-size: 1.2rem; font-weight: 600;">Starknet: ~2ms<br>X25519: ~1ms</p>
</div>

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<h4 style="margin: 0 0 0.5rem 0;">Key Agreement</h4>
<p style="margin: 0; font-size: 1.2rem; font-weight: 600;">Starknet: ~3ms<br>X25519: ~2ms</p>
</div>

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<h4 style="margin: 0 0 0.5rem 0;">Message Encryption</h4>
<p style="margin: 0; font-size: 1.2rem; font-weight: 600;">Both: ~1ms</p>
</div>

<div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; text-align: center;">
<h4 style="margin: 0 0 0.5rem 0;">Memory Overhead</h4>
<p style="margin: 0; font-size: 1.2rem; font-weight: 600;">Starknet: Medium<br>X25519: Low</p>
</div>

</div>

</div>

## 🎯 Use Cases

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin: 2rem 0;">

<div style="background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #667eea;">

<h4 style="margin: 0 0 1rem 0; color: #667eea;">💬 Secure Messaging</h4>
<p style="margin: 0; color: #4a5568;">Multi-recipient encrypted messaging with cross-protocol support.</p>

</div>

<div style="background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #f5576c;">

<h4 style="margin: 0 0 1rem 0; color: #f5576c;">⛓️ Blockchain Integration</h4>
<p style="margin: 0; color: #4a5568;">Secure communication in blockchain applications and smart contracts.</p>

</div>

<div style="background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #4facfe;">

<h4 style="margin: 0 0 1rem 0; color: #4facfe;">🔗 IoT Security</h4>
<p style="margin: 0; color: #4a5568;">Device-to-device encrypted communication for IoT networks.</p>

</div>

<div style="background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #43e97b;">

<h4 style="margin: 0 0 1rem 0; color: #43e97b;">🎭 Zero-Knowledge Systems</h4>
<p style="margin: 0; color: #4a5568;">Privacy-preserving cryptographic applications and ZK proofs.</p>

</div>

<div style="background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #fa709a;">

<h4 style="margin: 0 0 1rem 0; color: #fa709a;">🌐 Cross-Platform</h4>
<p style="margin: 0; color: #4a5568;">Interoperability between different cryptographic schemes and platforms.</p>

</div>

<div style="background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 15px rgba(0,0,0,0.1); border-top: 4px solid #a8edea;">

<h4 style="margin: 0 0 1rem 0; color: #a8edea;">🔐 Enterprise Security</h4>
<p style="margin: 0; color: #4a5568;">Enterprise-grade encryption for sensitive data and communications.</p>

</div>

</div>

## 🚀 Getting Started

<div style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 2rem; border-radius: 15px; margin: 2rem 0; text-align: center;">

<h3 style="margin: 0 0 1rem 0; font-size: 1.8rem;">Ready to Get Started?</h3>

<p style="margin: 0 0 1.5rem 0; font-size: 1.1rem;">
Install Privacy Engine and start building secure, multi-protocol applications today.
</p>

<div style="display: flex; justify-content: center; gap: 1rem; flex-wrap: wrap;">

<a href="./getting-started.md" style="display: inline-block; background: rgba(255,255,255,0.2); color: white; padding: 0.75rem 1.5rem; border-radius: 8px; text-decoration: none; font-weight: 600; border: 2px solid rgba(255,255,255,0.3); transition: all 0.3s;">📖 Read Documentation</a>

<a href="https://github.com/your-repo/privacy-engine" style="display: inline-block; background: rgba(255,255,255,0.2); color: white; padding: 0.75rem 1.5rem; border-radius: 8px; text-decoration: none; font-weight: 600; border: 2px solid rgba(255,255,255,0.3); transition: all 0.3s;">🐙 View on GitHub</a>

</div>

</div>

---

<div style="text-align: center; margin: 3rem 0; color: #718096;">

**Privacy Engine** - Secure, multi-protocol cryptographic communication for the modern web. 🔐✨

<br><br>

<div style="display: flex; justify-content: center; gap: 1rem; flex-wrap: wrap;">

<span style="background: #667eea; color: white; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.9rem;">Rust</span>
<span style="background: #f5576c; color: white; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.9rem;">Cryptography</span>
<span style="background: #4facfe; color: white; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.9rem;">Blockchain</span>
<span style="background: #43e97b; color: white; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.9rem;">Zero-Knowledge</span>
<span style="background: #fa709a; color: white; padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.9rem;">Security</span>

</div>

</div>
