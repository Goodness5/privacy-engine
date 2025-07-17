# 🔐 Blockchain-Secure Multi-Key Encryption Protocol (Rust)

## Overview

This project implements a **multi-recipient secure encryption protocol** tailored for decentralized systems like blockchain. Inspired by the [age](https://github.com/FiloSottile/age) encryption tool, this system allows data to be encrypted once and decrypted by **any of multiple authorized parties**, without requiring communication between them or re-encryption.

It uses **Elliptic Curve Diffie-Hellman (ECDH)** to derive shared secrets and **Authenticated Encryption with Associated Data (AEAD)** to encrypt the payload securely. This solution ensures high performance, small ciphertext size, and blockchain compatibility.

---

## 🔭 Use Case

You encrypt a message or file once (e.g. a transaction or off-chain agreement), and save it permanently. Multiple parties (e.g. validators, signers, arbiters) can decrypt it independently with their private keys. No need to re-encrypt for each recipient.

---

## 📐 Mathematical Foundations

### 🔑 Key Pairs (ECIES with Curve25519)

Each user has:

* A private key: `sk ∈ ℤp`
* A public key: `pk = sk·G`, where `G` is the generator point on the curve.

We use **Curve25519**, which is:

* A Montgomery curve: `y² = x³ + 486662x² + x`
* Fast, secure, and resistant to known quantum and side-channel attacks.

### 🔄 Shared Secret Generation

Given:

* Sender has ephemeral keypair `(esk, epk)`
* Recipient has static public key `pk_recipient`

Using ECDH:

```
shared_secret = esk · pk_recipient = esk · sk_recipient · G
```

This secret is known only to sender and recipient. It’s used to derive an encryption key.

### 🔐 Symmetric Encryption

From `shared_secret`, we derive an encryption key `k_enc` via HKDF:

```text
k_enc = HKDF(shared_secret || epk || pk_recipient)
```

Then, encrypt the payload with AEAD (e.g., XChaCha20-Poly1305):

```text
ciphertext = AEAD_ENCRYPT(k_enc, plaintext, associated_data)
```

### 📂 Multi-Key Support

We generate an `epk` and encrypt the same message key `k_enc` separately for each recipient:

```
For each pk_i:
  ss_i = ECDH(epk, pk_i)
  k_i  = HKDF(ss_i)
  wrap_i = AEAD_ENCRYPT(k_i, k_enc)
```

Each recipient gets:

* `epk` (common for all)
* `wrap_i` (unique for their pubkey)

To decrypt:

```
Recipient derives ss_i = ECDH(sk_i, epk)
Then unwraps wrap_i with AEAD and k_i to recover k_enc
```

Finally:

```
plaintext = AEAD_DECRYPT(k_enc, ciphertext)
```

---

## 🚀 Blockchain Compatibility

This system is:

* **Stateless**: Decryption doesn’t require on-chain coordination.
* **Tamper-Proof**: Encrypted messages can't be modified without invalidating MAC.
* **Gas Efficient**: Only symmetric keys are used for data; ECC is used only to wrap the key.
* **Trustless**: Recipients don’t need to trust each other or a middleman.

---

## 🔒 Security Guarantees

| Property           | Guarantee                       |
| ------------------ | ------------------------------- |
| Confidentiality    | AEAD encryption w/ unique nonce |
| Integrity          | MAC via Poly1305                |
| Forward Secrecy    | Ephemeral ECDH keys             |
| Multi-party access | Multiple key wraps              |
| Replay resistance  | Nonce + AEAD associated data    |
| Curve safety       | Uses Curve25519 / X25519        |

---

## 🦀 Implementation Notes (Rust)

* Uses `x25519-dalek` for ECDH.
* Uses `aead` crate with `xchacha20poly1305` for encryption.
* Modular design: easily portable to Substrate or Starknet off-chain workers.

---

## 📦 Example Output Structure

```json
{
  "ephemeral_pubkey": "base64(epk)",
  "ciphertext": "base64(data_encrypted)",
  "recipients": [
    {
      "pubkey": "base64(pk_recipient)",
      "encrypted_key": "base64(wrap_i)"
    },
    ...
  ]
}
```