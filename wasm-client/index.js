/**
 * Privacy Engine WebAssembly Client - Simplified Version
 * 
 * This module provides a JavaScript/TypeScript interface to the Privacy Engine
 * compiled to WebAssembly for browser usage.
 */

import init, {
    encrypt_message_wasm,
    decrypt_shared_secret_wasm,
    get_supported_protocols,
    validate_public_key,
    get_protocol_info
} from './pkg/privacy_engine.js';

/**
 * Privacy Engine Client Class
 */
export class PrivacyEngineClient {
    constructor() {
        this.initialized = false;
        this.wasmModule = null;
    }

    /**
     * Initialize the WASM module
     * @param {string} wasmPath - Path to the WASM file (optional)
     */
    async init(wasmPath = null) {
        if (this.initialized) {
            return;
        }

        try {
            this.wasmModule = await init(wasmPath);
            this.initialized = true;
            console.log('Privacy Engine WASM module initialized successfully');
        } catch (error) {
            console.error('Failed to initialize Privacy Engine WASM module:', error);
            throw error;
        }
    }

    /**
     * Encrypt a message for multiple recipients
     * @param {Uint8Array} message - The message to encrypt
     * @param {Array} recipients - Array of recipient objects with pubkey and protocol
     * @returns {Promise<Object>} The encryption result
     */
    async encryptMessage(message, recipients) {
        this.ensureInitialized();

        try {
            // Convert recipients to the format expected by the Rust code
            const rustRecipients = recipients.map(recipient => ({
                pubkey: Array.from(recipient.pubkey),
                protocol: recipient.protocol
            }));

            const recipientsJson = JSON.stringify(rustRecipients);
            const resultJson = encrypt_message_wasm(message, recipientsJson);
            return JSON.parse(resultJson);
        } catch (error) {
            console.error('Encryption failed:', error);
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt a shared secret using recipient's private key
     * @param {Uint8Array} privateKey - Recipient's private key
     * @param {Object} encryptedKey - The encrypted key object
     * @returns {Promise<Uint8Array>} The decrypted symmetric key
     */
    async decryptSharedSecret(privateKey, encryptedKey) {
        this.ensureInitialized();

        try {
            const encryptedKeyJson = JSON.stringify(encryptedKey);
            const result = decrypt_shared_secret_wasm(privateKey, encryptedKeyJson);
            return new Uint8Array(result);
        } catch (error) {
            console.error('Key decryption failed:', error);
            throw new Error(`Key decryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt a message using a symmetric key
     * @param {Uint8Array} ciphertext - The encrypted message
     * @param {Uint8Array} nonce - The nonce used for encryption
     * @param {Uint8Array} symmetricKey - The symmetric key
     * @returns {Promise<Uint8Array>} The decrypted message
     */
    async decryptMessage(ciphertext, nonce, symmetricKey) {
        this.ensureInitialized();

        try {
            // Use Web Crypto API for AES-GCM decryption
            const key = await crypto.subtle.importKey(
                'raw',
                symmetricKey,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            const result = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                key,
                ciphertext
            );

            return new Uint8Array(result);
        } catch (error) {
            console.error('Message decryption failed:', error);
            throw new Error(`Message decryption failed: ${error.message}`);
        }
    }

    /**
     * Get list of supported protocols
     * @returns {Array<string>} Array of supported protocol names
     */
    getSupportedProtocols() {
        this.ensureInitialized();
        return JSON.parse(get_supported_protocols());
    }

    /**
     * Validate a public key for a given protocol
     * @param {Uint8Array} pubkey - The public key to validate
     * @param {string} protocol - The protocol name
     * @returns {boolean} True if valid, false otherwise
     */
    validatePublicKey(pubkey, protocol) {
        this.ensureInitialized();
        return validate_public_key(pubkey, protocol);
    }

    /**
     * Get information about a protocol
     * @param {string} protocol - The protocol name
     * @returns {Object} Protocol information
     */
    getProtocolInfo(protocol) {
        this.ensureInitialized();
        return JSON.parse(get_protocol_info(protocol));
    }

    /**
     * Ensure the WASM module is initialized
     * @private
     */
    ensureInitialized() {
        if (!this.initialized) {
            throw new Error('Privacy Engine client not initialized. Call init() first.');
        }
    }
}

/**
 * Wallet Integration Utilities
 */
export class WalletIntegration {
    constructor(privacyEngine) {
        this.privacyEngine = privacyEngine;
    }

    /**
     * Extract public key from a connected wallet
     * @param {Object} wallet - The wallet object (e.g., from WalletConnect, MetaMask, etc.)
     * @param {string} protocol - The protocol to use ('starknet' or 'x25519')
     * @returns {Promise<Uint8Array>} The public key
     */
    async extractPublicKey(wallet, protocol) {
        try {
            switch (protocol.toLowerCase()) {
                case 'starknet':
                    return await this.extractStarknetPublicKey(wallet);
                case 'x25519':
                    return await this.extractX25519PublicKey(wallet);
                default:
                    throw new Error(`Unsupported protocol: ${protocol}`);
            }
        } catch (error) {
            console.error(`Failed to extract public key for ${protocol}:`, error);
            throw error;
        }
    }

    /**
     * Extract Starknet public key from wallet
     * @private
     */
    async extractStarknetPublicKey(wallet) {
        // For Starknet wallets (like ArgentX, Braavos)
        if (wallet.account && wallet.account.address) {
            // Convert address to public key (this is a simplified example)
            // In practice, you'd need to get the actual public key from the wallet
            const address = wallet.account.address;
            // This is a placeholder - actual implementation depends on wallet API
            return new Uint8Array(32); // 32-byte public key
        }
        throw new Error('Invalid Starknet wallet format');
    }

    /**
     * Extract X25519 public key from wallet
     * @private
     */
    async extractX25519PublicKey(wallet) {
        // For X25519, you'd typically generate or derive the key
        // This is a placeholder implementation
        if (wallet.publicKey) {
            return new Uint8Array(wallet.publicKey);
        }
        throw new Error('Invalid X25519 wallet format');
    }

    /**
     * Create recipient info from wallet
     * @param {Object} wallet - The wallet object
     * @param {string} protocol - The protocol to use
     * @returns {Promise<Object>} Recipient info object
     */
    async createRecipientInfo(wallet, protocol) {
        const pubkey = await this.extractPublicKey(wallet, protocol);
        return {
            pubkey: pubkey,
            protocol: protocol
        };
    }
}

/**
 * Utility functions for common operations
 */
export const Utils = {
    /**
     * Convert string to Uint8Array
     * @param {string} str - The string to convert
     * @returns {Uint8Array} The converted bytes
     */
    stringToBytes(str) {
        return new TextEncoder().encode(str);
    },

    /**
     * Convert Uint8Array to string
     * @param {Uint8Array} bytes - The bytes to convert
     * @returns {string} The converted string
     */
    bytesToString(bytes) {
        return new TextDecoder().decode(bytes);
    },

    /**
     * Convert hex string to Uint8Array
     * @param {string} hex - The hex string
     * @returns {Uint8Array} The converted bytes
     */
    hexToBytes(hex) {
        const cleanHex = hex.replace(/^0x/, '');
        const bytes = new Uint8Array(cleanHex.length / 2);
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
        }
        return bytes;
    },

    /**
     * Convert Uint8Array to hex string
     * @param {Uint8Array} bytes - The bytes to convert
     * @returns {string} The hex string
     */
    bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
};

// Export default instance
export default PrivacyEngineClient;