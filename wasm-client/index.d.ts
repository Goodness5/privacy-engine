/**
 * Privacy Engine WebAssembly Client TypeScript Definitions
 */

export interface EncryptResult {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    recipientKeys: RecipientEncryptedKey[];
}

export interface RecipientEncryptedKey {
    pubkey: Uint8Array;
    protocol: string;
    encryptedKey: EncryptedData;
}

export interface EncryptedData {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    ephemeralPubkey: Uint8Array;
}

export interface RecipientInfo {
    pubkey: Uint8Array;
    protocol: string;
}

export interface ProtocolInfo {
    name: string;
    curve: string;
    keySize: number;
    supportsSigning: boolean;
}

export interface Wallet {
    account?: {
        address: string;
        [key: string]: any;
    };
    publicKey?: Uint8Array;
    [key: string]: any;
}

export class PrivacyEngineClient {
    constructor();
    
    /**
     * Initialize the WASM module
     * @param wasmPath - Path to the WASM file (optional)
     */
    init(wasmPath?: string): Promise<void>;
    
    /**
     * Encrypt a message for multiple recipients
     * @param message - The message to encrypt
     * @param recipients - Array of recipient objects with pubkey and protocol
     * @returns The encryption result
     */
    encryptMessage(message: Uint8Array, recipients: RecipientInfo[]): Promise<EncryptResult>;
    
    /**
     * Decrypt a shared secret using recipient's private key
     * @param privateKey - Recipient's private key
     * @param encryptedKey - The encrypted key object
     * @returns The decrypted symmetric key
     */
    decryptSharedSecret(privateKey: Uint8Array, encryptedKey: RecipientEncryptedKey): Promise<Uint8Array>;
    
    /**
     * Decrypt a message using a symmetric key
     * @param ciphertext - The encrypted message
     * @param nonce - The nonce used for encryption
     * @param symmetricKey - The symmetric key
     * @returns The decrypted message
     */
    decryptMessage(ciphertext: Uint8Array, nonce: Uint8Array, symmetricKey: Uint8Array): Promise<Uint8Array>;
    
    /**
     * Get list of supported protocols
     * @returns Array of supported protocol names
     */
    getSupportedProtocols(): string[];
    
    /**
     * Validate a public key for a given protocol
     * @param pubkey - The public key to validate
     * @param protocol - The protocol name
     * @returns True if valid, false otherwise
     */
    validatePublicKey(pubkey: Uint8Array, protocol: string): boolean;
    
    /**
     * Get information about a protocol
     * @param protocol - The protocol name
     * @returns Protocol information
     */
    getProtocolInfo(protocol: string): ProtocolInfo;
}

export class WalletIntegration {
    constructor(privacyEngine: PrivacyEngineClient);
    
    /**
     * Extract public key from a connected wallet
     * @param wallet - The wallet object
     * @param protocol - The protocol to use
     * @returns The public key
     */
    extractPublicKey(wallet: Wallet, protocol: string): Promise<Uint8Array>;
    
    /**
     * Create recipient info from wallet
     * @param wallet - The wallet object
     * @param protocol - The protocol to use
     * @returns Recipient info object
     */
    createRecipientInfo(wallet: Wallet, protocol: string): Promise<RecipientInfo>;
}

export const Utils: {
    /**
     * Convert string to Uint8Array
     * @param str - The string to convert
     * @returns The converted bytes
     */
    stringToBytes(str: string): Uint8Array;
    
    /**
     * Convert Uint8Array to string
     * @param bytes - The bytes to convert
     * @returns The converted string
     */
    bytesToString(bytes: Uint8Array): string;
    
    /**
     * Convert hex string to Uint8Array
     * @param hex - The hex string
     * @returns The converted bytes
     */
    hexToBytes(hex: string): Uint8Array;
    
    /**
     * Convert Uint8Array to hex string
     * @param bytes - The bytes to convert
     * @returns The hex string
     */
    bytesToHex(bytes: Uint8Array): string;
};

export default PrivacyEngineClient;
